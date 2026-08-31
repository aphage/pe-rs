//! CFF-Explorer-style disk PE editor GUI built on the `pe-edit` library.
//!
//! A single-document editor shaped like CFF Explorer: a left-hand PE-structure
//! tree (DOS / COFF / Optional headers, data directories, sections, import &
//! export tables, resources, relocations, TLS, load config, address converter)
//! plus a right-hand content pane. Header fields are edited in place; the
//! Sections node offers an editable section table plus a virtualized raw-data
//! hex view; everything serializes back through the `pe-edit` writer, which
//! re-renders the physical structures on save.
//!
//! Safety: `Save` serializes, re-parses the result and refuses to write a file
//! that no longer parses (round-trip self-check). Every edit sets the dirty
//! flag; opening another file, Save-As or closing the window with unsaved
//! changes is gated behind a confirmation dialog.

// Run without a console window (Windows GUI subsystem).
#![windows_subsystem = "windows"]

// Locale resources are shared with pe-scylla-gui via pe-gui-common; each GUI
// declares its own `i18n!` so `t!` resolves to a backend in this crate.
rust_i18n::i18n!("../pe-gui-common/locales");

use eframe::egui;
use pe_edit::api::{ExportTableEditor, ImportTableEditor, PeEditor};
use pe_edit::domain::section::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use pe_edit::domain::{
    DataDirectory, DataDirectoryIndex, ExportSymbol, ImportFunction, Machine, OptionalHeader,
    PeDocument, RawOffset, ResourceName, Rva,
};
use pe_edit::feature::VaConverter;
use pe_edit::io::pe::{parse, serialize};
use rust_i18n::t;
use std::sync::mpsc;

/// Result of an async file dialog (picked path, or `None` if cancelled).
type PickResult = Option<std::path::PathBuf>;

fn main() -> eframe::Result<()> {
    // Choose the startup language (persisted choice, else system auto-detect)
    // before the window is built so the initial title is already localized.
    pe_gui_common::lang::init_lang();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 720.0])
            .with_title(t!("app.title")),
        ..Default::default()
    };
    eframe::run_native(
        "pe-edit",
        options,
        Box::new(|cc| {
            pe_gui_common::fonts::install_fonts(&cc.egui_ctx);
            pe_gui_common::theme::install_bright_theme(&cc.egui_ctx);
            Ok(Box::new(PeEditApp::default()))
        }),
    )
}

/// Left-hand PE-structure tree nodes (CFF-Explorer style).
#[derive(Default, PartialEq, Clone, Copy)]
enum PeNode {
    #[default]
    Dos,
    Coff,
    Optional,
    DataDirs,
    Sections,
    Imports,
    Exports,
    Resources,
    Relocations,
    Tls,
    LoadConfig,
    Converter,
}

impl PeNode {
    fn all() -> [(PeNode, String); 12] {
        [
            (PeNode::Dos, t!("node.dos").into_owned()),
            (PeNode::Coff, t!("node.coff").into_owned()),
            (PeNode::Optional, t!("node.optional").into_owned()),
            (PeNode::DataDirs, t!("node.data_dirs").into_owned()),
            (PeNode::Sections, t!("node.sections").into_owned()),
            (PeNode::Imports, t!("node.imports").into_owned()),
            (PeNode::Exports, t!("node.exports").into_owned()),
            (PeNode::Resources, t!("node.resources").into_owned()),
            (PeNode::Relocations, t!("node.relocations").into_owned()),
            (PeNode::Tls, t!("node.tls").into_owned()),
            (PeNode::LoadConfig, t!("node.load_config").into_owned()),
            (PeNode::Converter, t!("node.converter").into_owned()),
        ]
    }
}

/// An action that needs confirmation when there are unsaved changes.
#[derive(Default, PartialEq, Clone)]
enum Pending {
    #[default]
    None,
    Open,
    SaveAs,
    Exit,
    OpenPath(String),
}

#[derive(Default)]
struct PeEditApp {
    path: String,
    /// Last "Save As…" path (otherwise Save writes back to `path`).
    save_path: String,
    doc: Option<PeDocument>,
    status: String,
    node: PeNode,
    /// True once a field is edited and not yet saved.
    dirty: bool,
    /// Pending action gated on the unsaved-changes confirmation dialog.
    pending: Pending,

    // Sections node.
    new_section_name: String,
    new_section_size: u32,
    selected_section: usize,
    /// Per-row editable section names (kept in sync with `doc.sections`).
    section_names: Vec<String>,
    binary_scroll_to: Option<u32>,
    binary_jump: String,
    /// Byte-find input for the section hex view.
    binary_find: String,
    /// `false` = disk layout (PointerToRawData / SizeOfRawData), `true` =
    /// memory layout (VirtualAddress / VirtualSize).
    memory_view: bool,

    // Imports node.
    new_import_module: String,
    new_import_func: String,
    selected_import: Option<String>,
    new_import_add_fn: String,
    /// Case-insensitive filter for the import module list.
    import_filter: String,

    // Exports node.
    new_export_ordinal: u16,
    new_export_name: String,
    new_export_rva: u32,

    // Resources node.
    /// `(rva, size)` of the resource leaf selected for byte preview.
    selected_resource: Option<(Rva, u32)>,

    // Cross-tree search.
    search_query: String,
    search_hits: Vec<SearchHit>,
    /// Show the floating search-results list.
    search_active: bool,

    // Address converter node.
    conv_rva: String,
    conv_va: String,
    conv_raw: String,

    /// Pending async "open file" dialog result.
    pick_rx: Option<mpsc::Receiver<PickResult>>,
    /// Pending async "save file" dialog result.
    save_rx: Option<mpsc::Receiver<PickResult>>,

    // Undo / redo (snapshot-based, one snapshot per edit gesture).
    undo_stack: Vec<PeDocument>,
    redo_stack: Vec<PeDocument>,
    /// The document as it stood at the end of the last idle frame — the value
    /// pushed onto the undo stack when a new edit gesture begins.
    undo_baseline: Option<PeDocument>,
    /// `true` while an edit gesture spans consecutive frames.
    gesture_active: bool,
    /// Set by `touch()` whenever an edit mutates the document this frame.
    edited_this_frame: bool,
}

/// Maximum number of undo snapshots kept (each holds a full document copy).
const UNDO_LIMIT: usize = 32;

impl PeEditApp {
    fn sync_section_names(&mut self) {
        self.section_names = self
            .doc
            .as_ref()
            .map(|d| {
                d.sections
                    .iter()
                    .map(|s| s.name_str().to_string())
                    .collect()
            })
            .unwrap_or_default();
    }

    /// Revert to the document snapshot captured before the most recent edit
    /// gesture.
    fn undo(&mut self) {
        if self.undo_stack.is_empty() {
            return;
        }
        if let Some(prev) = self.undo_stack.pop() {
            if let Some(cur) = self.doc.take() {
                self.redo_stack.push(cur);
            }
            self.doc = Some(prev);
        }
        self.after_history_rewind();
    }

    /// Re-apply the most recently undone gesture.
    fn redo(&mut self) {
        if self.redo_stack.is_empty() {
            return;
        }
        if let Some(next) = self.redo_stack.pop() {
            if let Some(cur) = self.doc.take() {
                self.undo_stack.push(cur);
            }
            self.doc = Some(next);
        }
        self.after_history_rewind();
    }

    /// Bookkeeping shared by undo/redo: the restored document becomes the new
    /// baseline, the file is (re)marked dirty, and selection indexes are
    /// clamped so they never dangle after a structural change.
    fn after_history_rewind(&mut self) {
        self.gesture_active = false;
        self.edited_this_frame = false;
        self.undo_baseline = self.doc.clone();
        self.dirty = true;
        self.sync_section_names();
        if let Some(doc) = &self.doc {
            if self.selected_section >= doc.sections.len() {
                self.selected_section = self.selected_section.saturating_sub(1);
            }
            if !doc
                .imports
                .iter()
                .any(|d| self.selected_import.as_ref() == Some(&d.name))
            {
                self.selected_import = None;
            }
        }
    }

    /// Frame-end undo snapshot bookkeeping, run once per frame after all edits.
    /// When a new edit gesture begins (a frame with edits right after an idle
    /// frame), the pre-gesture document is pushed onto the undo stack; when a
    /// gesture ends (an idle frame after edit frames), the baseline is refreshed
    /// for the next gesture.
    fn frame_end(&mut self) {
        let edited = std::mem::take(&mut self.edited_this_frame);
        if edited {
            if !self.gesture_active {
                if let Some(prev) = self.undo_baseline.take() {
                    self.undo_stack.push(prev);
                    if self.undo_stack.len() > UNDO_LIMIT {
                        self.undo_stack.remove(0);
                    }
                    self.redo_stack.clear();
                }
                self.gesture_active = true;
            }
        } else if self.gesture_active {
            self.gesture_active = false;
            self.undo_baseline = self.doc.clone();
        }
    }

    fn load_file(&mut self) {
        match std::fs::read(&self.path) {
            Ok(bytes) => match parse(&bytes) {
                Ok(doc) => {
                    self.doc = Some(doc);
                    self.dirty = false;
                    self.pending = Pending::None;
                    self.selected_section = 0;
                    self.undo_stack.clear();
                    self.redo_stack.clear();
                    self.gesture_active = false;
                    self.edited_this_frame = false;
                    self.undo_baseline = self.doc.clone();
                    self.sync_section_names();
                    self.status = t!("status.loaded", path = &self.path).into_owned();
                }
                Err(e) => self.status = t!("status.parse_failed", err = e.to_string()).into_owned(),
            },
            Err(e) => self.status = t!("status.read_failed", err = e.to_string()).into_owned(),
        }
    }

    /// Serialize the document, re-parse the result (round-trip self-check) and
    /// only then write it to `path`. Refuses to write an image that no longer
    /// parses, so a bad edit cannot be silently saved.
    fn save_to(&mut self, path: String) {
        let Some(doc) = self.doc.as_ref() else {
            self.status = t!("status.no_document").into_owned();
            return;
        };
        match serialize(doc) {
            Ok(bytes) => match parse(&bytes) {
                Ok(_) => {
                    let len = bytes.len();
                    match std::fs::write(&path, bytes) {
                        Ok(()) => {
                            self.dirty = false;
                            self.status = t!("status.saved", len = len, path = &path).into_owned();
                        }
                        Err(e) => {
                            self.status =
                                t!("status.write_failed", err = e.to_string()).into_owned();
                        }
                    }
                }
                Err(e) => {
                    self.status = t!("status.roundtrip_invalid", err = e.to_string()).into_owned();
                }
            },
            Err(e) => self.status = t!("status.serialize_failed", err = e.to_string()).into_owned(),
        }
    }

    /// Save to the document's own path, or the last "Save As…" path; a file
    /// that has no path yet goes through the Save As dialog.
    fn save(&mut self, ctx: &egui::Context) {
        let path = if !self.save_path.trim().is_empty() {
            self.save_path.clone()
        } else if !self.path.trim().is_empty() {
            self.path.clone()
        } else {
            self.save_dialog(ctx);
            return;
        };
        self.save_to(path);
    }

    /// Open a native file dialog on a background thread (avoids blocking the
    /// egui event loop); the result lands in `pick_rx`.
    fn open_dialog(&mut self, ctx: &egui::Context) {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let picked = rfd::FileDialog::new()
                .set_title(t!("dialog.open_pe"))
                .add_filter("PE files", &["exe", "dll", "sys"])
                .pick_file();
            let _ = tx.send(picked);
            ctx.request_repaint();
        });
        self.pick_rx = Some(rx);
    }

    /// Open a native "save as" dialog on a background thread.
    fn save_dialog(&mut self, ctx: &egui::Context) {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let picked = rfd::FileDialog::new()
                .set_title(t!("dialog.save_pe"))
                .add_filter("PE files", &["exe", "dll", "sys"])
                .set_file_name("edited.bin")
                .save_file();
            let _ = tx.send(picked);
            ctx.request_repaint();
        });
        self.save_rx = Some(rx);
    }

    /// Collect a completed async dialog result, clearing the pending slot.
    fn drain_pick(rx: &mut Option<mpsc::Receiver<PickResult>>) -> PickResult {
        let r = rx.as_ref()?;
        match r.try_recv() {
            Ok(f) => {
                rx.take();
                f
            }
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                rx.take();
                None
            }
        }
    }

    // ---- Dirty-gated actions (menu / shortcuts / close) ----

    fn request_open(&mut self, ctx: &egui::Context) {
        if self.dirty && self.doc.is_some() {
            self.pending = Pending::Open;
        } else {
            self.open_dialog(ctx);
        }
    }

    fn request_save_as(&mut self, ctx: &egui::Context) {
        if self.dirty && self.doc.is_some() {
            self.pending = Pending::SaveAs;
        } else {
            self.save_dialog(ctx);
        }
    }

    fn request_exit(&mut self, ctx: &egui::Context) {
        if self.dirty && self.doc.is_some() {
            self.pending = Pending::Exit;
        } else {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn request_open_path(&mut self, path: String) {
        if self.dirty && self.doc.is_some() {
            self.pending = Pending::OpenPath(path);
        } else {
            self.path = path;
            self.load_file();
        }
    }
}

impl eframe::App for PeEditApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Apply results of async file dialogs (spawned on background threads).
        if let Some(path) = Self::drain_pick(&mut self.pick_rx) {
            self.path = path.to_string_lossy().into_owned();
            self.load_file();
        }
        if let Some(path) = Self::drain_pick(&mut self.save_rx) {
            self.save_path = path.to_string_lossy().into_owned();
            self.save_to(self.save_path.clone());
        }

        // Drag-and-drop a PE file onto the window.
        let dropped: Vec<_> = ui.ctx().input(|i| i.raw.dropped_files.clone());
        if let Some(file) = dropped.first() {
            let path = file.path().to_string_lossy().into_owned();
            if !path.is_empty() && self.path != path {
                self.request_open_path(path);
            }
        }

        // Intercept the window close button: with unsaved changes, cancel the
        // close and route it through the confirmation dialog.
        if ui.ctx().input(|i| i.viewport().close_requested()) && self.dirty {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.pending = Pending::Exit;
        }

        // Undo/redo enabled state + pending button flags (the menu/toolbar
        // buttons only set flags here; the action runs once no closure holds a
        // borrow of `self`, just before the central panel renders).
        let can_undo = self.doc.is_some() && !self.undo_stack.is_empty();
        let can_redo = self.doc.is_some() && !self.redo_stack.is_empty();
        let mut want_undo = false;
        let mut want_redo = false;

        // Menu bar.
        egui::Panel::top("menu").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button(t!("menu.file"), |ui| {
                    if ui.button(t!("menu.open")).clicked() {
                        self.request_open(ui.ctx());
                        ui.close();
                    }
                    ui.separator();
                    if ui.button(t!("menu.save")).clicked() {
                        self.save(ui.ctx());
                        ui.close();
                    }
                    if ui.button(t!("menu.save_as")).clicked() {
                        self.request_save_as(ui.ctx());
                        ui.close();
                    }
                    ui.separator();
                    if ui.button(t!("menu.exit")).clicked() {
                        self.request_exit(ui.ctx());
                        ui.close();
                    }
                });
                ui.menu_button(t!("menu.edit"), |ui| {
                    if ui
                        .add_enabled(can_undo, egui::Button::new(t!("menu.undo")))
                        .clicked()
                    {
                        want_undo = true;
                        ui.close();
                    }
                    if ui
                        .add_enabled(can_redo, egui::Button::new(t!("menu.redo")))
                        .clicked()
                    {
                        want_redo = true;
                        ui.close();
                    }
                });
                pe_gui_common::lang::lang_menu(ui, "app.title");
            });
        });

        // Keyboard shortcuts.
        let ctrl_s = ui
            .ctx()
            .input(|i| i.modifiers.command && i.key_pressed(egui::Key::S));
        let ctrl_o = ui
            .ctx()
            .input(|i| i.modifiers.command && i.key_pressed(egui::Key::O));
        let ctrl_z = ui
            .ctx()
            .input(|i| i.modifiers.command && !i.modifiers.shift && i.key_pressed(egui::Key::Z));
        let ctrl_shift_z = ui
            .ctx()
            .input(|i| i.modifiers.command && i.modifiers.shift && i.key_pressed(egui::Key::Z));
        let ctrl_y = ui
            .ctx()
            .input(|i| i.modifiers.command && i.key_pressed(egui::Key::Y));
        if ctrl_s {
            self.save(ui.ctx());
        }
        if ctrl_o {
            self.request_open(ui.ctx());
        }
        if ctrl_z {
            self.undo();
        }
        if ctrl_shift_z || ctrl_y {
            self.redo();
        }

        // Toolbar: undo/redo, file path, File/Memory layout switch, dirty flag.
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(can_undo, egui::Button::new(t!("menu.undo")).small())
                    .on_hover_text("Ctrl+Z")
                    .clicked()
                {
                    want_undo = true;
                }
                if ui
                    .add_enabled(can_redo, egui::Button::new(t!("menu.redo")).small())
                    .on_hover_text("Ctrl+Y / Ctrl+Shift+Z")
                    .clicked()
                {
                    want_redo = true;
                }
                ui.separator();
                ui.label(t!("toolbar.file"));
                if self.path.is_empty() {
                    ui.weak(t!("toolbar.not_open"));
                } else {
                    ui.label(&self.path);
                }
                ui.separator();
                ui.selectable_value(&mut self.memory_view, false, t!("view.file"));
                ui.selectable_value(&mut self.memory_view, true, t!("view.memory"));
                ui.separator();
                ui.label(t!("search.label"));
                let search_edit = ui.add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .desired_width(150.0)
                        .hint_text(t!("search.hint")),
                );
                let find_btn = ui.button(t!("search.find"));
                let submitted = find_btn.clicked()
                    || (search_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                if submitted {
                    self.search_active = true;
                    self.search_hits = self
                        .doc
                        .as_ref()
                        .map(|d| global_search(d, &self.search_query))
                        .unwrap_or_default();
                }
                ui.separator();
                if self.dirty {
                    ui.colored_label(
                        egui::Color32::from_rgb(0x9a, 0x5b, 0x00),
                        format!("● {}", t!("status.modified")),
                    );
                }
                ui.separator();
                ui.label(&self.status);
            });
        });

        // Apply pending undo/redo from the menu/toolbar buttons (no closure
        // holds a borrow of `self` at this point).
        if want_undo {
            self.undo();
        }
        if want_redo {
            self.redo();
        }

        // Left-hand PE structure tree.
        egui::Panel::left("tree")
            .resizable(true)
            .default_size(185.0)
            .frame(pe_gui_common::theme::sidebar_frame())
            .show(ui, |ui| {
                self.show_structure_tree(ui);
            });

        // Cross-tree search results (floating list, anchored under the toolbar).
        if self.search_active && !self.search_hits.is_empty() {
            let mut act: Option<SearchHit> = None;
            egui::Window::new(t!("search.results"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::LEFT_TOP, [210.0, 70.0])
                .default_width(320.0)
                .show(ui.ctx(), |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(260.0)
                        .show(ui, |ui| {
                            for hit in &self.search_hits {
                                if ui.button(&hit.label).clicked() {
                                    act = Some(hit.clone());
                                }
                            }
                        });
                });
            if let Some(hit) = act {
                self.apply_search_hit(&hit);
            }
        }

        // Central content pane.
        egui::CentralPanel::default_margins().show(ui, |ui| {
            if self.doc.is_some() {
                self.show_selected(ui);
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label(t!("guidance.open_pe"));
                });
            }
        });

        // Unsaved-changes confirmation dialog.
        if self.pending != Pending::None {
            let mut discard = false;
            let mut cancel = false;
            egui::Window::new(t!("dialog.unsaved_title"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.label(t!("dialog.unsaved_msg"));
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button(t!("dialog.discard")).clicked() {
                            discard = true;
                        }
                        if ui.button(t!("dialog.cancel")).clicked() {
                            cancel = true;
                        }
                    });
                });
            if discard {
                let action = std::mem::take(&mut self.pending);
                self.dirty = false;
                match action {
                    Pending::Open => self.open_dialog(ui.ctx()),
                    Pending::SaveAs => self.save_dialog(ui.ctx()),
                    Pending::OpenPath(path) => {
                        self.path = path;
                        self.load_file();
                    }
                    Pending::Exit => {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    Pending::None => {}
                }
            } else if cancel {
                self.pending = Pending::None;
            }
        }

        // Undo snapshot bookkeeping (run last, after all edits this frame).
        self.frame_end();
    }
}

impl PeEditApp {
    /// Apply a cross-tree search hit: switch node and select the target entry.
    fn apply_search_hit(&mut self, hit: &SearchHit) {
        self.node = hit.node;
        self.search_active = false;
        match hit.node {
            PeNode::Sections => {
                if let Some(i) = hit.section_index {
                    self.selected_section = i;
                    if let Some(doc) = &self.doc
                        && let Some(s) = doc.sections.get(i)
                    {
                        self.binary_scroll_to = Some(section_base(s, self.memory_view));
                    }
                }
            }
            PeNode::Imports => {
                if let Some(m) = &hit.import_module {
                    self.selected_import = Some(m.clone());
                }
            }
            _ => {}
        }
    }

    /// The left-hand PE-structure tree (CFF-Explorer style).
    fn show_structure_tree(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.strong(t!("app.title"));
        ui.separator();
        for (node, name) in PeNode::all() {
            if ui.selectable_label(self.node == node, name).clicked() {
                self.node = node;
            }
        }
    }

    /// Render the selected left-hand node in the central panel.
    fn show_selected(&mut self, ui: &mut egui::Ui) {
        match self.node {
            PeNode::Dos => self.show_dos(ui),
            PeNode::Coff => self.show_coff(ui),
            PeNode::Optional => self.show_optional(ui),
            PeNode::DataDirs => self.show_directories(ui),
            PeNode::Sections => self.show_sections(ui),
            PeNode::Imports => self.show_imports(ui),
            PeNode::Exports => self.show_exports(ui),
            PeNode::Resources => self.show_resources(ui),
            PeNode::Relocations => self.show_relocations(ui),
            PeNode::Tls => self.show_tls(ui),
            PeNode::LoadConfig => self.show_load_config(ui),
            PeNode::Converter => self.show_converter(ui),
        }
    }

    fn show_dos(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_mut() else { return };
        ui.strong(t!("node.dos"));
        ui.add_space(4.0);
        let mut changed = false;
        egui::ScrollArea::vertical()
            .id_salt("dos_scroll")
            .auto_shrink(false)
            .show(ui, |ui| {
                egui::Grid::new("dos_grid")
                    .num_columns(2)
                    .striped(true)
                    .show(ui, |ui| {
                        changed |= hdr_field(ui, "e_magic", &mut doc.dos.e_magic, 4);
                        changed |= hdr_field(ui, "e_cblp", &mut doc.dos.e_cblp, 4);
                        changed |= hdr_field(ui, "e_cp", &mut doc.dos.e_cp, 4);
                        changed |= hdr_field(ui, "e_crlc", &mut doc.dos.e_crlc, 4);
                        changed |= hdr_field(ui, "e_cparhdr", &mut doc.dos.e_cparhdr, 4);
                        changed |= hdr_field(ui, "e_minalloc", &mut doc.dos.e_minalloc, 4);
                        changed |= hdr_field(ui, "e_maxalloc", &mut doc.dos.e_maxalloc, 4);
                        changed |= hdr_field(ui, "e_ss", &mut doc.dos.e_ss, 4);
                        changed |= hdr_field(ui, "e_sp", &mut doc.dos.e_sp, 4);
                        changed |= hdr_field(ui, "e_csum", &mut doc.dos.e_csum, 4);
                        changed |= hdr_field(ui, "e_ip", &mut doc.dos.e_ip, 4);
                        changed |= hdr_field(ui, "e_cs", &mut doc.dos.e_cs, 4);
                        changed |= hdr_field(ui, "e_lfarlc", &mut doc.dos.e_lfarlc, 4);
                        changed |= hdr_field(ui, "e_ovno", &mut doc.dos.e_ovno, 4);
                        for i in 0..4 {
                            changed |=
                                hdr_field(ui, &format!("e_res[{i}]"), &mut doc.dos.e_res[i], 4);
                        }
                        changed |= hdr_field(ui, "e_oemid", &mut doc.dos.e_oemid, 4);
                        changed |= hdr_field(ui, "e_oeminfo", &mut doc.dos.e_oeminfo, 4);
                        for i in 0..10 {
                            changed |=
                                hdr_field(ui, &format!("e_res2[{i}]"), &mut doc.dos.e_res2[i], 4);
                        }
                        ui.label("e_lfanew");
                        ui.monospace(format!("{:#x}", doc.dos.e_lfanew));
                        ui.end_row();
                        ui.label("stub size");
                        ui.monospace(format!("{} bytes", doc.dos.stub.len()));
                        ui.end_row();
                    });
            });
        if changed {
            self.dirty = true;
            self.edited_this_frame = true;
        }
        ui.add_space(6.0);
        ui.weak(t!("hint.e_lfanew"));
    }

    fn show_coff(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_mut() else { return };
        ui.strong(t!("node.coff"));
        ui.add_space(4.0);
        let mut changed = false;
        egui::Grid::new("coff_grid")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                changed |= machine_field(ui, &mut doc.coff.machine);
                ui.label("number of sections");
                ui.monospace(format!("{}", doc.coff.number_of_sections));
                ui.end_row();
                changed |= hdr_field(ui, "time/date stamp", &mut doc.coff.time_date_stamp, 8);
                changed |= hdr_field(
                    ui,
                    "pointer to symbol table",
                    &mut doc.coff.pointer_to_symbol_table,
                    8,
                );
                changed |= hdr_field(ui, "number of symbols", &mut doc.coff.number_of_symbols, 8);
                ui.label("size of optional header");
                ui.monospace(format!("{}", doc.coff.size_of_optional_header));
                ui.end_row();
                changed |= hdr_field(ui, "characteristics", &mut doc.coff.characteristics, 4);
            });
        if changed {
            self.dirty = true;
            self.edited_this_frame = true;
        }
        ui.add_space(6.0);
        ui.weak(t!("hint.coff_derived"));
    }

    fn show_optional(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_mut() else { return };
        ui.strong(t!("node.optional"));
        ui.add_space(4.0);
        let mut changed = false;
        egui::ScrollArea::vertical()
            .id_salt("optional_scroll")
            .auto_shrink(false)
            .show(ui, |ui| match &mut doc.optional {
                OptionalHeader::Bit32(h) => {
                    egui::Grid::new("optional_grid32")
                        .num_columns(2)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label("magic");
                            ui.monospace(format!("{:#x} (PE32)", h.magic));
                            ui.end_row();
                            changed |= hdr_field(
                                ui,
                                "linker version (major)",
                                &mut h.major_linker_version,
                                2,
                            );
                            changed |= hdr_field(
                                ui,
                                "linker version (minor)",
                                &mut h.minor_linker_version,
                                2,
                            );
                            changed |= hdr_field(ui, "size of code", &mut h.size_of_code, 8);
                            changed |= hdr_field(
                                ui,
                                "size of initialized data",
                                &mut h.size_of_initialized_data,
                                8,
                            );
                            changed |= hdr_field(
                                ui,
                                "size of uninitialized data",
                                &mut h.size_of_uninitialized_data,
                                8,
                            );
                            changed |= hdr_field(
                                ui,
                                "address of entry point",
                                &mut h.address_of_entry_point.0,
                                8,
                            );
                            changed |= hdr_field(ui, "base of code", &mut h.base_of_code.0, 8);
                            changed |= hdr_field(ui, "base of data", &mut h.base_of_data.0, 8);
                            changed |= hdr_field(ui, "image base", &mut h.image_base, 8);
                            changed |=
                                hdr_field(ui, "section alignment", &mut h.section_alignment, 8);
                            changed |= hdr_field(ui, "file alignment", &mut h.file_alignment, 8);
                            changed |= hdr_field(
                                ui,
                                "os version (major)",
                                &mut h.major_operating_system_version,
                                4,
                            );
                            changed |= hdr_field(
                                ui,
                                "os version (minor)",
                                &mut h.minor_operating_system_version,
                                4,
                            );
                            changed |= hdr_field(
                                ui,
                                "image version (major)",
                                &mut h.major_image_version,
                                4,
                            );
                            changed |= hdr_field(
                                ui,
                                "image version (minor)",
                                &mut h.minor_image_version,
                                4,
                            );
                            changed |= hdr_field(
                                ui,
                                "subsystem version (major)",
                                &mut h.major_subsystem_version,
                                4,
                            );
                            changed |= hdr_field(
                                ui,
                                "subsystem version (minor)",
                                &mut h.minor_subsystem_version,
                                4,
                            );
                            changed |=
                                hdr_field(ui, "win32 version value", &mut h.win32_version_value, 8);
                            ui.label("size of image");
                            ui.monospace(format!("{:#x}", h.size_of_image));
                            ui.end_row();
                            ui.label("size of headers");
                            ui.monospace(format!("{:#x}", h.size_of_headers));
                            ui.end_row();
                            changed |= hdr_field(ui, "checksum", &mut h.checksum, 8);
                            changed |= hdr_field(ui, "subsystem", &mut h.subsystem, 4);
                            changed |=
                                hdr_field(ui, "dll characteristics", &mut h.dll_characteristics, 4);
                            changed |= hdr_field(
                                ui,
                                "size of stack reserve",
                                &mut h.size_of_stack_reserve,
                                8,
                            );
                            changed |= hdr_field(
                                ui,
                                "size of stack commit",
                                &mut h.size_of_stack_commit,
                                8,
                            );
                            changed |= hdr_field(
                                ui,
                                "size of heap reserve",
                                &mut h.size_of_heap_reserve,
                                8,
                            );
                            changed |=
                                hdr_field(ui, "size of heap commit", &mut h.size_of_heap_commit, 8);
                            changed |= hdr_field(ui, "loader flags", &mut h.loader_flags, 8);
                            ui.label("number of rva and sizes");
                            ui.monospace(format!("{}", h.number_of_rva_and_sizes));
                            ui.end_row();
                        });
                }
                OptionalHeader::Bit64(h) => {
                    egui::Grid::new("optional_grid64")
                        .num_columns(2)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label("magic");
                            ui.monospace(format!("{:#x} (PE32+)", h.magic));
                            ui.end_row();
                            changed |= hdr_field(
                                ui,
                                "linker version (major)",
                                &mut h.major_linker_version,
                                2,
                            );
                            changed |= hdr_field(
                                ui,
                                "linker version (minor)",
                                &mut h.minor_linker_version,
                                2,
                            );
                            changed |= hdr_field(ui, "size of code", &mut h.size_of_code, 8);
                            changed |= hdr_field(
                                ui,
                                "size of initialized data",
                                &mut h.size_of_initialized_data,
                                8,
                            );
                            changed |= hdr_field(
                                ui,
                                "size of uninitialized data",
                                &mut h.size_of_uninitialized_data,
                                8,
                            );
                            changed |= hdr_field(
                                ui,
                                "address of entry point",
                                &mut h.address_of_entry_point.0,
                                8,
                            );
                            changed |= hdr_field(ui, "base of code", &mut h.base_of_code.0, 8);
                            changed |= hdr_field(ui, "image base", &mut h.image_base, 16);
                            changed |=
                                hdr_field(ui, "section alignment", &mut h.section_alignment, 8);
                            changed |= hdr_field(ui, "file alignment", &mut h.file_alignment, 8);
                            changed |= hdr_field(
                                ui,
                                "os version (major)",
                                &mut h.major_operating_system_version,
                                4,
                            );
                            changed |= hdr_field(
                                ui,
                                "os version (minor)",
                                &mut h.minor_operating_system_version,
                                4,
                            );
                            changed |= hdr_field(
                                ui,
                                "image version (major)",
                                &mut h.major_image_version,
                                4,
                            );
                            changed |= hdr_field(
                                ui,
                                "image version (minor)",
                                &mut h.minor_image_version,
                                4,
                            );
                            changed |= hdr_field(
                                ui,
                                "subsystem version (major)",
                                &mut h.major_subsystem_version,
                                4,
                            );
                            changed |= hdr_field(
                                ui,
                                "subsystem version (minor)",
                                &mut h.minor_subsystem_version,
                                4,
                            );
                            changed |=
                                hdr_field(ui, "win32 version value", &mut h.win32_version_value, 8);
                            ui.label("size of image");
                            ui.monospace(format!("{:#x}", h.size_of_image));
                            ui.end_row();
                            ui.label("size of headers");
                            ui.monospace(format!("{:#x}", h.size_of_headers));
                            ui.end_row();
                            changed |= hdr_field(ui, "checksum", &mut h.checksum, 8);
                            changed |= hdr_field(ui, "subsystem", &mut h.subsystem, 4);
                            changed |=
                                hdr_field(ui, "dll characteristics", &mut h.dll_characteristics, 4);
                            changed |= hdr_field(
                                ui,
                                "size of stack reserve",
                                &mut h.size_of_stack_reserve,
                                16,
                            );
                            changed |= hdr_field(
                                ui,
                                "size of stack commit",
                                &mut h.size_of_stack_commit,
                                16,
                            );
                            changed |= hdr_field(
                                ui,
                                "size of heap reserve",
                                &mut h.size_of_heap_reserve,
                                16,
                            );
                            changed |= hdr_field(
                                ui,
                                "size of heap commit",
                                &mut h.size_of_heap_commit,
                                16,
                            );
                            changed |= hdr_field(ui, "loader flags", &mut h.loader_flags, 8);
                            ui.label("number of rva and sizes");
                            ui.monospace(format!("{}", h.number_of_rva_and_sizes));
                            ui.end_row();
                        });
                }
            });
        if changed {
            self.dirty = true;
            self.edited_this_frame = true;
        }
        ui.add_space(6.0);
        ui.weak(t!("hint.optional_32"));
        ui.weak(t!("hint.optional_derived"));
    }

    fn show_directories(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_mut() else { return };
        while doc.data_directories.len() < DataDirectoryIndex::COUNT {
            doc.data_directories.push(DataDirectory::default());
        }
        ui.strong(t!("node.data_dirs"));
        ui.add_space(4.0);
        let mut changed = false;
        egui::ScrollArea::vertical()
            .id_salt("dirs_scroll")
            .auto_shrink(false)
            .show(ui, |ui| {
                egui::Grid::new("dirs")
                    .num_columns(3)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("Directory");
                        ui.label("RVA");
                        ui.label("Size");
                        ui.end_row();
                        for i in 0..DataDirectoryIndex::COUNT {
                            let name = DataDirectoryIndex::from_usize(i)
                                .map(|d| d.name().to_string())
                                .unwrap_or_default();
                            let dd = &mut doc.data_directories[i];
                            ui.label(name);
                            if is_writer_managed(i) {
                                // Backed by the rich import/export/... forms:
                                // the writer re-renders these on save, so edits
                                // would be overwritten — show them read-only.
                                ui.monospace(format!("{:#x}", dd.rva.get()));
                                ui.monospace(format!("{:#x}", dd.size));
                                ui.end_row();
                            } else {
                                let r = ui.add(
                                    egui::DragValue::new(&mut dd.rva.0).hexadecimal(8, false, true),
                                );
                                let s = ui.add(
                                    egui::DragValue::new(&mut dd.size).hexadecimal(8, false, true),
                                );
                                changed |= r.changed() | s.changed();
                                ui.end_row();
                            }
                        }
                    });
            });
        if changed {
            self.dirty = true;
            self.edited_this_frame = true;
        }
        ui.add_space(6.0);
        ui.weak(t!("hint.dirs_managed"));
    }

    fn show_sections(&mut self, ui: &mut egui::Ui) {
        {
            let Some(doc) = self.doc.as_mut() else { return };
            if self.section_names.len() != doc.sections.len() {
                self.section_names = doc
                    .sections
                    .iter()
                    .map(|s| s.name_str().to_string())
                    .collect();
            }
            let mut remove: Option<usize> = None;
            egui::ScrollArea::vertical()
                .id_salt("sec_table")
                .auto_shrink(false)
                .show(ui, |ui| {
                    egui::Grid::new("sections")
                        .num_columns(7)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label("Name");
                            ui.label("VA");
                            ui.label("VSize");
                            ui.label("RawSize");
                            ui.label("RawPtr");
                            ui.label("Chars");
                            ui.label("");
                            ui.end_row();
                            for (i, s) in doc.sections.iter_mut().enumerate() {
                                let name = &mut self.section_names[i];
                                let resp =
                                    ui.add(egui::TextEdit::singleline(name).desired_width(64.0));
                                if resp.changed() {
                                    s.header.name = name_bytes(name);
                                    self.dirty = true;
                                    self.edited_this_frame = true;
                                }
                                if resp.clicked() {
                                    self.selected_section = i;
                                    self.binary_scroll_to = Some(section_base(s, self.memory_view));
                                }
                                let va = ui.add(
                                    egui::DragValue::new(&mut s.header.virtual_address.0)
                                        .hexadecimal(8, false, true),
                                );
                                if va.changed() {
                                    self.dirty = true;
                                    self.edited_this_frame = true;
                                }
                                let vs = ui.add(
                                    egui::DragValue::new(&mut s.header.virtual_size)
                                        .hexadecimal(8, false, true),
                                );
                                if vs.changed() {
                                    self.dirty = true;
                                    self.edited_this_frame = true;
                                }
                                ui.monospace(format!("{:#x}", s.header.size_of_raw_data));
                                ui.monospace(format!("{:#x}", s.header.pointer_to_raw_data.get()));
                                let c = ui.add(
                                    egui::DragValue::new(&mut s.header.characteristics)
                                        .hexadecimal(8, false, true),
                                );
                                if c.changed() {
                                    self.dirty = true;
                                    self.edited_this_frame = true;
                                }
                                if ui.small_button(t!("button.remove")).clicked() {
                                    remove = Some(i);
                                }
                                ui.end_row();
                            }
                        });
                });
            if let Some(i) = remove {
                match doc.remove_section(i) {
                    Ok(()) => {
                        self.section_names.remove(i);
                        if self.selected_section >= doc.sections.len() {
                            self.selected_section = self.selected_section.saturating_sub(1);
                        }
                        self.dirty = true;
                        self.edited_this_frame = true;
                    }
                    Err(e) => {
                        self.status = t!("status.remove_failed", err = e.to_string()).into_owned();
                    }
                }
            }
            ui.horizontal(|ui| {
                ui.label(t!("sections.add_section"));
                ui.add(egui::TextEdit::singleline(&mut self.new_section_name).desired_width(70.0));
                ui.add(egui::DragValue::new(&mut self.new_section_size));
                if ui.button(t!("button.add")).clicked() {
                    let name = self.new_section_name.clone();
                    let size = self.new_section_size as usize;
                    let chars =
                        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
                    match doc.add_section(name_bytes(&name), chars, vec![0; size]) {
                        Ok(_) => {
                            self.section_names.push(name.clone());
                            self.selected_section = doc.sections.len().saturating_sub(1);
                            self.dirty = true;
                            self.edited_this_frame = true;
                            self.status = t!("status.added_section", name = &name).into_owned();
                        }
                        Err(e) => {
                            self.status = t!("status.add_failed", err = e.to_string()).into_owned();
                        }
                    }
                }
            });
            // Warn about overlapping virtual-address ranges (memory view).
            let ranges: Vec<(u32, u32)> = doc
                .sections
                .iter()
                .map(|s| (s.header.virtual_address.get(), s.header.virtual_size))
                .collect();
            let overlaps = find_overlaps(&ranges);
            if !overlaps.is_empty() {
                let names: Vec<String> = overlaps
                    .iter()
                    .map(|(i, j)| {
                        format!(
                            "{}↔{}",
                            doc.sections[*i].name_str(),
                            doc.sections[*j].name_str()
                        )
                    })
                    .collect();
                ui.colored_label(
                    egui::Color32::from_rgb(0xb3, 0x2d, 0x00),
                    t!("sections.overlap", names = names.join(", ")),
                );
            }
            ui.add_space(6.0);
            ui.weak(t!("hint.section_raw"));
        }
        ui.separator();
        self.show_binary(ui);
    }

    /// The virtualized raw-data hex view of the selected section. The address
    /// basis follows the File/Memory layout toggle (raw offset vs RVA).
    fn show_binary(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_ref() else { return };
        let Some(s) = doc.sections.get(self.selected_section) else {
            ui.weak(t!("binary.select_section"));
            return;
        };
        let image_base = doc.optional.image_base();
        let base = section_base(s, self.memory_view);
        let len = s.data.len();
        if len == 0 {
            ui.label(t!("binary.empty", name = &s.name_str()));
            return;
        }
        let rows = len.div_ceil(16).max(1);
        let row_height = 18.0;
        ui.horizontal(|ui| {
            ui.label(t!(
                "binary.range",
                name = &s.name_str(),
                base = format!("{base:#x}"),
                end = format!("{:#x}", base + len as u32 - 1),
                len = len,
            ));
            ui.weak(t!("binary.jump_hint"));
        });
        ui.horizontal(|ui| {
            ui.label(t!("binary.find_label"));
            let edit =
                ui.add(egui::TextEdit::singleline(&mut self.binary_find).desired_width(110.0));
            let find = ui.button(t!("binary.find"));
            if (find.clicked()
                || (edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))))
                && let Some(needle) = parse_needle(&self.binary_find)
            {
                match find_bytes(&s.data, &needle) {
                    Some(off) => self.binary_scroll_to = Some(base + off as u32),
                    None => self.status = t!("binary.not_found").into_owned(),
                }
            }
        });

        let mut sa = egui::ScrollArea::vertical()
            .id_salt("section_binary")
            .auto_shrink(false);
        if let Some(addr) = self.binary_scroll_to {
            let off = (addr.saturating_sub(base) / 16) as f32 * row_height;
            sa = sa.vertical_scroll_offset(off);
        }
        let mut jump_requested = false;
        let out = sa.show_rows(ui, row_height, rows, |ui, range| {
            for row in range {
                let start = row * 16;
                let chunk = &s.data[start..(start + 16).min(len)];
                let addr = base + (row as u32) * 16;
                let hex: String = chunk.iter().map(|b| format!("{b:02X} ")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                ui.monospace(format!("{addr:#08x}: {hex:<48} {ascii}"));
            }
        });
        let ctx = ui.interact(
            out.inner_rect,
            egui::Id::new("sec_binary_ctx"),
            egui::Sense::click(),
        );
        // The jump input is typed inside the menu, so it must survive clicks on
        // the text box: CloseOnClickOutside still closes it when clicking
        // elsewhere; the Go / jump buttons close via `ui.close()`.
        egui::Popup::context_menu(&ctx)
            .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
            .show(|ui| {
                ui.label(t!("binary.jump_label"));
                ui.horizontal(|ui| {
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut self.binary_jump).desired_width(120.0),
                    );
                    let go = ui.button(t!("binary.go"));
                    let submitted = go.clicked()
                        || (edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                    if submitted {
                        if let Some(v) = parse_u64(&self.binary_jump) {
                            self.binary_scroll_to =
                                Some(parse_jump_target(v, image_base, base, len));
                            jump_requested = true;
                        }
                        ui.close();
                    }
                });
                ui.separator();
                if ui.button(t!("binary.jump_start")).clicked() {
                    self.binary_scroll_to = Some(base);
                    jump_requested = true;
                    ui.close();
                }
                if ui.button(t!("binary.jump_end")).clicked() {
                    self.binary_scroll_to = Some(base + len.saturating_sub(1) as u32);
                    jump_requested = true;
                    ui.close();
                }
            });
        // Consume the one-shot jump unless a new one was requested this frame.
        if !jump_requested {
            self.binary_scroll_to = None;
        }
    }

    fn show_imports(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_mut() else { return };
        // Two columns: import modules on the left, the selected module's
        // functions on the right. Editing the rich form (`doc.imports`) is
        // enough — the writer re-renders the physical table on save.
        ui.columns(2, |cols| {
            cols[0].vertical(|ui| {
                ui.strong(t!("node.imports"));
                ui.label(t!("imports.modules"));
                ui.horizontal(|ui| {
                    ui.label(t!("imports.add"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_import_module)
                            .hint_text(t!("imports.hint_module"))
                            .desired_width(90.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_import_func)
                            .hint_text(t!("imports.hint_func"))
                            .desired_width(90.0),
                    );
                    if ui.button(t!("button.add")).clicked() {
                        let module = self.new_import_module.clone();
                        let func = self.new_import_func.clone();
                        if module.trim().is_empty() || func.trim().is_empty() {
                            self.status = t!("status.module_func_required").into_owned();
                        } else {
                            match doc.add_import(&module, &[ImportFunction::by_name(func.clone())])
                            {
                                Ok(()) => {
                                    self.selected_import = Some(module.clone());
                                    self.new_import_module.clear();
                                    self.new_import_func.clear();
                                    self.dirty = true;
                                    self.edited_this_frame = true;
                                    self.status =
                                        t!("status.added_import", module = &module, func = &func)
                                            .into_owned();
                                }
                                Err(e) => {
                                    self.status =
                                        t!("status.add_import_failed", err = e.to_string())
                                            .into_owned();
                                }
                            }
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(t!("imports.filter"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.import_filter)
                            .desired_width(120.0)
                            .hint_text(t!("imports.filter_hint")),
                    );
                });
                let mut remove: Option<String> = None;
                egui::ScrollArea::vertical()
                    .id_salt("import_modules")
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        for d in &doc.imports {
                            if !import_matches(&d.name, &self.import_filter) {
                                continue;
                            }
                            let selected = self.selected_import.as_ref() == Some(&d.name);
                            let clicked = ui
                                .horizontal(|ui| {
                                    let r = ui.selectable_label(
                                        selected,
                                        format!("{} ({})", d.name, d.functions.len()),
                                    );
                                    if ui.small_button(t!("button.remove")).clicked() {
                                        remove = Some(d.name.clone());
                                    }
                                    r
                                })
                                .inner
                                .clicked();
                            if clicked {
                                self.selected_import = Some(d.name.clone());
                            }
                        }
                        if doc.imports.is_empty() {
                            ui.weak(t!("empty.no_imports"));
                        }
                    });
                if let Some(m) = remove {
                    if self.selected_import.as_deref() == Some(m.as_str()) {
                        self.selected_import = None;
                    }
                    if let Err(e) = doc.remove_import(&m) {
                        self.status =
                            t!("status.remove_import_failed", err = e.to_string()).into_owned();
                    } else {
                        self.dirty = true;
                        self.edited_this_frame = true;
                    }
                }
            });
            cols[1].vertical(|ui| {
                let Some(idx) = self
                    .selected_import
                    .as_ref()
                    .and_then(|name| doc.imports.iter().position(|d| &d.name == name))
                else {
                    ui.weak(t!("imports.select_module_left"));
                    return;
                };
                ui.strong(t!(
                    "imports.module_funcs",
                    module = &doc.imports[idx].name,
                    count = doc.imports[idx].functions.len()
                ));
                ui.horizontal(|ui| {
                    ui.label(t!("imports.add_fn"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_import_add_fn)
                            .hint_text(t!("imports.hint_func"))
                            .desired_width(130.0),
                    );
                    if ui.button(t!("button.add")).clicked() {
                        let func = self.new_import_add_fn.clone();
                        if !func.trim().is_empty() {
                            doc.imports[idx]
                                .functions
                                .push(ImportFunction::by_name(func));
                            self.new_import_add_fn.clear();
                            self.dirty = true;
                            self.edited_this_frame = true;
                        }
                    }
                });
                let mut remove_fn: Option<usize> = None;
                let mut renamed = false;
                egui::ScrollArea::vertical()
                    .id_salt("import_functions")
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        let desc = &mut doc.imports[idx];
                        for (i, f) in desc.functions.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                let mut resp = None;
                                match f {
                                    ImportFunction::Name { name, .. } => {
                                        resp = Some(ui.add(
                                            egui::TextEdit::singleline(name).desired_width(180.0),
                                        ));
                                    }
                                    ImportFunction::Ordinal { ordinal } => {
                                        ui.label(t!("imports.ordinal_fn", ordinal = ordinal));
                                    }
                                }
                                if let Some(r) = resp {
                                    renamed |= r.changed();
                                }
                                if ui.small_button(t!("button.remove")).clicked() {
                                    remove_fn = Some(i);
                                }
                            });
                        }
                        if desc.functions.is_empty() {
                            ui.weak(t!("empty.no_functions"));
                        }
                    });
                if renamed {
                    self.dirty = true;
                    self.edited_this_frame = true;
                }
                if let Some(i) = remove_fn {
                    doc.imports[idx].functions.remove(i);
                    self.dirty = true;
                    self.edited_this_frame = true;
                }
            });
        });
    }

    fn show_exports(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_mut() else { return };
        ui.strong(t!("node.exports"));
        let mut remove: Option<u16> = None;
        let mut renamed = false;
        egui::ScrollArea::vertical().show(ui, |ui| {
            if let Some(exports) = doc.exports.as_mut() {
                egui::Grid::new("exports")
                    .num_columns(5)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("Ordinal");
                        ui.label("Name");
                        ui.label("RVA");
                        ui.label("Forwarder");
                        ui.label("");
                        ui.end_row();
                        for s in &mut exports.symbols {
                            ui.label(format!("{}", s.ordinal));
                            let r = ui.add(
                                egui::TextEdit::singleline(s.name.get_or_insert_default())
                                    .desired_width(180.0),
                            );
                            renamed |= r.changed();
                            let rva = ui.add(
                                egui::DragValue::new(&mut s.rva.0).hexadecimal(8, false, true),
                            );
                            renamed |= rva.changed();
                            let f = ui.add(
                                egui::TextEdit::singleline(s.forwarder.get_or_insert_default())
                                    .desired_width(200.0),
                            );
                            renamed |= f.changed();
                            if ui.button(t!("button.remove")).clicked() {
                                remove = Some(s.ordinal);
                            }
                            ui.end_row();
                        }
                    });
            } else {
                ui.label(t!("empty.no_export_table"));
            }
        });
        if renamed {
            self.dirty = true;
            self.edited_this_frame = true;
        }
        if let Some(exports) = doc.exports.as_mut() {
            ui.horizontal(|ui| {
                ui.label(t!("exports.module"));
                let r = ui.add(
                    egui::TextEdit::singleline(exports.module_name.get_or_insert_default())
                        .desired_width(200.0),
                );
                if r.changed() {
                    self.dirty = true;
                    self.edited_this_frame = true;
                }
                ui.label(t!("exports.base"));
                let b = ui.add(egui::DragValue::new(&mut exports.base).hexadecimal(8, false, true));
                if b.changed() {
                    self.dirty = true;
                    self.edited_this_frame = true;
                }
            });
        }
        ui.horizontal(|ui| {
            ui.label(t!("exports.add"));
            ui.add(egui::DragValue::new(&mut self.new_export_ordinal));
            ui.add(
                egui::TextEdit::singleline(&mut self.new_export_name)
                    .hint_text(t!("exports.hint_name"))
                    .desired_width(200.0),
            );
            ui.add(egui::DragValue::new(&mut self.new_export_rva).hexadecimal(8, false, true));
            if ui.button(t!("button.add_export")).clicked() {
                let name = self.new_export_name.trim();
                let symbol = ExportSymbol {
                    name: (!name.is_empty()).then(|| name.to_string()),
                    ordinal: self.new_export_ordinal,
                    rva: Rva(self.new_export_rva),
                    forwarder: None,
                };
                match doc.add_export(symbol) {
                    Ok(()) => {
                        self.dirty = true;
                        self.edited_this_frame = true;
                        self.status = t!("status.added_export", ordinal = self.new_export_ordinal)
                            .into_owned();
                    }
                    Err(e) => {
                        self.status =
                            t!("status.add_export_failed", err = e.to_string()).into_owned();
                    }
                }
            }
        });
        if let Some(o) = remove
            && let Err(e) = doc.remove_export(o)
        {
            self.status = t!("status.remove_export_failed", err = e.to_string()).into_owned();
        } else if remove.is_some() {
            self.dirty = true;
            self.edited_this_frame = true;
        }
    }

    fn show_resources(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_ref() else { return };
        ui.strong(t!("node.resources"));
        ui.add_space(4.0);
        let Some(root) = &doc.resources else {
            ui.label(t!("empty.no_resources"));
            return;
        };
        egui::ScrollArea::vertical()
            .id_salt("resources")
            .auto_shrink(false)
            .show(ui, |ui| {
                render_resource_dir(ui, root, &mut self.selected_resource);
            });
        if let Some((rva, size)) = self.selected_resource {
            ui.separator();
            ui.strong(t!("resource.preview"));
            match doc.read(rva, size as usize) {
                Ok(data) => {
                    show_hex_dump(ui, data, rva.get());
                }
                Err(e) => {
                    ui.weak(format!("read: {e}"));
                }
            }
        }
    }

    fn show_relocations(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_ref() else { return };
        ui.strong(t!("node.relocations"));
        ui.add_space(4.0);
        let Some(t) = &doc.relocations else {
            ui.label(t!("empty.no_relocations"));
            return;
        };
        let entries: usize = t.blocks.iter().map(|b| b.entries.len()).sum();
        ui.label(t!(
            "reloc.summary",
            blocks = t.blocks.len(),
            entries = entries
        ));
        egui::ScrollArea::vertical()
            .id_salt("relocations")
            .auto_shrink(false)
            .show(ui, |ui| {
                egui::Grid::new("reloc_table")
                    .num_columns(4)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label(t!("reloc.col_block"));
                        ui.label(t!("reloc.col_page"));
                        ui.label(t!("reloc.col_offset"));
                        ui.label(t!("reloc.col_type"));
                        ui.end_row();
                        for (i, b) in t.blocks.iter().enumerate() {
                            for e in &b.entries {
                                ui.label(format!("{i}"));
                                ui.monospace(format!("{:#x}", b.page_rva.get()));
                                ui.monospace(format!("{:#x}", e.offset));
                                ui.monospace(reloc_type_name(e.reloc_type));
                                ui.end_row();
                            }
                        }
                    });
            });
    }

    fn show_tls(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_ref() else { return };
        ui.strong(t!("node.tls"));
        ui.add_space(4.0);
        let Some(t) = &doc.tls else {
            ui.label(t!("empty.no_tls"));
            return;
        };
        grid(
            ui,
            "tls_grid",
            &[
                ("start", format!("{:#x}", t.start_address_of_raw_data)),
                ("end", format!("{:#x}", t.end_address_of_raw_data)),
                ("index", format!("{:#x}", t.address_of_index)),
                ("callbacks", format!("{:#x}", t.address_of_callbacks)),
                ("zero fill", format!("{:#x}", t.size_of_zero_fill)),
            ],
        );
    }

    fn show_load_config(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_ref() else { return };
        ui.strong(t!("node.load_config"));
        ui.add_space(4.0);
        let Some(lc) = &doc.load_config else {
            ui.label(t!("empty.no_load_config"));
            return;
        };
        grid(
            ui,
            "loadconfig_grid",
            &[
                ("size", format!("{:#x}", lc.size)),
                ("cookie", format!("{:#x}", lc.security_cookie)),
                ("guard flags", format!("{:#x}", lc.guard_flags)),
                (
                    "cf table",
                    format!(
                        "{:#x} ({} funcs)",
                        lc.guard_cf_function_table, lc.guard_cf_function_count
                    ),
                ),
                (
                    "xfg check",
                    format!("{:#x}", lc.guard_xfg_check_function_pointer),
                ),
            ],
        );
    }

    fn show_converter(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_ref() else { return };
        let conv = VaConverter::from_document(doc);
        let image_base = doc.optional.image_base();
        ui.strong(t!("node.converter"));
        ui.add_space(4.0);
        egui::Grid::new("conv_in")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("RVA");
                ui.add(egui::TextEdit::singleline(&mut self.conv_rva).desired_width(160.0));
                ui.end_row();
                ui.label("VA");
                ui.add(egui::TextEdit::singleline(&mut self.conv_va).desired_width(160.0));
                ui.end_row();
                ui.label("File offset");
                ui.add(egui::TextEdit::singleline(&mut self.conv_raw).desired_width(160.0));
                ui.end_row();
            });
        ui.add_space(4.0);
        if ui.button(t!("button.convert")).clicked() {
            let out = convert_addresses(&conv, &self.conv_rva, &self.conv_va, &self.conv_raw);
            if let Some((rva, va, raw)) = out {
                self.conv_rva = rva;
                self.conv_va = va;
                self.conv_raw = raw;
            }
        }
        ui.add_space(4.0);
        ui.weak(t!("conv.image_base", base = format!("{image_base:#x}")));
    }
}

/// Compute a VA / RVA / file-offset triple from whichever input field is
/// filled, returning the three formatted values.
fn convert_addresses(
    conv: &VaConverter,
    rva: &str,
    va: &str,
    raw: &str,
) -> Option<(String, String, String)> {
    if let Some(r) = parse_u64(rva).map(|v| v as u32) {
        let rva = Rva(r);
        let va_v = conv.rva_to_va(rva);
        let raw_v = conv
            .rva_to_raw(rva)
            .map(|x| format!("{:#x}", x.get()))
            .unwrap_or_else(|| "—".to_string());
        return Some((format!("{r:#x}"), format!("{va_v:#x}"), raw_v));
    }
    if let Some(v) = parse_u64(va) {
        if let Some(r) = conv.va_to_rva(v) {
            let raw_v = conv
                .rva_to_raw(r)
                .map(|x| format!("{:#x}", x.get()))
                .unwrap_or_else(|| "—".to_string());
            return Some((format!("{:#x}", r.get()), format!("{v:#x}"), raw_v));
        }
        return None;
    }
    if let Some(o) = parse_u64(raw).map(|v| v as u32) {
        if let Some(r) = conv.raw_to_rva(RawOffset(o)) {
            let va_v = conv.rva_to_va(r);
            return Some((
                format!("{:#x}", r.get()),
                format!("{va_v:#x}"),
                format!("{o:#x}"),
            ));
        }
        return None;
    }
    None
}

/// Address used as the row basis for a section in the hex view: RVA in memory
/// layout, raw file offset in file layout.
fn section_base(s: &pe_edit::domain::Section, memory_view: bool) -> u32 {
    if memory_view {
        s.header.virtual_address.get()
    } else {
        s.header.pointer_to_raw_data.get()
    }
}

/// Pack an editable section name into the 8-byte `IMAGE_SECTION_HEADER.name`.
fn name_bytes(name: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    let n = name.len().min(8);
    out[..n].copy_from_slice(&name.as_bytes()[..n]);
    out
}

/// A label + editable hex field row; returns `true` if the value changed.
fn hdr_field<T: egui::emath::Numeric>(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut T,
    hex_width: usize,
) -> bool {
    ui.label(label);
    ui.add(egui::DragValue::new(value).hexadecimal(hex_width, false, true))
        .changed()
}

/// A label + machine-type combo box row; returns `true` if the value changed.
fn machine_field(ui: &mut egui::Ui, machine: &mut Machine) -> bool {
    ui.label("machine");
    let mut changed = false;
    egui::ComboBox::from_id_salt("coff_machine")
        .selected_text(machine_name(*machine))
        .show_ui(ui, |ui| {
            for m in [Machine::I386, Machine::Amd64, Machine::Arm64] {
                if ui
                    .selectable_label(*machine == m, machine_name(m))
                    .clicked()
                {
                    *machine = m;
                    changed = true;
                }
            }
            if let Machine::Unknown(v) = *machine {
                let _ = ui.selectable_label(true, format!("Other (0x{v:04x})"));
            }
        });
    changed
}

/// Human-readable COFF machine name.
fn machine_name(machine: Machine) -> String {
    match machine {
        Machine::I386 => "I386".to_string(),
        Machine::Amd64 => "AMD64".to_string(),
        Machine::Arm64 => "ARM64".to_string(),
        Machine::Unknown(v) => format!("Other (0x{v:04x})"),
    }
}

/// `true` for data directories the writer re-renders from the rich import /
/// export / resource / reloc / TLS / load-config forms on save (edits would be
/// overwritten, so the GUI shows them read-only). The remaining directories are
/// written verbatim and are freely editable.
fn is_writer_managed(idx: usize) -> bool {
    matches!(
        idx,
        0 /* Export */ | 1 /* Import */ | 2 /* Resource */ | 5 /* BaseReloc */
        | 9 /* TLS */ | 10 /* LoadConfig */ | 12 /* IAT */
    )
}

/// Case-insensitive "contains" filter for the import module list.
fn import_matches(name: &str, filter: &str) -> bool {
    let f = filter.trim();
    f.is_empty() || name.to_lowercase().contains(&f.to_lowercase())
}

/// Parse a hex-view find input into bytes: a run of hex digits (whitespace
/// allowed) with even length is treated as hexadecimal bytes, anything else as
/// the literal ASCII bytes.
fn parse_needle(s: &str) -> Option<Vec<u8>> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.is_empty()
        && compact.len().is_multiple_of(2)
        && compact.chars().all(|c| c.is_ascii_hexdigit())
    {
        (0..compact.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).ok())
            .collect()
    } else {
        Some(t.as_bytes().to_vec())
    }
}

/// First index where `needle` occurs in `haystack`, or `None`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Index pairs of `(start, size)` ranges that overlap in address space. Zero
/// or unset sizes never overlap. Each pair is reported once, smaller index
/// first.
fn find_overlaps(ranges: &[(u32, u32)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for i in 0..ranges.len() {
        let (a, alen) = ranges[i];
        if alen == 0 {
            continue;
        }
        let a_end = a.saturating_add(alen);
        for (j, &(b, blen)) in ranges.iter().enumerate().skip(i + 1) {
            if blen == 0 {
                continue;
            }
            let b_end = b.saturating_add(blen);
            if a < b_end && b < a_end {
                out.push((i, j));
            }
        }
    }
    out
}

/// One cross-tree search result: which node to jump to, a human label, and the
/// node-specific selection to apply on jump.
#[derive(Clone, PartialEq)]
struct SearchHit {
    node: PeNode,
    label: String,
    /// Import module to select (Imports node).
    import_module: Option<String>,
    /// Section index to select (Sections node).
    section_index: Option<usize>,
    /// Resource tree path (Resources node).
    resource_path: Option<String>,
}

/// Case-insensitive substring search across sections, import modules/functions,
/// export symbols and resource names. Empty queries yield no hits.
fn global_search(doc: &PeDocument, query: &str) -> Vec<SearchHit> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for (i, s) in doc.sections.iter().enumerate() {
        if s.name_str().to_lowercase().contains(&q) {
            hits.push(SearchHit {
                node: PeNode::Sections,
                label: format!("section · {}", s.name_str()),
                import_module: None,
                section_index: Some(i),
                resource_path: None,
            });
        }
    }
    for d in &doc.imports {
        if d.name.to_lowercase().contains(&q) {
            hits.push(SearchHit {
                node: PeNode::Imports,
                label: format!("import module · {}", d.name),
                import_module: Some(d.name.clone()),
                section_index: None,
                resource_path: None,
            });
        }
        for f in &d.functions {
            let fname = match f {
                ImportFunction::Name { name, .. } => name.clone(),
                ImportFunction::Ordinal { ordinal } => format!("#{ordinal}"),
            };
            if fname.to_lowercase().contains(&q) {
                hits.push(SearchHit {
                    node: PeNode::Imports,
                    label: format!("import · {}.{}", d.name, fname),
                    import_module: Some(d.name.clone()),
                    section_index: None,
                    resource_path: None,
                });
            }
        }
    }
    if let Some(exports) = &doc.exports {
        for sym in &exports.symbols {
            if let Some(name) = &sym.name
                && name.to_lowercase().contains(&q)
            {
                hits.push(SearchHit {
                    node: PeNode::Exports,
                    label: format!("export · {name}"),
                    import_module: None,
                    section_index: None,
                    resource_path: None,
                });
            }
        }
    }
    let mut res_paths = Vec::new();
    if let Some(root) = &doc.resources {
        collect_resource_paths(root, &mut res_paths);
    }
    for path in res_paths {
        if path.to_lowercase().contains(&q) {
            hits.push(SearchHit {
                node: PeNode::Resources,
                label: format!("resource · {path}"),
                import_module: None,
                section_index: None,
                resource_path: Some(path),
            });
        }
    }
    hits
}

/// Collect the display name of every resource entry (directories and leaves),
/// depth-first, so search can match e.g. `#24` (RT_MANIFEST) or a leaf name.
fn collect_resource_paths(dir: &pe_edit::domain::ResourceDirectory, out: &mut Vec<String>) {
    for e in &dir.entries {
        let name = match &e.name {
            ResourceName::Id(id) => format!("#{id}"),
            ResourceName::Named(n) => n.clone(),
        };
        out.push(name);
        if let pe_edit::domain::ResourceEntryData::Directory(d) = &e.data {
            collect_resource_paths(d, out);
        }
    }
}

/// Interpret a "jump" input as an offset (RVA/raw) or an absolute address (VA
/// ≥ image base), clamped to the section's range.
fn parse_jump_target(v: u64, image_base: u64, sec_base: u32, sec_len: usize) -> u32 {
    let rva = if v >= image_base {
        (v - image_base) as u32
    } else {
        v as u32
    };
    let end = sec_base.saturating_add(sec_len as u32).saturating_sub(1);
    rva.clamp(sec_base, end.max(sec_base))
}

/// Parse a string into a `u64`: a `0x`/`0X` prefix means hexadecimal, otherwise
/// decimal (`None` when empty or invalid).
fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// A simple two-column read-only label grid.
fn grid(ui: &mut egui::Ui, id: &str, rows: &[(&str, String)]) {
    egui::Grid::new(id)
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
            for (k, v) in rows {
                ui.label(*k);
                ui.monospace(v);
                ui.end_row();
            }
        });
}

/// Render a resource directory tree (read-only); clicking a leaf selects it for
/// byte preview via `sel`.
fn render_resource_dir(
    ui: &mut egui::Ui,
    dir: &pe_edit::domain::ResourceDirectory,
    sel: &mut Option<(Rva, u32)>,
) {
    for e in &dir.entries {
        let name = match &e.name {
            ResourceName::Id(id) => format!("#{id}"),
            ResourceName::Named(n) => n.clone(),
        };
        match &e.data {
            pe_edit::domain::ResourceEntryData::Directory(d) => {
                egui::CollapsingHeader::new(name)
                    .id_salt(format!("{:?}", e.name))
                    .show(ui, |ui| {
                        render_resource_dir(ui, d, sel);
                    });
            }
            pe_edit::domain::ResourceEntryData::Leaf(l) => {
                ui.horizontal(|ui| {
                    let selected = sel.map(|(r, _)| r == l.rva).unwrap_or(false);
                    if ui.selectable_label(selected, name).clicked() {
                        *sel = Some((l.rva, l.size));
                    }
                    ui.monospace(format!("rva {:#x} size {:#x}", l.rva.get(), l.size));
                });
            }
        }
    }
}

/// A virtualized hex dump (address | hex | ascii) for a read-only byte range.
fn show_hex_dump(ui: &mut egui::Ui, data: &[u8], base: u32) {
    let len = data.len();
    if len == 0 {
        ui.weak("(empty)");
        return;
    }
    let rows = len.div_ceil(16).max(1);
    let row_height = 18.0;
    egui::ScrollArea::vertical()
        .id_salt("resource_hex")
        .auto_shrink(false)
        .max_height(280.0)
        .show_rows(ui, row_height, rows, |ui, range| {
            for row in range {
                let start = row * 16;
                let end = (start + 16).min(len);
                let chunk = &data[start..end];
                let addr = base + (row as u32) * 16;
                let hex: String = chunk
                    .iter()
                    .map(|b| format!("{b:02X} "))
                    .collect::<String>()
                    .trim_end()
                    .to_string();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                ui.monospace(format!("{addr:#010x}: {hex:<48}  {ascii}"));
            }
        });
}

/// Human-readable name for a relocation entry's `IMAGE_REL_BASED_*` type.
fn reloc_type_name(t: u8) -> String {
    use pe_edit::domain::relocation::{
        IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH,
        IMAGE_REL_BASED_HIGHADJ, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW,
        IMAGE_REL_BASED_MIPS_JMPADDR,
    };
    let name = match t {
        IMAGE_REL_BASED_ABSOLUTE => "ABSOLUTE",
        IMAGE_REL_BASED_HIGH => "HIGH",
        IMAGE_REL_BASED_LOW => "LOW",
        IMAGE_REL_BASED_HIGHLOW => "HIGHLOW",
        IMAGE_REL_BASED_HIGHADJ => "HIGHADJ",
        IMAGE_REL_BASED_MIPS_JMPADDR => "MIPS_JMPADDR",
        IMAGE_REL_BASED_DIR64 => "DIR64",
        other => return format!("TYPE_{other}"),
    };
    format!("{t} {name}")
}

#[cfg(test)]
mod tests {
    use pe_edit::feature::VaConverter;
    use pe_edit::io::mock;

    use super::{
        convert_addresses, find_bytes, find_overlaps, global_search, import_matches,
        is_writer_managed, name_bytes, parse_jump_target, parse_needle, parse_u64,
    };

    #[test]
    fn parse_u64_handles_hex_and_decimal() {
        assert_eq!(parse_u64("0x1000"), Some(0x1000));
        assert_eq!(parse_u64("0X2A"), Some(0x2A));
        assert_eq!(parse_u64("4096"), Some(4096));
        assert_eq!(parse_u64(" 123 "), Some(123));
        assert_eq!(parse_u64(""), None);
        assert_eq!(parse_u64("0xZZ"), None);
        assert_eq!(parse_u64("abc"), None);
    }

    #[test]
    fn name_bytes_pads_and_truncates() {
        assert_eq!(name_bytes(".text"), *b".text\0\0\0");
        assert_eq!(name_bytes(""), [0u8; 8]);
        assert_eq!(name_bytes("0123456789"), *b"01234567");
        assert_eq!(name_bytes(".idata"), *b".idata\0\0");
    }

    #[test]
    fn jump_target_accepts_va_and_clamps() {
        let base = 0x1000u32;
        let len = 0x200usize;
        let ib = 0x1400_0000u64;
        // VA >= image base -> RVA
        assert_eq!(parse_jump_target(0x1400_1000, ib, base, len), 0x1000);
        // bare offset passes through
        assert_eq!(parse_jump_target(0x1100, ib, base, len), 0x1100);
        // below section start clamps to start
        assert_eq!(parse_jump_target(0x800, ib, base, len), 0x1000);
        // beyond section end clamps to end
        assert_eq!(parse_jump_target(0x5000, ib, base, len), 0x1000 + 0x200 - 1);
    }

    #[test]
    fn converter_round_trips_va_rva_raw() {
        let doc = mock::document();
        let conv = VaConverter::from_document(&doc);
        let text_va = format!("{:#x}", mock::MOCK_IMAGE_BASE + 0x1000);

        // RVA input -> VA + raw offset
        let (rva, va, raw) = convert_addresses(&conv, "0x1000", "", "").unwrap();
        assert_eq!(rva, "0x1000");
        assert_eq!(va, text_va);
        assert_eq!(raw, "0x200");

        // VA input -> RVA + raw
        let (rva2, va2, raw2) = convert_addresses(&conv, "", &text_va, "").unwrap();
        assert_eq!(rva2, "0x1000");
        assert_eq!(va2, text_va);
        assert_eq!(raw2, "0x200");

        // Raw offset input -> RVA + VA
        let (rva3, va3, raw3) = convert_addresses(&conv, "", "", "0x200").unwrap();
        assert_eq!(rva3, "0x1000");
        assert_eq!(va3, text_va);
        assert_eq!(raw3, "0x200");

        // Header region (raw < size_of_headers) maps 1:1
        let (rva4, va4, raw4) = convert_addresses(&conv, "", "", "0x10").unwrap();
        assert_eq!(rva4, "0x10");
        assert_eq!(raw4, "0x10");
        assert_eq!(va4, format!("{:#x}", mock::MOCK_IMAGE_BASE + 0x10));

        // Unmapped raw offset returns None
        assert!(convert_addresses(&conv, "", "", "0x9999").is_none());
        // No input at all returns None
        assert!(convert_addresses(&conv, "", "", "").is_none());
    }

    #[test]
    fn import_filter_is_case_insensitive_contains() {
        assert!(import_matches("KERNEL32.dll", ""));
        assert!(import_matches("KERNEL32.dll", "kernel"));
        assert!(import_matches("KERNEL32.dll", "DLL"));
        assert!(!import_matches("KERNEL32.dll", "user32"));
        assert!(import_matches("USER32.dll", "user"));
        assert!(import_matches("user32.dll", "USER"));
        assert!(import_matches("", ""));
    }

    #[test]
    fn parse_needle_hex_and_ascii() {
        // even-length hex digits -> bytes
        assert_eq!(parse_needle("4D 5A"), Some(vec![0x4D, 0x5A]));
        assert_eq!(parse_needle("4d5a"), Some(vec![0x4D, 0x5A]));
        // non-hex input falls back to ASCII bytes
        assert_eq!(parse_needle("MZ"), Some(vec![b'M', b'Z']));
        // empty -> None
        assert_eq!(parse_needle("  "), None);
        // odd-length hex run falls back to ASCII
        assert_eq!(parse_needle("abc"), Some(b"abc".to_vec()));
    }

    #[test]
    fn find_bytes_locates_first_occurrence() {
        let data = b"\x00\x01\x4d\x5a\x01\x02";
        assert_eq!(find_bytes(data, &[0x4d, 0x5a]), Some(2));
        assert_eq!(find_bytes(data, &[0x01]), Some(1));
        assert_eq!(find_bytes(data, b"xx"), None);
        assert_eq!(find_bytes(data, &[]), None);
        assert_eq!(find_bytes(b"ab", b"abc"), None);
        assert_eq!(find_bytes(b"ab", b"ab"), Some(0));
    }

    #[test]
    fn writer_managed_directory_set_is_exact() {
        // The 7 directories the writer re-renders from rich forms.
        for i in [0, 1, 2, 5, 9, 10, 12] {
            assert!(is_writer_managed(i), "dir {i} should be writer-managed");
        }
        // The other 8 are written verbatim (freely editable).
        for i in [3, 4, 6, 7, 8, 11, 13, 14] {
            assert!(!is_writer_managed(i), "dir {i} should be free");
        }
        assert!(!is_writer_managed(15));
    }

    #[test]
    fn section_overlap_detection() {
        // Disjoint: .text 0x1000..0x1200, .data 0x2000..0x2100
        let no = find_overlaps(&[(0x1000, 0x200), (0x2000, 0x100)]);
        assert_eq!(no, vec![]);
        // Adjacent (end == next start) is not an overlap
        let adj = find_overlaps(&[(0x1000, 0x200), (0x1200, 0x100)]);
        assert_eq!(adj, vec![]);
        // True overlap and containment
        let ov = find_overlaps(&[(0x1000, 0x200), (0x1100, 0x100), (0x3000, 0x10)]);
        assert_eq!(ov, vec![(0, 1)]);
        let contain = find_overlaps(&[(0x1000, 0x400), (0x1100, 0x100)]);
        assert_eq!(contain, vec![(0, 1)]);
        // Zero-size ranges never overlap
        let zero = find_overlaps(&[(0x1000, 0), (0x1000, 0x100)]);
        assert_eq!(zero, vec![]);
        // Every pair reported once, smaller index first
        let three = find_overlaps(&[(0x1000, 0x500), (0x1100, 0x500), (0x1200, 0x500)]);
        assert_eq!(three, vec![(0, 1), (0, 2), (1, 2)]);
    }

    #[test]
    fn global_search_finds_sections_imports_exports_resources() {
        let doc = mock::document();

        // Empty / whitespace query -> no hits.
        assert!(global_search(&doc, "").is_empty());
        assert!(global_search(&doc, "   ").is_empty());

        // Section names.
        let hits = global_search(&doc, "text");
        assert!(
            hits.iter()
                .any(|h| h.node == super::PeNode::Sections && h.section_index.is_some())
        );

        // Import module.
        let hits = global_search(&doc, "user32");
        assert!(hits.iter().any(|h| h.node == super::PeNode::Imports
            && h.import_module.as_deref() == Some("user32.dll")));

        // Import function (case-insensitive).
        let hits = global_search(&doc, "messagebox");
        assert!(hits.iter().any(|h| h.node == super::PeNode::Imports
            && h.import_module.as_deref() == Some("user32.dll")));

        // Export symbol.
        let hits = global_search(&doc, "DumpMe");
        assert!(hits.iter().any(|h| h.node == super::PeNode::Exports));

        // Resource entry name (the mock manifest leaf is #1033 / 0x409).
        let hits = global_search(&doc, "1033");
        assert!(hits.iter().any(|h| h.node == super::PeNode::Resources));

        // No match.
        assert!(global_search(&doc, "zzz_no_such_symbol").is_empty());
    }

    #[test]
    fn undo_redo_state_machine_captures_one_step_per_gesture() {
        use super::PeEditApp;

        let baseline = mock::document();
        let mut app = PeEditApp {
            doc: Some(baseline.clone()),
            undo_baseline: Some(baseline.clone()),
            ..Default::default()
        };

        // Frame 1: an edit gesture begins -> exactly one snapshot pushed.
        app.edited_this_frame = true;
        app.frame_end();
        assert_eq!(app.undo_stack.len(), 1);
        assert!(app.gesture_active);
        // The pushed snapshot is the pre-edit document.
        assert_eq!(app.undo_stack[0], baseline);

        // Frame 2: the same gesture continues -> no duplicate snapshot.
        app.edited_this_frame = true;
        app.frame_end();
        assert_eq!(app.undo_stack.len(), 1);

        // Frame 3: idle -> gesture ends, baseline refreshed for the next one.
        app.frame_end();
        assert!(!app.gesture_active);
        assert!(app.undo_baseline.is_some());

        // A second gesture starts on top of the refreshed baseline.
        app.edited_this_frame = true;
        app.frame_end();
        assert_eq!(app.undo_stack.len(), 2);
        app.frame_end(); // idle -> end gesture

        // Undo restores the pre-edit document and stages a redo.
        app.undo();
        assert_eq!(app.undo_stack.len(), 1);
        assert_eq!(app.redo_stack.len(), 1);
        assert!(app.dirty);
        assert_eq!(app.doc.as_ref().unwrap(), &baseline);

        // Redo re-applies it and returns to the edited document.
        app.redo();
        assert_eq!(app.redo_stack.len(), 0);
        assert!(app.doc.is_some());
    }
}
