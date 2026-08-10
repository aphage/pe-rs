//! CFF-Explorer-style disk PE editor GUI built on the `pe-edit` library.
//!
//! A single-document editor: a PE file is parsed into an editable
//! [`PeDocument`], edited through the disk-editing tabs (headers / sections /
//! imports / exports / directories), and serialized back to a file. No process
//! involvement — this is the *disk file editing* paradigm.

// Locale resources are shared with pe-scylla-gui via pe-gui-common; each GUI
// declares its own `i18n!` so `t!` resolves to a backend in this crate.
rust_i18n::i18n!("../pe-gui-common/locales");

use eframe::egui;
use pe_edit::api::{ExportTableEditor, ImportTableEditor, PeEditor, PeViewer};
use pe_edit::domain::section::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use pe_edit::domain::{DataDirectoryIndex, ExportSymbol, ImportFunction, PeDocument, Rva};
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
            .with_inner_size([1100.0, 700.0])
            .with_title(t!("app.title")),
        ..Default::default()
    };
    eframe::run_native(
        "pe-edit",
        options,
        Box::new(|cc| {
            pe_gui_common::fonts::install_fonts(&cc.egui_ctx);
            Ok(Box::new(PeEditApp::default()))
        }),
    )
}

#[derive(Default, PartialEq, Clone, Copy)]
enum Tab {
    #[default]
    Headers,
    Sections,
    Imports,
    Exports,
    Directories,
}

impl Tab {
    fn all() -> [(Tab, String); 5] {
        [
            (Tab::Headers, t!("tab.headers").into_owned()),
            (Tab::Sections, t!("tab.sections").into_owned()),
            (Tab::Imports, t!("tab.imports").into_owned()),
            (Tab::Exports, t!("tab.exports").into_owned()),
            (Tab::Directories, t!("tab.directories").into_owned()),
        ]
    }
}

/// Editable optional-header fields (synced from the document on load, applied
/// with the Apply button).
#[derive(Default)]
struct HeaderEdits {
    image_base: u64,
    entry_point: u32,
    section_alignment: u32,
    file_alignment: u32,
    subsystem: u16,
}

#[derive(Default)]
struct PeEditApp {
    path: String,
    /// Last "Save As…" path (otherwise Save writes back to `path`).
    save_path: String,
    doc: Option<PeDocument>,
    status: String,
    tab: Tab,
    header_edits: HeaderEdits,
    new_section_name: String,
    new_section_size: u32,
    new_import_module: String,
    new_import_func: String,
    /// Name of the import module selected in the Imports page (left column);
    /// its functions are shown in the right column.
    selected_import: Option<String>,
    /// "Add function" input for the selected module on the Imports page.
    new_import_add_fn: String,
    /// "Add export" input row state.
    new_export_ordinal: u16,
    new_export_name: String,
    new_export_rva: u32,
    /// Pending async "open file" dialog result.
    pick_rx: Option<mpsc::Receiver<PickResult>>,
    /// Pending async "save file" dialog result.
    save_rx: Option<mpsc::Receiver<PickResult>>,
}

impl PeEditApp {
    fn sync_header_edits(&mut self) {
        if let Some(doc) = &self.doc {
            let e = &mut self.header_edits;
            e.image_base = doc.optional_header().image_base();
            e.entry_point = doc.optional_header().address_of_entry_point().get();
            e.section_alignment = doc.optional_header().section_alignment();
            e.file_alignment = doc.optional_header().file_alignment();
            e.subsystem = doc.optional_header().subsystem();
        }
    }

    fn load_file(&mut self) {
        match std::fs::read(&self.path) {
            Ok(bytes) => match parse(&bytes) {
                Ok(doc) => {
                    self.doc = Some(doc);
                    self.sync_header_edits();
                    self.status = t!("status.loaded", path = &self.path).into_owned();
                }
                Err(e) => self.status = t!("status.parse_failed", err = e.to_string()).into_owned(),
            },
            Err(e) => self.status = t!("status.read_failed", err = e.to_string()).into_owned(),
        }
    }

    /// Serialize the document and write it to `path`.
    fn save_to(&mut self, path: String) {
        let Some(doc) = self.doc.as_ref() else {
            self.status = t!("status.no_document").into_owned();
            return;
        };
        match serialize(doc) {
            Ok(bytes) => {
                let len = bytes.len();
                match std::fs::write(&path, bytes) {
                    Ok(()) => {
                        self.status = t!("status.saved", len = len, path = &path).into_owned();
                    }
                    Err(e) => {
                        self.status = t!("status.write_failed", err = e.to_string()).into_owned();
                    }
                }
            }
            Err(e) => {
                self.status = t!("status.serialize_failed", err = e.to_string()).into_owned();
            }
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

    fn apply_headers(&mut self) {
        let Some(doc) = self.doc.as_mut() else {
            return;
        };
        let e = &self.header_edits;
        doc.optional.set_image_base(e.image_base);
        doc.optional.set_address_of_entry_point(Rva(e.entry_point));
        doc.optional.set_section_alignment(e.section_alignment);
        doc.optional.set_file_alignment(e.file_alignment);
        doc.optional.set_subsystem(e.subsystem);
        self.status = t!("status.headers_applied").into_owned();
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
            if !path.is_empty() {
                self.path = path;
                self.load_file();
            }
        }

        // Menu bar.
        egui::Panel::top("menu").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button(t!("menu.file"), |ui| {
                    if ui.button(t!("menu.open")).clicked() {
                        self.open_dialog(ui.ctx());
                        ui.close();
                    }
                    ui.separator();
                    if ui.button(t!("menu.save")).clicked() {
                        self.save(ui.ctx());
                        ui.close();
                    }
                    if ui.button(t!("menu.save_as")).clicked() {
                        self.save_dialog(ui.ctx());
                        ui.close();
                    }
                    ui.separator();
                    if ui.button(t!("menu.exit")).clicked() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
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
        if ctrl_s {
            self.save(ui.ctx());
        }
        if ctrl_o {
            self.open_dialog(ui.ctx());
        }

        // Document-source line: the file we are editing, plus the status.
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(t!("toolbar.file"));
                if self.path.is_empty() {
                    ui.weak(t!("toolbar.not_open"));
                } else {
                    ui.label(&self.path);
                }
                ui.separator();
                ui.label(&self.status);
            });
        });

        egui::CentralPanel::default_margins().show(ui, |ui| {
            ui.horizontal(|ui| {
                for (tab, name) in Tab::all() {
                    if ui.selectable_label(self.tab == tab, name).clicked() {
                        self.tab = tab;
                    }
                }
            });
            ui.separator();
            if self.doc.is_some() {
                self.show_doc(ui);
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label(t!("guidance.open_pe"));
                });
            }
        });
    }
}

impl PeEditApp {
    fn show_doc(&mut self, ui: &mut egui::Ui) {
        match self.tab {
            Tab::Headers => self.show_headers(ui),
            Tab::Sections => self.show_sections(ui),
            Tab::Imports => self.show_imports(ui),
            Tab::Exports => self.show_exports(ui),
            Tab::Directories => self.show_directories(ui),
        }
    }

    fn show_headers(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("headers")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("Image base");
                ui.add(
                    egui::DragValue::new(&mut self.header_edits.image_base)
                        .hexadecimal(16, false, true),
                );
                ui.end_row();
                ui.label("Entry point");
                ui.add(
                    egui::DragValue::new(&mut self.header_edits.entry_point)
                        .hexadecimal(8, false, true),
                );
                ui.end_row();
                ui.label("Section alignment");
                ui.add(
                    egui::DragValue::new(&mut self.header_edits.section_alignment)
                        .hexadecimal(8, false, true),
                );
                ui.end_row();
                ui.label("File alignment");
                ui.add(
                    egui::DragValue::new(&mut self.header_edits.file_alignment)
                        .hexadecimal(8, false, true),
                );
                ui.end_row();
                ui.label("Subsystem");
                ui.add(
                    egui::DragValue::new(&mut self.header_edits.subsystem)
                        .hexadecimal(4, false, true),
                );
                ui.end_row();
                ui.label(t!("headers.imports"));
                ui.label(t!(
                    "headers.modules",
                    count = self.doc.as_ref().map(|d| d.imports().len()).unwrap_or(0)
                ));
                ui.end_row();
                ui.label(t!("headers.exports"));
                ui.label(t!(
                    "headers.symbols",
                    count = self
                        .doc
                        .as_ref()
                        .and_then(|d| d.exports())
                        .map(|e| e.symbols.len())
                        .unwrap_or(0)
                ));
                ui.end_row();
            });
        if ui.button(t!("button.apply_headers")).clicked() {
            self.apply_headers();
        }
    }

    fn show_sections(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_mut() else { return };
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("sections")
                .num_columns(6)
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Name");
                    ui.label("VA");
                    ui.label("VSize");
                    ui.label("RawSize");
                    ui.label("Chars");
                    ui.label("");
                    ui.end_row();
                    let mut remove: Option<usize> = None;
                    for (i, s) in doc.sections().iter().enumerate() {
                        ui.label(s.name_str());
                        ui.label(format!("{:#x}", s.header.virtual_address.get()));
                        ui.label(format!("{:#x}", s.header.virtual_size));
                        ui.label(format!("{:#x}", s.header.size_of_raw_data));
                        ui.label(format!("{:#x}", s.header.characteristics));
                        if ui.button(t!("button.remove")).clicked() {
                            remove = Some(i);
                        }
                        ui.end_row();
                    }
                    if let Some(i) = remove
                        && let Err(e) = doc.remove_section(i)
                    {
                        self.status = t!("status.remove_failed", err = e.to_string()).into_owned();
                    }
                });
        });
        ui.horizontal(|ui| {
            ui.label(t!("sections.add_section"));
            ui.add(egui::TextEdit::singleline(&mut self.new_section_name).desired_width(70.0));
            ui.add(egui::DragValue::new(&mut self.new_section_size));
            if ui.button(t!("button.add")).clicked() {
                let name = self.new_section_name.clone();
                let size = self.new_section_size as usize;
                let mut name_bytes = [0u8; 8];
                let n = name.len().min(8);
                name_bytes[..n].copy_from_slice(&name.as_bytes()[..n]);
                let chars =
                    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
                match doc.add_section(name_bytes, chars, vec![0; size]) {
                    Ok(_) => self.status = t!("status.added_section", name = &name).into_owned(),
                    Err(e) => {
                        self.status = t!("status.add_failed", err = e.to_string()).into_owned();
                    }
                }
            }
        });
    }

    fn show_imports(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_mut() else { return };
        // Two columns: import modules on the left, the selected module's
        // functions on the right. Editing the rich form (`doc.imports`) is
        // enough — the writer re-renders the physical table on save.
        ui.columns(2, |cols| {
            // Left column: add row on top, then the module list.
            cols[0].vertical(|ui| {
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
                let mut remove: Option<String> = None;
                egui::ScrollArea::vertical()
                    .id_salt("import_modules")
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        for d in &doc.imports {
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
                    }
                }
            });
            // Right column: the selected module's functions.
            cols[1].vertical(|ui| {
                let Some(idx) = self
                    .selected_import
                    .as_ref()
                    .and_then(|name| doc.imports.iter().position(|d| &d.name == name))
                else {
                    ui.weak(t!("imports.select_module_left"));
                    return;
                };
                ui.label(t!(
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
                        }
                    }
                });
                let mut remove_fn: Option<usize> = None;
                egui::ScrollArea::vertical()
                    .id_salt("import_functions")
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        let desc = &mut doc.imports[idx];
                        for (i, f) in desc.functions.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                match f {
                                    ImportFunction::Name { name, .. } => {
                                        ui.add(
                                            egui::TextEdit::singleline(name).desired_width(180.0),
                                        );
                                    }
                                    ImportFunction::Ordinal { ordinal } => {
                                        ui.label(t!("imports.ordinal_fn", ordinal = ordinal));
                                    }
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
                if let Some(i) = remove_fn {
                    doc.imports[idx].functions.remove(i);
                }
            });
        });
    }

    fn show_exports(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_mut() else { return };
        let mut remove: Option<u16> = None;
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
                            ui.add(
                                egui::TextEdit::singleline(s.name.get_or_insert_default())
                                    .desired_width(180.0),
                            );
                            ui.add(egui::DragValue::new(&mut s.rva.0).hexadecimal(8, false, true));
                            ui.add(
                                egui::TextEdit::singleline(s.forwarder.get_or_insert_default())
                                    .desired_width(200.0),
                            );
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
        if let Some(exports) = doc.exports.as_mut() {
            ui.horizontal(|ui| {
                ui.label(t!("exports.module"));
                ui.add(
                    egui::TextEdit::singleline(exports.module_name.get_or_insert_default())
                        .desired_width(200.0),
                );
                ui.label(t!("exports.base"));
                ui.add(egui::DragValue::new(&mut exports.base).hexadecimal(8, false, true));
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
        }
    }

    fn show_directories(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_ref() else { return };
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
                    let dd = doc.data_directories.get(i).copied().unwrap_or_default();
                    ui.label(name);
                    ui.label(format!("{:#x}", dd.rva.get()));
                    ui.label(format!("{:#x}", dd.size));
                    ui.end_row();
                }
            });
    }
}
