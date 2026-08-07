//! Scylla-style PE editor GUI built on the `pe-rs` library.
//!
//! A CFF-Explorer-style single-document editor: a PE file or a dumped process
//! (main module or any loaded DLL) all land in the same editable
//! [`PeDocument`], and one Save writes it back out. The File menu covers both
//! workflows — Open PE File / Dump Process — and Save runs an import-table
//! health check first, letting you force-save a possibly-broken dump.

use eframe::egui;
use pe_rs::api::{ExportTableEditor, IatFixer, IatScanner, ImportTableEditor, PeEditor, PeViewer};
use pe_rs::domain::section::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use pe_rs::domain::{
    DataDirectoryIndex, ExportSymbol, IatEntry, IatFixOptions, IatFixReport, IatScan, IatTable,
    ImportFunction, PeDocument, Rva, ScanMethod, ScanOptions,
};
use pe_rs::io::pe::{parse, serialize};
use pe_rs::process::{self, ModuleInfo, ProcessInfo, ProcessResolver};
use std::sync::mpsc;

/// Result of an async file dialog (picked path, or `None` if cancelled).
type PickResult = Option<std::path::PathBuf>;

/// egui's bundled fonts have no CJK glyphs, so Chinese UI text renders as
/// boxes. Install a Windows system CJK font as a fallback family.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    for path in [
        "C:/Windows/Fonts/msyh.ttc",   // Microsoft YaHei (collection)
        "C:/Windows/Fonts/simhei.ttf", // SimHei
        "C:/Windows/Fonts/Deng.ttf",   // DengXian
    ] {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        fonts.font_data.insert(
            "cjk".to_owned(),
            std::sync::Arc::new(egui::FontData::from_owned(bytes)),
        );
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push("cjk".to_owned());
        }
        break;
    }
    ctx.set_fonts(fonts);
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native(
        "PE Editor",
        options,
        Box::new(|cc| {
            install_fonts(&cc.egui_ctx);
            Ok(Box::new(PeEditorApp::default()))
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
    Iat,
}

impl Tab {
    fn all() -> [(Tab, &'static str); 6] {
        [
            (Tab::Headers, "Headers"),
            (Tab::Sections, "Sections"),
            (Tab::Imports, "Imports"),
            (Tab::Exports, "Exports"),
            (Tab::Directories, "Directories"),
            (Tab::Iat, "IAT"),
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

/// Where the current document came from — drives Save behaviour and the
/// save-time import-table health check.
#[derive(Default, PartialEq, Clone, Copy)]
enum Source {
    #[default]
    File,
    Dump,
}

#[derive(Default)]
struct PeEditorApp {
    path: String,
    pid: String,
    /// Short label of the dumped module ("main module" or the DLL name), for
    /// the document-source line in the toolbar.
    dump_label: String,
    save_path: String,
    doc: Option<PeDocument>,
    resolver: Option<ProcessResolver>,
    scan: Option<IatScan>,
    source: Source,
    /// Outcome of the last successful IAT fix, for the save health check.
    last_fix: Option<IatFixReport>,
    /// Pending save-time confirmation: the warning text to show and the path
    /// to write once the user force-saves a possibly-broken import table.
    save_warning: Option<String>,
    pending_save_path: Option<String>,
    /// Curated IAT entries (scan result + hand-added regions) with one keep
    /// flag per entry — uncheck to drop a false positive before fixing.
    iat_entries: Vec<IatEntry>,
    iat_keep: Vec<bool>,
    /// "Add region" / "Add entry" input state for the IAT page.
    iat_region_rva: u32,
    iat_region_size: u32,
    iat_add_rva: u32,
    iat_add_value: u64,
    /// Scan method used by "Scan IAT" (Resolver / Code references /
    /// Reflection — see `ScanMethod`).
    scan_method: ScanMethod,
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
    /// Process picker state.
    processes: Vec<ProcessInfo>,
    /// Loaded modules of the process selected in the picker (module-level dump).
    modules: Vec<ModuleInfo>,
    /// Index into `modules` of the highlighted row in the picker's module list.
    selected_module: Option<usize>,
    process_filter: String,
    show_process_picker: bool,
}

/// Human-readable label for a scan method (used in the IAT-page selector and
/// the status bar).
fn scan_method_name(m: ScanMethod) -> &'static str {
    match m {
        ScanMethod::Resolver => "Resolver",
        ScanMethod::CodeReference => "Code references",
        ScanMethod::Reflection => "Reflection",
    }
}

impl PeEditorApp {
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
        self.scan = None;
        self.iat_entries.clear();
        self.iat_keep.clear();
        self.last_fix = None;
        match std::fs::read(&self.path) {
            Ok(bytes) => match parse(&bytes) {
                Ok(doc) => {
                    self.doc = Some(doc);
                    self.source = Source::File;
                    self.sync_header_edits();
                    self.status = format!("loaded {}", self.path);
                }
                Err(e) => self.status = format!("parse failed: {e}"),
            },
            Err(e) => self.status = format!("read failed: {e}"),
        }
    }

    /// Dump a process's main module (`base: None`) or one of its loaded
    /// modules (`base: Some`) into the editor, replacing the current document.
    fn dump_module_at(&mut self, pid: u32, base: Option<u64>, label: &str) {
        self.scan = None;
        self.iat_entries.clear();
        self.iat_keep.clear();
        self.last_fix = None;
        let dumped = match base {
            Some(base) => process::dump_module(pid, base),
            None => process::dump(pid),
        };
        match dumped {
            Ok(doc) => {
                self.resolver = ProcessResolver::for_process(pid).ok();
                self.doc = Some(doc);
                self.source = Source::Dump;
                self.dump_label = label.to_string();
                self.sync_header_edits();
                self.status = format!("dumped {label} (pid {pid})");
            }
            Err(e) => self.status = format!("dump failed: {e}"),
        }
    }

    fn scan_iat(&mut self) {
        let Some(doc) = self.doc.as_ref() else {
            self.status = "no document".into();
            return;
        };
        let Some(resolver) = self.resolver.as_ref() else {
            self.status = "no process resolver — dump a process first".into();
            return;
        };
        let method = self.scan_method;
        let opts = ScanOptions {
            method,
            ..Default::default()
        };
        match doc.scan(resolver, &opts) {
            Ok(scan) => {
                self.iat_entries = scan.entries.clone();
                self.iat_keep = vec![true; scan.entries.len()];
                self.status = format!(
                    "scan ({}) — IAT at {:#x}, {} entries",
                    scan_method_name(method),
                    scan.base_rva.get(),
                    scan.entries.len()
                );
                self.scan = Some(scan);
            }
            Err(e) => {
                self.status = format!("scan ({}) failed: {e}", scan_method_name(method));
                self.scan = None;
            }
        }
    }

    fn fix_iat(&mut self) {
        let resolver = match self.resolver.as_ref() {
            Some(r) => r,
            None => {
                self.status = "no process resolver".into();
                return;
            }
        };
        let scan = match self.scan.as_ref() {
            Some(s) => s,
            None => {
                self.status = "no IAT scan".into();
                return;
            }
        };
        let doc = match self.doc.as_mut() {
            Some(d) => d,
            None => {
                self.status = "no document".into();
                return;
            }
        };
        match doc.fix_iat(scan, resolver, &IatFixOptions::default()) {
            Ok(report) => {
                self.last_fix = Some(report.clone());
                self.status = format!(
                    "fixed {} imports ({} unresolved, new table at {:#x})",
                    report.imports_built,
                    report.unresolved.len(),
                    report.new_import_rva.map(|r| r.get()).unwrap_or(0),
                )
            }
            Err(e) => self.status = format!("fix failed: {e}"),
        }
    }

    /// Serialize the document and write it to `path`. When the import table
    /// looks broken (a dump that was never fixed, unresolved entries, or an
    /// empty import table), stash the path and ask the user first — they can
    /// still force the save.
    fn save_to(&mut self, path: String) {
        if let Some(warn) = self.import_health_warning() {
            self.save_warning = Some(warn);
            self.pending_save_path = Some(path);
            return;
        }
        self.write_file(path);
    }

    fn write_file(&mut self, path: String) {
        let Some(doc) = self.doc.as_ref() else {
            self.status = "no document".into();
            return;
        };
        match serialize(doc) {
            Ok(bytes) => {
                let len = bytes.len();
                match std::fs::write(&path, bytes) {
                    Ok(()) => self.status = format!("saved {len} bytes to {path}"),
                    Err(e) => self.status = format!("write failed: {e}"),
                }
            }
            Err(e) => self.status = format!("serialize failed: {e}"),
        }
    }

    /// Save to the document's own path (file source) or the last "Save As…"
    /// path; a dump that has never been saved goes through the Save As dialog.
    fn save(&mut self, ctx: &egui::Context) {
        let path = if self.source == Source::File && self.save_path.trim().is_empty() {
            self.path.clone()
        } else if !self.save_path.trim().is_empty() {
            self.save_path.clone()
        } else {
            self.save_dialog(ctx);
            return;
        };
        self.save_to(path);
    }

    /// Reason to warn before saving, if any: the saved file may not run.
    fn import_health_warning(&self) -> Option<String> {
        let doc = self.doc.as_ref()?;
        if let Some(r) = &self.last_fix
            && !r.unresolved.is_empty()
        {
            return Some(format!(
                "上次修复有 {} 个导入未能解析,依赖它们的调用会失效。",
                r.unresolved.len()
            ));
        }
        if self.source == Source::Dump && self.last_fix.is_none() {
            return Some(
                "该文件来自进程 dump,导入表尚未修复,保存的 dump 通常无法直接运行。".into(),
            );
        }
        if doc.imports.is_empty() {
            return Some("导入表为空,可能无法正常运行。".into());
        }
        None
    }

    /// Open a native file dialog on a background thread (avoids blocking the
    /// egui event loop); the result lands in `pick_rx`.
    fn open_dialog(&mut self, ctx: &egui::Context) {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let picked = rfd::FileDialog::new()
                .set_title("Open PE file")
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
                .set_title("Save PE file")
                .add_filter("PE files", &["exe", "dll", "sys"])
                .set_file_name("fixed.bin")
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
        self.status = "headers applied".into();
    }
}

impl eframe::App for PeEditorApp {
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

        // Menu bar: the primary entry point for both workflows.
        egui::Panel::top("menu").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open PE File…").clicked() {
                        self.open_dialog(ui.ctx());
                        ui.close();
                    }
                    if ui.button("选择进程…").clicked() {
                        self.processes = process::list_processes().unwrap_or_default();
                        self.modules.clear();
                        self.selected_module = None;
                        self.show_process_picker = true;
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Save").clicked() {
                        self.save(ui.ctx());
                        ui.close();
                    }
                    if ui.button("Save As…").clicked() {
                        self.save_dialog(ui.ctx());
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
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

        // Document-source line: what we are editing (a file path, or a dumped
        // process/module) plus the status. Opening/dumping happens via the menu.
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.horizontal(|ui| {
                match self.source {
                    Source::File => {
                        ui.label("文件:");
                        if self.path.is_empty() {
                            ui.weak("(未打开)");
                        } else {
                            ui.label(&self.path);
                        }
                    }
                    Source::Dump => {
                        ui.label("进程:");
                        ui.label(format!("pid {} · {}", self.pid, self.dump_label));
                    }
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
                    ui.label("Open a PE file (File → Open) or dump a process (File → Dump Process) to begin.");
                });
            }
        });

        // Process picker: a separate native window, detached from the main
        // window — pick a process on the left, then pick one of its modules on
        // the right. Dismiss via the Cancel button, ESC, or the window's own
        // close button.
        let mut close_picker = false;
        if self.show_process_picker {
            let ctx = ui.ctx().clone();
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("process_picker_viewport"),
                egui::ViewportBuilder::default()
                    .with_title("选择进程")
                    .with_inner_size([760.0, 480.0])
                    .with_resizable(true),
                |ui, _class| {
                    // The user closed the window (X / Alt+F4) or pressed ESC.
                    if ui.ctx().input(|i| i.viewport().close_requested())
                        || ui.ctx().input(|i| i.key_pressed(egui::Key::Escape))
                    {
                        close_picker = true;
                    }
                    egui::CentralPanel::default().show(ui, |ui| {
                        // Header row: title on the left, Cancel on the right.
                        ui.horizontal(|ui| {
                            ui.strong("选择进程");
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("取消").clicked() {
                                        close_picker = true;
                                    }
                                },
                            );
                        });
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.label("Filter:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.process_filter)
                                    .desired_width(220.0),
                            );
                            if ui.button("Refresh").clicked() {
                                self.processes = process::list_processes().unwrap_or_default();
                            }
                        });
                        ui.separator();
                        // Two columns: processes on the left, their modules on
                        // the right. Each list fills its own column.
                        ui.columns(2, |cols| {
                            // Left: process list.
                            cols[0].vertical(|ui| {
                                ui.label("进程");
                                egui::ScrollArea::vertical()
                                    .id_salt("process_list")
                                    .auto_shrink(false)
                                    .show(ui, |ui| {
                                        let filter = self.process_filter.trim().to_lowercase();
                                        let current = if self.modules.is_empty() {
                                            None
                                        } else {
                                            self.pid.parse::<u32>().ok()
                                        };
                                        let mut pick_pid: Option<u32> = None;
                                        for p in &self.processes {
                                            let matches = filter.is_empty()
                                                || p.name.to_lowercase().contains(&filter)
                                                || p.pid.to_string().contains(&filter);
                                            if !matches {
                                                continue;
                                            }
                                            if ui
                                                .selectable_label(
                                                    current == Some(p.pid),
                                                    format!("{:<7} {}", p.pid, p.name),
                                                )
                                                .clicked()
                                            {
                                                pick_pid = Some(p.pid);
                                            }
                                        }
                                        if self.processes.is_empty() {
                                            ui.weak("no processes");
                                        }
                                        if let Some(pid) = pick_pid {
                                            self.pid = pid.to_string();
                                            self.modules =
                                                process::list_modules(pid).unwrap_or_default();
                                            self.selected_module = None;
                                        }
                                    });
                            });
                            // Right: module list with one independent
                            // "选择模块" button instead of a button per row.
                            cols[1].vertical(|ui| {
                                ui.horizontal(|ui| {
                                    if self.modules.is_empty() {
                                        ui.label("模块");
                                    } else {
                                        ui.label(format!("模块 (pid {})", self.pid));
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            let enabled = self.selected_module.is_some();
                                            if ui
                                                .add_enabled(enabled, egui::Button::new("选择模块"))
                                                .clicked()
                                            {
                                                let module = self
                                                    .selected_module
                                                    .and_then(|idx| self.modules.get(idx))
                                                    .map(|m| (m.base, m.name.clone()));
                                                if let Some((base, name)) = module {
                                                    self.dump_module_at(
                                                        self.pid.parse().unwrap_or(0),
                                                        Some(base),
                                                        &name,
                                                    );
                                                    close_picker = true;
                                                }
                                            }
                                        },
                                    );
                                });
                                if self.modules.is_empty() {
                                    ui.weak("在左边选择一个进程");
                                } else {
                                    let mut dump: Option<(u64, String)> = None;
                                    egui::ScrollArea::vertical()
                                        .id_salt("module_list")
                                        .auto_shrink(false)
                                        .show(ui, |ui| {
                                            for (i, m) in self.modules.iter().enumerate() {
                                                let mark =
                                                    if i == 0 { "[main] " } else { "       " };
                                                let selected = self.selected_module == Some(i);
                                                let resp = ui.selectable_label(
                                                    selected,
                                                    format!("{mark}{:<28} {:#x}", m.name, m.base),
                                                );
                                                if resp.double_clicked() {
                                                    self.selected_module = Some(i);
                                                    dump = Some((m.base, m.name.clone()));
                                                } else if resp.clicked() {
                                                    self.selected_module = Some(i);
                                                }
                                            }
                                            if self.modules.is_empty() {
                                                ui.weak("no modules");
                                            }
                                        });
                                    if let Some((base, name)) = dump {
                                        self.dump_module_at(
                                            self.pid.parse().unwrap_or(0),
                                            Some(base),
                                            &name,
                                        );
                                        close_picker = true;
                                    }
                                }
                            });
                        });
                    });
                },
            );
            if close_picker {
                self.show_process_picker = false;
            }
        }

        // Save-time confirmation: the import table looks broken, the user can
        // still force the save.
        if self.save_warning.is_some() {
            egui::Window::new("Confirm save")
                .collapsible(false)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.label("导入表可能损坏,保存的文件可能无法正常运行:");
                    if let Some(warn) = &self.save_warning {
                        ui.label(warn);
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("仍然保存").clicked() {
                            if let Some(path) = self.pending_save_path.take() {
                                self.write_file(path);
                            }
                            self.save_warning = None;
                        }
                        if ui.button("取消").clicked() {
                            self.save_warning = None;
                            self.pending_save_path = None;
                        }
                    });
                });
        }
    }
}

impl PeEditorApp {
    fn show_doc(&mut self, ui: &mut egui::Ui) {
        match self.tab {
            Tab::Headers => self.show_headers(ui),
            Tab::Sections => self.show_sections(ui),
            Tab::Imports => self.show_imports(ui),
            Tab::Exports => self.show_exports(ui),
            Tab::Directories => self.show_directories(ui),
            Tab::Iat => self.show_iat(ui),
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
                ui.label("Imports");
                ui.label(format!(
                    "{} modules",
                    self.doc.as_ref().map(|d| d.imports().len()).unwrap_or(0)
                ));
                ui.end_row();
                ui.label("Exports");
                ui.label(format!(
                    "{} symbols",
                    self.doc
                        .as_ref()
                        .and_then(|d| d.exports())
                        .map(|e| e.symbols.len())
                        .unwrap_or(0)
                ));
                ui.end_row();
            });
        if ui.button("Apply header edits").clicked() {
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
                        if ui.button("Remove").clicked() {
                            remove = Some(i);
                        }
                        ui.end_row();
                    }
                    if let Some(i) = remove
                        && let Err(e) = doc.remove_section(i)
                    {
                        self.status = format!("remove failed: {e}");
                    }
                });
        });
        ui.horizontal(|ui| {
            ui.label("Add section:");
            ui.add(egui::TextEdit::singleline(&mut self.new_section_name).desired_width(70.0));
            ui.add(egui::DragValue::new(&mut self.new_section_size));
            if ui.button("Add").clicked() {
                let name = self.new_section_name.clone();
                let size = self.new_section_size as usize;
                let mut name_bytes = [0u8; 8];
                let n = name.len().min(8);
                name_bytes[..n].copy_from_slice(&name.as_bytes()[..n]);
                let chars =
                    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
                match doc.add_section(name_bytes, chars, vec![0; size]) {
                    Ok(_) => self.status = format!("added section {name}"),
                    Err(e) => self.status = format!("add failed: {e}"),
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
                ui.label("模块");
                ui.horizontal(|ui| {
                    ui.label("Add:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_import_module)
                            .hint_text("module")
                            .desired_width(90.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_import_func)
                            .hint_text("func")
                            .desired_width(90.0),
                    );
                    if ui.button("Add").clicked() {
                        let module = self.new_import_module.clone();
                        let func = self.new_import_func.clone();
                        if module.trim().is_empty() || func.trim().is_empty() {
                            self.status = "module and function names required".into();
                        } else {
                            match doc.add_import(&module, &[ImportFunction::by_name(func.clone())])
                            {
                                Ok(()) => {
                                    self.selected_import = Some(module.clone());
                                    self.new_import_module.clear();
                                    self.new_import_func.clear();
                                    self.status = format!("added import {module}!{func}");
                                }
                                Err(e) => self.status = format!("add import failed: {e}"),
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
                                    if ui.small_button("Remove").clicked() {
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
                            ui.weak("no imports");
                        }
                    });
                if let Some(m) = remove {
                    if self.selected_import.as_deref() == Some(m.as_str()) {
                        self.selected_import = None;
                    }
                    if let Err(e) = doc.remove_import(&m) {
                        self.status = format!("remove import failed: {e}");
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
                    ui.weak("在左边选择一个模块");
                    return;
                };
                ui.label(format!(
                    "{} — {} 个函数",
                    doc.imports[idx].name,
                    doc.imports[idx].functions.len()
                ));
                ui.horizontal(|ui| {
                    ui.label("Add fn:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_import_add_fn)
                            .hint_text("func")
                            .desired_width(130.0),
                    );
                    if ui.button("Add").clicked() {
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
                                        ui.label(format!("#{ordinal} (ordinal)"));
                                    }
                                }
                                if ui.small_button("Remove").clicked() {
                                    remove_fn = Some(i);
                                }
                            });
                        }
                        if desc.functions.is_empty() {
                            ui.weak("no functions");
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
                            if ui.button("Remove").clicked() {
                                remove = Some(s.ordinal);
                            }
                            ui.end_row();
                        }
                    });
            } else {
                ui.label("No export table — add a symbol below to create one.");
            }
        });
        if let Some(exports) = doc.exports.as_mut() {
            ui.horizontal(|ui| {
                ui.label("Module:");
                ui.add(
                    egui::TextEdit::singleline(exports.module_name.get_or_insert_default())
                        .desired_width(200.0),
                );
                ui.label("Base:");
                ui.add(egui::DragValue::new(&mut exports.base).hexadecimal(8, false, true));
            });
        }
        ui.horizontal(|ui| {
            ui.label("Add:");
            ui.add(egui::DragValue::new(&mut self.new_export_ordinal));
            ui.add(
                egui::TextEdit::singleline(&mut self.new_export_name)
                    .hint_text("name (empty = ordinal-only)")
                    .desired_width(200.0),
            );
            ui.add(egui::DragValue::new(&mut self.new_export_rva).hexadecimal(8, false, true));
            if ui.button("Add export").clicked() {
                let name = self.new_export_name.trim();
                let symbol = ExportSymbol {
                    name: (!name.is_empty()).then(|| name.to_string()),
                    ordinal: self.new_export_ordinal,
                    rva: Rva(self.new_export_rva),
                    forwarder: None,
                };
                match doc.add_export(symbol) {
                    Ok(()) => {
                        self.status = format!("added export ordinal {}", self.new_export_ordinal)
                    }
                    Err(e) => self.status = format!("add export failed: {e}"),
                }
            }
        });
        if let Some(o) = remove
            && let Err(e) = doc.remove_export(o)
        {
            self.status = format!("remove export failed: {e}");
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

    fn show_iat(&mut self, ui: &mut egui::Ui) {
        // Scan controls (moved in from the old toolbar).
        ui.horizontal(|ui| {
            ui.label("Method:").on_hover_text(
                "Resolver: values that resolve via the process modules\n\
                 Code references: disassemble code sections for direct memory operands\n\
                 Reflection: recover the IAT from the PE structure (overwritten OriginalFirstThunk / IAT directory)",
            );
            let mut method_changed = false;
            egui::ComboBox::from_id_salt("scan_method")
                .selected_text(scan_method_name(self.scan_method))
                .show_ui(ui, |ui| {
                    method_changed |= ui
                        .selectable_value(&mut self.scan_method, ScanMethod::Resolver, "Resolver")
                        .changed();
                    method_changed |= ui
                        .selectable_value(
                            &mut self.scan_method,
                            ScanMethod::CodeReference,
                            "Code references",
                        )
                        .changed();
                    method_changed |= ui
                        .selectable_value(
                            &mut self.scan_method,
                            ScanMethod::Reflection,
                            "Reflection",
                        )
                        .changed();
                });
            // A scan is only meaningful for the method that produced it.
            if method_changed {
                self.scan = None;
            }
            if ui.button("Scan IAT").clicked() {
                self.scan_iat();
            }
            if ui.button("Fix IAT").clicked() {
                self.fix_iat();
            }
        });
        ui.separator();

        let Some(doc) = self.doc.as_mut() else { return };
        let resolver = self.resolver.as_ref();
        let status = &mut self.status;
        let entries = &mut self.iat_entries;
        let keep = &mut self.iat_keep;
        let last_fix = &mut self.last_fix;
        let mut region_rva = self.iat_region_rva;
        let mut region_size = self.iat_region_size;
        let mut add_rva = self.iat_add_rva;
        let mut add_value = self.iat_add_value;

        if entries.is_empty() {
            ui.label("Dump a process, then Scan IAT to curate the table here.");
            return;
        }

        let kept = entries.iter().zip(keep.iter()).filter(|(_, k)| **k).count();
        ui.label(format!(
            "IAT — {} entries, {} kept (uncheck to drop false positives)",
            entries.len(),
            kept
        ));
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("iat")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    ui.label("#");
                    ui.label("RVA");
                    ui.label("Value");
                    ui.label("Keep");
                    ui.end_row();
                    for (i, (e, k)) in entries.iter().zip(keep.iter_mut()).enumerate() {
                        ui.label(format!("{i}"));
                        ui.label(format!("{:#x}", e.rva.get()));
                        ui.label(format!("{:#x}", e.value));
                        ui.checkbox(k, "");
                        ui.end_row();
                    }
                });
        });

        ui.horizontal(|ui| {
            ui.label("Add region (RVA, size):");
            ui.add(egui::DragValue::new(&mut region_rva).hexadecimal(8, false, true));
            ui.add(egui::DragValue::new(&mut region_size));
            if ui.button("Add region").clicked() {
                let mut t = IatTable::new();
                match t.add_region(doc, Rva(region_rva), region_size as usize) {
                    Ok(()) => {
                        let added = t.entries().to_vec();
                        let n = added.len();
                        entries.extend(added);
                        keep.extend(std::iter::repeat_n(true, n));
                        *status = format!("added {n} entries from region {:#x}", region_rva);
                    }
                    Err(e) => *status = format!("add region failed: {e}"),
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Add entry (RVA, value):");
            ui.add(egui::DragValue::new(&mut add_rva).hexadecimal(8, false, true));
            ui.add(egui::DragValue::new(&mut add_value).hexadecimal(16, false, true));
            if ui.button("Add entry").clicked() {
                entries.push(IatEntry {
                    rva: Rva(add_rva),
                    value: add_value,
                });
                keep.push(true);
                *status = format!("added entry {:#x} = {:#x}", add_rva, add_value);
            }
        });
        ui.horizontal(|ui| {
            ui.separator();
            if ui.button("Fix curated table").clicked() {
                let Some(resolver) = resolver else {
                    *status = "no process resolver".into();
                    return;
                };
                let kept: Vec<IatEntry> = entries
                    .iter()
                    .zip(keep.iter())
                    .filter(|(_, k)| **k)
                    .map(|(e, _)| *e)
                    .collect();
                if kept.is_empty() {
                    *status = "no entries kept".into();
                    return;
                }
                let table = IatTable::from_entries(kept);
                match doc.fix_iat_table(&table, resolver, &IatFixOptions::default()) {
                    Ok(report) => {
                        *last_fix = Some(report.clone());
                        *status = format!(
                            "fixed {} imports ({} unresolved, new table at {:#x})",
                            report.imports_built,
                            report.unresolved.len(),
                            report.new_import_rva.map(|r| r.get()).unwrap_or(0),
                        );
                    }
                    Err(e) => *status = format!("fix curated failed: {e}"),
                }
            }
        });

        self.iat_region_rva = region_rva;
        self.iat_region_size = region_size;
        self.iat_add_rva = add_rva;
        self.iat_add_value = add_value;
    }
}
