//! Scylla-style PE editor GUI built on the `pe-rs` library.
//!
//! Load a PE file (path, or drag-and-drop), inspect and edit headers /
//! sections / imports / exports / directories, dump a live process, scan &
//! fix its IAT, and save the result.

use eframe::egui;
use pe_rs::api::{IatFixer, IatScanner, ImportTableEditor, PeEditor, PeViewer};
use pe_rs::domain::section::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use pe_rs::domain::{
    DataDirectoryIndex, IatFixOptions, IatScan, ImportFunction, PeDocument, Rva, ScanMethod,
    ScanOptions,
};
use pe_rs::io::pe::{parse, serialize};
use pe_rs::process::{self, ProcessInfo, ProcessResolver};
use std::sync::mpsc;

/// Result of an async file dialog (picked path, or `None` if cancelled).
type PickResult = Option<std::path::PathBuf>;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native(
        "PE Editor",
        options,
        Box::new(|_cc| Ok(Box::new(PeEditorApp::default()))),
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

#[derive(Default)]
struct PeEditorApp {
    path: String,
    pid: String,
    save_path: String,
    doc: Option<PeDocument>,
    resolver: Option<ProcessResolver>,
    scan: Option<IatScan>,
    /// Scan method used by the "Scan IAT" button (Resolver / Code references /
    /// Reflection — see `ScanMethod`).
    scan_method: ScanMethod,
    status: String,
    tab: Tab,
    header_edits: HeaderEdits,
    new_section_name: String,
    new_section_size: u32,
    new_import_module: String,
    new_import_func: String,
    /// Pending async "open file" dialog result.
    pick_rx: Option<mpsc::Receiver<PickResult>>,
    /// Pending async "save file" dialog result.
    save_rx: Option<mpsc::Receiver<PickResult>>,
    /// Process picker state.
    processes: Vec<ProcessInfo>,
    process_filter: String,
    show_process_picker: bool,
}

/// Human-readable label for a scan method (used in the toolbar selector and
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
        match std::fs::read(&self.path) {
            Ok(bytes) => match parse(&bytes) {
                Ok(doc) => {
                    self.doc = Some(doc);
                    self.sync_header_edits();
                    self.status = format!("loaded {}", self.path);
                }
                Err(e) => self.status = format!("parse failed: {e}"),
            },
            Err(e) => self.status = format!("read failed: {e}"),
        }
    }

    fn dump_process(&mut self) {
        self.scan = None;
        let pid: u32 = match self.pid.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                self.status = "invalid pid".into();
                return;
            }
        };
        match process::dump(pid) {
            Ok(doc) => {
                self.resolver = ProcessResolver::for_process(pid).ok();
                self.doc = Some(doc);
                self.sync_header_edits();
                self.status = format!("dumped pid {pid}");
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

    fn save(&mut self) {
        let Some(doc) = self.doc.as_ref() else {
            self.status = "no document".into();
            return;
        };
        let path = if self.save_path.trim().is_empty() {
            if self.path.trim().is_empty() {
                "fixed.bin".to_string()
            } else {
                self.path.clone()
            }
        } else {
            self.save_path.clone()
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
            self.save();
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

        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("PE:");
                let resp = ui.add(egui::TextEdit::singleline(&mut self.path).desired_width(300.0));
                let enter = ui.ctx().input(|i| i.key_pressed(egui::Key::Enter));
                if resp.lost_focus() && enter {
                    self.load_file();
                }
                if ui.button("Load").clicked() {
                    self.load_file();
                }
                if ui.button("Browse…").clicked() {
                    self.open_dialog(ui.ctx());
                }

                ui.separator();
                ui.label("PID:");
                ui.add(egui::TextEdit::singleline(&mut self.pid).desired_width(60.0));
                if ui.button("Dump").clicked() {
                    self.dump_process();
                }
                if ui.button("Select…").clicked() {
                    self.processes = process::list_processes().unwrap_or_default();
                    self.show_process_picker = true;
                }

                ui.separator();
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
                if ui.button("Save").clicked() {
                    self.save();
                }
            });
            ui.horizontal(|ui| {
                ui.label("Save as:");
                ui.add(egui::TextEdit::singleline(&mut self.save_path).desired_width(300.0));
                if ui.button("Save As…").clicked() {
                    self.save_dialog(ui.ctx());
                }
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
                    ui.label("Open a PE file or dump a process to begin.");
                });
            }
        });

        // Modal-ish process picker: filter + click a row to select its PID.
        if self.show_process_picker {
            egui::Window::new("Select process")
                .collapsible(false)
                .resizable(true)
                .default_width(460.0)
                .show(ui.ctx(), |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Filter:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.process_filter)
                                .desired_width(260.0),
                        );
                        if ui.button("Refresh").clicked() {
                            self.processes = process::list_processes().unwrap_or_default();
                        }
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .max_height(380.0)
                        .show(ui, |ui| {
                            let filter = self.process_filter.trim().to_lowercase();
                            let mut pick: Option<u32> = None;
                            for p in &self.processes {
                                let matches = filter.is_empty()
                                    || p.name.to_lowercase().contains(&filter)
                                    || p.pid.to_string().contains(&filter);
                                if !matches {
                                    continue;
                                }
                                if ui
                                    .selectable_label(false, format!("{:<7} {}", p.pid, p.name))
                                    .clicked()
                                {
                                    pick = Some(p.pid);
                                }
                            }
                            if self.processes.is_empty() {
                                ui.label("no processes");
                            }
                            if let Some(pid) = pick {
                                self.pid = pid.to_string();
                                self.show_process_picker = false;
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
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("imports")
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Module");
                    ui.label("Functions");
                    ui.label("");
                    ui.end_row();
                    let mut remove: Option<String> = None;
                    for d in doc.imports() {
                        ui.label(&d.name);
                        ui.label(
                            d.functions
                                .iter()
                                .map(|f| f.display_name())
                                .collect::<Vec<_>>()
                                .join(", "),
                        );
                        if ui.button("Remove").clicked() {
                            remove = Some(d.name.clone());
                        }
                        ui.end_row();
                    }
                    if let Some(m) = remove
                        && let Err(e) = doc.remove_import(&m)
                    {
                        self.status = format!("remove import failed: {e}");
                    }
                });
        });
        ui.horizontal(|ui| {
            ui.label("Add import:");
            ui.add(egui::TextEdit::singleline(&mut self.new_import_module).desired_width(130.0));
            ui.add(egui::TextEdit::singleline(&mut self.new_import_func).desired_width(130.0));
            if ui.button("Add").clicked() {
                let module = self.new_import_module.clone();
                let func = self.new_import_func.clone();
                match doc.add_import(&module, &[ImportFunction::by_name(func.clone())]) {
                    Ok(()) => self.status = format!("added import {module}!{func}"),
                    Err(e) => self.status = format!("add import failed: {e}"),
                }
            }
        });
    }

    fn show_exports(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_ref() else { return };
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("exports")
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Ordinal");
                    ui.label("Name");
                    ui.label("RVA");
                    ui.end_row();
                    if let Some(exports) = doc.exports() {
                        for s in &exports.symbols {
                            ui.label(format!("{}", s.ordinal));
                            ui.label(s.name.as_deref().unwrap_or("<ordinal>"));
                            ui.label(format!("{:#x}", s.rva.get()));
                            ui.end_row();
                        }
                    }
                });
        });
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
        match &self.scan {
            Some(scan) => {
                ui.label(format!(
                    "IAT at {:#x}, {} entries",
                    scan.base_rva.get(),
                    scan.entries.len()
                ));
                egui::ScrollArea::vertical().show(ui, |ui| {
                    egui::Grid::new("iat")
                        .num_columns(3)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label("#");
                            ui.label("RVA");
                            ui.label("Value");
                            ui.end_row();
                            for (i, e) in scan.entries.iter().enumerate() {
                                ui.label(format!("{i}"));
                                ui.label(format!("{:#x}", e.rva.get()));
                                ui.label(format!("{:#x}", e.value));
                                ui.end_row();
                            }
                        });
                });
            }
            None => {
                ui.label("Dump a process, then Scan IAT to see the table here.");
            }
        }
    }
}
