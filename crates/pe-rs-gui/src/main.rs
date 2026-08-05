//! Scylla-style PE editor GUI built on the `pe-rs` library.
//!
//! Load a PE file (path, or drag-and-drop), inspect headers / sections /
//! imports / exports / directories, dump a live process, scan & fix its IAT,
//! and save the result.

use eframe::egui;
use pe_rs::api::{IatFixer, IatScanner, PeViewer};
use pe_rs::domain::{DataDirectoryIndex, IatFixOptions, IatScan, PeDocument, ScanOptions};
use pe_rs::io::pe::{parse, serialize};
use pe_rs::process::{self, ProcessResolver};

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

#[derive(Default)]
struct PeEditorApp {
    path: String,
    pid: String,
    save_path: String,
    doc: Option<PeDocument>,
    resolver: Option<ProcessResolver>,
    scan: Option<IatScan>,
    status: String,
    tab: Tab,
}

impl PeEditorApp {
    fn load_file(&mut self) {
        self.scan = None;
        match std::fs::read(&self.path) {
            Ok(bytes) => match parse(&bytes) {
                Ok(doc) => {
                    self.doc = Some(doc);
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
        match doc.scan(resolver, &ScanOptions::default()) {
            Ok(scan) => {
                self.status = format!(
                    "IAT at {:#x}, {} entries",
                    scan.base_rva.get(),
                    scan.entries.len()
                );
                self.scan = Some(scan);
            }
            Err(e) => {
                self.status = format!("scan failed: {e}");
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
}

impl eframe::App for PeEditorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drag-and-drop a PE file onto the window.
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if let Some(file) = dropped.first()
            && let Some(path) = &file.path
        {
            self.path = path.display().to_string();
            self.load_file();
        }

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("PE:");
                let resp = ui.add(egui::TextEdit::singleline(&mut self.path).desired_width(360.0));
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.load_file();
                }
                if ui.button("Load").clicked() {
                    self.load_file();
                }

                ui.separator();
                ui.label("PID:");
                ui.add(egui::TextEdit::singleline(&mut self.pid).desired_width(60.0));
                if ui.button("Dump").clicked() {
                    self.dump_process();
                }

                ui.separator();
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
                ui.add(egui::TextEdit::singleline(&mut self.save_path).desired_width(360.0));
                ui.label(&self.status);
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                for (tab, name) in Tab::all() {
                    if ui.selectable_label(self.tab == tab, name).clicked() {
                        self.tab = tab;
                    }
                }
            });
            ui.separator();
            match &self.doc {
                Some(doc) => self.show_doc(ui, doc),
                None => {
                    ui.centered_and_justified(|ui| {
                        ui.label("Open a PE file or dump a process to begin.");
                    });
                }
            }
        });
    }
}

impl PeEditorApp {
    fn show_doc(&self, ui: &mut egui::Ui, doc: &PeDocument) {
        match self.tab {
            Tab::Headers => self.show_headers(ui, doc),
            Tab::Sections => self.show_sections(ui, doc),
            Tab::Imports => self.show_imports(ui, doc),
            Tab::Exports => self.show_exports(ui, doc),
            Tab::Directories => self.show_directories(ui, doc),
            Tab::Iat => self.show_iat(ui),
        }
    }

    fn show_headers(&self, ui: &mut egui::Ui, doc: &PeDocument) {
        egui::Grid::new("headers")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("Arch");
                ui.label(format!("{:?}", doc.arch()));
                ui.end_row();
                ui.label("Machine");
                ui.label(format!("{:?}", doc.coff_header().machine));
                ui.end_row();
                ui.label("Image base");
                ui.label(format!("{:#x}", doc.optional_header().image_base()));
                ui.end_row();
                ui.label("Entry point");
                ui.label(format!(
                    "{:#x}",
                    doc.optional_header().address_of_entry_point().get()
                ));
                ui.end_row();
                ui.label("Subsystem");
                ui.label(format!("{}", doc.optional_header().subsystem()));
                ui.end_row();
                ui.label("Sections");
                ui.label(format!("{}", doc.sections().len()));
                ui.end_row();
                ui.label("Imports");
                ui.label(format!("{} modules", doc.imports().len()));
                ui.end_row();
                ui.label("Exports");
                ui.label(format!(
                    "{} symbols",
                    doc.exports().map(|e| e.symbols.len()).unwrap_or(0)
                ));
                ui.end_row();
                ui.label("Relocations");
                ui.label(format!(
                    "{} blocks",
                    doc.relocations().map(|t| t.blocks.len()).unwrap_or(0)
                ));
                ui.end_row();
                ui.label("Security cookie");
                ui.label(format!(
                    "{:#x}",
                    doc.load_config().map(|l| l.security_cookie).unwrap_or(0)
                ));
                ui.end_row();
                ui.label("CFG guard flags");
                ui.label(format!(
                    "{:#x}",
                    doc.load_config().map(|l| l.guard_flags).unwrap_or(0)
                ));
                ui.end_row();
            });
    }

    fn show_sections(&self, ui: &mut egui::Ui, doc: &PeDocument) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("sections")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Name");
                    ui.label("VA");
                    ui.label("VSize");
                    ui.label("RawSize");
                    ui.label("Chars");
                    ui.end_row();
                    for s in doc.sections() {
                        ui.label(s.name_str());
                        ui.label(format!("{:#x}", s.header.virtual_address.get()));
                        ui.label(format!("{:#x}", s.header.virtual_size));
                        ui.label(format!("{:#x}", s.header.size_of_raw_data));
                        ui.label(format!("{:#x}", s.header.characteristics));
                        ui.end_row();
                    }
                });
        });
    }

    fn show_imports(&self, ui: &mut egui::Ui, doc: &PeDocument) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("imports")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Module");
                    ui.label("Functions");
                    ui.end_row();
                    for d in doc.imports() {
                        ui.label(&d.name);
                        ui.label(
                            d.functions
                                .iter()
                                .map(|f| f.display_name())
                                .collect::<Vec<_>>()
                                .join(", "),
                        );
                        ui.end_row();
                    }
                });
        });
    }

    fn show_exports(&self, ui: &mut egui::Ui, doc: &PeDocument) {
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

    fn show_directories(&self, ui: &mut egui::Ui, doc: &PeDocument) {
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

    fn show_iat(&self, ui: &mut egui::Ui) {
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
