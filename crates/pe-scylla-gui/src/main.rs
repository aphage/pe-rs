//! Scylla-style process dump / IAT fix GUI built on the `pe-scylla` library.
//!
//! The workflow is process-oriented (Scylla benchmark): pick a process (and
//! optionally one of its loaded modules), dump its image into a
//! [`PeDocument`], scan the IAT with the chosen method, curate the entries,
//! fix the imports and save the rebuilt dump. An existing dump file can also be
//! opened and scanned against a process's loaded modules. This is not a PE
//! *editor* — the disk-editing side lives in `pe-edit-gui`.

use eframe::egui;
use pe_edit::domain::{
    IatEntry, IatFixOptions, IatFixReport, IatScan, IatTable, Rva, ScanMethod, ScanOptions,
};
use pe_edit::io::pe::{parse, serialize};
use pe_scylla::api::{IatFixer, IatScanner};
use pe_scylla::process::{self, ModuleInfo, ProcessInfo, ProcessResolver};
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
        "pe-scylla",
        options,
        Box::new(|cc| {
            install_fonts(&cc.egui_ctx);
            Ok(Box::new(ScyllaGui::default()))
        }),
    )
}

/// Human-readable label for a scan method (used in the IAT-page selector).
fn scan_method_name(m: ScanMethod) -> &'static str {
    match m {
        ScanMethod::Resolver => "Resolver",
        ScanMethod::CodeReference => "Code references",
        ScanMethod::Reflection => "Reflection",
    }
}

/// Read-only summary of the current document, for the toolbar.
fn summary(doc: &pe_edit::domain::PeDocument) -> String {
    let imports: usize = doc.imports.iter().map(|d| d.functions.len()).sum();
    format!(
        "{} · base {:#x} · entry {:#x} · {} sections · {} imports",
        match doc.arch {
            pe_edit::domain::Arch::Bit64 => "x64",
            pe_edit::domain::Arch::Bit32 => "x86",
        },
        doc.optional.image_base(),
        doc.optional.address_of_entry_point().get(),
        doc.sections.len(),
        imports,
    )
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
struct ScyllaGui {
    path: String,
    pid: String,
    /// Short label of the dumped module ("main module" or the DLL name), for
    /// the document-source line in the toolbar.
    dump_label: String,
    save_path: String,
    doc: Option<pe_edit::domain::PeDocument>,
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

impl ScyllaGui {
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
                    self.status = format!("loaded {}", self.path);
                }
                Err(e) => self.status = format!("parse failed: {e}"),
            },
            Err(e) => self.status = format!("read failed: {e}"),
        }
    }

    /// Dump a process's main module (`base: None`) or one of its loaded
    /// modules (`base: Some`) into the working image, replacing the current one.
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
}

impl eframe::App for ScyllaGui {
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

        // Document-source line: what we are working on (a file path, or a
        // dumped process/module) plus a read-only image summary and the status.
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
                if let Some(doc) = &self.doc {
                    ui.separator();
                    ui.weak(summary(doc));
                }
                ui.separator();
                ui.label(&self.status);
            });
        });

        egui::CentralPanel::default_margins().show(ui, |ui| {
            if self.doc.is_some() {
                self.show_iat(ui);
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("Dump a process (File → 选择进程…) or open a PE file to begin.");
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

impl ScyllaGui {
    fn show_iat(&mut self, ui: &mut egui::Ui) {
        // Scan controls.
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
