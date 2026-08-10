//! Scylla-style process dump / IAT fix GUI built on the `pe-scylla` library.
//!
//! The workflow is process-oriented (Scylla benchmark): pick a process (and
//! optionally one of its loaded modules), dump its image into a
//! [`PeDocument`], then drive the Scylla interaction model — an **OEP** field,
//! an **IAT address/size** (typed by hand or filled by Scan IAT), **Get Imports**
//! resolves the live process's IAT into a per-module import tree (✓ valid /
//! ? suspect / ✗ invalid), the tree is curated, and **Fix Dump** rebuilds the
//! imports from it (writing the OEP).

use eframe::egui;
use pe_edit::domain::{
    DataDirectoryIndex, IatFixOptions, IatFixReport, IatScan, ResourceEntryData, ResourceName,
    ScanMethod, ScanOptions,
};
use pe_edit::io::pe::serialize;
use pe_scylla::api::{
    IatScanner, ImportStatus, ImportsTree, fix_iat_from_tree, get_imports_regions,
};
use pe_scylla::io::tree::{TreeFile, load_json, load_xml, save_json, save_xml};
use pe_scylla::process::{self, ModuleInfo, ProcessInfo, ProcessResolver};
use std::path::Path;
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

/// Status glyph for an import-tree entry.
fn status_glyph(s: ImportStatus) -> &'static str {
    match s {
        ImportStatus::Valid => "✓",
        ImportStatus::Suspect => "?",
        ImportStatus::Invalid => "✗",
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

/// Parse a hex or decimal string into a `u64` (`None` when empty or invalid).
fn parse_hex64(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        u64::from_str_radix(s, 16)
            .or_else(|_| s.parse::<u64>())
            .ok()
    }
}

/// The left-hand PE-structure tree node selected, shown in the central panel
/// (CFF-Explorer-style layout). Selecting "Sections" makes the right side a
/// top/bottom split: the section table over a binary viewport preview.
#[derive(Default, Clone, Copy, PartialEq)]
enum PeNode {
    /// The Scylla workflow (dump → IAT → fix).
    #[default]
    Scylla,
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
}

#[derive(Default)]
struct ScyllaGui {
    pid: String,
    /// Short label of the dumped module ("main module" or the DLL name), for
    /// the document-source line in the toolbar.
    dump_label: String,
    save_path: String,
    doc: Option<pe_edit::domain::PeDocument>,
    resolver: Option<ProcessResolver>,
    scan: Option<IatScan>,
    /// Outcome of the last successful IAT fix, for the save health check.
    last_fix: Option<IatFixReport>,
    /// Pending save-time confirmation: the warning text to show and the path
    /// to write once the user force-saves a possibly-broken import table.
    save_warning: Option<String>,
    pending_save_path: Option<String>,
    /// Scan method used by "Scan IAT" (Resolver / Code references /
    /// Reflection — see `ScanMethod`).
    scan_method: ScanMethod,
    /// Scylla fields: original entry point (RVA) and the **IAT regions** — a
    /// normal IAT is one `(va, size)`, a sliced/scattered IAT is several,
    /// added by hand. Filled by Scan IAT / IAT Auto, editable in the list.
    oep: String,
    iat_regions: Vec<(u64, usize)>,
    /// "Add IAT region" input fields.
    iat_region_va: String,
    iat_region_size: String,
    /// The Get Imports result: a curated per-module import tree.
    tree: Option<ImportsTree>,
    /// One "keep" flag per tree entry (flattened module → entry order);
    /// uncheck to drop the entry from Fix Dump.
    tree_keep: Vec<bool>,
    status: String,
    /// Rolling log of actions, shown at the bottom.
    log: Vec<String>,
    /// Options dialog visibility + the tunable flags.
    show_options: bool,
    suspend_before_dump: bool,
    advanced_search: bool,
    scan_direct_imports: bool,
    /// Disassembler view state.
    show_disasm: bool,
    disasm_section: usize,
    /// Selected left-hand PE-structure tree node.
    selected: PeNode,
    /// The section selected in the left pane's section table, whose bytes are
    /// shown in the binary view.
    selected_section: usize,
    /// "Jump to offset/address" input in the binary view's context menu.
    binary_jump: String,
    /// One-shot "scroll the binary view to this RVA" request.
    binary_scroll_to: Option<u32>,
    /// Pending async tree save/load dialog results.
    tree_save_rx: Option<mpsc::Receiver<PickResult>>,
    tree_load_rx: Option<mpsc::Receiver<PickResult>>,
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
    fn clear_iat(&mut self) {
        self.scan = None;
        self.tree = None;
        self.tree_keep.clear();
        self.last_fix = None;
    }

    /// Append a line to the log (bounded) and the status bar.
    fn log_line(&mut self, s: String) {
        if self.log.len() >= 200 {
            self.log.remove(0);
        }
        self.log.push(s.clone());
        self.status = s;
    }

    /// Dump a process's main module (`base: None`) or one of its loaded
    /// modules (`base: Some`) into the working image, replacing the current one.
    fn dump_module_at(&mut self, pid: u32, base: Option<u64>, label: &str) {
        self.clear_iat();
        let suspended = self.suspend_before_dump && process::suspend(pid).is_ok();
        let dumped = match base {
            Some(base) => process::dump_module(pid, base),
            None => process::dump(pid),
        };
        if suspended {
            let _ = process::resume(pid);
        }
        match dumped {
            Ok(doc) => {
                let entry = doc.optional.address_of_entry_point().get();
                self.resolver = ProcessResolver::for_process(pid).ok();
                self.doc = Some(doc);
                self.dump_label = label.to_string();
                // Pre-fill the OEP field with the dumped entry point (RVA).
                if self.oep.is_empty() {
                    self.oep = format!("{entry:#x}");
                }
                self.status = format!("dumped {label} (pid {pid})");
            }
            Err(e) => self.status = format!("dump failed: {e}"),
        }
    }

    /// Scan the dumped image's IAT with the chosen method and fill the IAT
    /// address/size fields with the result (Scylla's "find the IAT first").
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
                let psize = pe_edit::domain::types::ptr_size(doc.arch);
                let base_va = resolver.image_base;
                // A scan finds one contiguous region; replace the list with it.
                self.iat_regions.clear();
                self.iat_regions.push((
                    base_va + scan.base_rva.get() as u64,
                    scan.entries.len() * psize,
                ));
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

    /// Scylla's "Get Imports": read the live process's IAT region(s) and
    /// resolve every thunk into the import tree. A sliced IAT is covered by
    /// several regions added by hand.
    fn get_imports(&mut self) {
        let (Some(resolver), Some(_doc)) = (self.resolver.as_ref(), self.doc.as_ref()) else {
            self.status = "no process — dump a process first".into();
            return;
        };
        if self.iat_regions.is_empty() {
            self.status = "add at least one IAT region (or Scan IAT / IAT Auto)".into();
            return;
        }
        let pid = self.pid.parse::<u32>().unwrap_or(0);
        // An IAT size of 0 means "a few pointers" — default to 0x100 bytes.
        let regions: Vec<(u64, usize)> = self
            .iat_regions
            .iter()
            .map(|&(va, size)| (va, if size == 0 { 0x100 } else { size }))
            .collect();
        match get_imports_regions(pid, resolver, &regions) {
            Ok(tree) => {
                let n = tree.total();
                self.tree_keep = vec![true; n];
                self.status = format!(
                    "get imports — {} imports ({} valid, {} suspect, {} invalid)",
                    tree.total(),
                    tree.valid(),
                    tree.suspect(),
                    tree.invalid(),
                );
                self.tree = Some(tree);
            }
            Err(e) => {
                self.status = format!("get imports failed: {e}");
                self.tree = None;
                self.tree_keep.clear();
            }
        }
    }

    /// Scylla's "Fix Dump": rebuild the imports in the dumped image from the
    /// curated tree, writing the OEP field when set.
    fn fix_dump(&mut self) {
        let Some(tree) = self.tree.as_ref() else {
            self.status = "no import tree — Get Imports first".into();
            return;
        };
        let Some(doc) = self.doc.as_mut() else {
            self.status = "no document".into();
            return;
        };
        // Apply the keep flags: unchecked entries are dropped (invalidated).
        let mut fixed = tree.clone();
        let mut keep = self.tree_keep.iter();
        for m in &mut fixed.modules {
            for e in &mut m.entries {
                if keep.next() == Some(&false) {
                    e.status = ImportStatus::Invalid;
                }
            }
        }
        let oep = parse_hex64(&self.oep).map(|v| v as u32);
        match fix_iat_from_tree(doc, &fixed, &IatFixOptions::default(), oep) {
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

    /// Scylla's "IAT Autosearch": find the IAT in the live process starting
    /// from the OEP (or the dumped entry point) and fill the IAT fields.
    fn iat_autosearch(&mut self) {
        let Some(resolver) = self.resolver.as_ref() else {
            self.status = "no process — dump a process first".into();
            return;
        };
        let pid = self.pid.parse::<u32>().unwrap_or(0);
        let entry_rva = self
            .doc
            .as_ref()
            .map(|d| d.optional.address_of_entry_point().get() as u64)
            .unwrap_or(0);
        let oep_rva = parse_hex64(&self.oep).unwrap_or(entry_rva);
        let start = resolver.image_base + oep_rva;
        match process::search_iat(pid, start, self.advanced_search) {
            Ok(Some((va, size))) => {
                // Autosearch finds one region; replace the list with it.
                self.iat_regions.clear();
                self.iat_regions.push((va, size));
                self.status = format!(
                    "IAT autosearch — VA {va:#x} RVA {:#x} size {size}",
                    va.saturating_sub(resolver.image_base)
                );
            }
            Ok(None) => self.status = format!("IAT not found from {start:#x}"),
            Err(e) => self.status = format!("IAT autosearch failed: {e}"),
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

    /// Save to the last "Save As…" path, or open the Save As dialog for a dump
    /// that has not been saved yet (Scylla's dump is always written to a
    /// user-chosen path).
    fn save(&mut self, ctx: &egui::Context) {
        if self.save_path.trim().is_empty() {
            self.save_dialog(ctx);
            return;
        }
        let path = self.save_path.clone();
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
        if self.last_fix.is_none() {
            return Some(
                "该文件来自进程 dump,导入表尚未修复,保存的 dump 通常无法直接运行。".into(),
            );
        }
        if doc.imports.is_empty() {
            return Some("导入表为空,可能无法正常运行。".into());
        }
        None
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

    /// Open a "save tree" dialog (XML or JSON) on a background thread.
    fn save_tree_dialog(&mut self, ctx: &egui::Context) {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let picked = rfd::FileDialog::new()
                .set_title("Save import tree")
                .add_filter("XML", &["xml"])
                .add_filter("JSON", &["json"])
                .set_file_name("imports.xml")
                .save_file();
            let _ = tx.send(picked);
            ctx.request_repaint();
        });
        self.tree_save_rx = Some(rx);
    }

    /// Open a "load tree" dialog on a background thread.
    fn load_tree_dialog(&mut self, ctx: &egui::Context) {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let picked = rfd::FileDialog::new()
                .set_title("Load import tree")
                .add_filter("Import trees", &["xml", "json"])
                .pick_file();
            let _ = tx.send(picked);
            ctx.request_repaint();
        });
        self.tree_load_rx = Some(rx);
    }

    /// Persist the current import tree (XML or JSON by extension) with the
    /// OEP / IAT metadata.
    fn save_tree(&mut self, path: String) {
        let Some(tree) = self.tree.as_ref() else {
            self.log_line("no import tree to save".into());
            return;
        };
        let file = TreeFile {
            oep: parse_hex64(&self.oep).unwrap_or(0) as u32,
            iat_va: self.iat_regions.first().map(|r| r.0).unwrap_or(0),
            iat_size: self.iat_regions.first().map(|r| r.1).unwrap_or(0),
            iat_regions: self.iat_regions.clone(),
            tree: tree.clone(),
        };
        let res = if path.ends_with(".json") {
            save_json(Path::new(&path), &file)
        } else {
            save_xml(Path::new(&path), &file)
        };
        match res {
            Ok(()) => self.log_line(format!("saved import tree to {path}")),
            Err(e) => self.log_line(format!("save tree failed: {e}")),
        }
    }

    /// Load a saved import tree into the working tree.
    fn load_tree(&mut self, path: String) {
        let res = if path.ends_with(".json") {
            load_json(Path::new(&path))
        } else {
            load_xml(Path::new(&path))
        };
        match res {
            Ok(file) => {
                self.tree = Some(file.tree);
                self.tree_keep = vec![true; self.tree.as_ref().map(|t| t.total()).unwrap_or(0)];
                if file.oep != 0 {
                    self.oep = format!("{:#x}", file.oep);
                }
                if !file.iat_regions.is_empty() {
                    self.iat_regions = file.iat_regions;
                } else if file.iat_va != 0 {
                    self.iat_regions = vec![(file.iat_va, file.iat_size)];
                }
                self.log_line(format!("loaded import tree from {path}"));
            }
            Err(e) => self.log_line(format!("load tree failed: {e}")),
        }
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
        if let Some(path) = Self::drain_pick(&mut self.save_rx) {
            self.save_path = path.to_string_lossy().into_owned();
            self.save_to(self.save_path.clone());
        }
        if let Some(path) = Self::drain_pick(&mut self.tree_save_rx) {
            let path = path.to_string_lossy().into_owned();
            self.save_tree(path);
        }
        if let Some(path) = Self::drain_pick(&mut self.tree_load_rx) {
            let path = path.to_string_lossy().into_owned();
            self.load_tree(path);
        }

        // Menu bar: the primary entry point for both workflows.
        egui::Panel::top("menu").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
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
                ui.menu_button("Imports", |ui| {
                    if ui.button("Save Tree…").clicked() {
                        self.save_tree_dialog(ui.ctx());
                        ui.close();
                    }
                    if ui.button("Load Tree…").clicked() {
                        self.load_tree_dialog(ui.ctx());
                        ui.close();
                    }
                });
                ui.menu_button("View", |ui| {
                    if ui.button("Disassembler").clicked() {
                        self.show_disasm = true;
                        ui.close();
                    }
                    if ui.button("Options…").clicked() {
                        self.show_options = true;
                        ui.close();
                    }
                });
            });
        });

        // Keyboard shortcuts.
        let ctrl_s = ui
            .ctx()
            .input(|i| i.modifiers.command && i.key_pressed(egui::Key::S));
        if ctrl_s {
            self.save(ui.ctx());
        }

        // Document-source line: the dumped process/module plus a read-only
        // image summary and the status.
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("进程:");
                ui.label(format!("pid {} · {}", self.pid, self.dump_label));
                if let Some(doc) = &self.doc {
                    ui.separator();
                    ui.weak(summary(doc));
                }
                ui.separator();
                ui.label(&self.status);
            });
        });

        // CFF-Explorer-style layout: a left menu tree; the selected node's
        // content on the right. Selecting "Sections" turns the right side into
        // a section table (top) + binary viewport preview (bottom).
        egui::Panel::left("tree_pane")
            .resizable(true)
            .default_size(200.0)
            .show(ui, |ui| {
                self.show_structure_tree(ui);
            });
        egui::CentralPanel::default_margins().show(ui, |ui| {
            self.show_selected(ui);
        });

        // Log panel: the last few actions.
        egui::Panel::bottom("log").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong("Log");
                ui.separator();
                let start = self.log.len().saturating_sub(5);
                for line in &self.log[start..] {
                    ui.weak(line);
                    ui.separator();
                }
            });
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
                        // Title row (the window's X / ESC dismiss the picker).
                        ui.strong("选择进程");
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

        // Options dialog: Scylla's tunable flags, in its own native window.
        let mut close_options = false;
        if self.show_options {
            let ctx = ui.ctx().clone();
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("options_viewport"),
                egui::ViewportBuilder::default()
                    .with_title("Options")
                    .with_resizable(false),
                |ui, _class| {
                    if ui.ctx().input(|i| i.viewport().close_requested())
                        || ui.ctx().input(|i| i.key_pressed(egui::Key::Escape))
                    {
                        close_options = true;
                    }
                    egui::CentralPanel::default().show(ui, |ui| {
                        ui.checkbox(&mut self.suspend_before_dump, "Suspend process for dumping");
                        ui.checkbox(&mut self.advanced_search, "Advanced IAT search");
                        ui.checkbox(&mut self.scan_direct_imports, "Scan direct imports");
                        ui.separator();
                        if ui.button("Close").clicked() {
                            close_options = true;
                        }
                    });
                },
            );
            if close_options {
                self.show_options = false;
            }
        }

        // Disassembler view: disassemble a section, in its own native window.
        let mut close_disasm = false;
        if self.show_disasm {
            let ctx = ui.ctx().clone();
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("disasm_viewport"),
                egui::ViewportBuilder::default()
                    .with_title("Disassembler")
                    .with_inner_size([620.0, 480.0])
                    .with_resizable(true),
                |ui, _class| {
                    if ui.ctx().input(|i| i.viewport().close_requested())
                        || ui.ctx().input(|i| i.key_pressed(egui::Key::Escape))
                    {
                        close_disasm = true;
                    }
                    egui::CentralPanel::default().show(ui, |ui| {
                        if let Some(doc) = self.doc.as_ref() {
                            ui.horizontal(|ui| {
                                ui.label("Section:");
                                egui::ComboBox::from_id_salt("disasm_sec")
                                    .selected_text(format!(
                                        "#{} {}",
                                        self.disasm_section,
                                        doc.sections
                                            .get(self.disasm_section)
                                            .map(|s| s.name_str())
                                            .unwrap_or_else(|| "?".to_string())
                                    ))
                                    .show_ui(ui, |ui| {
                                        for i in 0..doc.sections.len() {
                                            ui.selectable_value(
                                                &mut self.disasm_section,
                                                i,
                                                format!("#{i} {}", doc.sections[i].name_str()),
                                            );
                                        }
                                    });
                            });
                            if let Ok(lines) = pe_scylla::feature::disassemble_section(
                                doc,
                                self.disasm_section,
                                500,
                            ) {
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    for line in lines {
                                        ui.monospace(line);
                                    }
                                });
                            }
                        } else {
                            ui.label("no document");
                        }
                        if ui.button("Close").clicked() {
                            close_disasm = true;
                        }
                    });
                },
            );
            if close_disasm {
                self.show_disasm = false;
            }
        }

        // Save-time confirmation: the import table looks broken, the user can
        // still force the save. Shown in its own native window.
        let mut close_save = false;
        if self.save_warning.is_some() {
            let ctx = ui.ctx().clone();
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("confirm_save_viewport"),
                egui::ViewportBuilder::default()
                    .with_title("Confirm save")
                    .with_resizable(false),
                |ui, _class| {
                    if ui.ctx().input(|i| i.viewport().close_requested())
                        || ui.ctx().input(|i| i.key_pressed(egui::Key::Escape))
                    {
                        close_save = true;
                    }
                    egui::CentralPanel::default().show(ui, |ui| {
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
                                close_save = true;
                            }
                        });
                    });
                },
            );
            if close_save {
                self.save_warning = None;
                self.pending_save_path = None;
            }
        }
    }
}

impl ScyllaGui {
    /// The Scylla workflow: IAT info fields + Get Imports tree + Fix Dump.
    fn show_workflow(&mut self, ui: &mut egui::Ui) {
        let has_resolver = self.resolver.is_some();
        ui.horizontal(|ui| {
            ui.label("OEP:");
            ui.add(egui::TextEdit::singleline(&mut self.oep).desired_width(90.0))
                .on_hover_text("Original entry point (RVA) written by Fix Dump");
        });
        // IAT regions: a normal IAT is one (VA, size); a sliced / scattered
        // IAT is several non-contiguous regions, added by hand.
        ui.horizontal(|ui| {
            ui.label("IAT:");
            let mut remove: Option<usize> = None;
            for (i, (va, size)) in self.iat_regions.iter().enumerate() {
                ui.monospace(format!("{va:#x}:{size:#x}"));
                if ui.small_button(format!("×{i}")).clicked() {
                    remove = Some(i);
                }
            }
            if let Some(i) = remove {
                self.iat_regions.remove(i);
            }
            if self.iat_regions.is_empty() {
                ui.weak("(no regions — Scan IAT / IAT Auto or add below)");
            }
        });
        ui.horizontal(|ui| {
            ui.label("Add:");
            ui.add(
                egui::TextEdit::singleline(&mut self.iat_region_va)
                    .hint_text("VA")
                    .desired_width(110.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.iat_region_size)
                    .hint_text("size")
                    .desired_width(70.0),
            );
            if ui.button("Add region").clicked() {
                let va = parse_hex64(&self.iat_region_va);
                let size = parse_hex64(&self.iat_region_size).map(|v| v as usize);
                match (va, size) {
                    (Some(va), Some(size)) => {
                        self.iat_regions.push((va, size));
                        self.iat_region_va.clear();
                        self.iat_region_size.clear();
                        self.status = format!("added IAT region {va:#x}:{size:#x}");
                    }
                    _ => self.status = "region needs VA and size (hex)".into(),
                }
            }
        });

        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Method:");
            egui::ComboBox::from_id_salt("scan_method")
                .selected_text(scan_method_name(self.scan_method))
                .show_ui(ui, |ui| {
                    for (m, name) in [
                        (ScanMethod::Resolver, "Resolver"),
                        (ScanMethod::CodeReference, "Code references"),
                        (ScanMethod::Reflection, "Reflection"),
                    ] {
                        ui.selectable_value(&mut self.scan_method, m, name);
                    }
                });
            if ui
                .add_enabled(has_resolver, egui::Button::new("Scan IAT"))
                .on_hover_text("Scan the dumped image to find the IAT; fills the IAT region")
                .clicked()
            {
                self.scan_iat();
            }
            if ui
                .add_enabled(has_resolver, egui::Button::new("IAT Auto"))
                .on_hover_text(
                    "Autosearch the IAT in the live process (from the OEP); fills the IAT region",
                )
                .clicked()
            {
                self.iat_autosearch();
            }
            if ui
                .add_enabled(has_resolver, egui::Button::new("Get Imports"))
                .on_hover_text("Resolve the live process's IAT into the import tree")
                .clicked()
            {
                self.get_imports();
            }
            if ui
                .add_enabled(self.tree.is_some(), egui::Button::new("Fix Dump"))
                .on_hover_text("Rebuild the imports in the dumped image from the tree")
                .clicked()
            {
                self.fix_dump();
            }
        });
        ui.separator();

        match &self.tree {
            None => {
                if self.scan.is_some() {
                    ui.label(
                        "IAT found — keep the scan region (or add more) and click Get Imports.",
                    );
                } else {
                    ui.label("Dump a process, find the IAT (Scan IAT / IAT Auto or add regions), then Get Imports.");
                }
            }
            Some(tree) => show_tree(ui, tree, &mut self.tree_keep),
        }
    }
}

/// Render the curated import tree (module → entries with keep flags).
fn show_tree(ui: &mut egui::Ui, tree: &ImportsTree, keep: &mut [bool]) {
    ui.label(format!(
        "{} imports — {} valid, {} suspect, {} invalid (uncheck to drop)",
        tree.total(),
        tree.valid(),
        tree.suspect(),
        tree.invalid(),
    ));
    egui::ScrollArea::vertical()
        .id_salt("imports_tree")
        .auto_shrink(false)
        .show(ui, |ui| {
            let mut keep_iter = keep.iter_mut();
            for module in &tree.modules {
                let kept = module
                    .entries
                    .iter()
                    .filter(|e| e.status != ImportStatus::Invalid)
                    .count();
                egui::CollapsingHeader::new(format!(
                    "{}  ({} entries, {} kept)  first_thunk {:#x}",
                    module.name,
                    module.entries.len(),
                    kept,
                    module.first_thunk,
                ))
                .id_salt((&module.name, module.first_thunk))
                .default_open(true)
                .show(ui, |ui| {
                    for entry in &module.entries {
                        ui.horizontal(|ui| {
                            let k = keep_iter.next().unwrap();
                            ui.checkbox(k, "");
                            ui.label(status_glyph(entry.status));
                            ui.monospace(format!("{:#x}", entry.slot_rva));
                            ui.label(entry.label());
                        });
                    }
                });
            }
        });
}

impl ScyllaGui {
    /// The left-hand PE-structure tree (CFF-Explorer style).
    fn show_structure_tree(&mut self, ui: &mut egui::Ui) {
        let mut select = self.selected;
        let mut node = |ui: &mut egui::Ui, label: &str, n: PeNode| {
            if ui.selectable_label(select == n, label).clicked() {
                select = n;
            }
        };
        node(ui, "Scylla (dump / IAT / fix)", PeNode::Scylla);
        ui.separator();
        node(ui, "DOS Header", PeNode::Dos);
        node(ui, "COFF Header", PeNode::Coff);
        node(ui, "Optional Header", PeNode::Optional);
        node(ui, "Data Directories", PeNode::DataDirs);
        node(ui, "Sections", PeNode::Sections);
        node(ui, "Import Table", PeNode::Imports);
        node(ui, "Export Table", PeNode::Exports);
        node(ui, "Resources", PeNode::Resources);
        node(ui, "Relocations", PeNode::Relocations);
        node(ui, "TLS", PeNode::Tls);
        node(ui, "Load Config", PeNode::LoadConfig);
        self.selected = select;
    }

    /// Render the selected left-hand node in the central panel.
    fn show_selected(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = self.doc.as_ref() else {
            if self.selected == PeNode::Scylla {
                self.show_workflow(ui);
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("Dump a process (File → 选择进程…) to begin.");
                });
            }
            return;
        };
        match self.selected {
            PeNode::Scylla => self.show_workflow(ui),
            PeNode::Sections => self.show_sections_pane(ui),
            node => show_pe_node(ui, doc, node),
        }
    }

    /// The right-side content when "Sections" is selected: the section table
    /// (top) over a virtualized binary viewport preview (bottom).
    fn show_sections_pane(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("sec_table_pane")
            .resizable(true)
            .default_size(200.0)
            .show(ui, |ui| {
                self.show_section_list(ui);
            });
        egui::CentralPanel::default_margins().show(ui, |ui| {
            self.show_binary(ui);
        });
    }

    /// The section table (selectable rows) in the top half of the Sections page.
    fn show_section_list(&mut self, ui: &mut egui::Ui) {
        ui.strong("Sections");
        let Some(doc) = self.doc.as_ref() else {
            ui.weak("dump a process to see sections");
            return;
        };
        egui::ScrollArea::vertical()
            .id_salt("sec_list")
            .auto_shrink(false)
            .show(ui, |ui| {
                for (i, s) in doc.sections.iter().enumerate() {
                    let selected = self.selected_section == i;
                    let clicked = ui
                        .selectable_label(
                            selected,
                            format!(
                                "{}  va {:#x}  size {:#x}",
                                s.name_str(),
                                s.header.virtual_address.get(),
                                s.data.len()
                            ),
                        )
                        .clicked();
                    if clicked {
                        self.selected_section = i;
                        self.binary_scroll_to = Some(s.header.virtual_address.get());
                    }
                }
            });
    }

    /// The binary view of the selected section in the bottom half of the
    /// Sections page. Virtualized (`show_rows`): only the rows in the visible
    /// window are rendered, so even multi-megabyte sections stay responsive.
    /// Right-click opens a menu to jump to an offset/address or the section
    /// start/end.
    fn show_binary(&mut self, ui: &mut egui::Ui) {
        let ScyllaGui {
            doc,
            selected_section,
            binary_scroll_to,
            binary_jump,
            ..
        } = self;
        let image_base = doc.as_ref().map(|d| d.optional.image_base()).unwrap_or(0);
        let Some(s) = doc.as_ref().and_then(|d| d.sections.get(*selected_section)) else {
            ui.weak("select a section");
            return;
        };
        let base = s.header.virtual_address.get();
        let len = s.data.len();
        if len == 0 {
            ui.label(format!("{} — empty", s.name_str()));
            return;
        }
        let rows = len.div_ceil(16).max(1);
        let row_height = 18.0;
        ui.horizontal(|ui| {
            ui.label(format!(
                "{} — rva {base:#x}..{:#x} — {len} bytes",
                s.name_str(),
                base + len as u32 - 1
            ));
            ui.weak("(right-click to jump)");
        });

        // One-shot scroll to a requested RVA.
        let mut sa = egui::ScrollArea::vertical()
            .id_salt("binary")
            .auto_shrink(false);
        if let Some(rva) = *binary_scroll_to {
            let off = (rva.saturating_sub(base) / 16) as f32 * row_height;
            sa = sa.vertical_scroll_offset(off);
        }
        let mut jump_requested = false;
        let out = sa.show_rows(ui, row_height, rows, |ui, range| {
            for row in range {
                let start = row * 16;
                let chunk = &s.data[start..(start + 16).min(len)];
                let rva = base + (row as u32) * 16;
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
                ui.monospace(format!("{rva:#08x}: {hex:<48} {ascii}"));
            }
        });
        let ctx = ui.interact(
            out.inner_rect,
            egui::Id::new("binary_ctx"),
            egui::Sense::click(),
        );
        ctx.context_menu(|ui| {
            ui.label("跳转偏移/RVA:");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(binary_jump).desired_width(120.0));
                if ui.button("Go").clicked() {
                    if let Some(v) = parse_hex64(binary_jump) {
                        *binary_scroll_to = Some(parse_jump_target(v, image_base, base, len));
                        jump_requested = true;
                    }
                    ui.close();
                }
            });
            ui.separator();
            if ui.button("跳转到区段开始").clicked() {
                *binary_scroll_to = Some(base);
                jump_requested = true;
                ui.close();
            }
            if ui.button("跳转到区段结束").clicked() {
                *binary_scroll_to = Some(base + len.saturating_sub(1) as u32);
                jump_requested = true;
                ui.close();
            }
        });
        // Consume the one-shot jump unless a new one was requested this frame.
        if !jump_requested {
            *binary_scroll_to = None;
        }
    }
}

/// Interpret a "jump" input as an offset (RVA) or an absolute address (VA ≥
/// image base), clamped to the section's range.
fn parse_jump_target(v: u64, image_base: u64, sec_base: u32, sec_len: usize) -> u32 {
    let rva = if v >= image_base {
        (v - image_base) as u32
    } else {
        v as u32
    };
    let end = sec_base.saturating_add(sec_len as u32).saturating_sub(1);
    rva.clamp(sec_base, end.max(sec_base))
}

/// Render a PE-structure node's content (read-only).
fn show_pe_node(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument, node: PeNode) {
    match node {
        PeNode::Dos => show_dos(ui, doc),
        PeNode::Coff => show_coff(ui, doc),
        PeNode::Optional => show_optional(ui, doc),
        PeNode::DataDirs => show_data_dirs(ui, doc),
        PeNode::Imports => show_imports(ui, doc),
        PeNode::Exports => show_exports(ui, doc),
        PeNode::Resources => show_resources(ui, doc),
        PeNode::Relocations => show_relocations(ui, doc),
        PeNode::Tls => show_tls(ui, doc),
        PeNode::LoadConfig => show_load_config(ui, doc),
        // Handled in ScyllaGui::show_selected.
        PeNode::Scylla | PeNode::Sections => {}
    }
}

/// A `(name, value)` field grid.
fn grid(ui: &mut egui::Ui, rows: &[(&str, String)]) {
    egui::Grid::new("field_grid")
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

fn show_dos(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument) {
    let d = &doc.dos;
    grid(
        ui,
        &[
            ("e_magic", format!("0x{:x}", d.e_magic)),
            ("e_lfanew", format!("0x{:x}", d.e_lfanew)),
            ("stub len", format!("{}", d.stub.len())),
        ],
    );
}

fn show_coff(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument) {
    let c = &doc.coff;
    grid(
        ui,
        &[
            ("machine", format!("{:?}", c.machine)),
            ("sections", format!("{}", c.number_of_sections)),
            ("time/date", format!("0x{:x}", c.time_date_stamp)),
            ("opt header", format!("{}", c.size_of_optional_header)),
            ("characteristics", format!("0x{:x}", c.characteristics)),
        ],
    );
}

fn show_optional(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument) {
    let o = &doc.optional;
    grid(
        ui,
        &[
            ("arch", format!("{:?}", o.arch())),
            ("image base", format!("{:#x}", o.image_base())),
            (
                "entry point",
                format!("{:#x}", o.address_of_entry_point().get()),
            ),
            ("section align", format!("0x{:x}", o.section_alignment())),
            ("file align", format!("0x{:x}", o.file_alignment())),
            ("size of image", format!("0x{:x}", o.size_of_image())),
            ("size of headers", format!("0x{:x}", o.size_of_headers())),
            ("checksum", format!("0x{:x}", o.checksum())),
            ("subsystem", format!("{}", o.subsystem())),
            ("dll chars", format!("0x{:x}", o.dll_characteristics())),
        ],
    );
}

fn show_data_dirs(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument) {
    egui::Grid::new("data_dirs")
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
                ui.monospace(format!("{:#x}", dd.rva.get()));
                ui.monospace(format!("{:#x}", dd.size));
                ui.end_row();
            }
        });
}

fn show_imports(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument) {
    if doc.imports.is_empty() {
        ui.label("no imports");
        return;
    }
    for d in &doc.imports {
        egui::CollapsingHeader::new(format!("{} ({})", d.name, d.functions.len()))
            .id_salt(&d.name)
            .default_open(false)
            .show(ui, |ui| {
                for f in &d.functions {
                    ui.monospace(f.display_name());
                }
            });
    }
}

fn show_exports(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument) {
    let Some(e) = &doc.exports else {
        ui.label("no export table");
        return;
    };
    egui::Grid::new("exports")
        .num_columns(4)
        .striped(true)
        .show(ui, |ui| {
            ui.label("Ordinal");
            ui.label("Name");
            ui.label("RVA");
            ui.label("Forwarder");
            ui.end_row();
            for s in &e.symbols {
                ui.label(format!("{}", s.ordinal));
                ui.monospace(s.name.as_deref().unwrap_or("<ordinal>"));
                ui.monospace(format!("{:#x}", s.rva.get()));
                ui.monospace(s.forwarder.as_deref().unwrap_or(""));
                ui.end_row();
            }
        });
}

fn show_resources(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument) {
    let Some(root) = &doc.resources else {
        ui.label("no resources");
        return;
    };
    render_resource_dir(ui, root);
}

fn render_resource_dir(ui: &mut egui::Ui, dir: &pe_edit::domain::ResourceDirectory) {
    for e in &dir.entries {
        let name = match &e.name {
            ResourceName::Id(id) => format!("#{id}"),
            ResourceName::Named(n) => n.clone(),
        };
        match &e.data {
            ResourceEntryData::Directory(d) => {
                egui::CollapsingHeader::new(name)
                    .id_salt(format!("{:?}", e.name))
                    .show(ui, |ui| {
                        render_resource_dir(ui, d);
                    });
            }
            ResourceEntryData::Leaf(l) => {
                ui.horizontal(|ui| {
                    ui.label(name);
                    ui.monospace(format!("rva {:#x} size {:#x}", l.rva.get(), l.size));
                });
            }
        }
    }
}

fn show_relocations(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument) {
    let Some(t) = &doc.relocations else {
        ui.label("no relocations");
        return;
    };
    for (i, b) in t.blocks.iter().enumerate() {
        ui.label(format!(
            "block {i}: page {:#x}, {} entries",
            b.page_rva.get(),
            b.entries.len()
        ));
    }
}

fn show_tls(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument) {
    let Some(t) = &doc.tls else {
        ui.label("no TLS");
        return;
    };
    grid(
        ui,
        &[
            ("start", format!("{:#x}", t.start_address_of_raw_data)),
            ("end", format!("{:#x}", t.end_address_of_raw_data)),
            ("index", format!("{:#x}", t.address_of_index)),
            ("callbacks", format!("{:#x}", t.address_of_callbacks)),
            ("zero fill", format!("{:#x}", t.size_of_zero_fill)),
        ],
    );
}

fn show_load_config(ui: &mut egui::Ui, doc: &pe_edit::domain::PeDocument) {
    let Some(lc) = &doc.load_config else {
        ui.label("no load config");
        return;
    };
    grid(
        ui,
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
