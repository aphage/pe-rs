//! Harness for the simulation target: spawn it with a corruption scenario,
//! dump it, run the pe-rs dump → scan → fix → serialize pipeline, save the
//! rebuilt executable, then launch it and verify it actually runs.
//!
//! This is the "模拟测试程序" driver: it reproduces a real packed/protected
//! environment where a running image was corrupted, and proves the fix output
//! is a runnable standalone PE.

#![cfg(target_os = "windows")]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

use pe_rs::api::{IatFixer, IatScanner};
use pe_rs::domain::{IatFixOptions, ScanMethod, ScanOptions};
use pe_rs::io::pe::serialize;

/// Outcome of one simulation run.
#[derive(Debug, Clone)]
pub struct SimReport {
    pub scenario: String,
    pub pid: u32,
    /// Scan method the harness picked for this scenario (the doc's selection
    /// table): `Resolver` / `Reflection` / `CodeReference`.
    pub scan_method: &'static str,
    pub imports_built: usize,
    /// Whether the fixer rebuilt the FirstThunk arrays in place at the original
    /// IAT slots (the runnable-dump shape).
    pub iat_reused: bool,
    pub fixed_path: std::path::PathBuf,
    /// The fixed executable's own stdout (must contain `SIM_TARGET_OK`).
    pub fixed_stdout: String,
}

/// Locate the `sim-target` binary. Cargo sets `CARGO_BIN_EXE_sim-target` for
/// integration tests; examples build into `target/debug/examples/` while the
/// bin sits in `target/debug/`, so fall back to the sibling.
pub fn target_exe() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_sim-target") {
        return std::path::PathBuf::from(p);
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.to_path_buf()))
    {
        let sibling = dir.parent().map(|p| p.join("sim-target.exe"));
        if let Some(p) = sibling.filter(|p| p.exists()) {
            return p;
        }
        let local = dir.join("sim-target.exe");
        if local.exists() {
            return local;
        }
    }
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/sim-target.exe")
}

/// Drive the full simulation for `scenario`:
///
/// 1. spawn `target_exe corrupt <scenario>` and wait for `SIM_TARGET_READY:<pid>`;
/// 2. dump the target, build a resolver over its loaded modules;
/// 3. scan the IAT with the doc's per-scenario method, fix the imports;
/// 4. serialize to `out` (an `.exe`);
/// 5. kill the corrupt target, then launch `out` and check it prints
///    `SIM_TARGET_OK` and exits 0.
pub fn run_simulation(target_exe: &Path, scenario: &str, out: &Path) -> Result<SimReport, String> {
    let mut child = Command::new(target_exe)
        .arg("corrupt")
        .arg(scenario)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn target {}: {e}", target_exe.display()))?;
    let stdout = child.stdout.take().ok_or("target produced no stdout")?;
    let pid = match wait_ready(BufReader::new(stdout)) {
        Ok(pid) => pid,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };

    let dump_result = (|| -> Result<(&'static str, usize, bool), String> {
        let mut doc = pe_rs::process::dump(pid).map_err(|e| e.to_string())?;
        let resolver = pe_rs::process::ProcessResolver::for_process(pid)
            .and_then(|r| r.with_fingerprints())
            .map_err(|e| e.to_string())?;
        let (method, opts) = scan_for(scenario);
        let scan = doc
            .scan(&resolver, &opts)
            .map_err(|e| format!("scan ({method}): {e}"))?;
        let report = doc
            .fix_iat(&scan, &resolver, &IatFixOptions::default())
            .map_err(|e| format!("fix_iat: {e}"))?;
        if !report.unresolved.is_empty() {
            return Err(format!(
                "{} IAT entries could not be resolved",
                report.unresolved.len()
            ));
        }
        let bytes = serialize(&doc).map_err(|e| format!("serialize: {e}"))?;
        std::fs::write(out, &bytes).map_err(|e| format!("write {}: {e}", out.display()))?;
        Ok((method, report.imports_built, report.iat_reused))
    })();

    let _ = child.kill();
    let _ = child.wait();

    let (method, imports_built, iat_reused) = dump_result?;

    let fixed = Command::new(out)
        .arg("verify")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn fixed dump {}: {e}", out.display()))?;
    let output = fixed
        .wait_with_output()
        .map_err(|e| format!("wait fixed dump: {e}"))?;
    let fixed_stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let fixed_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !fixed_stdout.contains("SIM_TARGET_OK") {
        return Err(format!(
            "fixed dump did not print SIM_TARGET_OK (status {})\nstdout: {}\nstderr: {}",
            output.status, fixed_stdout, fixed_stderr
        ));
    }
    if !output.status.success() {
        return Err(format!(
            "fixed dump exited with {}\nstdout: {}\nstderr: {}",
            output.status, fixed_stdout, fixed_stderr
        ));
    }

    Ok(SimReport {
        scenario: scenario.to_string(),
        pid,
        scan_method: method,
        imports_built,
        iat_reused,
        fixed_path: out.to_path_buf(),
        fixed_stdout,
    })
}

/// Read lines until `SIM_TARGET_READY:<pid>` appears (the target then keeps
/// sleeping until killed). Errors when the target dies or the marker never
/// comes.
fn wait_ready<R: BufRead>(mut reader: R) -> Result<u32, String> {
    let mut line = String::new();
    for _ in 0..2000 {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("read target stdout: {e}"))?;
        if n == 0 {
            return Err("target exited before SIM_TARGET_READY".into());
        }
        if let Some(rest) = line.trim().strip_prefix("SIM_TARGET_READY:") {
            return rest
                .trim()
                .parse::<u32>()
                .map_err(|_| format!("bad pid in readiness line: {line}"));
        }
    }
    Err("timeout waiting for SIM_TARGET_READY".into())
}

/// The scan method for a scenario, per docs/dump 情况分析和处理.md's selection
/// table: A → code references (on a live dump the resolver run is noisy; the
/// code-referenced slots are exactly the per-module IAT runs), B/C →
/// Reflection, D → CodeReference (structure erased, so slot content is not
/// validated).
fn scan_for(scenario: &str) -> (&'static str, ScanOptions) {
    let opts = |method: ScanMethod, validate: bool| ScanOptions {
        method,
        validate_slots: validate,
        ..Default::default()
    };
    match scenario {
        "normal" | "a" => ("CodeReference", opts(ScanMethod::CodeReference, true)),
        "oft" | "b" | "iatdir" | "c" => ("Reflection", opts(ScanMethod::Reflection, true)),
        // The target's scattered IAT slots still hold live, resolvable addresses
        // (unlike a real protector), so validation keeps exactly those slots and
        // filters the unrelated code-referenced globals.
        "erased" | "d" => ("CodeReference", opts(ScanMethod::CodeReference, true)),
        other => panic!("unknown scenario '{other}'"),
    }
}
