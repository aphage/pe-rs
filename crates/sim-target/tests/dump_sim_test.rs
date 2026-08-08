//! End-to-end simulation, driven exactly like the real scenario:
//!
//! 1. spawn `sim-target corrupt <scenario>` — it corrupts its own in-memory PE
//!    and then **pauses itself** (like a debugger break), printing the pid;
//! 2. a standalone pe dump tool (here pe-rs, the library `examples/dump.rs`
//!    wraps) dumps the paused process, scans its IAT with the per-scenario
//!    method, fixes the imports and writes a rebuilt executable;
//! 3. the fixed dump is run — it must print `SIM_TARGET_OK` and exit 0.
//!
//! Spawns real processes, so it is ignored by default:
//!
//! ```text
//! cargo test -p sim-target -- --ignored
//! ```

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use pe_rs::api::{IatFixer, IatScanner};
use pe_rs::domain::{IatFixOptions, ScanMethod, ScanOptions};

/// Spawn the target in `scenario`, wait for its readiness line, and return the
/// (paused) child plus its pid.
fn spawn_target(scenario: &str) -> (Child, u32) {
    let mut child = Command::new(target_exe())
        .arg("corrupt")
        .arg(scenario)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn sim-target");
    let pid = wait_ready(BufReader::new(child.stdout.take().expect("target stdout")));
    (child, pid)
}

fn wait_ready<R: BufRead>(mut reader: R) -> u32 {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).expect("read target") == 0 {
            panic!("target exited before SIM_TARGET_READY");
        }
        if let Some(rest) = line.trim().strip_prefix("SIM_TARGET_READY:") {
            return rest.trim().parse().expect("pid");
        }
    }
}

fn target_exe() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_sim-target") {
        return p.into();
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.join("sim-target.exe")))
        .filter(|p| p.exists())
        .expect("locate sim-target.exe")
}

/// The scan method for a scenario (docs/dump 情况分析和处理.md selection table).
fn scan_for(scenario: &str) -> ScanOptions {
    let opts = |method: ScanMethod, validate: bool| ScanOptions {
        method,
        validate_slots: validate,
        ..Default::default()
    };
    match scenario {
        "normal" | "a" => opts(ScanMethod::CodeReference, true),
        "oft" | "b" | "iatdir" | "c" => opts(ScanMethod::Reflection, true),
        "erased" | "d" => opts(ScanMethod::CodeReference, true),
        other => panic!("unknown scenario '{other}'"),
    }
}

#[test]
#[ignore]
fn all_scenarios_dump_fix_and_rerun() {
    for scenario in ["normal", "oft", "iatdir", "erased"] {
        let (mut target, pid) = spawn_target(scenario);
        let out = std::env::temp_dir().join(format!("sim_target_fixed_{scenario}.exe"));

        // Standalone dump + fix, exactly what
        // `cargo run -p pe-rs --example dump -- <pid> <out> --method <...>` does.
        let mut doc = pe_rs::process::dump(pid).expect("dump paused target");
        let resolver = pe_rs::process::ProcessResolver::for_process(pid).expect("build resolver");
        let scan = doc.scan(&resolver, &scan_for(scenario)).expect("scan IAT");
        let report = doc
            .fix_iat(&scan, &resolver, &IatFixOptions::default())
            .expect("fix IAT");
        assert!(
            report.unresolved.is_empty(),
            "scenario {scenario}: {} IAT entries unresolved",
            report.unresolved.len()
        );
        let bytes = pe_rs::io::pe::serialize(&doc).expect("serialize");
        std::fs::write(&out, &bytes).expect("write fixed dump");

        // Terminate the paused target, then run the fixed dump.
        let _ = target.kill();
        let _ = target.wait();
        let output = Command::new(&out)
            .arg("verify")
            .output()
            .expect("run fixed dump");
        assert!(
            output.status.success(),
            "scenario {scenario}: fixed dump exited {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("SIM_TARGET_OK"),
            "scenario {scenario}: fixed dump did not print SIM_TARGET_OK: {stdout}"
        );
        std::fs::remove_file(&out).ok();
    }
}
