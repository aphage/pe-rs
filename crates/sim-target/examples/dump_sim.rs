//! Command-line driver for the simulation: build the target, then
//!
//! ```text
//! cargo run -p sim-target --example dump_sim -- --scenario <normal|oft|iatdir|erased> [--out fixed.exe]
//! ```
//!
//! Dumps the corrupt target, fixes its imports, writes `out` and re-runs it to
//! confirm the fixed dump works standalone.

use std::path::Path;

fn main() {
    let mut scenario = "normal".to_string();
    let mut out = std::path::PathBuf::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--scenario" => scenario = args.next().expect("--scenario needs a value"),
            "--out" => out = args.next().expect("--out needs a value").into(),
            other => {
                eprintln!("dump_sim: unknown argument '{other}'");
                std::process::exit(2);
            }
        }
    }
    if out.as_os_str().is_empty() {
        out = Path::new(std::env!("CARGO_MANIFEST_DIR"))
            .join(format!("target/sim_target_fixed_{scenario}.exe"));
    }

    // The harness and its target live in the same crate, so they always agree.
    match sim_target::run_simulation(&sim_target::target_exe(), &scenario, &out) {
        Ok(report) => {
            println!(
                "OK scenario={} pid={} scan={} imports_built={} iat_reused={} -> {}",
                report.scenario,
                report.pid,
                report.scan_method,
                report.imports_built,
                report.iat_reused,
                report.fixed_path.display()
            );
            println!("fixed stdout: {}", report.fixed_stdout.trim());
        }
        Err(e) => {
            eprintln!("FAILED: {e}");
            std::process::exit(1);
        }
    }
}
