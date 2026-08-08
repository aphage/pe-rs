//! End-to-end simulation: for each corruption scenario of
//! `docs/dump 情况分析和处理.md`, spawn the target in that shape, dump it, fix
//! the imports, save, and re-run the fixed dump — it must run and print
//! `SIM_TARGET_OK`.
//!
//! Spawns real processes, so it is ignored by default:
//!
//! ```text
//! cargo test -p sim-target -- --ignored
//! ```

#[test]
#[ignore]
fn all_scenarios_dump_fix_and_rerun() {
    let target = sim_target::target_exe();
    for scenario in ["normal", "oft", "iatdir", "erased"] {
        let out = std::env::temp_dir().join(format!("sim_target_fixed_{scenario}.exe"));
        let report = sim_target::run_simulation(&target, scenario, &out)
            .unwrap_or_else(|e| panic!("scenario {scenario}: {e}"));
        assert!(
            report.fixed_stdout.contains("SIM_TARGET_OK"),
            "scenario {scenario}: fixed dump must print SIM_TARGET_OK, got: {}",
            report.fixed_stdout
        );
        assert!(
            report.imports_built >= 1,
            "scenario {scenario}: imports rebuilt"
        );
        std::fs::remove_file(&out).ok();
    }
}
