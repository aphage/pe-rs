//! Live-process dump verification (ignored: requires a real Windows process).
//!
//! Dumps the current process's image, scans its IAT with a resolver built from
//! the process's own loaded modules, and rebuilds the import table — the full
//! Scylla "dump → scan → fix" pipeline.
//!
//! ```text
//! cargo test -p pe-rs --test process_dump_test -- --ignored
//! ```

use pe_rs::api::{IatFixer, IatScanner};
use pe_rs::domain::{IatFixOptions, ScanOptions};
use pe_rs::process;

#[test]
#[ignore]
fn dump_and_fix_current_process() {
    let pid = std::process::id();
    let mut doc = process::dump(pid).expect("dump current process");
    assert!(!doc.sections.is_empty(), "expected sections");
    assert!(
        !doc.imports.is_empty(),
        "expected imports in the test binary"
    );

    let resolver = process::ProcessResolver::for_process(pid).expect("resolver");
    assert!(
        !resolver.module_names().is_empty(),
        "expected loaded modules"
    );

    let scan = doc
        .scan(&resolver, &ScanOptions::default())
        .expect("scan IAT");
    assert!(scan.entries.len() >= 2, "expected an IAT run");

    let report = doc
        .fix_iat(&scan, &resolver, &IatFixOptions::default())
        .expect("fix IAT");
    assert!(report.imports_built >= 1, "expected imports to be rebuilt");
}
