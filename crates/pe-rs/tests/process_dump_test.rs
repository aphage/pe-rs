//! Live-process dump verification (ignored: requires a real Windows process).
//!
//! Dumps the current process's image, scans its IAT with a resolver built from
//! the process's own loaded modules, and rebuilds the import table — the full
//! Scylla "dump → scan → fix" pipeline.
//!
//! ```text
//! cargo test -p pe-rs --test process_dump_test -- --ignored
//! ```

use pe_rs::api::{IatFixer, IatScanner, ImportResolver};
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

#[test]
#[ignore]
fn resolver_fingerprint_matches_system_module() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    let pid = std::process::id();
    let resolver = process::ProcessResolver::for_process(pid)
        .expect("resolver")
        .with_fingerprints()
        .expect("fingerprints");

    let name: Vec<u16> = "kernel32.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let hmod = unsafe { GetModuleHandleW(name.as_ptr()) };
    assert!(!hmod.is_null(), "kernel32 must be loaded");
    let addr = unsafe { GetProcAddress(hmod, c"GetProcAddress".as_ptr() as *const u8) };
    let func_addr = addr.expect("GetProcAddress") as usize as u64;

    // Fast path: kernel32 is an OS-loaded module.
    let via_module = resolver.resolve(func_addr).expect("resolve via module");
    assert_eq!(via_module.module.to_lowercase(), "kernel32.dll");
    assert_eq!(via_module.function.name(), Some("GetProcAddress"));

    // Fingerprint path (used when the module is memory-loaded and absent from
    // the OS module list): the code matches the system-loaded copy.
    let via_fingerprint = resolver
        .resolve_fingerprint(func_addr)
        .expect("resolve via fingerprint");
    assert_eq!(via_fingerprint.module.to_lowercase(), "kernel32.dll");
    assert_eq!(via_fingerprint.function.name(), Some("GetProcAddress"));
}
