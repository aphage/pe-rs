//! Verification against real Windows PE files.
//!
//! These tests are `#[ignore]`d because they need a real Windows install. Run
//! them explicitly with:
//!
//! ```text
//! cargo test -p pe-rs --test real_pe_test -- --ignored
//! ```
//!
//! The file to parse is taken from the `PE_RS_TEST_PE` env var, or defaults to
//! `%SystemRoot%\System32\kernel32.dll` (64-bit) and the SysWOW64 kernel32 for
//! the 32-bit check.

use pe_rs::domain::{Arch, Machine, PeDocument};
use pe_rs::io::pe::{parse, serialize};

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())
}

fn default_pe() -> String {
    std::env::var("PE_RS_TEST_PE")
        .unwrap_or_else(|_| format!(r"{}\System32\kernel32.dll", system_root()))
}

/// serialize → re-parse must preserve imports, exports and section count.
fn roundtrip_ok(doc: &PeDocument) -> bool {
    let Ok(bytes) = serialize(doc) else {
        return false;
    };
    let Ok(re) = parse(&bytes) else {
        return false;
    };
    re.imports == doc.imports
        && re.exports == doc.exports
        && re.sections.len() == doc.sections.len()
}

#[test]
#[ignore]
fn parses_real_pe_and_roundtrips() {
    let path = default_pe();
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let doc = parse(&bytes).expect("parse PE file");
    assert!(!doc.sections.is_empty(), "expected sections");
    assert!(roundtrip_ok(&doc), "round-trip failed for {path}");

    // kernel32 (or anything defaulting to it) must carry imports + exports and
    // export the classic GetProcAddress.
    if path.contains("kernel32") {
        assert!(!doc.imports.is_empty(), "expected imports");
        let exports = doc.exports.expect("expected exports");
        assert!(
            exports
                .symbols
                .iter()
                .any(|s| s.name.as_deref() == Some("GetProcAddress"))
        );
    }
}

#[test]
#[ignore]
fn parses_32bit_real_pe() {
    let path = format!(r"{}\SysWOW64\kernel32.dll", system_root());
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("skipping (no 32-bit kernel32 at {path}): {e}");
            return;
        }
    };
    let doc = parse(&bytes).expect("parse 32-bit PE");
    assert_eq!(doc.arch, Arch::Bit32);
    assert_eq!(doc.coff.machine, Machine::I386);
    assert!(roundtrip_ok(&doc), "32-bit round-trip failed");
}
