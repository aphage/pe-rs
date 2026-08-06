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

use pe_rs::api::IatScanner;
use pe_rs::domain::section::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE};
use pe_rs::domain::{Arch, DataDirectoryIndex, Machine, PeDocument, Rva, ScanMethod, ScanOptions};
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

/// A resolver that resolves nothing: the code-reference scan runs with
/// `validate_slots = false` (on-disk IAT slots are zeroed until load time).
struct NoResolver;
impl pe_rs::api::ImportResolver for NoResolver {
    fn resolve(&self, _address: u64) -> Option<pe_rs::api::ResolvedImport> {
        None
    }
}

fn read_pt(e: &[u8], psize: u32) -> u64 {
    if psize == 8 {
        u64::from_le_bytes(e[..8].try_into().unwrap())
    } else {
        u32::from_le_bytes(e[..4].try_into().unwrap()) as u64
    }
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0)
}

/// IAT slot RVAs described by a run of descriptors: each descriptor's
/// `iat_field` is the IAT RVA, sized by counting non-zero entries of its
/// `int_field` array (both are non-zero on disk).
fn descriptor_iat_slots(
    doc: &PeDocument,
    dir_rva: Rva,
    dir_size: u32,
    psize: u32,
    desc_len: u32,
    iat_field: usize,
    int_field: usize,
) -> Vec<u32> {
    let mut slots = Vec::new();
    let mut off = 0u32;
    while off + desc_len <= dir_size {
        let Some(rva) = dir_rva.checked_add(off) else {
            break;
        };
        let Ok(desc) = doc.read(rva, desc_len as usize) else {
            break;
        };
        let int_rva = u32_at(desc, int_field);
        let iat_rva = u32_at(desc, iat_field);
        if int_rva == 0 && iat_rva == 0 {
            break; // terminator descriptor
        }
        if iat_rva != 0 {
            let count_rva = if int_rva != 0 { int_rva } else { iat_rva };
            let mut n = 0u32;
            while let Ok(e) = doc.read(Rva(count_rva + n * psize), psize as usize) {
                if read_pt(e, psize) == 0 {
                    break;
                }
                n += 1;
            }
            for i in 0..n {
                slots.push(iat_rva + i * psize);
            }
        }
        off += desc_len;
    }
    slots
}

/// The RVA of every real IAT slot: the normal import directory's `FirstThunk`
/// arrays, plus the delay-load directory's `pIAT` arrays (shell32/gdi32 etc.
/// carry large delay-load tables the disassembly scan surfaces).
fn known_iat_slots(doc: &PeDocument) -> Vec<u32> {
    let psize: u32 = if doc.arch == Arch::Bit64 { 8 } else { 4 };
    let mut slots = Vec::new();
    if let Ok(dd) = doc.data_directory(DataDirectoryIndex::Import) {
        slots.extend(descriptor_iat_slots(doc, dd.rva, dd.size, psize, 20, 16, 0));
    }
    if let Ok(dd) = doc.data_directory(DataDirectoryIndex::DelayImport) {
        slots.extend(descriptor_iat_slots(
            doc, dd.rva, dd.size, psize, 32, 12, 16,
        ));
    }
    slots
}

/// Run the disassembly code-reference scan on a real document and check it
/// recovers actual IAT slots: the run is substantial, pointer-aligned, lands
/// in data (not code) sections, and mostly overlaps the known IAT arrays.
fn verify_code_reference_scan(doc: &PeDocument, known: &[u32], path: &str) {
    use std::collections::HashSet;

    let psize: u32 = if doc.arch == Arch::Bit64 { 8 } else { 4 };
    let opts = ScanOptions {
        method: ScanMethod::CodeReference,
        validate_slots: false,
        ..Default::default()
    };
    let scan = doc
        .scan(&NoResolver, &opts)
        .unwrap_or_else(|e| panic!("scan {path}: {e}"));
    assert!(
        scan.entries.len() >= 20,
        "expected a substantial IAT run in {path}, got {}",
        scan.entries.len()
    );

    for e in &scan.entries {
        assert_eq!(
            e.rva.get() % psize,
            0,
            "{path}: slot {:#x} not {psize}-aligned",
            e.rva.get()
        );
        let sec = doc
            .sections
            .iter()
            .find(|s| {
                let s0 = s.header.virtual_address.get();
                s0 <= e.rva.get() && e.rva.get() < s0 + s.data.len() as u32
            })
            .unwrap_or_else(|| panic!("{path}: slot {:#x} in no section", e.rva.get()));
        assert_eq!(
            sec.header.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE),
            0,
            "{path}: slot {:#x} points into a code section",
            e.rva.get()
        );
    }

    let known_set: HashSet<u32> = known.iter().copied().collect();
    let hits = scan
        .entries
        .iter()
        .filter(|e| known_set.contains(&e.rva.get()))
        .count();
    let ratio = hits as f64 / scan.entries.len() as f64;
    let pct = ratio * 100.0;
    eprintln!(
        "{path}: {hits}/{} run entries ({pct:.0}%) fall in the real IAT",
        scan.entries.len()
    );
    assert!(
        ratio >= 0.5,
        "{path}: only {hits}/{} ({pct:.0}%) run entries fall in the real IAT",
        scan.entries.len()
    );
}

#[test]
#[ignore]
fn code_reference_scan_locates_iat_in_real_pe() {
    let path = default_pe();
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let doc = parse(&bytes).expect("parse PE file");

    let known = known_iat_slots(&doc);
    assert!(
        !known.is_empty(),
        "{path} should have a real IAT to verify against"
    );
    verify_code_reference_scan(&doc, &known, &path);
}

#[test]
#[ignore]
fn code_reference_scan_locates_iat_in_32bit_real_pe() {
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

    let known = known_iat_slots(&doc);
    assert!(
        !known.is_empty(),
        "{path} should have a real IAT to verify against"
    );
    verify_code_reference_scan(&doc, &known, &path);
}
