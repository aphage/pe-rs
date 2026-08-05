//! IAT scanner tests: the resolver-based scan must locate the known IAT array
//! in both the mock and the round-tripped real document.

mod common;

use pe_rs::api::IatScanner;
use pe_rs::domain::{Rva, ScanMethod, ScanOptions};
use pe_rs::io::{MOCK_APIS_BASE, MOCK_IAT_RVA, MockResolver};

#[test]
fn scan_finds_mock_iat_over_whole_image() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
        assert_eq!(scan.base_rva.get(), MOCK_IAT_RVA);
        assert_eq!(scan.entries.len(), 6);
        assert_eq!(scan.entries[0].value, MOCK_APIS_BASE);
        assert_eq!(scan.entries[1].value, MOCK_APIS_BASE + 0x100);
    });
}

#[test]
fn scan_region_limited_window() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let opts = ScanOptions {
            region: Some((Rva(MOCK_IAT_RVA), 0x100)),
            min_entries: 4,
            ..Default::default()
        };
        let scan = doc.scan(&resolver, &opts).unwrap();
        assert_eq!(scan.entries.len(), 6);
        assert_eq!(scan.base_rva.get(), MOCK_IAT_RVA);
    });
}

#[test]
fn scan_min_entries_filters() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        // min_entries above the real run length -> not found
        let opts = ScanOptions {
            region: Some((Rva(MOCK_IAT_RVA), 0x100)),
            min_entries: 100,
            ..Default::default()
        };
        assert!(doc.scan(&resolver, &opts).is_err());
    });
}

#[test]
fn scan_ignores_unresolvable_region() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        // .text is a NOP sled, nothing resolvable there
        let opts = ScanOptions {
            region: Some((Rva(0x1000), 0x100)),
            ..Default::default()
        };
        assert!(doc.scan(&resolver, &opts).is_err());
    });
}

#[test]
fn opcode_pattern_method_is_not_yet_implemented() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let opts = ScanOptions {
            method: ScanMethod::OpcodePattern,
            ..Default::default()
        };
        assert!(doc.scan(&resolver, &opts).is_err());
    });
}
