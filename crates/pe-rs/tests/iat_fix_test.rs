//! IAT fixer tests: rebuilding the import table from a scan (or a manual
//! entry array), with optional redirect of the original IAT slots.

mod common;

use pe_rs::api::{IatFixer, IatScanner, ImportResolver, PeViewer};
use pe_rs::domain::{IatEntry, IatFixOptions, IatScan, Rva, ScanOptions};
use pe_rs::io::pe::{parse, serialize};
use pe_rs::io::{MockResolver, MOCK_APIS_BASE, MOCK_IAT_RVA};

#[test]
fn fix_iat_rebuilds_import_table() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
        let report = doc.fix_iat(&scan, &resolver, &IatFixOptions::default()).unwrap();
        assert_eq!(report.imports_built, 2);
        assert!(report.unresolved.is_empty());
        assert_eq!(report.total_entries, 6);
        let rva = report.new_import_rva.unwrap();
        assert_ne!(rva, Rva::NULL);
        assert!(report.new_import_size > 0);

        // The rich form now matches the canonical imports.
        assert_eq!(doc.imports().len(), 2);
        assert_eq!(doc.imports()[0].name, "kernel32.dll");
        assert_eq!(doc.imports()[0].functions.len(), 5);
    });
}

#[test]
fn fix_iat_redirect_rewrites_slots() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
        let first_slot = scan.entries[0].rva;
        doc.fix_iat(&scan, &resolver, &IatFixOptions { redirect_iat: true })
            .unwrap();
        let after = u64::from_le_bytes(doc.read(first_slot, 8).unwrap().try_into().unwrap());
        assert_ne!(after, MOCK_APIS_BASE);
        assert!(resolver.resolve(after).is_none());
    });
}

#[test]
fn fix_iat_without_redirect_keeps_slots() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
        let first_slot = scan.entries[0].rva;
        doc.fix_iat(&scan, &resolver, &IatFixOptions { redirect_iat: false })
            .unwrap();
        let after = u64::from_le_bytes(doc.read(first_slot, 8).unwrap().try_into().unwrap());
        assert_eq!(after, MOCK_APIS_BASE);
    });
}

#[test]
fn fixed_document_serializes_and_reparses_with_imports() {
    let resolver = MockResolver::new();
    let mut doc = common::doc_via_mock();
    let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
    doc.fix_iat(&scan, &resolver, &IatFixOptions::default()).unwrap();

    let bytes = serialize(&doc).unwrap();
    let reparsed = parse(&bytes).unwrap();
    assert_eq!(reparsed.imports, doc.imports);
    assert_eq!(reparsed.imports.len(), 2);
    assert_eq!(reparsed.imports[0].functions.len(), 5);
}

#[test]
fn fix_iat_reports_unresolved() {
    common::both(|doc| {
        let resolver = MockResolver::new();
        let scan = IatScan {
            base_rva: Rva(MOCK_IAT_RVA),
            size: 2,
            entries: vec![
                IatEntry { rva: Rva(MOCK_IAT_RVA), value: 0xDEAD_BEEF },
                IatEntry { rva: Rva(MOCK_IAT_RVA + 8), value: MOCK_APIS_BASE },
            ],
        };
        let report = doc
            .fix_iat(&scan, &resolver, &IatFixOptions { redirect_iat: true })
            .unwrap();
        assert_eq!(report.unresolved.len(), 1);
        assert_eq!(report.imports_built, 1);
    });
}

#[test]
fn fix_iat_all_unresolvable_errors() {
    common::both(|doc| {
        let resolver = MockResolver::new();
        let scan = IatScan {
            base_rva: Rva(0x2000),
            size: 1,
            entries: vec![IatEntry { rva: Rva(0x2000), value: 0x1234 }],
        };
        assert!(doc.fix_iat(&scan, &resolver, &IatFixOptions::default()).is_err());
    });
}
