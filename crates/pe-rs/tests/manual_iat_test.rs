//! Manual IAT array tests: `IatFixer::add_iat_array` takes a caller-supplied
//! array of `(rva, value)` entries and rebuilds the import table from them.

mod common;

use pe_rs::api::{IatFixer, PeViewer};
use pe_rs::domain::{IatEntry, IatFixOptions, IatTable, Rva};
use pe_rs::io::pe::{parse, serialize};
use pe_rs::io::{MOCK_APIS_BASE, MOCK_IAT_RVA, MockResolver};

#[test]
fn add_iat_array_builds_imports() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let entries = [
            IatEntry {
                rva: Rva(MOCK_IAT_RVA),
                value: MOCK_APIS_BASE,
            }, // kernel32.GetProcAddress
            IatEntry {
                rva: Rva(MOCK_IAT_RVA + 8),
                value: MOCK_APIS_BASE + 0x200,
            }, // VirtualAlloc
            IatEntry {
                rva: Rva(MOCK_IAT_RVA + 16),
                value: MOCK_APIS_BASE + 0x500,
            }, // user32.MessageBoxA
        ];
        let report = doc
            .add_iat_array(&entries, &resolver, &IatFixOptions::default())
            .unwrap();
        assert!(report.unresolved.is_empty());
        assert_eq!(report.imports_built, 2);
        assert!(doc.imports().iter().any(|d| d.name == "kernel32.dll"));
        assert!(doc.imports().iter().any(|d| d.name == "user32.dll"));
        let kernel = doc
            .imports()
            .iter()
            .find(|d| d.name == "kernel32.dll")
            .unwrap();
        assert_eq!(kernel.functions.len(), 2);
    });
}

#[test]
fn add_iat_array_empty_errors() {
    common::both(|doc| {
        let resolver = MockResolver::new();
        assert!(
            doc.add_iat_array(&[], &resolver, &IatFixOptions::default())
                .is_err()
        );
    });
}

#[test]
fn add_iat_array_reports_unresolved() {
    common::both(|doc| {
        let resolver = MockResolver::new();
        let entries = [
            IatEntry {
                rva: Rva(MOCK_IAT_RVA),
                value: 0xCAFE,
            },
            IatEntry {
                rva: Rva(MOCK_IAT_RVA + 8),
                value: MOCK_APIS_BASE,
            },
        ];
        let report = doc
            .add_iat_array(&entries, &resolver, &IatFixOptions::default())
            .unwrap();
        assert_eq!(report.unresolved.len(), 1);
        assert_eq!(report.imports_built, 1);
    });
}

#[test]
fn manual_iat_document_roundtrips() {
    let resolver = MockResolver::new();
    let mut doc = common::doc_via_mock();
    let entries = [IatEntry {
        rva: Rva(MOCK_IAT_RVA),
        value: MOCK_APIS_BASE + 0x500,
    }];
    doc.add_iat_array(&entries, &resolver, &IatFixOptions::default())
        .unwrap();

    let bytes = serialize(&doc).unwrap();
    let reparsed = parse(&bytes).unwrap();
    assert_eq!(reparsed.imports, doc.imports);
    assert_eq!(reparsed.imports.len(), 1);
    assert_eq!(reparsed.imports[0].name, "user32.dll");
}

#[test]
fn iat_table_add_region_builds_imports() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        // Two non-contiguous IAT regions, added by reading the document's
        // slots (as a user would for a dump whose IAT was split).
        let mut table = IatTable::new();
        table.add_region(doc, Rva(MOCK_IAT_RVA), 0x18).unwrap(); // 3 kernel32 slots
        table
            .add_region(doc, Rva(MOCK_IAT_RVA + 0x28), 0x8)
            .unwrap(); // 1 user32 slot
        assert_eq!(table.len(), 4);

        let report = doc
            .fix_iat_table(&table, &resolver, &IatFixOptions::default())
            .unwrap();
        assert!(report.unresolved.is_empty());
        assert_eq!(report.imports_built, 2);

        // The rebuilt import table round-trips as a normal contiguous table.
        let re = parse(&serialize(doc).unwrap()).unwrap();
        assert_eq!(re.imports.len(), 2);
        let kernel = re
            .imports
            .iter()
            .find(|d| d.name == "kernel32.dll")
            .unwrap();
        assert_eq!(kernel.functions.len(), 3);
    });
}

#[test]
fn iat_table_from_scan_curation() {
    use pe_rs::api::IatScanner;
    use pe_rs::domain::ScanOptions;
    let resolver = MockResolver::new();
    common::both(|doc| {
        // Start from the automatic scan, then curate (drop a false positive,
        // merge in an extra region).
        let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
        let mut table = IatTable::from_scan(&scan);
        assert_eq!(table.len(), 6);

        table.remove(Rva(MOCK_IAT_RVA + 8));
        assert_eq!(table.len(), 5);
        // re-adding an already-present slot is deduped by to_scan
        table.add(IatEntry {
            rva: Rva(MOCK_IAT_RVA + 0x28),
            value: MOCK_APIS_BASE + 0x500,
        });
        assert_eq!(table.to_scan().entries.len(), 5);

        let report = doc
            .fix_iat_table(&table, &resolver, &IatFixOptions::default())
            .unwrap();
        assert_eq!(report.imports_built, 2);
        assert_eq!(report.total_entries, 5);
    });
}

#[test]
fn iat_table_to_scan_sorts_and_dedupes() {
    let table = IatTable::from_entries(vec![
        IatEntry {
            rva: Rva(0x3000),
            value: 1,
        },
        IatEntry {
            rva: Rva(0x1000),
            value: 2,
        },
        IatEntry {
            rva: Rva(0x1000),
            value: 3,
        }, // duplicate RVA
    ]);
    let scan = table.to_scan();
    assert_eq!(scan.entries.len(), 2);
    assert_eq!(scan.base_rva.get(), 0x1000);
    assert_eq!(scan.entries[0].rva.get(), 0x1000);
    assert_eq!(scan.entries[1].rva.get(), 0x3000);

    assert!(IatTable::new().to_scan().entries.is_empty());
}
