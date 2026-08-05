//! Manual IAT array tests: `IatFixer::add_iat_array` takes a caller-supplied
//! array of `(rva, value)` entries and rebuilds the import table from them.

mod common;

use pe_rs::api::{IatFixer, PeViewer};
use pe_rs::domain::{IatEntry, IatFixOptions, Rva};
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
