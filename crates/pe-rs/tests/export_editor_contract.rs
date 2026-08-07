//! Contract tests for [`pe_rs::api::ExportTableEditor`], run against both the
//! mock document and the same content through the real parser.

mod common;

use pe_rs::api::{ExportTableEditor, PeViewer};
use pe_rs::domain::{ExportSymbol, Rva};
use pe_rs::io::pe::{parse, serialize};

#[test]
fn set_exports_none_clears() {
    common::both(|doc| {
        assert!(doc.exports().is_some());
        doc.set_exports(None).unwrap();
        assert!(doc.exports().is_none());
    });
}

#[test]
fn add_export_creates_table_when_absent() {
    common::both(|doc| {
        doc.set_exports(None).unwrap();
        doc.add_export(ExportSymbol {
            name: Some("New".into()),
            ordinal: 7,
            rva: Rva(0x1000),
            forwarder: None,
        })
        .unwrap();
        let ex = doc.exports().expect("table auto-created");
        assert_eq!(ex.symbols.len(), 1);
        assert_eq!(ex.symbols[0].ordinal, 7);
        assert_eq!(ex.symbols[0].name.as_deref(), Some("New"));
    });
}

#[test]
fn add_export_replaces_same_ordinal() {
    common::both(|doc| {
        let before = doc.exports().unwrap().symbols.len();
        doc.add_export(ExportSymbol {
            name: Some("Renamed".into()),
            ordinal: 2,
            rva: Rva(0x2000),
            forwarder: None,
        })
        .unwrap();
        let syms = &doc.exports().unwrap().symbols;
        assert_eq!(syms.len(), before, "no new slot for an existing ordinal");
        assert_eq!(syms.iter().filter(|s| s.ordinal == 2).count(), 1);
        let replaced = syms.iter().find(|s| s.ordinal == 2).unwrap();
        assert_eq!(replaced.name.as_deref(), Some("Renamed"));
        assert_eq!(replaced.rva, Rva(0x2000));
    });
}

#[test]
fn remove_export_removes_and_last_clears() {
    common::both(|doc| {
        doc.remove_export(1).unwrap();
        assert!(
            doc.exports()
                .unwrap()
                .symbols
                .iter()
                .all(|s| s.ordinal != 1)
        );
        doc.remove_export(2).unwrap();
        assert!(
            doc.exports().is_none(),
            "removing the last symbol clears the table"
        );
    });
}

#[test]
fn remove_export_absent_errors() {
    common::both(|doc| {
        assert!(doc.remove_export(0xFFFF).is_err());
    });
}

#[test]
fn added_export_survives_serialize() {
    let mut doc = common::doc_via_mock();
    doc.add_export(ExportSymbol {
        name: Some("Extra".into()),
        ordinal: 3,
        rva: Rva(0x1234),
        forwarder: None,
    })
    .unwrap();
    let bytes = serialize(&doc).expect("serialize");
    let reparsed = parse(&bytes).expect("parse");
    assert_eq!(reparsed.exports(), doc.exports());
}
