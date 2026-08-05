//! Contract tests for [`pe_rs::api::ImportTableEditor`] (rich form), run
//! against both the mock document and the same content through the real parser.

mod common;

use pe_rs::api::{ImportTableEditor, PeViewer};
use pe_rs::domain::ImportFunction;

#[test]
fn add_new_import() {
    common::both(|doc| {
        doc.add_import(
            "ntdll.dll",
            &[ImportFunction::by_name("NtQueryInformationProcess")],
        )
        .unwrap();
        let d = doc
            .imports()
            .iter()
            .find(|d| d.name == "ntdll.dll")
            .unwrap();
        assert_eq!(d.functions.len(), 1);
    });
}

#[test]
fn add_existing_import_merges_and_dedupes() {
    common::both(|doc| {
        doc.add_import("kernel32.dll", &[ImportFunction::by_name("GetLastError")])
            .unwrap();
        let d = doc
            .imports()
            .iter()
            .find(|d| d.name == "kernel32.dll")
            .unwrap();
        assert_eq!(d.functions.len(), 6); // 5 canonical + 1 new

        doc.add_import("kernel32.dll", &[ImportFunction::by_name("GetLastError")])
            .unwrap();
        let d = doc
            .imports()
            .iter()
            .find(|d| d.name == "kernel32.dll")
            .unwrap();
        assert_eq!(d.functions.len(), 6); // duplicate not added twice
    });
}

#[test]
fn remove_import_removes_and_errors_on_missing() {
    common::both(|doc| {
        doc.remove_import("user32.dll").unwrap();
        assert!(!doc.imports().iter().any(|d| d.name == "user32.dll"));
        assert!(doc.remove_import("nonexistent.dll").is_err());
    });
}

#[test]
fn empty_module_name_rejected() {
    common::both(|doc| {
        assert!(doc.add_import("", &[ImportFunction::by_name("X")]).is_err());
    });
}

#[test]
fn ordinal_import_supported() {
    common::both(|doc| {
        doc.add_import("ntdll.dll", &[ImportFunction::by_ordinal(0x123)])
            .unwrap();
        let d = doc
            .imports()
            .iter()
            .find(|d| d.name == "ntdll.dll")
            .unwrap();
        assert_eq!(d.functions[0].display_name(), "#291");
    });
}
