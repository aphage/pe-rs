//! Contract tests for the [`pe_rs::io::PeFile`] facade over both backends.

mod common;

use pe_rs::api::{ImportTableEditor, PeViewer};
use pe_rs::domain::{Arch, ImportFunction};

#[test]
fn pefile_loads_mock_document() {
    let file = common::file_via_mock();
    assert_eq!(file.doc().sections().len(), 2);
    assert_eq!(file.doc().imports().len(), 2);
}

#[test]
fn pefile_loads_real_document() {
    let file = common::file_via_real();
    assert_eq!(file.doc().arch(), Arch::Bit64);
    assert_eq!(file.doc().imports().len(), 2);
}

#[test]
fn pefile_doc_mut_edits_and_save_is_noop_for_mock() {
    let mut file = common::file_via_mock();
    file.doc_mut()
        .add_import("ntdll.dll", &[ImportFunction::by_name("NtClose")])
        .unwrap();
    assert!(file
        .doc()
        .imports()
        .iter()
        .any(|d| d.name == "ntdll.dll"));
    assert!(file.save().is_ok());
}

#[test]
fn pefile_save_serializes_real_document() {
    let mut file = common::file_via_real();
    file.doc_mut()
        .add_import("ntdll.dll", &[ImportFunction::by_name("NtClose")])
        .unwrap();
    assert!(file.save().is_ok());
}
