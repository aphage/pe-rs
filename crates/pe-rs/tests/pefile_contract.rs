//! Contract tests for the [`pe_rs::io::PeFile`] facade over the mock.

mod common;

use pe_rs::api::{ImportTableEditor, PeViewer};
use pe_rs::domain::ImportFunction;

#[test]
fn pefile_loads_mock_document() {
    let file = common::file_via_mock();
    assert_eq!(file.doc().sections().len(), 2);
    assert_eq!(file.doc().imports().len(), 2);
}

#[test]
fn pefile_doc_mut_edits_and_save_is_noop() {
    let mut file = common::file_via_mock();
    file.doc_mut()
        .add_import("ntdll.dll", &[ImportFunction::by_name("NtClose")])
        .unwrap();
    assert!(file
        .doc()
        .imports()
        .iter()
        .any(|d| d.name == "ntdll.dll"));
    // mock save() is a no-op but must not fail.
    assert!(file.save().is_ok());
}
