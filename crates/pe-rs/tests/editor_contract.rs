//! Contract tests for [`pe_rs::api::PeEditor`], run against the mock document.

mod common;

use pe_rs::api::{PeEditor, PeViewer};
use pe_rs::domain::section::{IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use pe_rs::domain::{DataDirectoryIndex, Rva};
use pe_rs::io::MOCK_TEXT_RVA;

#[test]
fn set_data_directory_updates() {
    let mut doc = common::doc_via_mock();
    doc.set_data_directory(DataDirectoryIndex::Resource, Rva(0x7000), 0x100)
        .unwrap();
    let dd = doc.data_directory(DataDirectoryIndex::Resource).unwrap();
    assert_eq!(dd.rva.get(), 0x7000);
    assert_eq!(dd.size, 0x100);
}

#[test]
fn add_section_appends_and_is_readable() {
    let mut doc = common::doc_via_mock();
    let before = doc.sections().len();
    let id = doc
        .add_section(
            *b".data\0\0\0",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            vec![0xAB; 0x100],
        )
        .unwrap();
    assert_eq!(id, before);
    assert_eq!(doc.sections().len(), before + 1);
    let rva = doc.sections()[id].header.virtual_address;
    assert_eq!(doc.read(rva, 4).unwrap(), &[0xAB; 4]);
}

#[test]
fn write_then_read_roundtrips() {
    let mut doc = common::doc_via_mock();
    let rva = Rva(MOCK_TEXT_RVA + 0x40);
    doc.write(rva, &[1, 2, 3, 4]).unwrap();
    assert_eq!(doc.read(rva, 4).unwrap(), &[1, 2, 3, 4]);
}

#[test]
fn alloc_appends_section_at_end_of_image() {
    let mut doc = common::doc_via_mock();
    let rva = doc.alloc(0x40, 0x1000).unwrap();
    // image end = .idata end (0x2000 + 0x100 = 0x2100), aligned up to 0x1000.
    assert_eq!(rva.get(), 0x3000);
    doc.write(rva, &[7; 0x10]).unwrap();
    assert_eq!(doc.read(rva, 0x10).unwrap(), &[7; 0x10]);
}

#[test]
fn remove_section_works_and_guards() {
    let mut doc = common::doc_via_mock();
    assert!(doc.remove_section(99).is_err());
    doc.remove_section(1).unwrap();
    assert_eq!(doc.sections().len(), 1);
    assert!(doc.remove_section(0).is_err());
}

#[test]
fn write_out_of_range_errors() {
    let mut doc = common::doc_via_mock();
    assert!(doc.write(Rva(0x9000), &[1]).is_err());
}
