//! Contract tests for [`pe_rs::api::PeEditor`], run against both the mock
//! document and the same content through the real parser.

mod common;

use pe_rs::api::{PeEditor, PeViewer};
use pe_rs::domain::section::{IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use pe_rs::domain::{DataDirectoryIndex, Rva};
use pe_rs::io::MOCK_TEXT_RVA;

#[test]
fn set_data_directory_updates() {
    common::both(|doc| {
        doc.set_data_directory(DataDirectoryIndex::Resource, Rva(0x7000), 0x100)
            .unwrap();
        let dd = doc.data_directory(DataDirectoryIndex::Resource).unwrap();
        assert_eq!(dd.rva.get(), 0x7000);
        assert_eq!(dd.size, 0x100);
    });
}

#[test]
fn add_section_appends_and_is_readable() {
    common::both(|doc| {
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
    });
}

#[test]
fn write_then_read_roundtrips() {
    common::both(|doc| {
        let rva = Rva(MOCK_TEXT_RVA + 0x40);
        doc.write(rva, &[1, 2, 3, 4]).unwrap();
        assert_eq!(doc.read(rva, 4).unwrap(), &[1, 2, 3, 4]);
    });
}

#[test]
fn alloc_appends_aligned_section() {
    common::both(|doc| {
        let align = doc.optional_header().section_alignment();
        let before_end = doc
            .sections()
            .iter()
            .map(|s| s.header.virtual_address.get().saturating_add(s.data.len() as u32))
            .max()
            .unwrap();
        let rva = doc.alloc(0x40, align).unwrap();
        assert!(rva.get() >= before_end);
        assert_eq!(rva.get() % align, 0);
        doc.write(rva, &[7; 0x10]).unwrap();
        assert_eq!(doc.read(rva, 0x10).unwrap(), &[7; 0x10]);
    });
}

#[test]
fn remove_section_guards_last_one() {
    common::both(|doc| {
        while doc.sections().len() > 1 {
            let last = doc.sections().len() - 1;
            doc.remove_section(last).unwrap();
        }
        assert!(doc.remove_section(0).is_err());
        assert!(doc.remove_section(999).is_err());
    });
}

#[test]
fn write_out_of_range_errors() {
    common::both(|doc| {
        assert!(doc.write(Rva(0x9000), &[1]).is_err());
    });
}
