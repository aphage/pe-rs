//! Section table rebuild / merge tests.

mod common;

use pe_rs::api::PeViewer;
use pe_rs::domain::section::{IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ};
use pe_rs::domain::{align_up, RawOffset, Rva, Section, SectionHeader};
use pe_rs::feature::{merge_sections, rebuild_section_table};

#[test]
fn rebuild_normalizes_section_headers() {
    common::both(|doc| {
        let fa = doc.optional_header().file_alignment();
        rebuild_section_table(doc).unwrap();
        for s in doc.sections() {
            assert_eq!(s.header.size_of_raw_data, align_up(s.data.len() as u32, fa));
            assert_eq!(s.header.pointer_to_raw_data.get() % fa, 0);
            assert_eq!(s.header.virtual_size, s.data.len() as u32);
        }
        assert_eq!(doc.optional_header().size_of_headers() % fa, 0);
    });
}

/// A document with two contiguous sections at 0x1000 and 0x1100.
fn contiguous_doc() -> pe_rs::domain::PeDocument {
    let mut doc = common::doc_via_mock();
    let ch = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    doc.sections = vec![
        Section {
            header: SectionHeader {
                name: *b".aaa\0\0\0\0",
                virtual_size: 0x100,
                virtual_address: Rva(0x1000),
                size_of_raw_data: 0,
                pointer_to_raw_data: RawOffset::NULL,
                characteristics: ch,
            },
            data: vec![1; 0x100],
        },
        Section {
            header: SectionHeader {
                name: *b".bbb\0\0\0\0",
                virtual_size: 0x100,
                virtual_address: Rva(0x1100),
                size_of_raw_data: 0,
                pointer_to_raw_data: RawOffset::NULL,
                characteristics: ch,
            },
            data: vec![2; 0x100],
        },
    ];
    doc
}

#[test]
fn merge_contiguous_sections() {
    let mut doc = contiguous_doc();
    merge_sections(&mut doc, 0, 1).unwrap();
    assert_eq!(doc.sections().len(), 1);
    let merged = &doc.sections()[0];
    assert_eq!(merged.name_str(), ".merged");
    assert_eq!(merged.data.len(), 0x200);
    // both original ranges are still readable from the merged section
    assert_eq!(doc.read(Rva(0x1000), 1).unwrap(), &[1]);
    assert_eq!(doc.read(Rva(0x1100), 1).unwrap(), &[2]);
}

#[test]
fn merge_non_contiguous_rejected() {
    // mock .text/.idata have a gap between them -> not contiguous
    let mut doc = common::doc_via_mock();
    assert!(merge_sections(&mut doc, 0, 1).is_err());
}

#[test]
fn merge_bad_range_rejected() {
    let mut doc = contiguous_doc();
    assert!(merge_sections(&mut doc, 0, 0).is_err());
    assert!(merge_sections(&mut doc, 0, 5).is_err());
}
