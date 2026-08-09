//! `VaConverter` tests: raw ↔ RVA ↔ VA mapping, including the header region
//! and non-aligned dumps.

mod common;

use pe_edit::domain::{RawOffset, Rva};
use pe_edit::feature::VaConverter;
use pe_edit::io::{MOCK_IMAGE_BASE, MOCK_TEXT_RVA};

#[test]
fn rva_va_roundtrips() {
    common::both(|doc| {
        let c = VaConverter::from_document(doc);
        let va = c.rva_to_va(Rva(MOCK_TEXT_RVA));
        assert_eq!(va, MOCK_IMAGE_BASE + MOCK_TEXT_RVA as u64);
        assert_eq!(c.va_to_rva(va), Some(Rva(MOCK_TEXT_RVA)));
    });
}

#[test]
fn section_raw_roundtrips() {
    common::both(|doc| {
        let c = VaConverter::from_document(doc);
        let raw = c.rva_to_raw(Rva(MOCK_TEXT_RVA)).unwrap();
        assert_eq!(c.raw_to_rva(raw), Some(Rva(MOCK_TEXT_RVA)));
        assert_eq!(
            c.raw_to_va(raw),
            Some(MOCK_IMAGE_BASE + MOCK_TEXT_RVA as u64)
        );
        assert_eq!(
            c.va_to_raw(MOCK_IMAGE_BASE + MOCK_TEXT_RVA as u64),
            Some(raw)
        );
    });
}

#[test]
fn header_region_maps_one_to_one() {
    common::both(|doc| {
        let c = VaConverter::from_document(doc);
        // an RVA below size_of_headers maps to the same raw offset
        let rva = Rva(0x40);
        assert_eq!(c.rva_to_raw(rva), Some(RawOffset(0x40)));
        assert_eq!(c.raw_to_rva(RawOffset(0x40)), Some(rva));
    });
}

#[test]
fn unmapped_addresses_return_none() {
    common::both(|doc| {
        let c = VaConverter::from_document(doc);
        assert!(c.rva_to_raw(Rva(0x9000)).is_none());
        assert!(c.va_to_rva(MOCK_IMAGE_BASE - 1).is_none());
    });
}

#[test]
fn non_aligned_dump_maps_virtual_and_raw_sides_independently() {
    // Simulate a dump where .text declares a bigger virtual region than its raw
    // data: the virtual side still maps the whole region, the raw side only its
    // raw extent.
    let mut doc = common::doc_via_mock();
    let text = &mut doc.sections[0];
    text.header.virtual_size = 0x400;
    text.header.size_of_raw_data = 0x80;
    text.header.pointer_to_raw_data = RawOffset(0x200);

    let c = VaConverter::from_document(&doc);
    // virtual-side: maps deep into the virtual region
    let raw = c.rva_to_raw(Rva(MOCK_TEXT_RVA + 0x200)).unwrap();
    assert_eq!(raw.get(), 0x200 + 0x200);
    // raw-side: only the raw extent is addressable; the gap after it (0x280,
    // before .idata's raw at 0x400) is not
    assert_eq!(c.raw_to_rva(RawOffset(0x200)), Some(Rva(MOCK_TEXT_RVA)));
    assert!(c.raw_to_rva(RawOffset(0x280)).is_none());
}
