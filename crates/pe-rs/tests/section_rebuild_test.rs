//! Section table rebuild / merge tests.

mod common;

use pe_rs::api::{PeEditor, PeViewer};
use pe_rs::domain::section::{IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ};
use pe_rs::domain::{
    DataDirectoryIndex, RawOffset, ResourceEntryData, Rva, Section, SectionHeader, align_up,
};
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

/// A document with three non-contiguous sections and pointers into the first
/// two: the entry point, a data directory, an export RVA, a resource leaf
/// content RVA, a relocation page, and a value in `.ccc` pointing at `.bbb`.
fn non_contiguous_doc() -> pe_rs::domain::PeDocument {
    use pe_rs::domain::export::{ExportSymbol, ExportTable};
    use pe_rs::domain::relocation::{RelocationBlock, RelocationEntry, RelocationTable};
    use pe_rs::domain::resource::{
        ResourceDataEntry, ResourceDirectory, ResourceEntry, ResourceEntryData, ResourceName,
    };
    let mut doc = common::doc_via_mock();
    let ch = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    let mut ccc_data = vec![0u8; 0x100];
    ccc_data[8..16].copy_from_slice(&0x3020u64.to_le_bytes()); // pointer into .bbb
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
                virtual_address: Rva(0x3000),
                size_of_raw_data: 0,
                pointer_to_raw_data: RawOffset::NULL,
                characteristics: ch,
            },
            data: vec![2; 0x100],
        },
        Section {
            header: SectionHeader {
                name: *b".ccc\0\0\0\0",
                virtual_size: 0x100,
                virtual_address: Rva(0x5000),
                size_of_raw_data: 0,
                pointer_to_raw_data: RawOffset::NULL,
                characteristics: ch,
            },
            data: ccc_data,
        },
    ];
    doc.optional.set_address_of_entry_point(Rva(0x3010)); // into .bbb
    doc.set_data_directory(DataDirectoryIndex::Debug, Rva(0x3020), 0x10)
        .unwrap();
    doc.exports = Some(ExportTable {
        module_name: Some("m.exe".into()),
        base: 1,
        number_of_functions: 1,
        symbols: vec![ExportSymbol {
            name: Some("f".into()),
            ordinal: 1,
            rva: Rva(0x3030),
            forwarder: None,
        }],
    });
    doc.resources = Some(ResourceDirectory {
        entries: vec![ResourceEntry {
            name: ResourceName::Id(10),
            data: ResourceEntryData::Leaf(ResourceDataEntry {
                rva: Rva(0x1010), // into .aaa
                size: 4,
                code_page: 0,
            }),
        }],
    });
    doc.relocations = Some(RelocationTable {
        blocks: vec![RelocationBlock {
            page_rva: Rva(0x1000), // into .aaa
            entries: vec![RelocationEntry {
                reloc_type: 3,
                offset: 0,
            }],
        }],
    });
    doc.imports = Vec::new(); // avoid import-table re-render noise on round-trip
    doc
}

#[test]
fn merge_non_contiguous_remaps_rvas() {
    let mut doc = non_contiguous_doc();
    merge_sections(&mut doc, 0, 1).unwrap();

    // .aaa stays at 0x1000; .bbb's content moves to 0x1000 + 0x100 = 0x1100.
    assert_eq!(doc.sections().len(), 2);
    let merged = &doc.sections()[0];
    assert_eq!(merged.name_str(), ".merged");
    assert_eq!(merged.header.virtual_address.get(), 0x1000);
    assert_eq!(merged.data.len(), 0x200);
    assert_eq!(&merged.data[..0x100], &[1; 0x100]);
    assert_eq!(&merged.data[0x100..], &[2; 0x100]);

    // entry point 0x3010 -> 0x1110
    assert_eq!(doc.optional_header().address_of_entry_point().get(), 0x1110);
    // debug directory 0x3020 -> 0x1120
    assert_eq!(
        doc.data_directory(DataDirectoryIndex::Debug)
            .unwrap()
            .rva
            .get(),
        0x1120
    );
    // export RVA 0x3030 -> 0x1130
    assert_eq!(doc.exports().unwrap().symbols[0].rva.get(), 0x1130);
    // resource leaf content in .aaa (0x1010) is unchanged
    let ResourceEntryData::Leaf(leaf) = &doc.resources().unwrap().entries[0].data else {
        panic!("expected leaf");
    };
    assert_eq!(leaf.rva.get(), 0x1010);
    // relocation page in .aaa (0x1000) is unchanged
    assert_eq!(doc.relocations().unwrap().blocks[0].page_rva.get(), 0x1000);
    // the value in .ccc pointing at .bbb (0x3020) is byte-patched -> 0x1120
    let ccc = &doc.sections()[1];
    assert_eq!(
        u64::from_le_bytes(ccc.data[8..16].try_into().unwrap()),
        0x1120
    );

    // the merged document still serializes and re-parses with the re-mapped rvas
    let bytes = pe_rs::io::pe::serialize(&doc).unwrap();
    let re = pe_rs::io::pe::parse(&bytes).unwrap();
    assert_eq!(re.optional_header().address_of_entry_point().get(), 0x1110);
    assert_eq!(
        re.data_directory(DataDirectoryIndex::Debug)
            .unwrap()
            .rva
            .get(),
        0x1120
    );
}

#[test]
fn merge_bad_range_rejected() {
    let mut doc = contiguous_doc();
    assert!(merge_sections(&mut doc, 0, 0).is_err());
    assert!(merge_sections(&mut doc, 0, 5).is_err());
}
