//! Resource / relocation / TLS directory parsing tests, run against both the
//! mock document and the same content through the real parser (round-trip).

mod common;

use pe_rs::api::{DirectoryEditor, PeViewer};
use pe_rs::domain::load_config::IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT;
use pe_rs::domain::relocation::IMAGE_REL_BASED_HIGHLOW;
use pe_rs::domain::resource::RT_MANIFEST;
use pe_rs::domain::{ResourceEntryData, ResourceName, Rva};
use pe_rs::io::pe::{parse, serialize};
use pe_rs::io::{MOCK_IMAGE_BASE, MOCK_RSRC_RVA};

#[test]
fn resource_tree_is_parsed() {
    common::both(|doc| {
        let res = doc.resources().expect("mock has resources");
        assert_eq!(res.entries.len(), 1);

        let type_entry = &res.entries[0];
        assert_eq!(type_entry.name, ResourceName::Id(RT_MANIFEST));
        let ResourceEntryData::Directory(manifest_dir) = &type_entry.data else {
            panic!("type level should be a directory");
        };

        assert_eq!(manifest_dir.entries.len(), 1);
        let name_entry = &manifest_dir.entries[0];
        assert_eq!(name_entry.name, ResourceName::Id(1));
        let ResourceEntryData::Directory(lang_dir) = &name_entry.data else {
            panic!("name level should be a directory");
        };

        assert_eq!(lang_dir.entries.len(), 1);
        let lang_entry = &lang_dir.entries[0];
        assert_eq!(lang_entry.name, ResourceName::Id(0x409));
        let ResourceEntryData::Leaf(leaf) = &lang_entry.data else {
            panic!("lang level should be a leaf");
        };
        assert_eq!(leaf.rva.get(), MOCK_RSRC_RVA + 0x70);
        assert!(leaf.size > 0);
        assert_eq!(leaf.code_page, 0);
    });
}

#[test]
fn relocations_are_parsed() {
    common::both(|doc| {
        let reloc = doc.relocations().expect("mock has relocations");
        assert_eq!(reloc.blocks.len(), 1);
        let block = &reloc.blocks[0];
        assert_eq!(block.page_rva.get(), 0x1000);
        assert_eq!(block.entries.len(), 1);
        assert_eq!(block.entries[0].reloc_type, IMAGE_REL_BASED_HIGHLOW);
        assert_eq!(block.entries[0].offset, 0x10);
    });
}

#[test]
fn tls_directory_is_parsed() {
    common::both(|doc| {
        let tls = doc.tls().expect("mock has tls");
        // start/end are VAs of the TLS template; index is a VA of a 4-byte slot.
        assert_eq!(
            tls.start_address_of_raw_data,
            MOCK_IMAGE_BASE + MOCK_RSRC_RVA as u64 + 0x100
        );
        assert_eq!(
            tls.end_address_of_raw_data,
            MOCK_IMAGE_BASE + MOCK_RSRC_RVA as u64 + 0x104
        );
        assert_eq!(
            tls.address_of_index,
            MOCK_IMAGE_BASE + MOCK_RSRC_RVA as u64 + 0x110
        );
        assert_eq!(tls.address_of_callbacks, 0);
        assert_eq!(tls.size_of_zero_fill, 0);
        assert_eq!(tls.characteristics, 0);

        // The template bytes are real: start -> image RVA 0x3100 holds 4 bytes.
        let template_rva = Rva(MOCK_RSRC_RVA + 0x100);
        assert_eq!(
            doc.read(template_rva, 4).unwrap(),
            &[0x2A, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            tls.start_address_of_raw_data,
            MOCK_IMAGE_BASE + template_rva.get() as u64
        );
    });
}

#[test]
fn load_config_is_parsed() {
    common::both(|doc| {
        let lc = doc.load_config().expect("mock has load config");
        assert_eq!(lc.size, 0x140);
        assert_eq!(lc.security_cookie, MOCK_IMAGE_BASE + 0x2000);
        assert_eq!(lc.guard_cf_function_table, MOCK_IMAGE_BASE + 0x3100);
        assert_eq!(lc.guard_cf_function_count, 5);
        assert_ne!(lc.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, 0);
        assert_eq!(
            lc.guard_xfg_check_function_pointer,
            MOCK_IMAGE_BASE + 0x3180
        );
        assert_eq!(lc.hot_patch_table_offset, 0x100);
    });
}

#[test]
fn load_config_roundtrips() {
    let orig = common::doc_via_mock();
    let bytes = serialize(&orig).unwrap();
    let reparsed = parse(&bytes).unwrap();
    assert_eq!(reparsed.load_config, orig.load_config);
}

#[test]
fn absent_directories_parse_to_none() {
    // The rich form is the source of truth: clear it (via the editor API), then
    // a saved file has no resource/reloc/TLS directories at all.
    let mut doc = common::doc_via_mock();
    doc.set_resources(None);
    doc.set_relocations(None);
    doc.set_tls(None);

    let bytes = serialize(&doc).unwrap();
    let reparsed = parse(&bytes).unwrap();
    assert!(reparsed.resources.is_none());
    assert!(reparsed.relocations.is_none());
    assert!(reparsed.tls.is_none());
}
