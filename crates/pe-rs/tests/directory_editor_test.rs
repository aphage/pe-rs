//! Resource / relocation / TLS directory editing tests: edits to the rich
//! forms must persist through serialize → re-parse.

mod common;

use pe_rs::api::DirectoryEditor;
use pe_rs::domain::resource::RT_MANIFEST;
use pe_rs::domain::{RelocationEntry, ResourceEntryData, ResourceName, Rva};
use pe_rs::io::MOCK_IMAGE_BASE;
use pe_rs::io::pe::{parse, serialize};

fn find_dir(
    dir: &pe_rs::domain::ResourceDirectory,
    name: ResourceName,
) -> &pe_rs::domain::ResourceDirectory {
    let e = dir.entries.iter().find(|e| e.name == name).expect("entry");
    match &e.data {
        ResourceEntryData::Directory(d) => d,
        _ => panic!("expected a directory"),
    }
}

#[test]
fn tls_mut_edits_persist() {
    common::both(|doc| {
        let tls = doc.tls_mut().expect("mock has tls");
        tls.size_of_zero_fill = 0x100;
        tls.characteristics = 4;

        let re = parse(&serialize(doc).unwrap()).unwrap();
        let t = re.tls.expect("tls present after round-trip");
        assert_eq!(t.size_of_zero_fill, 0x100);
        assert_eq!(t.characteristics, 4);
        // untouched fields survive
        assert_eq!(t.start_address_of_raw_data, MOCK_IMAGE_BASE + 0x3100);
    });
}

#[test]
fn add_relocation_block_persists() {
    common::both(|doc| {
        doc.add_relocation_block(
            Rva(0x2000),
            vec![RelocationEntry {
                reloc_type: 3,
                offset: 0x20,
            }],
        )
        .unwrap();

        let re = parse(&serialize(doc).unwrap()).unwrap();
        let table = re.relocations.expect("relocations present");
        let block = table
            .blocks
            .iter()
            .find(|b| b.page_rva.get() == 0x2000)
            .expect("new block");
        assert_eq!(block.entries.len(), 1);
        assert_eq!(block.entries[0].reloc_type, 3);
        assert_eq!(block.entries[0].offset, 0x20);
        // the original block survives too
        assert!(table.blocks.iter().any(|b| b.page_rva.get() == 0x1000));
    });
}

#[test]
fn remove_relocation_block_persists() {
    common::both(|doc| {
        let before = doc.relocations_mut().map(|t| t.blocks.len()).unwrap_or(0);
        doc.remove_relocation_block(0).unwrap();

        let re = parse(&serialize(doc).unwrap()).unwrap();
        let after = re.relocations.map(|t| t.blocks.len()).unwrap_or(0);
        assert_eq!(before, after + 1);
    });
}

#[test]
fn add_resource_data_persists() {
    common::both(|doc| {
        let data = b"<assembly>edited</assembly>".to_vec();
        let rva = doc
            .add_resource_data(RT_MANIFEST, ResourceName::Id(2), 0x409, data.clone())
            .unwrap();
        // content is immediately readable at the returned RVA
        assert_eq!(doc.read(rva, data.len()).unwrap(), data.as_slice());

        let re = parse(&serialize(doc).unwrap()).unwrap();
        let root = re.resources.as_ref().expect("resources present");
        let type_dir = find_dir(root, ResourceName::Id(RT_MANIFEST));
        let name_dir = find_dir(type_dir, ResourceName::Id(2));
        let lang_entry = name_dir
            .entries
            .iter()
            .find(|e| e.name == ResourceName::Id(0x409))
            .expect("language entry");
        let ResourceEntryData::Leaf(leaf) = &lang_entry.data else {
            panic!("expected a leaf");
        };
        assert_eq!(leaf.size as usize, data.len());
        // the content is still readable from the reparsed document
        assert_eq!(
            re.read(leaf.rva, leaf.size as usize).unwrap(),
            data.as_slice()
        );
    });
}

#[test]
fn remove_resource_persists() {
    common::both(|doc| {
        doc.add_resource_data(RT_MANIFEST, ResourceName::Id(2), 0x409, vec![1; 8])
            .unwrap();
        doc.remove_resource(RT_MANIFEST, &ResourceName::Id(1))
            .unwrap();

        let re = parse(&serialize(doc).unwrap()).unwrap();
        let root = re.resources.expect("resources present");
        let type_dir = find_dir(&root, ResourceName::Id(RT_MANIFEST));
        assert!(
            type_dir
                .entries
                .iter()
                .any(|e| e.name == ResourceName::Id(2))
        );
        assert!(
            !type_dir
                .entries
                .iter()
                .any(|e| e.name == ResourceName::Id(1))
        );
    });
}

#[test]
fn clear_all_directories_removes_them() {
    common::both(|doc| {
        doc.set_resources(None);
        doc.set_relocations(None);
        doc.set_tls(None);

        let re = parse(&serialize(doc).unwrap()).unwrap();
        assert!(re.resources.is_none());
        assert!(re.relocations.is_none());
        assert!(re.tls.is_none());
    });
}

#[test]
fn mut_helpers_are_none_when_absent() {
    let mut doc = common::doc_via_mock();
    doc.set_tls(None);
    doc.set_resources(None);
    doc.set_relocations(None);
    assert!(doc.tls_mut().is_none());
    assert!(doc.resources_mut().is_none());
    assert!(doc.relocations_mut().is_none());
}
