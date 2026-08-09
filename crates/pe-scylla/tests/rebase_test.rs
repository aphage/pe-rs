//! Rebase-dump tests: rebuilding a dump's base relocation table so a fixed
//! dump runs standalone even when the program's runtime wrote absolute
//! pointers into `.data`.

mod common;

use pe_edit::domain::Rva;
use pe_edit::domain::relocation::{
    IMAGE_REL_BASED_DIR64, RelocationBlock, RelocationEntry, RelocationTable,
};
use pe_edit::io::{MOCK_IDATA_RVA, MOCK_IMAGE_BASE};
use pe_scylla::feature::rebase_dump;

/// Two relocation slots in `.idata`: an image-internal pointer and a
/// runtime-written external (system DLL) pointer.
fn doc_with_reloc_slots() -> pe_edit::domain::PeDocument {
    let mut doc = common::doc_via_mock();
    let actual = doc.optional.image_base();
    let img_rva = Rva(MOCK_IDATA_RVA + 0x80);
    let ext_rva = Rva(MOCK_IDATA_RVA + 0x88);
    doc.write(img_rva, &(actual + 0x1000).to_le_bytes())
        .unwrap();
    doc.write(ext_rva, &0x7ffe_dead_beef_0000u64.to_le_bytes())
        .unwrap();
    doc.relocations = Some(RelocationTable {
        blocks: vec![RelocationBlock {
            page_rva: Rva(MOCK_IDATA_RVA),
            entries: vec![
                RelocationEntry {
                    reloc_type: IMAGE_REL_BASED_DIR64,
                    offset: 0x80,
                },
                RelocationEntry {
                    reloc_type: IMAGE_REL_BASED_DIR64,
                    offset: 0x88,
                },
            ],
        }],
    });
    doc
}

#[test]
fn rebase_rewrites_image_pointers_and_clears_runtime_slots() {
    let mut doc = doc_with_reloc_slots();
    let actual = doc.optional.image_base();
    assert_eq!(actual, MOCK_IMAGE_BASE);

    // Rebase to a *different* base so the rewrite is observable.
    let preferred = 0x2000_0000u64;
    let report = rebase_dump(&mut doc, preferred).unwrap();
    assert_eq!(report.rebased, 1);
    assert_eq!(report.cleared, 1);
    assert_eq!(doc.optional.image_base(), preferred);

    let img = u64::from_le_bytes(
        doc.read(Rva(MOCK_IDATA_RVA + 0x80), 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        img,
        preferred + 0x1000,
        "image pointer rebased to preferred base"
    );
    let ext = u64::from_le_bytes(
        doc.read(Rva(MOCK_IDATA_RVA + 0x88), 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(ext, 0, "runtime-written slot cleared");

    // The rebuilt table keeps only the image-internal entry.
    let t = doc.relocations.as_ref().unwrap();
    assert_eq!(t.blocks.len(), 1);
    assert_eq!(t.blocks[0].entries.len(), 1, "external entry dropped");
    assert_eq!(t.blocks[0].entries[0].offset, 0x80);
}

#[test]
fn rebase_serializes_to_a_reloadable_file() {
    let mut doc = doc_with_reloc_slots();
    rebase_dump(&mut doc, 0x2000_0000u64).unwrap();

    // Serialize → re-parse: the rebuilt relocation table survives, and the
    // external slot stays cleared.
    let bytes = pe_edit::io::pe::serialize(&doc).unwrap();
    let re = pe_edit::io::pe::parse(&bytes).unwrap();
    let t = re.relocations.as_ref().unwrap();
    assert_eq!(t.blocks.len(), 1);
    assert_eq!(t.blocks[0].entries.len(), 1);
    let ext = u64::from_le_bytes(
        re.read(Rva(MOCK_IDATA_RVA + 0x88), 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(ext, 0);
}

#[test]
fn rebase_with_no_reloc_table_only_sets_base() {
    let mut doc = common::doc_via_mock();
    doc.relocations = None;
    let report = rebase_dump(&mut doc, 0x3000_0000u64).unwrap();
    assert_eq!(report.rebased, 0);
    assert_eq!(report.cleared, 0);
    assert_eq!(doc.optional.image_base(), 0x3000_0000);
}
