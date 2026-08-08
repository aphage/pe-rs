//! IAT fixer tests: rebuilding the import table from a scan (or a manual
//! entry array), with optional redirect of the original IAT slots.

mod common;

use pe_rs::api::{IatFixer, IatScanner, ImportResolver, PeViewer};
use pe_rs::domain::data_directory::DataDirectoryIndex;
use pe_rs::domain::{IatEntry, IatFixOptions, IatScan, Rva, ScanOptions};
use pe_rs::io::pe::{parse, serialize};
use pe_rs::io::{MOCK_APIS_BASE, MOCK_IAT_RVA, MOCK_TEXT_RVA, MockResolver};

#[test]
fn fix_iat_rebuilds_import_table() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
        let report = doc
            .fix_iat(&scan, &resolver, &IatFixOptions::default())
            .unwrap();
        assert_eq!(report.imports_built, 2);
        assert!(report.unresolved.is_empty());
        assert_eq!(report.total_entries, 6);
        let rva = report.new_import_rva.unwrap();
        assert_ne!(rva, Rva::NULL);
        assert!(report.new_import_size > 0);

        // The rich form now matches the canonical imports.
        assert_eq!(doc.imports().len(), 2);
        assert_eq!(doc.imports()[0].name, "kernel32.dll");
        assert_eq!(doc.imports()[0].functions.len(), 5);
    });
}

#[test]
fn fix_iat_redirect_rewrites_slots() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
        let first_slot = scan.entries[0].rva;
        doc.fix_iat(
            &scan,
            &resolver,
            &IatFixOptions {
                redirect_iat: true,
                ..Default::default()
            },
        )
        .unwrap();
        let after = u64::from_le_bytes(doc.read(first_slot, 8).unwrap().try_into().unwrap());
        assert_ne!(after, MOCK_APIS_BASE);
        assert!(resolver.resolve(after).is_none());
    });
}

#[test]
fn fix_iat_reuses_original_iat_slots_in_place() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
        let report = doc
            .fix_iat(&scan, &resolver, &IatFixOptions::default())
            .unwrap();
        // The mock IAT is one contiguous run, so the rebuilt descriptors'
        // FirstThunk arrays must be placed at the original slot RVAs — the
        // shape that makes a fixed dump runnable.
        assert!(report.iat_reused, "contiguous IAT should rebuild in place");

        let dir_rva = report.new_import_rva.unwrap();
        let desc = doc.read(dir_rva, 20).unwrap();
        let ft = u32::from_le_bytes(desc[16..20].try_into().unwrap());
        assert_eq!(
            ft, MOCK_IAT_RVA,
            "descriptor FirstThunk should point at the original IAT run"
        );
        let iat_dir = doc.data_directory(DataDirectoryIndex::Iat).unwrap();
        assert_eq!(iat_dir.rva.get(), MOCK_IAT_RVA);

        // The original slot now holds the new thunk (loader will overwrite it).
        let slot = u64::from_le_bytes(doc.read(Rva(MOCK_IAT_RVA), 8).unwrap().try_into().unwrap());
        assert_ne!(slot, MOCK_APIS_BASE);

        // Round-trip preserves the rebuilt table.
        let bytes = serialize(doc).unwrap();
        let reparsed = parse(&bytes).unwrap();
        assert_eq!(reparsed.imports, doc.imports);
        assert_eq!(reparsed.imports[0].functions.len(), 5);
    });
}

#[test]
fn fix_iat_falls_back_when_slots_not_contiguous() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        // Two slots of the same module that are NOT adjacent (0x10 gap instead
        // of the 8-byte pointer size): in-place reuse is impossible, so the
        // fixer must fall back to the new table's own IAT arrays.
        let scan = IatScan {
            base_rva: Rva(MOCK_IAT_RVA),
            size: 2,
            entries: vec![
                IatEntry {
                    rva: Rva(MOCK_IAT_RVA),
                    value: MOCK_APIS_BASE,
                },
                IatEntry {
                    rva: Rva(MOCK_IAT_RVA + 0x10),
                    value: MOCK_APIS_BASE + 0x100,
                },
            ],
        };
        let report = doc
            .fix_iat(&scan, &resolver, &IatFixOptions::default())
            .unwrap();
        assert!(!report.iat_reused, "non-contiguous slots must fall back");
        assert_eq!(report.imports_built, 1);
        assert!(report.unresolved.is_empty());
    });
}

#[test]
fn fix_iat_fallback_remaps_across_multiple_modules() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        // Non-contiguous slots spanning two modules: in-place is impossible, so
        // the fixer falls back and rewrites the code references to the rebuilt
        // IAT. The rebuilt IAT arrays are separated by a NULL terminator, and
        // the remap must account for it.
        let scan = IatScan {
            base_rva: Rva(MOCK_IAT_RVA),
            size: 3,
            entries: vec![
                IatEntry {
                    rva: Rva(MOCK_IAT_RVA),
                    value: MOCK_APIS_BASE, // kernel32 fn0
                },
                IatEntry {
                    rva: Rva(MOCK_IAT_RVA + 0x10),
                    value: MOCK_APIS_BASE + 0x100, // kernel32 fn1 (gap -> not contiguous)
                },
                IatEntry {
                    rva: Rva(MOCK_IAT_RVA + 0x20),
                    value: MOCK_APIS_BASE + 0x500, // other module
                },
            ],
        };
        let report = doc
            .fix_iat(&scan, &resolver, &IatFixOptions::default())
            .unwrap();
        assert!(!report.iat_reused);
        assert_eq!(report.imports_built, 2);
        assert!(report.unresolved.is_empty());

        // descriptor[1]'s FirstThunk sits after descriptor[0]'s array plus its
        // NULL terminator — the offset the code remap must have used.
        // Read each rebuilt descriptor's FirstThunk (the renderer interleaves
        // INT/IAT arrays per module), then verify the repointed code bytes
        // reference exactly those slots.
        let dir_rva = report.new_import_rva.unwrap();
        let d0 = doc.read(dir_rva, 20).unwrap();
        let ft0 = u32::from_le_bytes(d0[16..20].try_into().unwrap());
        let d1 = doc.read(dir_rva.checked_add(20).unwrap(), 20).unwrap();
        let ft1 = u32::from_le_bytes(d1[16..20].try_into().unwrap());

        // The mock text's even slots are `call [rip+disp]` (FF 15) referencing
        // slots 0/2/4 — the scan entries. After the fallback remap they must
        // target the rebuilt IAT (the blob's IAT is not pointer-aligned, so the
        // alignment-filtered scan can't see them; inspect the bytes directly).
        for (i, expect) in [(0usize, ft0), (2, ft0 + 8), (4, ft1)] {
            let insn_rva = MOCK_TEXT_RVA + (i as u32) * 8;
            let bytes = doc.read(Rva(insn_rva), 6).unwrap();
            assert_eq!(
                &bytes[0..2],
                &[0xFF, 0x15],
                "instruction {i} is a call [rip]"
            );
            let disp = i32::from_le_bytes(bytes[2..6].try_into().unwrap());
            let target = (insn_rva as i64 + 6 + disp as i64) as u32;
            assert_eq!(
                target, expect,
                "instruction {i} should reference the rebuilt slot"
            );
        }
    });
}

#[test]
fn fix_iat_without_redirect_keeps_slots() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
        let first_slot = scan.entries[0].rva;
        doc.fix_iat(
            &scan,
            &resolver,
            &IatFixOptions {
                redirect_iat: false,
                ..Default::default()
            },
        )
        .unwrap();
        let after = u64::from_le_bytes(doc.read(first_slot, 8).unwrap().try_into().unwrap());
        assert_eq!(after, MOCK_APIS_BASE);
    });
}

#[test]
fn fixed_document_serializes_and_reparses_with_imports() {
    let resolver = MockResolver::new();
    let mut doc = common::doc_via_mock();
    let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
    doc.fix_iat(&scan, &resolver, &IatFixOptions::default())
        .unwrap();

    let bytes = serialize(&doc).unwrap();
    let reparsed = parse(&bytes).unwrap();
    assert_eq!(reparsed.imports, doc.imports);
    assert_eq!(reparsed.imports.len(), 2);
    assert_eq!(reparsed.imports[0].functions.len(), 5);
}

#[test]
fn fix_iat_reports_unresolved() {
    common::both(|doc| {
        let resolver = MockResolver::new();
        let scan = IatScan {
            base_rva: Rva(MOCK_IAT_RVA),
            size: 2,
            entries: vec![
                IatEntry {
                    rva: Rva(MOCK_IAT_RVA),
                    value: 0xDEAD_BEEF,
                },
                IatEntry {
                    rva: Rva(MOCK_IAT_RVA + 8),
                    value: MOCK_APIS_BASE,
                },
            ],
        };
        let report = doc
            .fix_iat(
                &scan,
                &resolver,
                &IatFixOptions {
                    redirect_iat: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(report.unresolved.len(), 1);
        assert_eq!(report.imports_built, 1);
    });
}

#[test]
fn fix_iat_all_unresolvable_errors() {
    common::both(|doc| {
        let resolver = MockResolver::new();
        let scan = IatScan {
            base_rva: Rva(0x2000),
            size: 1,
            entries: vec![IatEntry {
                rva: Rva(0x2000),
                value: 0x1234,
            }],
        };
        assert!(
            doc.fix_iat(&scan, &resolver, &IatFixOptions::default())
                .is_err()
        );
    });
}
