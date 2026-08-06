//! IAT scanner tests: the resolver-based scan must locate the known IAT array
//! in both the mock and the round-tripped real document.

mod common;

use pe_rs::api::IatScanner;
use pe_rs::domain::{DataDirectoryIndex, Rva, ScanMethod, ScanOptions};
use pe_rs::io::{MOCK_APIS_BASE, MOCK_IAT_RVA, MOCK_IDATA_RVA, MOCK_TEXT_RVA, MockResolver};

#[test]
fn scan_finds_mock_iat_over_whole_image() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let scan = doc.scan(&resolver, &ScanOptions::default()).unwrap();
        assert_eq!(scan.base_rva.get(), MOCK_IAT_RVA);
        assert_eq!(scan.entries.len(), 6);
        assert_eq!(scan.entries[0].value, MOCK_APIS_BASE);
        assert_eq!(scan.entries[1].value, MOCK_APIS_BASE + 0x100);
    });
}

#[test]
fn scan_region_limited_window() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        let opts = ScanOptions {
            region: Some((Rva(MOCK_IAT_RVA), 0x100)),
            min_entries: 4,
            ..Default::default()
        };
        let scan = doc.scan(&resolver, &opts).unwrap();
        assert_eq!(scan.entries.len(), 6);
        assert_eq!(scan.base_rva.get(), MOCK_IAT_RVA);
    });
}

#[test]
fn scan_min_entries_filters() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        // min_entries above the real run length -> not found
        let opts = ScanOptions {
            region: Some((Rva(MOCK_IAT_RVA), 0x100)),
            min_entries: 100,
            ..Default::default()
        };
        assert!(doc.scan(&resolver, &opts).is_err());
    });
}

#[test]
fn scan_ignores_unresolvable_region() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        // .text is a NOP sled, nothing resolvable there
        let opts = ScanOptions {
            region: Some((Rva(0x1000), 0x100)),
            ..Default::default()
        };
        assert!(doc.scan(&resolver, &opts).is_err());
    });
}

#[test]
fn code_reference_scan_finds_iat_via_code_references() {
    // The mock .text contains `call [rip+disp]` / `mov rax, [rip+disp]`
    // instructions referencing the six IAT slots.
    let resolver = MockResolver::new();
    common::both(|doc| {
        let opts = ScanOptions {
            method: ScanMethod::CodeReference,
            ..Default::default()
        };
        let scan = doc.scan(&resolver, &opts).unwrap();
        assert_eq!(scan.base_rva.get(), MOCK_IAT_RVA);
        assert_eq!(scan.entries.len(), 6);
        assert_eq!(scan.entries[0].value, MOCK_APIS_BASE);
    });
}

#[test]
fn code_reference_scan_respects_region_and_min_entries() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        // Restrict to the part of .text holding the references.
        let opts = ScanOptions {
            method: ScanMethod::CodeReference,
            region: Some((Rva(MOCK_TEXT_RVA), 0x40)),
            min_entries: 6,
            ..Default::default()
        };
        let scan = doc.scan(&resolver, &opts).unwrap();
        assert_eq!(scan.base_rva.get(), MOCK_IAT_RVA);
        assert_eq!(scan.entries.len(), 6);

        // min_entries above the run length -> not found.
        let opts = ScanOptions {
            method: ScanMethod::CodeReference,
            region: Some((Rva(MOCK_TEXT_RVA), 0x40)),
            min_entries: 100,
            ..Default::default()
        };
        assert!(doc.scan(&resolver, &opts).is_err());
    });
}

#[test]
fn code_reference_scan_with_no_code_references_errors() {
    let resolver = MockResolver::new();
    common::both(|doc| {
        // .idata holds no opcode references.
        let opts = ScanOptions {
            method: ScanMethod::CodeReference,
            region: Some((Rva(MOCK_IDATA_RVA), 0x100)),
            ..Default::default()
        };
        assert!(doc.scan(&resolver, &opts).is_err());
    });
}

#[test]
fn resolver_scan_groups_across_null_separators() {
    // A real IAT has per-module NULL separators; the scan must group the two
    // segments into a single run.
    use pe_rs::domain::section::{
        IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    };
    use pe_rs::domain::{DataDirectory, RawOffset, Section, SectionHeader};

    let addrs = [
        MOCK_APIS_BASE,
        MOCK_APIS_BASE + 0x100,
        MOCK_APIS_BASE + 0x200,
        0, // module separator
        MOCK_APIS_BASE + 0x300,
        MOCK_APIS_BASE + 0x400,
        MOCK_APIS_BASE + 0x500,
        0, // terminator
    ];
    let mut data = vec![0u8; 0x80];
    for (i, a) in addrs.iter().enumerate() {
        data[i * 8..i * 8 + 8].copy_from_slice(&a.to_le_bytes());
    }
    let mut doc = common::doc_via_mock();
    doc.sections = vec![Section {
        header: SectionHeader {
            name: *b".idata\0\0",
            virtual_size: data.len() as u32,
            virtual_address: Rva(0x2000),
            size_of_raw_data: 0,
            pointer_to_raw_data: RawOffset::NULL,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        },
        data,
    }];
    doc.data_directories = vec![DataDirectory::default(); DataDirectoryIndex::COUNT];
    doc.imports = Vec::new();

    let resolver = MockResolver::new();
    let opts = ScanOptions {
        region: Some((Rva(0x2000), 0x80)),
        min_entries: 4,
        ..Default::default()
    };
    let scan = doc.scan(&resolver, &opts).unwrap();
    assert_eq!(scan.base_rva.get(), 0x2000);
    assert_eq!(scan.entries.len(), 6);
}

#[test]
fn code_reference_scan_signature_mode_without_resolution() {
    // A resolver that resolves nothing: the opcode scan still finds the IAT via
    // code references alone (`validate_slots = false`), for protected dumps
    // (erased / split IAT) where slot contents do not resolve.
    use pe_rs::api::{ImportResolver, ResolvedImport};
    struct NoResolver;
    impl ImportResolver for NoResolver {
        fn resolve(&self, _address: u64) -> Option<ResolvedImport> {
            None
        }
    }

    common::both(|doc| {
        let opts = ScanOptions {
            method: ScanMethod::CodeReference,
            validate_slots: false,
            ..Default::default()
        };
        let scan = doc.scan(&NoResolver, &opts).unwrap();
        assert_eq!(scan.base_rva.get(), MOCK_IAT_RVA);
        assert_eq!(scan.entries.len(), 6);
    });
}

#[test]
fn code_reference_scan_finds_non_rax_register_variants() {
    // Instructions the old byte-pattern scanner missed (destination registers
    // other than rax, REX.R) must still be located by the disassembler.
    use pe_rs::domain::section::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ};
    use pe_rs::domain::{RawOffset, Section, SectionHeader};

    let mut doc = common::doc_via_mock();
    // Rebuild .text (doc.sections[0]) as a mix of rip-relative memory
    // references: `48 8B 0D` (mov rcx) and `4C 8B 05` (mov r8) are register
    // variants that only a real disassembler recognizes.
    let insns: [(&[u8], usize); 6] = [
        (&[0xFF, 0x15], 6),       // call qword [rip+disp]
        (&[0xFF, 0x25], 6),       // jmp  qword [rip+disp]
        (&[0x48, 0x8B, 0x0D], 7), // mov rcx, qword [rip+disp]
        (&[0x4C, 0x8B, 0x05], 7), // mov r8,  qword [rip+disp]
        (&[0x48, 0x8D, 0x05], 7), // lea rax, qword [rip+disp]
        (&[0x48, 0x8B, 0x05], 7), // mov rax, qword [rip+disp]
    ];
    let mut data = vec![0x90u8; 0x100];
    for (i, (prefix, len)) in insns.iter().enumerate() {
        let insn_rva = MOCK_TEXT_RVA + (i as u32) * 8;
        let slot_rva = MOCK_IAT_RVA + (i as u32) * 8;
        let disp = slot_rva as i64 - (insn_rva as i64 + *len as i64);
        let off = i * 8;
        data[off..off + prefix.len()].copy_from_slice(prefix);
        data[off + prefix.len()..off + prefix.len() + 4]
            .copy_from_slice(&(disp as i32).to_le_bytes());
    }
    doc.sections[0] = Section {
        header: SectionHeader {
            name: *b".text\0\0\0",
            virtual_size: data.len() as u32,
            virtual_address: Rva(MOCK_TEXT_RVA),
            size_of_raw_data: 0x200,
            pointer_to_raw_data: RawOffset(0x200),
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        },
        data,
    };

    let resolver = MockResolver::new();
    let opts = ScanOptions {
        method: ScanMethod::CodeReference,
        ..Default::default()
    };
    let scan = doc.scan(&resolver, &opts).unwrap();
    assert_eq!(scan.base_rva.get(), MOCK_IAT_RVA);
    assert_eq!(scan.entries.len(), 6);
}
