//! Tests for direct-import handling (Scylla's IATReferenceScan): scanning code
//! for direct `call`/`jmp` to an API address, adding those imports, building a
//! jump table and patching the calls to it.

use pe_edit::domain::coff::IMAGE_FILE_EXECUTABLE_IMAGE;
use pe_edit::domain::dos::{DOS_MAGIC, DosHeader};
use pe_edit::domain::optional::{OptionalHeader, OptionalHeader64, PE32_PLUS_MAGIC};
use pe_edit::domain::section::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, Section, SectionHeader,
};
use pe_edit::domain::{Arch, CoffHeader, Machine, PeDocument, Rva};
use pe_edit::io::{MOCK_APIS_BASE, MockResolver};

const IMAGE_BASE: u64 = 0x1000_0000; // low base so a direct call to a mock API fits rel32
const TEXT_RVA: u32 = 0x1000;

/// A 64-bit document whose `.text` holds one direct `call <API>` instruction
/// at `TEXT_RVA` (the mock resolver maps `MOCK_APIS_BASE` to an API).
fn doc_with_direct_call() -> (PeDocument, usize) {
    // E8 <rel32> call MOCK_APIS_BASE, at RVA 0x1000.
    let disp = (MOCK_APIS_BASE as i64 - (IMAGE_BASE + TEXT_RVA as u64 + 5) as i64) as i32;
    let mut text = vec![0xE8u8];
    text.extend_from_slice(&disp.to_le_bytes());
    let text_rva = TEXT_RVA;
    let text_section = Section {
        header: SectionHeader {
            name: *b".text\0\0\0",
            virtual_size: text.len() as u32,
            virtual_address: Rva(text_rva),
            size_of_raw_data: 0x200,
            pointer_to_raw_data: pe_edit::domain::RawOffset(0x400),
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        },
        data: text.clone(),
    };
    let optional = OptionalHeader::Bit64(OptionalHeader64 {
        magic: PE32_PLUS_MAGIC,
        major_linker_version: 14,
        minor_linker_version: 0,
        size_of_code: 0x100,
        size_of_initialized_data: 0,
        size_of_uninitialized_data: 0,
        address_of_entry_point: Rva(text_rva),
        base_of_code: Rva(text_rva),
        image_base: IMAGE_BASE,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        major_operating_system_version: 6,
        minor_operating_system_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 6,
        minor_subsystem_version: 0,
        win32_version_value: 0,
        size_of_image: 0x4000,
        size_of_headers: 0x200,
        checksum: 0,
        subsystem: 2,
        dll_characteristics: 0,
        size_of_stack_reserve: 0x100000,
        size_of_stack_commit: 0x1000,
        size_of_heap_reserve: 0x100000,
        size_of_heap_commit: 0x1000,
        loader_flags: 0,
        number_of_rva_and_sizes: 16,
    });
    let doc = PeDocument {
        arch: Arch::Bit64,
        dos: DosHeader {
            e_magic: DOS_MAGIC,
            e_lfanew: 0x40,
            ..DosHeader::default()
        },
        coff: CoffHeader {
            machine: Machine::Amd64,
            number_of_sections: 1,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0xF0,
            characteristics: IMAGE_FILE_EXECUTABLE_IMAGE,
        },
        optional,
        sections: vec![text_section],
        data_directories: vec![],
        imports: vec![],
        exports: None,
        resources: None,
        relocations: None,
        tls: None,
        load_config: None,
    };
    (doc, text.len())
}

#[test]
fn scan_finds_direct_call_to_api() {
    let (doc, _) = doc_with_direct_call();
    let resolver = MockResolver::new();
    let direct = pe_scylla::api::scan_direct_imports(&doc, &resolver).expect("scan");
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].insn_rva.get(), TEXT_RVA);
    assert_eq!(direct[0].api_va, MOCK_APIS_BASE);
    assert_eq!(direct[0].module, "kernel32.dll");
    assert_eq!(direct[0].function.name(), Some("GetProcAddress"));
}

#[test]
fn add_imports_then_build_jump_table_and_patch() {
    let (mut doc, _) = doc_with_direct_call();
    let resolver = MockResolver::new();
    let direct = pe_scylla::api::scan_direct_imports(&doc, &resolver).expect("scan");

    // Adding the directly-called API makes it an import.
    let added = pe_scylla::api::add_direct_imports_to_doc(&mut doc, &direct).expect("add");
    assert_eq!(added, 1);
    assert_eq!(doc.imports.len(), 1);
    assert_eq!(doc.imports[0].name, "kernel32.dll");

    // A jump table entry forwards to the IAT slot.
    let jump_rva =
        pe_scylla::api::build_direct_import_jump_table(&mut doc, &direct, &[IMAGE_BASE + 0x2000])
            .expect("jump table");
    let patched = pe_scylla::api::patch_direct_imports_to_jump_table(&mut doc, &direct, jump_rva)
        .expect("patch");
    assert_eq!(patched, 1);

    // The call now targets the jump-table entry (an absolute VA).
    let sec = &doc.sections[0];
    let bytes = sec.data.as_slice();
    let disp = i32::from_le_bytes(bytes[1..5].try_into().unwrap()) as i64;
    let target = (IMAGE_BASE as i64 + TEXT_RVA as i64 + 5) + disp;
    assert_eq!(target as u64, IMAGE_BASE + jump_rva.get() as u64);
}
