//! Mock adapter: a deterministic in-memory PE and resolver, used to exercise
//! the outer API before the real parser exists.
//!
//! `MockSource` fabricates a 64-bit `PeDocument` with two sections (`.text`,
//! `.idata`), a known import table and a contiguous IAT pointer array at a
//! known RVA. `MockResolver` maps a fixed address range to those imports.
//! Tests reference the public constants here instead of hardcoding values.

use std::collections::HashMap;

use crate::api::{ImportResolver, ResolvedImport};
use crate::domain::coff::IMAGE_FILE_EXECUTABLE_IMAGE;
use crate::domain::data_directory::{DataDirectory, DataDirectoryIndex};
use crate::domain::dos::{DOS_MAGIC, DosHeader};
use crate::domain::load_config::{
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION, IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
    IMAGE_GUARD_CF_INSTRUMENTED, LoadConfigDirectory,
};
use crate::domain::optional::{
    IMAGE_SUBSYSTEM_WINDOWS_CUI, OptionalHeader, OptionalHeader64, PE32_PLUS_MAGIC,
};
use crate::domain::relocation::{
    IMAGE_REL_BASED_HIGHLOW, RelocationBlock, RelocationEntry, RelocationTable,
};
use crate::domain::resource::{
    RT_MANIFEST, ResourceDataEntry, ResourceDirectory, ResourceEntry, ResourceEntryData,
    ResourceName,
};
use crate::domain::section::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE, Section, SectionHeader,
};
use crate::domain::tls::TlsDirectory;
use crate::domain::{
    Arch, CoffHeader, ExportSymbol, ExportTable, ImportDescriptor, ImportFunction, Machine,
    PeDocument, RawOffset, Rva,
};
use crate::error::Result;
use crate::io::pe::directory_render::render_load_config;
use crate::io::source::PeSource;

/// Image base of the mock executable.
pub const MOCK_IMAGE_BASE: u64 = 0x1400_0000;
/// First address handed out by the mock resolver.
pub const MOCK_APIS_BASE: u64 = 0x1800_0000;
/// RVA of the `.text` section.
pub const MOCK_TEXT_RVA: u32 = 0x1000;
/// RVA of the `.idata` section.
pub const MOCK_IDATA_RVA: u32 = 0x2000;
/// Offset of the IAT array inside `.idata`.
pub const MOCK_IAT_OFFSET_IN_IDATA: usize = 0x80;
/// RVA of the first IAT slot.
pub const MOCK_IAT_RVA: u32 = MOCK_IDATA_RVA + MOCK_IAT_OFFSET_IN_IDATA as u32;
pub const MOCK_SECTION_ALIGNMENT: u32 = 0x1000;
pub const MOCK_FILE_ALIGNMENT: u32 = 0x200;
/// RVA of the `.rsrc` section (holds resource / relocation / TLS data).
pub const MOCK_RSRC_RVA: u32 = 0x3000;

/// The canonical import table the mock document carries.
pub fn mock_imports() -> Vec<ImportDescriptor> {
    vec![
        ImportDescriptor::new(
            "kernel32.dll",
            vec![
                ImportFunction::by_name("GetProcAddress"),
                ImportFunction::by_name("LoadLibraryA"),
                ImportFunction::by_name("VirtualAlloc"),
                ImportFunction::by_name("WriteProcessMemory"),
                ImportFunction::by_name("ExitProcess"),
            ],
        ),
        ImportDescriptor::new("user32.dll", vec![ImportFunction::by_name("MessageBoxA")]),
    ]
}

/// The canonical import table as flattened `(module, function)` pairs, in the
/// same order the resolver hands out addresses.
fn flat_imports() -> Vec<(String, ImportFunction)> {
    let mut out = Vec::new();
    for desc in mock_imports() {
        for f in desc.functions {
            out.push((desc.name.clone(), f));
        }
    }
    out
}

/// Build the deterministic `PeDocument` the mock serves.
pub fn document() -> PeDocument {
    let imports = mock_imports();
    let flat = flat_imports();

    // `.text`: a NOP sled with six instructions that reference the IAT slots,
    // so the code-reference scanner can locate the IAT from code references.
    // Even slots use `call [rip+disp]` (FF 15), odd slots `mov rax, [rip+disp]`
    // (48 8B 05) — covering both rip-relative forms.
    let mut text_data = vec![0x90u8; 0x100];
    for i in 0..6usize {
        let insn_rva = MOCK_TEXT_RVA + (i as u32) * 8;
        let slot_rva = MOCK_IAT_RVA + (i as u32) * 8;
        let off = i * 8;
        if i % 2 == 0 {
            let disp = slot_rva as i64 - (insn_rva + 6) as i64;
            text_data[off] = 0xFF;
            text_data[off + 1] = 0x15;
            text_data[off + 2..off + 6].copy_from_slice(&(disp as i32).to_le_bytes());
        } else {
            let disp = slot_rva as i64 - (insn_rva + 7) as i64;
            text_data[off..off + 3].copy_from_slice(&[0x48, 0x8B, 0x05]);
            text_data[off + 3..off + 7].copy_from_slice(&(disp as i32).to_le_bytes());
        }
    }
    let text = Section {
        header: SectionHeader {
            name: *b".text\0\0\0",
            virtual_size: text_data.len() as u32,
            virtual_address: Rva(MOCK_TEXT_RVA),
            size_of_raw_data: 0x200,
            pointer_to_raw_data: RawOffset(0x200),
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        },
        data: text_data,
    };

    // `.idata`: a name blob at the front and the contiguous IAT pointer array
    // at `MOCK_IAT_OFFSET_IN_IDATA`.
    let mut idata = vec![0u8; 0x100];
    let iat_bytes = flat.len() * 8;
    for (i, _) in flat.iter().enumerate() {
        let val = (MOCK_APIS_BASE + (i as u64) * 0x100).to_le_bytes();
        let off = MOCK_IAT_OFFSET_IN_IDATA + i * 8;
        idata[off..off + 8].copy_from_slice(&val);
    }
    let idata = Section {
        header: SectionHeader {
            name: *b".idata\0\0",
            virtual_size: idata.len() as u32,
            virtual_address: Rva(MOCK_IDATA_RVA),
            size_of_raw_data: 0x200,
            pointer_to_raw_data: RawOffset(0x400),
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        },
        data: idata,
    };

    // `.rsrc`: hand-built resource directory tree + one base-reloc block + one
    // TLS directory, so the directory parsers have real data to read. The raw
    // bytes here must match the rich forms stored on the document below.
    let manifest = b"<assembly manifestVersion=\"1.0\"></assembly>";
    let mut rsrc = vec![0u8; 0x300];
    // root directory: 1 ID entry
    rsrc[14..16].copy_from_slice(&1u16.to_le_bytes());
    // root entry: type 24 (manifest), subdirectory at 0x20
    rsrc[0x10..0x14].copy_from_slice(&RT_MANIFEST.to_le_bytes());
    rsrc[0x14..0x18].copy_from_slice(&(0x8000_0000u32 | 0x20).to_le_bytes());
    // name-level directory: 1 ID entry
    rsrc[0x20 + 14..0x20 + 16].copy_from_slice(&1u16.to_le_bytes());
    // name entry: ID 1, subdirectory at 0x40
    rsrc[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
    rsrc[0x34..0x38].copy_from_slice(&(0x8000_0000u32 | 0x40).to_le_bytes());
    // language directory: 1 ID entry
    rsrc[0x40 + 14..0x40 + 16].copy_from_slice(&1u16.to_le_bytes());
    // language entry: 0x409, leaf data entry at 0x60
    rsrc[0x50..0x54].copy_from_slice(&0x409u32.to_le_bytes());
    rsrc[0x54..0x58].copy_from_slice(&0x60u32.to_le_bytes());
    // data entry at 0x60: manifest bytes at 0x70
    rsrc[0x60..0x64].copy_from_slice(&(MOCK_RSRC_RVA + 0x70).to_le_bytes());
    rsrc[0x64..0x68].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
    rsrc[0x70..0x70 + manifest.len()].copy_from_slice(manifest);
    // base relocation block at 0xA0: one HIGHLOW entry at offset 0x10
    rsrc[0xA0..0xA4].copy_from_slice(&0x1000u32.to_le_bytes());
    rsrc[0xA4..0xA8].copy_from_slice(&10u32.to_le_bytes());
    rsrc[0xA8..0xAA]
        .copy_from_slice(&(((IMAGE_REL_BASED_HIGHLOW as u16) << 12) | 0x10).to_le_bytes());
    // terminator block at 0xAC (zeros); TLS directory at 0xC0
    //
    // StartAddressOfRawData / EndAddressOfRawData are the *VAs* of the TLS
    // template — the initialized data block the loader copies per thread — so
    // they must point at real bytes in the image. We place a 4-byte template at
    // 0x100 and a zeroed TLS-index slot at 0x110, and reference those.
    rsrc[0xC0..0xC8]
        .copy_from_slice(&(MOCK_IMAGE_BASE + MOCK_RSRC_RVA as u64 + 0x100).to_le_bytes());
    rsrc[0xC8..0xD0]
        .copy_from_slice(&(MOCK_IMAGE_BASE + MOCK_RSRC_RVA as u64 + 0x104).to_le_bytes());
    rsrc[0xD0..0xD8]
        .copy_from_slice(&(MOCK_IMAGE_BASE + MOCK_RSRC_RVA as u64 + 0x110).to_le_bytes());
    // callbacks / zero-fill / characteristics stay zero
    rsrc[0x100..0x104].copy_from_slice(&[0x2A, 0x00, 0x00, 0x00]); // TLS template data
    // TLS-index slot at 0x110 stays zero (the loader would write the index)

    // Load configuration directory (CFG data) at 0x140: rendered from the rich
    // form so the raw bytes match exactly.
    let load_config = LoadConfigDirectory {
        size: 0x140,
        time_date_stamp: 0x5c0a_1234,
        major_version: 0,
        minor_version: 0,
        global_flags_clear: 0,
        global_flags_set: 0x8000_0000,
        security_cookie: MOCK_IMAGE_BASE + 0x2000,
        se_handler_table: 0,
        se_handler_count: 0,
        guard_cf_check_function_pointer: MOCK_IMAGE_BASE + 0x3000,
        guard_cf_dispatch_function_pointer: MOCK_IMAGE_BASE + 0x3008,
        guard_cf_function_table: MOCK_IMAGE_BASE + 0x3100,
        guard_cf_function_count: 5,
        guard_flags: IMAGE_GUARD_CF_INSTRUMENTED
            | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
            | IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION,
        guard_address_taken_iat_entry_table: MOCK_IMAGE_BASE + 0x3120,
        guard_address_taken_iat_entry_count: 2,
        guard_long_jump_target_table: MOCK_IMAGE_BASE + 0x3140,
        guard_long_jump_target_count: 3,
        guard_eh_continuation_table: MOCK_IMAGE_BASE + 0x3160,
        guard_eh_continuation_count: 4,
        guard_xfg_check_function_pointer: MOCK_IMAGE_BASE + 0x3180,
        guard_xfg_dispatch_function_pointer: MOCK_IMAGE_BASE + 0x3188,
        chpe_metadata_pointer: 0,
        hot_patch_table_offset: 0x100,
    };
    let lc_bytes = render_load_config(&load_config, Arch::Bit64);
    rsrc[0x140..0x140 + lc_bytes.len()].copy_from_slice(&lc_bytes);

    let rsrc = Section {
        header: SectionHeader {
            name: *b".rsrc\0\0\0",
            virtual_size: rsrc.len() as u32,
            virtual_address: Rva(MOCK_RSRC_RVA),
            size_of_raw_data: 0x200,
            pointer_to_raw_data: RawOffset(0x600),
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        },
        data: rsrc,
    };

    let mut dirs = vec![DataDirectory::default(); DataDirectoryIndex::COUNT];
    dirs[DataDirectoryIndex::Import.to_usize()] = DataDirectory {
        rva: Rva(MOCK_IDATA_RVA),
        size: 0x80,
    };
    dirs[DataDirectoryIndex::Iat.to_usize()] = DataDirectory {
        rva: Rva(MOCK_IAT_RVA),
        size: iat_bytes as u32,
    };
    dirs[DataDirectoryIndex::Resource.to_usize()] = DataDirectory {
        rva: Rva(MOCK_RSRC_RVA),
        size: 0x80,
    };
    dirs[DataDirectoryIndex::BaseReloc.to_usize()] = DataDirectory {
        rva: Rva(MOCK_RSRC_RVA + 0xA0),
        size: 0x1C,
    };
    dirs[DataDirectoryIndex::Tls.to_usize()] = DataDirectory {
        rva: Rva(MOCK_RSRC_RVA + 0xC0),
        size: 0x30,
    };
    dirs[DataDirectoryIndex::LoadConfig.to_usize()] = DataDirectory {
        rva: Rva(MOCK_RSRC_RVA + 0x140),
        size: 0x140,
    };

    PeDocument {
        arch: Arch::Bit64,
        dos: DosHeader {
            e_magic: DOS_MAGIC,
            e_lfanew: 0x40,
            ..DosHeader::default()
        },
        coff: CoffHeader {
            machine: Machine::Amd64,
            number_of_sections: 3,
            time_date_stamp: 0x5c0a_1234,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0xf0,
            characteristics: IMAGE_FILE_EXECUTABLE_IMAGE,
        },
        optional: OptionalHeader::Bit64(OptionalHeader64 {
            magic: PE32_PLUS_MAGIC,
            major_linker_version: 14,
            minor_linker_version: 0,
            size_of_code: 0x100,
            size_of_initialized_data: 0x100,
            size_of_uninitialized_data: 0,
            address_of_entry_point: Rva(MOCK_TEXT_RVA),
            base_of_code: Rva(MOCK_TEXT_RVA),
            image_base: MOCK_IMAGE_BASE,
            section_alignment: MOCK_SECTION_ALIGNMENT,
            file_alignment: MOCK_FILE_ALIGNMENT,
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
            subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI,
            dll_characteristics: 0,
            size_of_stack_reserve: 0x100000,
            size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 16,
        }),
        sections: vec![text, idata, rsrc],
        data_directories: dirs,
        exports: Some(ExportTable {
            module_name: Some("mock.exe".to_string()),
            base: 1,
            number_of_functions: 2,
            symbols: vec![
                ExportSymbol {
                    name: Some("Start".to_string()),
                    ordinal: 1,
                    rva: Rva(MOCK_TEXT_RVA),
                    forwarder: None,
                },
                ExportSymbol {
                    name: Some("DumpMe".to_string()),
                    ordinal: 2,
                    rva: Rva(MOCK_TEXT_RVA + 0x10),
                    forwarder: None,
                },
            ],
        }),
        imports,
        resources: Some(ResourceDirectory {
            entries: vec![ResourceEntry {
                name: ResourceName::Id(RT_MANIFEST),
                data: ResourceEntryData::Directory(ResourceDirectory {
                    entries: vec![ResourceEntry {
                        name: ResourceName::Id(1),
                        data: ResourceEntryData::Directory(ResourceDirectory {
                            entries: vec![ResourceEntry {
                                name: ResourceName::Id(0x409),
                                data: ResourceEntryData::Leaf(ResourceDataEntry {
                                    rva: Rva(MOCK_RSRC_RVA + 0x70),
                                    size: manifest.len() as u32,
                                    code_page: 0,
                                }),
                            }],
                        }),
                    }],
                }),
            }],
        }),
        relocations: Some(RelocationTable {
            blocks: vec![RelocationBlock {
                page_rva: Rva(0x1000),
                entries: vec![RelocationEntry {
                    reloc_type: IMAGE_REL_BASED_HIGHLOW,
                    offset: 0x10,
                }],
            }],
        }),
        tls: Some(TlsDirectory {
            start_address_of_raw_data: MOCK_IMAGE_BASE + MOCK_RSRC_RVA as u64 + 0x100,
            end_address_of_raw_data: MOCK_IMAGE_BASE + MOCK_RSRC_RVA as u64 + 0x104,
            address_of_index: MOCK_IMAGE_BASE + MOCK_RSRC_RVA as u64 + 0x110,
            address_of_callbacks: 0,
            size_of_zero_fill: 0,
            characteristics: 0,
        }),
        load_config: Some(load_config),
    }
}

/// `PeSource` that serves the deterministic document above and whose `save`
/// is a no-op (mock documents are never serialized).
pub struct MockSource;

impl MockSource {
    pub fn new() -> Self {
        Self
    }

    pub fn document() -> PeDocument {
        document()
    }
}

impl Default for MockSource {
    fn default() -> Self {
        Self::new()
    }
}

impl PeSource for MockSource {
    fn load(&self) -> Result<PeDocument> {
        Ok(Self::document())
    }

    fn save(&self, _doc: &PeDocument) -> Result<()> {
        Ok(())
    }
}

/// Resolves addresses to the mock import table. Addresses are handed out in
/// flattened `(module, function)` order starting at [`MOCK_APIS_BASE`], one
/// every `0x100` bytes.
pub struct MockResolver {
    map: HashMap<u64, ResolvedImport>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self::from_imports(&mock_imports())
    }

    pub fn from_imports(imports: &[ImportDescriptor]) -> Self {
        let mut map = HashMap::new();
        let mut addr = MOCK_APIS_BASE;
        for desc in imports {
            for f in &desc.functions {
                map.insert(
                    addr,
                    ResolvedImport {
                        module: desc.name.clone(),
                        function: f.clone(),
                    },
                );
                addr += 0x100;
            }
        }
        Self { map }
    }

    /// The address this resolver assigned to a given import, if any.
    pub fn address_of(&self, module: &str, name: &str) -> Option<u64> {
        self.map.iter().find_map(|(&addr, r)| {
            if r.module == module && r.function.name() == Some(name) {
                Some(addr)
            } else {
                None
            }
        })
    }
}

impl Default for MockResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ImportResolver for MockResolver {
    fn resolve(&self, address: u64) -> Option<ResolvedImport> {
        self.map.get(&address).cloned()
    }
}
