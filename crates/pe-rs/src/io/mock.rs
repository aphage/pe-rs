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
use crate::domain::dos::{DosHeader, DOS_MAGIC};
use crate::domain::optional::{OptionalHeader, OptionalHeader64, PE32_PLUS_MAGIC, IMAGE_SUBSYSTEM_WINDOWS_CUI};
use crate::domain::section::{
    Section, SectionHeader, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use crate::domain::{
    Arch, CoffHeader, ExportSymbol, ExportTable, ImportDescriptor, ImportFunction, Machine,
    PeDocument, RawOffset, Rva,
};
use crate::error::Result;
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
        ImportDescriptor::new(
            "user32.dll",
            vec![ImportFunction::by_name("MessageBoxA")],
        ),
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

    // `.text`: a NOP sled; purely decorative for now.
    let text_data = vec![0x90u8; 0x100];
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
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        },
        data: idata,
    };

    let mut dirs = vec![DataDirectory::default(); DataDirectoryIndex::COUNT];
    dirs[DataDirectoryIndex::Import.to_usize()] =
        DataDirectory { rva: Rva(MOCK_IDATA_RVA), size: 0x80 };
    dirs[DataDirectoryIndex::Iat.to_usize()] =
        DataDirectory { rva: Rva(MOCK_IAT_RVA), size: iat_bytes as u32 };

    PeDocument {
        arch: Arch::Bit64,
        dos: DosHeader { e_magic: DOS_MAGIC, e_lfanew: 0x40, ..DosHeader::default() },
        coff: CoffHeader {
            machine: Machine::Amd64,
            number_of_sections: 2,
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
            size_of_image: 0x3000,
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
        sections: vec![text, idata],
        data_directories: dirs,
        exports: Some(ExportTable {
            module_name: Some("mock.exe".to_string()),
            base: 1,
            number_of_functions: 2,
            symbols: vec![
                ExportSymbol { name: Some("Start".to_string()), ordinal: 1, rva: Rva(MOCK_TEXT_RVA), forwarder: None },
                ExportSymbol { name: Some("DumpMe".to_string()), ordinal: 2, rva: Rva(MOCK_TEXT_RVA + 0x10), forwarder: None },
            ],
        }),
        imports,
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
                    ResolvedImport { module: desc.name.clone(), function: f.clone() },
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
