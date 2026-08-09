//! Base relocation table (`IMAGE_BASE_RELOCATION`).

use crate::domain::types::Rva;

/// `IMAGE_REL_BASED_*` relocation types.
pub const IMAGE_REL_BASED_ABSOLUTE: u8 = 0;
pub const IMAGE_REL_BASED_HIGH: u8 = 1;
pub const IMAGE_REL_BASED_LOW: u8 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u8 = 3;
pub const IMAGE_REL_BASED_HIGHADJ: u8 = 4;
pub const IMAGE_REL_BASED_MIPS_JMPADDR: u8 = 5;
pub const IMAGE_REL_BASED_ARM_MOV32: u8 = 5;
pub const IMAGE_REL_BASED_RISCV_HIGH20: u8 = 5;
pub const IMAGE_REL_BASED_DIR64: u8 = 10;

/// One 16-bit relocation entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationEntry {
    pub reloc_type: u8,
    pub offset: u16,
}

/// One relocation block: all entries for a single 64 KiB page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationBlock {
    pub page_rva: Rva,
    pub entries: Vec<RelocationEntry>,
}

/// The full base relocation table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RelocationTable {
    pub blocks: Vec<RelocationBlock>,
}
