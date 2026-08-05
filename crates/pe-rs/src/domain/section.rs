//! Section table.

use crate::domain::types::{RawOffset, Rva};

pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Index of a section in a document's section table, as returned by the editor.
pub type SectionId = usize;

/// `IMAGE_SECTION_HEADER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: Rva,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: RawOffset,
    pub characteristics: u32,
}

impl Default for SectionHeader {
    fn default() -> Self {
        Self {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: Rva::NULL,
            size_of_raw_data: 0,
            pointer_to_raw_data: RawOffset::NULL,
            characteristics: 0,
        }
    }
}

/// A section: its header plus the in-memory image of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub header: SectionHeader,
    pub data: Vec<u8>,
}

impl Section {
    /// Section name as a string (NUL-trimmed).
    pub fn name_str(&self) -> String {
        let end = self
            .header
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.header.name.len());
        String::from_utf8_lossy(&self.header.name[..end]).into_owned()
    }
}
