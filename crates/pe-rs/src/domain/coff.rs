//! COFF file header (`IMAGE_FILE_HEADER`).

use crate::domain::types::Machine;

pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// The COFF (file) header that follows the DOS stub and the `PE\0\0` signature.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoffHeader {
    pub machine: Machine,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}
