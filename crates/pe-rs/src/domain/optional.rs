//! Optional header, 32- and 64-bit variants.

use crate::domain::types::{Arch, Rva};

pub const PE32_MAGIC: u16 = 0x10b;
pub const PE32_PLUS_MAGIC: u16 = 0x20b;

pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;

/// `IMAGE_OPTIONAL_HEADER32`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: Rva,
    pub base_of_code: Rva,
    pub base_of_data: Rva,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// `IMAGE_OPTIONAL_HEADER64` (a.k.a. PE32+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: Rva,
    pub base_of_code: Rva,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionalHeader {
    Bit32(OptionalHeader32),
    Bit64(OptionalHeader64),
}

/// Read a field that has identical type in both variants.
macro_rules! get {
    ($self:expr, $field:ident) => {
        match $self {
            OptionalHeader::Bit32(h) => h.$field,
            OptionalHeader::Bit64(h) => h.$field,
        }
    };
}

/// Write a field that has identical type in both variants.
macro_rules! set {
    ($self:expr, $field:ident, $v:expr) => {
        match $self {
            OptionalHeader::Bit32(h) => h.$field = $v,
            OptionalHeader::Bit64(h) => h.$field = $v,
        }
    };
}

/// Read a field widened to `u64` (32-bit variant is `u32`).
macro_rules! get_wide {
    ($self:expr, $field:ident) => {
        match $self {
            OptionalHeader::Bit32(h) => h.$field as u64,
            OptionalHeader::Bit64(h) => h.$field,
        }
    };
}

/// Write a `u64` into a field whose 32-bit variant is `u32`.
macro_rules! set_wide {
    ($self:expr, $field:ident, $v:expr) => {
        match $self {
            OptionalHeader::Bit32(h) => h.$field = $v as u32,
            OptionalHeader::Bit64(h) => h.$field = $v,
        }
    };
}

impl OptionalHeader {
    pub fn arch(&self) -> Arch {
        match self {
            OptionalHeader::Bit32(_) => Arch::Bit32,
            OptionalHeader::Bit64(_) => Arch::Bit64,
        }
    }

    pub fn magic(&self) -> u16 {
        get!(self, magic)
    }

    pub fn image_base(&self) -> u64 {
        get_wide!(self, image_base)
    }

    pub fn address_of_entry_point(&self) -> Rva {
        get!(self, address_of_entry_point)
    }

    pub fn base_of_code(&self) -> Rva {
        get!(self, base_of_code)
    }

    pub fn section_alignment(&self) -> u32 {
        get!(self, section_alignment)
    }

    pub fn file_alignment(&self) -> u32 {
        get!(self, file_alignment)
    }

    pub fn size_of_image(&self) -> u32 {
        get!(self, size_of_image)
    }

    pub fn size_of_headers(&self) -> u32 {
        get!(self, size_of_headers)
    }

    pub fn checksum(&self) -> u32 {
        get!(self, checksum)
    }

    pub fn subsystem(&self) -> u16 {
        get!(self, subsystem)
    }

    pub fn dll_characteristics(&self) -> u16 {
        get!(self, dll_characteristics)
    }

    pub fn size_of_stack_reserve(&self) -> u64 {
        get_wide!(self, size_of_stack_reserve)
    }

    pub fn size_of_heap_reserve(&self) -> u64 {
        get_wide!(self, size_of_heap_reserve)
    }

    pub fn number_of_rva_and_sizes(&self) -> u32 {
        get!(self, number_of_rva_and_sizes)
    }

    pub fn set_image_base(&mut self, v: u64) {
        set_wide!(self, image_base, v);
    }

    pub fn set_address_of_entry_point(&mut self, rva: Rva) {
        set!(self, address_of_entry_point, rva);
    }

    pub fn set_section_alignment(&mut self, v: u32) {
        set!(self, section_alignment, v);
    }

    pub fn set_file_alignment(&mut self, v: u32) {
        set!(self, file_alignment, v);
    }

    pub fn set_size_of_image(&mut self, v: u32) {
        set!(self, size_of_image, v);
    }

    pub fn set_size_of_headers(&mut self, v: u32) {
        set!(self, size_of_headers, v);
    }

    pub fn set_checksum(&mut self, v: u32) {
        set!(self, checksum, v);
    }
}
