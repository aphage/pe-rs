//! Basic scalar types shared across the domain model.

/// A virtual address relative to the image base (RVA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Rva(pub u32);

impl Rva {
    pub const NULL: Rva = Rva(0);

    #[inline]
    pub fn get(self) -> u32 {
        self.0
    }

    #[inline]
    pub fn checked_add(self, delta: u32) -> Option<Rva> {
        self.0.checked_add(delta).map(Rva)
    }

    #[inline]
    pub fn checked_sub(self, delta: u32) -> Option<Rva> {
        self.0.checked_sub(delta).map(Rva)
    }
}

/// An offset into the raw file on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RawOffset(pub u32);

impl RawOffset {
    pub const NULL: RawOffset = RawOffset(0);

    #[inline]
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Image base used to compute an absolute VA from an RVA.
pub type ImageBase = u64;

/// Target architecture of the PE image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    Bit32,
    Bit64,
}

/// `IMAGE_FILE_MACHINE_*` values.
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

/// The COFF machine type from the file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Machine {
    I386,
    Amd64,
    Arm64,
    Unknown(u16),
}

impl Default for Machine {
    fn default() -> Self {
        Machine::Unknown(0)
    }
}

impl Machine {
    pub fn from_u16(v: u16) -> Machine {
        match v {
            IMAGE_FILE_MACHINE_I386 => Machine::I386,
            IMAGE_FILE_MACHINE_AMD64 => Machine::Amd64,
            IMAGE_FILE_MACHINE_ARM64 => Machine::Arm64,
            other => Machine::Unknown(other),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Machine::I386 => IMAGE_FILE_MACHINE_I386,
            Machine::Amd64 => IMAGE_FILE_MACHINE_AMD64,
            Machine::Arm64 => IMAGE_FILE_MACHINE_ARM64,
            Machine::Unknown(v) => v,
        }
    }
}

/// Round `n` up to the next multiple of `align`. `align` of 0 or 1 is a no-op.
#[inline]
pub fn align_up(n: u32, align: u32) -> u32 {
    if align <= 1 {
        return n;
    }
    n.wrapping_add(align - 1) / align * align
}

/// Size in bytes of a pointer for the given architecture.
#[inline]
pub fn ptr_size(arch: Arch) -> usize {
    match arch {
        Arch::Bit32 => 4,
        Arch::Bit64 => 8,
    }
}
