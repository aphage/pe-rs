//! DOS MZ header.

/// The DOS "MZ" magic value.
pub const DOS_MAGIC: u16 = 0x5a4d;

/// The DOS header at the start of every PE file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    /// Offset of the "PE\0\0" signature (`e_lfanew`).
    pub e_lfanew: u32,
    /// The DOS stub: bytes between the fixed 64-byte header and `e_lfanew`.
    pub stub: Vec<u8>,
}

impl DosHeader {
    pub fn is_mz(&self) -> bool {
        self.e_magic == DOS_MAGIC
    }
}
