//! The central in-memory representation of a PE file (pure data).

use crate::domain::coff::CoffHeader;
use crate::domain::data_directory::{DataDirectory, DataDirectoryIndex};
use crate::domain::dos::DosHeader;
use crate::domain::export::ExportTable;
use crate::domain::import::ImportDescriptor;
use crate::domain::optional::OptionalHeader;
use crate::domain::section::{
    Section, SectionHeader, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
};
use crate::domain::types::{align_up, Arch, RawOffset, Rva};
use crate::error::{PeError, Result};

/// A PE file's contents, independent of where the bytes came from (a real file
/// or a mock). The capability traits in [`crate::api`] operate on this model.
#[derive(Debug, Clone, PartialEq)]
pub struct PeDocument {
    pub arch: Arch,
    pub dos: DosHeader,
    pub coff: CoffHeader,
    pub optional: OptionalHeader,
    pub sections: Vec<Section>,
    /// Data directory array. Normally 16 entries; may be shorter until the
    /// editor or parser pads it.
    pub data_directories: Vec<DataDirectory>,
    /// Parsed, rich form of the import table.
    pub imports: Vec<ImportDescriptor>,
    pub exports: Option<ExportTable>,
}

impl PeDocument {
    /// The section containing `rva`, as `(index, offset_into_section_data)`.
    pub fn section_containing_rva(&self, rva: Rva) -> Option<(usize, u32)> {
        let r = rva.get();
        self.sections.iter().enumerate().find_map(|(i, s)| {
            let va = s.header.virtual_address.get();
            let len = s.data.len() as u32;
            if r >= va && r < va.saturating_add(len) {
                Some((i, r - va))
            } else {
                None
            }
        })
    }

    /// Read `len` bytes at `rva` from the in-memory image.
    pub fn read(&self, rva: Rva, len: usize) -> Result<&[u8]> {
        let (i, off) = self
            .section_containing_rva(rva)
            .ok_or_else(|| PeError::InvalidArgument(format!("read: RVA {:#x} not mapped", rva.get())))?;
        let start = off as usize;
        let end = start
            .checked_add(len)
            .ok_or_else(|| PeError::InvalidArgument("read: length overflow".into()))?;
        self.sections[i]
            .data
            .get(start..end)
            .ok_or_else(|| PeError::InvalidArgument(format!("read: RVA {:#x} len {len} exceeds section", rva.get())))
    }

    /// Overwrite `bytes` at `rva` in the in-memory image.
    pub fn write(&mut self, rva: Rva, bytes: &[u8]) -> Result<()> {
        let (i, off) = self
            .section_containing_rva(rva)
            .ok_or_else(|| PeError::InvalidArgument(format!("write: RVA {:#x} not mapped", rva.get())))?;
        let start = off as usize;
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| PeError::InvalidArgument("write: length overflow".into()))?;
        let sec = &mut self.sections[i];
        if end > sec.data.len() {
            return Err(PeError::InvalidArgument(format!(
                "write: RVA {:#x} len {} exceeds section",
                rva.get(),
                bytes.len()
            )));
        }
        sec.data[start..end].copy_from_slice(bytes);
        Ok(())
    }

    /// Append a new initialized-data section at the end of the image and return
    /// its RVA. The raw file offset is assigned during serialization.
    pub fn alloc(&mut self, size: usize, alignment: u32) -> Result<Rva> {
        let align = alignment.max(1);
        let end = self
            .sections
            .iter()
            .map(|s| s.header.virtual_address.get().saturating_add(s.data.len() as u32))
            .max()
            .unwrap_or(0);
        let va = align_up(end, align);
        self.sections.push(Section {
            header: SectionHeader {
                name: *b".pefix\0\0",
                virtual_size: size as u32,
                virtual_address: Rva(va),
                size_of_raw_data: 0,
                pointer_to_raw_data: RawOffset::NULL,
                characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            },
            data: vec![0u8; size],
        });
        Ok(Rva(va))
    }

    /// Translate an RVA to a raw file offset, or error when not mapped.
    pub fn rva_to_raw(&self, rva: Rva) -> Result<RawOffset> {
        let r = rva.get();
        for s in &self.sections {
            let va = s.header.virtual_address.get();
            let len = s.data.len() as u32;
            if r >= va && r < va.saturating_add(len) {
                return Ok(RawOffset(s.header.pointer_to_raw_data.get() + (r - va)));
            }
        }
        Err(PeError::InvalidArgument(format!("rva_to_raw: RVA {:#x} not mapped", rva.get())))
    }

    /// Translate a raw file offset to an RVA, or error when not mapped.
    pub fn raw_to_rva(&self, raw: RawOffset) -> Result<Rva> {
        let o = raw.get();
        for s in &self.sections {
            let base = s.header.pointer_to_raw_data.get();
            let len = s.data.len() as u32;
            if o >= base && o < base.saturating_add(len) {
                return Ok(Rva(s.header.virtual_address.get() + (o - base)));
            }
        }
        Err(PeError::InvalidArgument(format!("raw_to_rva: offset {:#x} not mapped", raw.get())))
    }

    /// Direct access to one data directory entry.
    pub fn data_directory(&self, index: DataDirectoryIndex) -> Result<&DataDirectory> {
        self.data_directories
            .get(index.to_usize())
            .ok_or_else(|| PeError::InvalidArgument(format!("data_directory: no entry for {:?}", index)))
    }
}
