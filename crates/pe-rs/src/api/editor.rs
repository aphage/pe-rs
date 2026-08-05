//! Mutating access to a [`PeDocument`].

use crate::domain::{
    align_up, CoffHeader, DataDirectory, DataDirectoryIndex, DosHeader, OptionalHeader, Rva,
    Section, SectionHeader, SectionId,
};
use crate::error::{PeError, Result};

/// Edit access to a PE file. Implemented by [`PeDocument`].
pub trait PeEditor {
    fn set_dos_header(&mut self, dos: DosHeader);
    fn set_coff_header(&mut self, coff: CoffHeader);
    fn set_optional_header(&mut self, optional: OptionalHeader);
    fn set_data_directory(&mut self, index: DataDirectoryIndex, rva: Rva, size: u32) -> Result<()>;
    /// Append a new section at the end of the image.
    fn add_section(&mut self, name: [u8; 8], characteristics: u32, data: Vec<u8>) -> Result<SectionId>;
    fn remove_section(&mut self, id: SectionId) -> Result<()>;
    fn write(&mut self, rva: Rva, bytes: &[u8]) -> Result<()>;
    fn alloc(&mut self, size: usize, alignment: u32) -> Result<Rva>;
}

impl PeEditor for crate::domain::PeDocument {
    fn set_dos_header(&mut self, dos: DosHeader) {
        self.dos = dos;
    }

    fn set_coff_header(&mut self, coff: CoffHeader) {
        self.coff = coff;
    }

    fn set_optional_header(&mut self, optional: OptionalHeader) {
        self.optional = optional;
    }

    fn set_data_directory(&mut self, index: DataDirectoryIndex, rva: Rva, size: u32) -> Result<()> {
        let i = index.to_usize();
        while self.data_directories.len() <= i {
            self.data_directories.push(DataDirectory::default());
        }
        self.data_directories[i] = DataDirectory { rva, size };
        Ok(())
    }

    fn add_section(&mut self, name: [u8; 8], characteristics: u32, data: Vec<u8>) -> Result<SectionId> {
        let align = self.optional.section_alignment().max(1);
        let end = self
            .sections
            .iter()
            .map(|s| s.header.virtual_address.get().saturating_add(s.data.len() as u32))
            .max()
            .unwrap_or(0);
        let va = align_up(end, align);
        self.sections.push(Section {
            header: SectionHeader {
                name,
                virtual_size: data.len() as u32,
                virtual_address: Rva(va),
                size_of_raw_data: 0,
                pointer_to_raw_data: crate::domain::RawOffset::NULL,
                characteristics,
            },
            data,
        });
        Ok(self.sections.len() - 1)
    }

    fn remove_section(&mut self, id: SectionId) -> Result<()> {
        if id >= self.sections.len() {
            return Err(PeError::InvalidArgument(format!("remove_section: no section #{id}")));
        }
        if self.sections.len() <= 1 {
            return Err(PeError::InvalidArgument("remove_section: cannot remove the last section".into()));
        }
        self.sections.remove(id);
        Ok(())
    }

    fn write(&mut self, rva: Rva, bytes: &[u8]) -> Result<()> {
        self.write(rva, bytes)
    }

    fn alloc(&mut self, size: usize, alignment: u32) -> Result<Rva> {
        self.alloc(size, alignment)
    }
}
