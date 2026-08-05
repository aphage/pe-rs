//! Read-only access to a [`PeDocument`].

use crate::domain::{
    Arch, CoffHeader, DataDirectory, DataDirectoryIndex, DosHeader, ExportTable, ImportDescriptor,
    OptionalHeader, RawOffset, RelocationTable, ResourceDirectory, Rva, Section, TlsDirectory,
};
use crate::error::Result;

/// Read access to a PE file. Implemented by [`PeDocument`], so it works the
/// same whether the document came from a mock or a real parser.
pub trait PeViewer {
    fn arch(&self) -> Arch;
    fn dos_header(&self) -> &DosHeader;
    fn coff_header(&self) -> &CoffHeader;
    fn optional_header(&self) -> &OptionalHeader;
    fn sections(&self) -> &[Section];
    fn data_directory(&self, index: DataDirectoryIndex) -> Result<&DataDirectory>;
    fn imports(&self) -> &[ImportDescriptor];
    fn exports(&self) -> Option<&ExportTable>;
    fn resources(&self) -> Option<&ResourceDirectory>;
    fn relocations(&self) -> Option<&RelocationTable>;
    fn tls(&self) -> Option<&TlsDirectory>;
    fn rva_to_raw(&self, rva: Rva) -> Result<RawOffset>;
    fn raw_to_rva(&self, raw: RawOffset) -> Result<Rva>;
    fn read(&self, rva: Rva, len: usize) -> Result<&[u8]>;
}

impl PeViewer for crate::domain::PeDocument {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn dos_header(&self) -> &DosHeader {
        &self.dos
    }

    fn coff_header(&self) -> &CoffHeader {
        &self.coff
    }

    fn optional_header(&self) -> &OptionalHeader {
        &self.optional
    }

    fn sections(&self) -> &[Section] {
        &self.sections
    }

    fn data_directory(&self, index: DataDirectoryIndex) -> Result<&DataDirectory> {
        self.data_directory(index)
    }

    fn imports(&self) -> &[ImportDescriptor] {
        &self.imports
    }

    fn exports(&self) -> Option<&ExportTable> {
        self.exports.as_ref()
    }

    fn resources(&self) -> Option<&ResourceDirectory> {
        self.resources.as_ref()
    }

    fn relocations(&self) -> Option<&RelocationTable> {
        self.relocations.as_ref()
    }

    fn tls(&self) -> Option<&TlsDirectory> {
        self.tls.as_ref()
    }

    fn rva_to_raw(&self, rva: Rva) -> Result<RawOffset> {
        self.rva_to_raw(rva)
    }

    fn raw_to_rva(&self, raw: RawOffset) -> Result<Rva> {
        self.raw_to_rva(raw)
    }

    fn read(&self, rva: Rva, len: usize) -> Result<&[u8]> {
        self.read(rva, len)
    }
}
