//! Pure-data domain model of a PE file, independent of where the bytes came
//! from (a real file or a mock). All capability traits in [`crate::api`]
//! operate on this model.

pub mod coff;
pub mod data_directory;
pub mod document;
pub mod dos;
pub mod export;
pub mod iat;
pub mod import;
pub mod load_config;
pub mod optional;
pub mod relocation;
pub mod resource;
pub mod section;
pub mod tls;
pub mod types;

pub use coff::CoffHeader;
pub use data_directory::{DataDirectory, DataDirectoryIndex};
pub use document::PeDocument;
pub use dos::DosHeader;
pub use export::{ExportSymbol, ExportTable};
pub use iat::{
    IatEntry, IatFixOptions, IatFixReport, IatScan, IatTable, RebuiltImportTable, ScanMethod,
    ScanOptions,
};
pub use import::{ImportDescriptor, ImportFunction};
pub use load_config::LoadConfigDirectory;
pub use optional::OptionalHeader;
pub use relocation::{RelocationBlock, RelocationEntry, RelocationTable};
pub use resource::{
    ResourceDataEntry, ResourceDirectory, ResourceEntry, ResourceEntryData, ResourceName,
};
pub use section::{Section, SectionHeader, SectionId};
pub use tls::TlsDirectory;
pub use types::{Arch, Machine, RawOffset, Rva, align_up, ptr_size};
