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
pub mod optional;
pub mod section;
pub mod types;

pub use coff::CoffHeader;
pub use data_directory::{DataDirectory, DataDirectoryIndex};
pub use document::PeDocument;
pub use dos::DosHeader;
pub use export::{ExportSymbol, ExportTable};
pub use iat::{
    IatEntry, IatFixOptions, IatFixReport, IatScan, ScanMethod, ScanOptions,
};
pub use import::{ImportDescriptor, ImportFunction};
pub use optional::OptionalHeader;
pub use section::{Section, SectionHeader, SectionId};
pub use types::{align_up, ptr_size, Arch, Machine, RawOffset, Rva};
