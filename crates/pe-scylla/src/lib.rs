//! # pe-scylla
//!
//! A Rust library for the **process-dump / IAT-fix** paradigm (Scylla
//! benchmark): attach to a debugged process, read its PE image out of memory
//! into [`PeDocument`] (pe-edit's shared image model), scan the IAT with one of
//! the three scan lines (resolver / code-reference / reflection), and rebuild
//! the import table ("Fix Dump"). It depends on [`pe_edit`] for the image
//! model and disk-level parse/serialize; everything here is process-oriented.
//!
//! Windows-only (compiled under `#[cfg(target_os = "windows")]` where the
//! process code lives).

pub mod api;
pub mod feature;

#[cfg(target_os = "windows")]
pub mod process;

// Re-export the pe-edit image-model types the API operates on, so consumers of
// the dump workflow don't need to reach into pe-edit for the common surface.
pub use pe_edit::api::ImportResolver;
pub use pe_edit::domain::{
    DumpImportRecovery, IatEntry, IatFixOptions, IatFixReport, IatScan, IatTable, ImportDescriptor,
    ImportFunction, PeDocument, Rva, ScanMethod, ScanOptions,
};
pub use pe_edit::error::{PeError, Result};

pub use api::{
    ImportEntry, ImportModule, ImportStatus, ImportsTree, fix_iat_from_tree, get_imports,
};
