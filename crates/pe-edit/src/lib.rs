//! # pe-edit
//!
//! A Rust library for **viewing and editing PE (Portable Executable) files on
//! disk** — the *disk file editing* paradigm (CFF-Explorer style). The PE
//! image is parsed into a rich [`PeDocument`](crate::domain::PeDocument)
//! (headers, sections, data directories and the import/export/resource/reloc/
//! TLS/LoadConfig rich forms), edited through the capability traits in
//! [`crate::api`], and serialized back to bytes. It has no process dependency.
//!
//! It is built *outside-in*: a stable public API (domain model + capability
//! traits) is fixed first, then backed by either a [`MockSource`](crate::io::MockSource)
//! (for testing the API contract without a real file) or a real PE parser/writer.
//!
//! The companion crate [`pe_scylla`] builds the *process-dump* paradigm
//! (Scylla benchmark) on top of this image model: it reads a live process's
//! memory into the same [`PeDocument`], then scans/fixes its IAT.

pub mod api;
pub mod domain;
pub mod error;
pub mod feature;
pub mod io;

pub use error::{PeError, Result};
