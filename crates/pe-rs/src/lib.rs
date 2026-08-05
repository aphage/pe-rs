//! # pe-rs
//!
//! A Rust library for viewing and editing PE (Portable Executable) files.
//!
//! It is built *outside-in*: a stable public API (domain model + capability
//! traits) is fixed first, then backed by either a [`MockSource`](crate::io::MockSource)
//! (for testing the API contract without a real file) or a real PE parser/writer.
//!
//! The library covers the *file-level* feature set of the
//! [Scylla](https://github.com/NtQuery/Scylla) tool: header/section viewing and
//! editing, import/export tables, IAT scanning, **IAT fixing** (import table
//! rebuilding, "Fix Dump") and **manual IAT array** addition.

pub mod api;
pub mod domain;
pub mod error;
pub mod feature;
pub mod io;

#[cfg(target_os = "windows")]
pub mod process;

pub use error::{PeError, Result};
