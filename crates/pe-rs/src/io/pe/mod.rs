//! Real PE parser and writer (the adapter behind `ByteSource` / `FileSource`).

pub mod export_render;
pub mod import_render;
pub mod parser;
pub mod writer;

pub use parser::parse;
pub use writer::serialize;
