//! Real PE parser and writer (the adapter behind `ByteSource` / `FileSource`).

pub mod directory_render;
pub mod export_render;
pub mod import_render;
pub mod parser;
pub mod writer;

pub use parser::parse;
pub use writer::serialize;

/// Append the raw bytes of a fully-initialized `#[repr(C)]` structure.
pub(crate) fn write_struct<T>(out: &mut Vec<u8>, value: &T) {
    let size = std::mem::size_of::<T>();
    // SAFETY: `value` is a fully-initialized plain structure (every field set,
    // no padding — the `IMAGE_*` structs match the on-disk layout), so reading
    // its bytes is sound. Mirrors `parser::read_struct` in reverse.
    let bytes = unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size) };
    out.extend_from_slice(bytes);
}
