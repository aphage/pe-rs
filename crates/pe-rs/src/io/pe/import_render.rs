//! Renders a rich import table into the physical
//! `IMAGE_IMPORT_DESCRIPTOR` / thunk / name bytes of a PE, and vice versa.
//!
//! Layout of the rendered blob (offsets relative to its base RVA):
//! 1. descriptor array (`N + 1` entries of 20 bytes, NULL-terminated)
//! 2. per module: OriginalFirstThunk (INT) array, then FirstThunk (IAT) array
//! 3. hint/name entries (aligned to 2)
//! 4. DLL name strings
//!
//! The IAT entries mirror the INT entries, so the loader can fix them in place
//! — this is the standard "fix dump" shape.

use crate::domain::import::{ImportDescriptor, ImportFunction};
use crate::domain::types::{ptr_size, Arch, Rva};
use crate::error::{PeError, Result};

fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn put_thunk(b: &mut [u8], off: usize, psize: usize, v: u64) {
    if psize == 8 {
        put_u64(b, off, v);
    } else {
        put_u32(b, off, v as u32);
    }
}

/// The result of rendering an import table into a contiguous byte blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedImport {
    /// The rendered bytes, laid out as described above.
    pub blob: Vec<u8>,
    /// RVA of the descriptor array (equals the section's base RVA).
    pub dir_rva: u32,
    /// RVA of the first FirstThunk (IAT) array.
    pub iat_rva: u32,
    /// Total size of the rendered blob.
    pub size: u32,
    /// Combined byte size of all IAT (FirstThunk) arrays.
    pub iat_size: u32,
}

/// Render `imports` into a blob based at `base_rva`.
pub fn render_import_table(
    imports: &[ImportDescriptor],
    arch: Arch,
    base_rva: Rva,
) -> Result<RenderedImport> {
    let psize = ptr_size(arch);
    let high_bit = 1u64 << (psize * 8 - 1);
    let n = imports.len();

    let mut cursor = 0usize;
    let dir_off = 0usize;
    cursor += (n + 1) * 20;

    let mut int_off = Vec::with_capacity(n);
    let mut iat_off = Vec::with_capacity(n);
    for desc in imports {
        int_off.push(cursor);
        cursor += (desc.functions.len() + 1) * psize;
        iat_off.push(cursor);
        cursor += (desc.functions.len() + 1) * psize;
    }

    // Reserve hint/name entries (aligned to 2). `func_off[i]` is the offset of
    // the i-th function's hint/name blob, or `None` for ordinal imports.
    cursor = align(cursor);
    let mut func_off = Vec::with_capacity(n);
    for desc in imports {
        for f in &desc.functions {
            match f {
                ImportFunction::Name { name, .. } => {
                    func_off.push(Some(cursor));
                    cursor = align(cursor + 2 + name.len() + 1);
                }
                ImportFunction::Ordinal { .. } => func_off.push(None),
            }
        }
    }

    let mut dll_name_off = Vec::with_capacity(n);
    for desc in imports {
        dll_name_off.push(cursor);
        cursor += desc.name.len() + 1;
    }

    let mut blob = vec![0u8; cursor];
    let rva = |off: usize| base_rva.get().checked_add(off as u32).ok_or_else(|| {
        PeError::InvalidArgument("import table too large".into())
    });

    // DLL name strings.
    for (m, desc) in imports.iter().enumerate() {
        let off = dll_name_off[m];
        blob[off..off + desc.name.len()].copy_from_slice(desc.name.as_bytes());
        blob[off + desc.name.len()] = 0;
    }

    let mut fi = 0; // flattened function index
    for (m, desc) in imports.iter().enumerate() {
        // Descriptor.
        let d = dir_off + m * 20;
        put_u32(&mut blob, d, rva(int_off[m])?); // OriginalFirstThunk
        put_u32(&mut blob, d + 4, 0); // TimeDateStamp
        put_u32(&mut blob, d + 8, 0); // ForwarderChain
        put_u32(&mut blob, d + 12, rva(dll_name_off[m])?); // Name
        put_u32(&mut blob, d + 16, rva(iat_off[m])?); // FirstThunk

        for (k, f) in desc.functions.iter().enumerate() {
            let thunk = match f {
                ImportFunction::Name { hint, name } => {
                    let off = func_off[fi].expect("named function has an entry");
                    put_u16(&mut blob, off, *hint);
                    blob[off + 2..off + 2 + name.len()].copy_from_slice(name.as_bytes());
                    blob[off + 2 + name.len()] = 0;
                    rva(off)? as u64
                }
                ImportFunction::Ordinal { ordinal } => high_bit | (*ordinal as u64),
            };
            put_thunk(&mut blob, int_off[m] + k * psize, psize, thunk);
            put_thunk(&mut blob, iat_off[m] + k * psize, psize, thunk);
            fi += 1;
        }
    }

    let iat_size = imports
        .iter()
        .map(|d| (d.functions.len() + 1) * psize)
        .sum::<usize>() as u32;

    let size = blob.len() as u32;
    Ok(RenderedImport {
        blob,
        dir_rva: base_rva.get(),
        iat_rva: base_rva.get().saturating_add(iat_off[0] as u32),
        size,
        iat_size,
    })
}

fn align(v: usize) -> usize {
    (v + 1) & !1
}
