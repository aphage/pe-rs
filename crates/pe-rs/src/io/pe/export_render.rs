//! Renders a rich export table into the physical `IMAGE_EXPORT_DIRECTORY`
//! bytes of a PE.
//!
//! Layout: export directory (40 bytes) + function address array + name pointer
//! array + name-ordinal array + strings (module name, export names, forwarders).

use crate::domain::export::{ExportSymbol, ExportTable};
use crate::domain::types::Rva;
use crate::error::{PeError, Result};

fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// The result of rendering an export table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedExport {
    pub blob: Vec<u8>,
    pub rva: u32,
    pub size: u32,
}

/// Render `exports` into a blob based at `base_rva`. Symbols are sorted by
/// ordinal and assumed contiguous (`base..base + symbols.len()`).
pub fn render_export_table(exports: &ExportTable, base_rva: Rva) -> Result<RenderedExport> {
    let mut syms: Vec<&ExportSymbol> = exports.symbols.iter().collect();
    syms.sort_by_key(|s| s.ordinal);
    let named: Vec<&ExportSymbol> = syms.iter().filter(|s| s.name.is_some()).cloned().collect();

    let n_funcs = syms.len();
    let funcs_off = 40usize;
    let names_off = funcs_off + n_funcs * 4;
    let ordinals_off = names_off + named.len() * 4;
    let mut str_off = align(ordinals_off + named.len() * 2);

    let module_off = str_off;
    str_off += exports.module_name.as_deref().unwrap_or("").len() + 1;

    let mut name_offs = Vec::with_capacity(named.len());
    for s in &named {
        name_offs.push(str_off);
        str_off += s.name.as_deref().unwrap().len() + 1;
    }

    let mut fwd_off = Vec::new();
    for s in &syms {
        if let Some(f) = &s.forwarder {
            fwd_off.push((s.ordinal, str_off));
            str_off += f.len() + 1;
        }
    }

    let mut blob = vec![0u8; str_off];
    let rva = |off: usize| {
        base_rva
            .get()
            .checked_add(off as u32)
            .ok_or_else(|| PeError::InvalidArgument("export table too large".into()))
    };

    // Export directory.
    put_u32(&mut blob, 0, 0); // characteristics
    put_u32(&mut blob, 4, 0); // timestamp
    put_u32(&mut blob, 8, 0); // version
    put_u32(&mut blob, 12, rva(module_off)?); // Name
    put_u32(&mut blob, 16, exports.base); // Base
    put_u32(&mut blob, 20, n_funcs as u32); // NumberOfFunctions
    put_u32(&mut blob, 24, named.len() as u32); // NumberOfNames
    put_u32(&mut blob, 28, rva(funcs_off)?); // AddressOfFunctions
    put_u32(&mut blob, 32, rva(names_off)?); // AddressOfNames
    put_u32(&mut blob, 36, rva(ordinals_off)?); // AddressOfNameOrdinals

    let module_name = exports.module_name.as_deref().unwrap_or("");
    blob[module_off..module_off + module_name.len()].copy_from_slice(module_name.as_bytes());

    for (slot, s) in syms.iter().enumerate() {
        // Function address: either a forwarder string RVA or the symbol's RVA.
        let fwd = fwd_off
            .iter()
            .find(|(o, _)| *o == s.ordinal)
            .map(|(_, off)| *off);
        let addr = match fwd {
            Some(off) => rva(off)?,
            None => s.rva.get(),
        };
        put_u32(&mut blob, funcs_off + slot * 4, addr);

        if let Some(name) = &s.name {
            let ni = named
                .iter()
                .position(|x| x.ordinal == s.ordinal)
                .expect("named");
            put_u32(&mut blob, names_off + ni * 4, rva(name_offs[ni])?);
            put_u16(&mut blob, ordinals_off + ni * 2, slot as u16);
            let ns = name.as_bytes();
            blob[name_offs[ni]..name_offs[ni] + ns.len()].copy_from_slice(ns);
        }

        if let Some((_, off)) = fwd_off.iter().find(|(o, _)| *o == s.ordinal) {
            let f = s.forwarder.as_deref().unwrap();
            blob[*off..*off + f.len()].copy_from_slice(f.as_bytes());
        }
    }

    let size = blob.len() as u32;
    Ok(RenderedExport {
        blob,
        rva: base_rva.get(),
        size,
    })
}

fn align(v: usize) -> usize {
    (v + 1) & !1
}
