//! Raw ↔ VA conversion utilities.
//!
//! The document's strict `rva_to_raw`/`raw_to_rva` only accept RVAs inside a
//! section's *data*. The [`VaConverter`] here also maps the header region
//! (RVA < `size_of_headers` ↔ file offset 0) and handles dumps where a
//! section's raw size does not match its virtual size, by resolving each side
//! independently.

use crate::domain::{PeDocument, RawOffset, Rva};

/// Converts between absolute virtual addresses, RVAs and raw file offsets for
/// one document.
#[derive(Debug, Clone)]
pub struct VaConverter {
    image_base: u64,
    size_of_headers: u32,
    /// `(virtual_address, virtual_size, raw_ptr, raw_size)` per section.
    sections: Vec<(Rva, u32, RawOffset, u32)>,
}

impl VaConverter {
    pub fn from_document(doc: &PeDocument) -> Self {
        let sections = doc
            .sections
            .iter()
            .map(|s| {
                let vs = if s.header.virtual_size != 0 {
                    s.header.virtual_size
                } else {
                    s.data.len() as u32
                };
                (
                    s.header.virtual_address,
                    vs,
                    s.header.pointer_to_raw_data,
                    s.header.size_of_raw_data,
                )
            })
            .collect();
        Self {
            image_base: doc.optional.image_base(),
            size_of_headers: doc.optional.size_of_headers(),
            sections,
        }
    }

    pub fn va_to_rva(&self, va: u64) -> Option<Rva> {
        if va < self.image_base {
            return None;
        }
        let r = va - self.image_base;
        if r > u32::MAX as u64 {
            return None;
        }
        Some(Rva(r as u32))
    }

    pub fn rva_to_va(&self, rva: Rva) -> u64 {
        self.image_base + rva.get() as u64
    }

    /// Map an RVA to a raw file offset. The header region maps 1:1; otherwise a
    /// section's virtual extent (virtual size) is used.
    pub fn rva_to_raw(&self, rva: Rva) -> Option<RawOffset> {
        let r = rva.get();
        if r < self.size_of_headers {
            return Some(RawOffset(r));
        }
        for &(va, vs, raw_ptr, _rs) in &self.sections {
            if r >= va.get() && r < va.get().saturating_add(vs) {
                return Some(RawOffset(raw_ptr.get() + (r - va.get())));
            }
        }
        None
    }

    /// Map a raw file offset back to an RVA (using a section's raw extent).
    pub fn raw_to_rva(&self, raw: RawOffset) -> Option<Rva> {
        let o = raw.get();
        if o < self.size_of_headers {
            return Some(Rva(o));
        }
        for &(va, _vs, raw_ptr, rs) in &self.sections {
            if o >= raw_ptr.get() && o < raw_ptr.get().saturating_add(rs) {
                return Some(Rva(va.get() + (o - raw_ptr.get())));
            }
        }
        None
    }

    pub fn va_to_raw(&self, va: u64) -> Option<RawOffset> {
        self.va_to_rva(va).and_then(|rva| self.rva_to_raw(rva))
    }

    pub fn raw_to_va(&self, raw: RawOffset) -> Option<u64> {
        self.raw_to_rva(raw).map(|rva| self.rva_to_va(rva))
    }
}
