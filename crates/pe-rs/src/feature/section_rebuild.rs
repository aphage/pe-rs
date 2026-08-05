//! Section table rebuilding and merging (Scylla's "rebuild section table").
//!
//! `rebuild_section_table` makes a document's headers internally consistent:
//! raw sizes/pointers are recomputed from each section's data, virtual
//! addresses re-aligned, and `size_of_headers` / `size_of_image` fixed.
//! `merge_sections` combines a contiguous run of sections into one.

use crate::domain::types::align_up;
use crate::domain::{
    DataDirectoryIndex, OptionalHeader, PeDocument, RawOffset, Rva, Section, SectionHeader,
};
use crate::error::{PeError, Result};

/// Re-align and re-lay-out the section table so the file is internally
/// consistent.
pub fn rebuild_section_table(doc: &mut PeDocument) -> Result<()> {
    let file_alignment = doc.optional.file_alignment().max(1);
    let section_alignment = doc.optional.section_alignment().max(1);

    let size_of_headers = {
        let optional_struct_len = match &doc.optional {
            OptionalHeader::Bit32(_) => 96,
            OptionalHeader::Bit64(_) => 112,
        };
        let optional_len = optional_struct_len + DataDirectoryIndex::COUNT * 8;
        let head_end = 64 + doc.dos.stub.len() + 4 + 20 + optional_len + 40 * doc.sections.len();
        align_up(head_end as u32, file_alignment)
    };
    doc.optional.set_size_of_headers(size_of_headers);

    let mut raw_ptr = size_of_headers;
    let mut image_end = 0u32;
    for s in &mut doc.sections {
        let va = align_up(s.header.virtual_address.get(), section_alignment);
        let data_len = s.data.len() as u32;
        let raw_len = align_up(data_len, file_alignment);
        s.header.virtual_address = Rva(va);
        s.header.virtual_size = data_len;
        s.header.size_of_raw_data = raw_len;
        s.header.pointer_to_raw_data = RawOffset(raw_ptr);
        raw_ptr = raw_ptr
            .checked_add(raw_len)
            .ok_or_else(|| PeError::InvalidArgument("section table size overflow".into()))?;
        image_end = image_end.max(va.saturating_add(data_len));
    }
    doc.optional
        .set_size_of_image(align_up(image_end, section_alignment));
    Ok(())
}

/// Merge `sections[start..=end]` into a single section. The merged sections
/// must be contiguous in the address space (as produced by `alloc` /
/// `add_section`); otherwise internal RVAs could not be preserved and the
/// operation is rejected as unsupported.
pub fn merge_sections(doc: &mut PeDocument, start: usize, end: usize) -> Result<()> {
    if start >= end || end >= doc.sections.len() {
        return Err(PeError::InvalidArgument("merge_sections: bad range".into()));
    }
    for i in start..end {
        let cur = doc.sections[i].header.virtual_address.get();
        let next = doc.sections[i + 1].header.virtual_address.get();
        if next != cur.saturating_add(doc.sections[i].data.len() as u32) {
            return Err(PeError::Unsupported(
                "merge_sections: sections are not contiguous".into(),
            ));
        }
    }

    let first = doc.sections[start].header.clone();
    let mut data = Vec::new();
    for i in start..=end {
        data.extend_from_slice(&doc.sections[i].data);
    }
    let merged = Section {
        header: SectionHeader {
            name: *b".merged\0",
            virtual_size: data.len() as u32,
            virtual_address: first.virtual_address,
            size_of_raw_data: 0,
            pointer_to_raw_data: RawOffset::NULL,
            characteristics: first.characteristics,
        },
        data,
    };
    doc.sections.drain(start..=end);
    doc.sections.insert(start, merged);
    rebuild_section_table(doc)
}
