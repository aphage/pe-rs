//! Section table rebuilding and merging (Scylla's "rebuild section table").
//!
//! `rebuild_section_table` makes a document's headers internally consistent:
//! raw sizes/pointers are recomputed from each section's data, virtual
//! addresses re-aligned, and `size_of_headers` / `size_of_image` fixed.
//! `merge_sections` combines a run of sections (contiguous or not) into one,
//! re-mapping every RVA that pointed into the merged range.

use crate::domain::types::align_up;
use crate::domain::{
    DataDirectoryIndex, OptionalHeader, PeDocument, RawOffset, ResourceDirectory,
    ResourceEntryData, Rva, Section, SectionHeader,
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

/// Merge `sections[start..=end]` into a single section.
///
/// The merged sections need not be contiguous: the run's data is concatenated
/// into one section starting at the first section's virtual address, and every
/// RVA that pointed into the merged range is re-mapped — the data directory
/// entries, the optional-header RVAs (entry point / base of code / base of
/// data), the export/resource/relocation/TLS rich forms, and any aligned
/// 4/8-byte value across the whole image that falls inside a merged range
/// (IAT slots, import-thunk pointers, …). The latter is a Scylla-style
/// heuristic, so values that merely *look* like an RVA in the merged range are
/// rewritten too.
pub fn merge_sections(doc: &mut PeDocument, start: usize, end: usize) -> Result<()> {
    if start >= end || end >= doc.sections.len() {
        return Err(PeError::InvalidArgument("merge_sections: bad range".into()));
    }

    // Build the move map: `(old_va, old_len, new_va)` per merged source section.
    let merged_base = doc.sections[start].header.virtual_address.get();
    let mut cursor = merged_base;
    let mut ranges: Vec<(u32, u32, u32)> = Vec::new();
    for i in start..=end {
        let s = &doc.sections[i];
        ranges.push((s.header.virtual_address.get(), s.data.len() as u32, cursor));
        cursor = cursor.saturating_add(s.data.len() as u32);
    }

    // 1. Re-map every RVA the document tracks explicitly.
    for dd in &mut doc.data_directories {
        if let Some(nr) = remap_rva(dd.rva.get(), &ranges) {
            dd.rva = Rva(nr);
        }
    }
    remap_optional_rvas(doc, &ranges);
    remap_exports(doc, &ranges);
    remap_resources(doc, &ranges);
    remap_relocations(doc, &ranges);
    remap_tls(doc, &ranges);

    // 2. Byte-patch the whole image so embedded pointers (IAT slots, import
    //    thunk RVAs, code/data references) follow the move.
    for section in &mut doc.sections {
        let data = &mut section.data;
        for off in (0..data.len().saturating_sub(8)).step_by(8) {
            let v = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            if v <= u32::MAX as u64
                && let Some(nr) = remap_rva(v as u32, &ranges)
            {
                data[off..off + 8].copy_from_slice(&(nr as u64).to_le_bytes());
            }
        }
        for off in (0..data.len().saturating_sub(4)).step_by(4) {
            let v = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
            if let Some(nr) = remap_rva(v, &ranges) {
                data[off..off + 4].copy_from_slice(&nr.to_le_bytes());
            }
        }
    }

    // 3. Build the merged section from the (patched) source data.
    let mut data = Vec::new();
    for i in start..=end {
        data.extend_from_slice(&doc.sections[i].data);
    }
    let first = doc.sections[start].header.clone();
    let merged = Section {
        header: SectionHeader {
            name: *b".merged\0",
            virtual_size: data.len() as u32,
            virtual_address: Rva(merged_base),
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

/// Re-map `rva` if it falls inside one of the moved ranges.
fn remap_rva(rva: u32, ranges: &[(u32, u32, u32)]) -> Option<u32> {
    for &(old_va, old_len, new_va) in ranges {
        if rva >= old_va && rva < old_va.saturating_add(old_len) {
            return Some(new_va + (rva - old_va));
        }
    }
    None
}

fn remap_optional_rvas(doc: &mut PeDocument, ranges: &[(u32, u32, u32)]) {
    let entry = doc.optional.address_of_entry_point().get();
    if let Some(nr) = remap_rva(entry, ranges) {
        doc.optional.set_address_of_entry_point(Rva(nr));
    }
    match &mut doc.optional {
        OptionalHeader::Bit32(h) => {
            if let Some(nr) = remap_rva(h.base_of_code.get(), ranges) {
                h.base_of_code = Rva(nr);
            }
            if let Some(nr) = remap_rva(h.base_of_data.get(), ranges) {
                h.base_of_data = Rva(nr);
            }
        }
        OptionalHeader::Bit64(h) => {
            if let Some(nr) = remap_rva(h.base_of_code.get(), ranges) {
                h.base_of_code = Rva(nr);
            }
        }
    }
}

fn remap_exports(doc: &mut PeDocument, ranges: &[(u32, u32, u32)]) {
    if let Some(exports) = &mut doc.exports {
        for s in &mut exports.symbols {
            if let Some(nr) = remap_rva(s.rva.get(), ranges) {
                s.rva = Rva(nr);
            }
        }
    }
}

fn remap_resources(doc: &mut PeDocument, ranges: &[(u32, u32, u32)]) {
    if let Some(root) = &mut doc.resources {
        remap_resource_dir(root, ranges);
    }
}

fn remap_resource_dir(dir: &mut ResourceDirectory, ranges: &[(u32, u32, u32)]) {
    for e in &mut dir.entries {
        match &mut e.data {
            ResourceEntryData::Directory(d) => remap_resource_dir(d, ranges),
            ResourceEntryData::Leaf(leaf) => {
                if let Some(nr) = remap_rva(leaf.rva.get(), ranges) {
                    leaf.rva = Rva(nr);
                }
            }
        }
    }
}

fn remap_relocations(doc: &mut PeDocument, ranges: &[(u32, u32, u32)]) {
    if let Some(table) = &mut doc.relocations {
        for b in &mut table.blocks {
            if let Some(nr) = remap_rva(b.page_rva.get(), ranges) {
                b.page_rva = Rva(nr);
            }
        }
    }
}

fn remap_tls(doc: &mut PeDocument, ranges: &[(u32, u32, u32)]) {
    let image_base = doc.optional.image_base();
    if let Some(tls) = &mut doc.tls {
        for va in [
            &mut tls.start_address_of_raw_data,
            &mut tls.end_address_of_raw_data,
            &mut tls.address_of_index,
        ] {
            if *va >= image_base {
                let rva = (*va - image_base) as u32;
                if let Some(nr) = remap_rva(rva, ranges) {
                    *va = image_base + nr as u64;
                }
            }
        }
    }
}
