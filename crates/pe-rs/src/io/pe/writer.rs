//! Real PE writer: [`PeDocument`] → bytes.
//!
//! The writer re-renders the import and export tables from the document's rich
//! form into dedicated `.peimp` / `.peexp` sections (the Scylla-style rebuild),
//! then serializes headers + section data with recomputed raw offsets/sizes.
//! This means `parse(serialize(doc))` preserves the document's *content*
//! (headers, section data, imports, exports) while the file layout is canonical.

use crate::domain::PeDocument;
use crate::domain::coff::CoffHeader;
use crate::domain::data_directory::{DataDirectory, DataDirectoryIndex};
use crate::domain::dos::DosHeader;
use crate::domain::optional::OptionalHeader;
use crate::domain::section::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, Section, SectionHeader,
};
use crate::domain::types::{RawOffset, Rva, align_up};
use crate::error::Result;

use super::export_render::render_export_table;
use super::import_render::render_import_table;
use super::parser;

const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";

/// Serialize a document back into a PE file image.
pub fn serialize(doc: &PeDocument) -> Result<Vec<u8>> {
    let file_alignment = doc.optional.file_alignment().max(1);
    let section_alignment = doc.optional.section_alignment().max(1);

    let mut sections: Vec<Section> = doc.sections.clone();
    let mut dirs = doc.data_directories.clone();
    while dirs.len() < DataDirectoryIndex::COUNT {
        dirs.push(DataDirectory::default());
    }

    let image_end = |sections: &[Section]| {
        sections
            .iter()
            .map(|s| {
                s.header
                    .virtual_address
                    .get()
                    .saturating_add(s.data.len() as u32)
            })
            .max()
            .unwrap_or(0)
    };

    // Import table: re-render only when the document's rich imports are not
    // already represented by an existing, matching import directory. This keeps
    // serialization idempotent (a saved-and-reparsed document stays stable).
    if doc.imports.is_empty() {
        dirs[DataDirectoryIndex::Import.to_usize()] = DataDirectory::default();
        dirs[DataDirectoryIndex::Iat.to_usize()] = DataDirectory::default();
    } else {
        let import_dir = dirs[DataDirectoryIndex::Import.to_usize()];
        let matches = import_dir.rva != Rva::NULL
            && parser::parse_imports_from_doc(doc, import_dir.rva)
                .map(|im| im == doc.imports)
                .unwrap_or(false);
        if !matches {
            let base = align_up(image_end(&sections), section_alignment);
            let rendered = render_import_table(&doc.imports, doc.arch, Rva(base))?;
            sections.push(Section {
                header: section_header_for(*b".peimp\0\0", Rva(base), rendered.blob.len()),
                data: rendered.blob,
            });
            dirs[DataDirectoryIndex::Import.to_usize()] = DataDirectory {
                rva: Rva(rendered.dir_rva),
                size: rendered.size,
            };
            dirs[DataDirectoryIndex::Iat.to_usize()] = DataDirectory {
                rva: Rva(rendered.iat_rva),
                size: rendered.iat_size,
            };
        }
    }

    // Export table: same "reuse when already matching" logic.
    if doc.exports.is_none() {
        dirs[DataDirectoryIndex::Export.to_usize()] = DataDirectory::default();
    } else if let Some(exports) = &doc.exports {
        let export_dir = dirs[DataDirectoryIndex::Export.to_usize()];
        let matches = !exports.symbols.is_empty()
            && export_dir.rva != Rva::NULL
            && parser::parse_exports_from_doc(doc, export_dir)
                .map(|e| e == doc.exports)
                .unwrap_or(false);
        if !matches {
            let base = align_up(image_end(&sections), section_alignment);
            let rendered = render_export_table(exports, Rva(base))?;
            sections.push(Section {
                header: section_header_for(*b".peexp\0\0", Rva(base), rendered.blob.len()),
                data: rendered.blob,
            });
            dirs[DataDirectoryIndex::Export.to_usize()] = DataDirectory {
                rva: Rva(rendered.rva),
                size: rendered.size,
            };
        }
    }

    let optional_struct_len = match &doc.optional {
        OptionalHeader::Bit32(_) => 96,
        OptionalHeader::Bit64(_) => 112,
    };
    let optional_full_len = optional_struct_len + DataDirectoryIndex::COUNT * 8;
    let head_end = 64 + doc.dos.stub.len() + 4 + 20 + optional_full_len + 40 * sections.len();
    let size_of_headers = align_up(head_end as u32, file_alignment);
    let size_of_image = align_up(image_end(&sections), section_alignment);

    // Assign raw file offsets.
    let mut raw_cursor = size_of_headers as usize;
    let mut raw_offsets = Vec::with_capacity(sections.len());
    for s in &sections {
        let size = align_up(s.data.len() as u32, file_alignment) as usize;
        raw_offsets.push((raw_cursor, size));
        raw_cursor += size;
    }

    let mut out = Vec::new();
    out.extend_from_slice(&encode_dos(&doc.dos));
    out.extend_from_slice(&PE_SIGNATURE);
    let optional = encode_optional(&doc.optional, size_of_headers, size_of_image, &dirs);
    let coff = encode_coff(&doc.coff, sections.len() as u16, optional.len() as u16);
    out.extend_from_slice(&coff);
    out.extend_from_slice(&optional);
    for (i, s) in sections.iter().enumerate() {
        let (ptr, size) = raw_offsets[i];
        out.extend_from_slice(&encode_section_header(
            &s.header,
            size as u32,
            RawOffset(ptr as u32),
        ));
    }
    out.resize(size_of_headers as usize, 0);

    for (i, s) in sections.iter().enumerate() {
        let (ptr, size) = raw_offsets[i];
        if out.len() < ptr {
            out.resize(ptr, 0);
        }
        out.extend_from_slice(&s.data);
        out.resize(out.len() + (size - s.data.len()), 0);
    }
    Ok(out)
}

fn section_header_for(name: [u8; 8], rva: Rva, len: usize) -> SectionHeader {
    SectionHeader {
        name,
        virtual_size: len as u32,
        virtual_address: rva,
        size_of_raw_data: 0,
        pointer_to_raw_data: RawOffset::NULL,
        characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    }
}

fn encode_dos(dos: &DosHeader) -> Vec<u8> {
    let mut b = Vec::with_capacity(64 + dos.stub.len());
    b.extend_from_slice(&dos.e_magic.to_le_bytes());
    b.extend_from_slice(&dos.e_cblp.to_le_bytes());
    b.extend_from_slice(&dos.e_cp.to_le_bytes());
    b.extend_from_slice(&dos.e_crlc.to_le_bytes());
    b.extend_from_slice(&dos.e_cparhdr.to_le_bytes());
    b.extend_from_slice(&dos.e_minalloc.to_le_bytes());
    b.extend_from_slice(&dos.e_maxalloc.to_le_bytes());
    b.extend_from_slice(&dos.e_ss.to_le_bytes());
    b.extend_from_slice(&dos.e_sp.to_le_bytes());
    b.extend_from_slice(&dos.e_csum.to_le_bytes());
    b.extend_from_slice(&dos.e_ip.to_le_bytes());
    b.extend_from_slice(&dos.e_cs.to_le_bytes());
    b.extend_from_slice(&dos.e_lfarlc.to_le_bytes());
    b.extend_from_slice(&dos.e_ovno.to_le_bytes());
    for v in dos.e_res {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&dos.e_oemid.to_le_bytes());
    b.extend_from_slice(&dos.e_oeminfo.to_le_bytes());
    for v in dos.e_res2 {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&((64 + dos.stub.len()) as u32).to_le_bytes()); // e_lfanew
    b.extend_from_slice(&dos.stub);
    b
}

fn encode_coff(
    coff: &CoffHeader,
    number_of_sections: u16,
    size_of_optional_header: u16,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(20);
    b.extend_from_slice(&coff.machine.to_u16().to_le_bytes());
    b.extend_from_slice(&number_of_sections.to_le_bytes());
    b.extend_from_slice(&coff.time_date_stamp.to_le_bytes());
    b.extend_from_slice(&coff.pointer_to_symbol_table.to_le_bytes());
    b.extend_from_slice(&coff.number_of_symbols.to_le_bytes());
    b.extend_from_slice(&size_of_optional_header.to_le_bytes());
    b.extend_from_slice(&coff.characteristics.to_le_bytes());
    b
}

fn encode_section_header(sh: &SectionHeader, size_of_raw_data: u32, ptr: RawOffset) -> Vec<u8> {
    let mut b = Vec::with_capacity(40);
    b.extend_from_slice(&sh.name);
    b.extend_from_slice(&sh.virtual_size.to_le_bytes());
    b.extend_from_slice(&sh.virtual_address.get().to_le_bytes());
    b.extend_from_slice(&size_of_raw_data.to_le_bytes());
    b.extend_from_slice(&ptr.get().to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // pointer to relocations
    b.extend_from_slice(&0u32.to_le_bytes()); // pointer to line numbers
    b.extend_from_slice(&0u16.to_le_bytes()); // number of relocations
    b.extend_from_slice(&0u16.to_le_bytes()); // number of line numbers
    b.extend_from_slice(&sh.characteristics.to_le_bytes());
    b
}

fn encode_optional(
    optional: &OptionalHeader,
    size_of_headers: u32,
    size_of_image: u32,
    dirs: &[DataDirectory],
) -> Vec<u8> {
    let mut b = Vec::new();
    match optional {
        OptionalHeader::Bit32(h) => {
            b.extend_from_slice(&h.magic.to_le_bytes());
            b.push(h.major_linker_version);
            b.push(h.minor_linker_version);
            b.extend_from_slice(&h.size_of_code.to_le_bytes());
            b.extend_from_slice(&h.size_of_initialized_data.to_le_bytes());
            b.extend_from_slice(&h.size_of_uninitialized_data.to_le_bytes());
            b.extend_from_slice(&h.address_of_entry_point.get().to_le_bytes());
            b.extend_from_slice(&h.base_of_code.get().to_le_bytes());
            b.extend_from_slice(&h.base_of_data.get().to_le_bytes());
            b.extend_from_slice(&h.image_base.to_le_bytes());
            b.extend_from_slice(&h.section_alignment.to_le_bytes());
            b.extend_from_slice(&h.file_alignment.to_le_bytes());
            b.extend_from_slice(&h.major_operating_system_version.to_le_bytes());
            b.extend_from_slice(&h.minor_operating_system_version.to_le_bytes());
            b.extend_from_slice(&h.major_image_version.to_le_bytes());
            b.extend_from_slice(&h.minor_image_version.to_le_bytes());
            b.extend_from_slice(&h.major_subsystem_version.to_le_bytes());
            b.extend_from_slice(&h.minor_subsystem_version.to_le_bytes());
            b.extend_from_slice(&h.win32_version_value.to_le_bytes());
            b.extend_from_slice(&size_of_image.to_le_bytes());
            b.extend_from_slice(&size_of_headers.to_le_bytes());
            b.extend_from_slice(&h.checksum.to_le_bytes());
            b.extend_from_slice(&h.subsystem.to_le_bytes());
            b.extend_from_slice(&h.dll_characteristics.to_le_bytes());
            b.extend_from_slice(&h.size_of_stack_reserve.to_le_bytes());
            b.extend_from_slice(&h.size_of_stack_commit.to_le_bytes());
            b.extend_from_slice(&h.size_of_heap_reserve.to_le_bytes());
            b.extend_from_slice(&h.size_of_heap_commit.to_le_bytes());
            b.extend_from_slice(&h.loader_flags.to_le_bytes());
            b.extend_from_slice(&(DataDirectoryIndex::COUNT as u32).to_le_bytes());
        }
        OptionalHeader::Bit64(h) => {
            b.extend_from_slice(&h.magic.to_le_bytes());
            b.push(h.major_linker_version);
            b.push(h.minor_linker_version);
            b.extend_from_slice(&h.size_of_code.to_le_bytes());
            b.extend_from_slice(&h.size_of_initialized_data.to_le_bytes());
            b.extend_from_slice(&h.size_of_uninitialized_data.to_le_bytes());
            b.extend_from_slice(&h.address_of_entry_point.get().to_le_bytes());
            b.extend_from_slice(&h.base_of_code.get().to_le_bytes());
            b.extend_from_slice(&h.image_base.to_le_bytes());
            b.extend_from_slice(&h.section_alignment.to_le_bytes());
            b.extend_from_slice(&h.file_alignment.to_le_bytes());
            b.extend_from_slice(&h.major_operating_system_version.to_le_bytes());
            b.extend_from_slice(&h.minor_operating_system_version.to_le_bytes());
            b.extend_from_slice(&h.major_image_version.to_le_bytes());
            b.extend_from_slice(&h.minor_image_version.to_le_bytes());
            b.extend_from_slice(&h.major_subsystem_version.to_le_bytes());
            b.extend_from_slice(&h.minor_subsystem_version.to_le_bytes());
            b.extend_from_slice(&h.win32_version_value.to_le_bytes());
            b.extend_from_slice(&size_of_image.to_le_bytes());
            b.extend_from_slice(&size_of_headers.to_le_bytes());
            b.extend_from_slice(&h.checksum.to_le_bytes());
            b.extend_from_slice(&h.subsystem.to_le_bytes());
            b.extend_from_slice(&h.dll_characteristics.to_le_bytes());
            b.extend_from_slice(&h.size_of_stack_reserve.to_le_bytes());
            b.extend_from_slice(&h.size_of_stack_commit.to_le_bytes());
            b.extend_from_slice(&h.size_of_heap_reserve.to_le_bytes());
            b.extend_from_slice(&h.size_of_heap_commit.to_le_bytes());
            b.extend_from_slice(&h.loader_flags.to_le_bytes());
            b.extend_from_slice(&(DataDirectoryIndex::COUNT as u32).to_le_bytes());
        }
    }
    for i in 0..DataDirectoryIndex::COUNT {
        let dd = dirs.get(i).copied().unwrap_or_default();
        b.extend_from_slice(&dd.rva.get().to_le_bytes());
        b.extend_from_slice(&dd.size.to_le_bytes());
    }
    b
}
