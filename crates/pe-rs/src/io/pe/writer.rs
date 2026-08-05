//! Real PE writer: [`PeDocument`] → bytes.
//!
//! The writer re-renders the import and export tables from the document's rich
//! form into dedicated `.peimp` / `.peexp` sections (the Scylla-style rebuild),
//! then serializes headers + section data with recomputed raw offsets/sizes.
//! On-disk headers are encoded through the official `windows-sys` `IMAGE_*`
//! structs (mirroring the parser). This means `parse(serialize(doc))` preserves
//! the document's *content* (headers, section data, imports, exports) while the
//! file layout is canonical.

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

use super::directory_render;
use super::export_render::render_export_table;
use super::import_render::render_import_table;
use super::parser;
use super::write_struct;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64,
    IMAGE_SECTION_HEADER, IMAGE_SECTION_HEADER_0,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

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

    // Resource / relocation / TLS directories: same "reuse when the existing
    // directory already matches the rich form" logic.
    match &doc.resources {
        None => dirs[DataDirectoryIndex::Resource.to_usize()] = DataDirectory::default(),
        Some(root) => {
            let resource_dir = dirs[DataDirectoryIndex::Resource.to_usize()];
            let matches = resource_dir.rva != Rva::NULL
                && parser::parse_resources_from_doc(doc, resource_dir)
                    .map(|t| &t == root)
                    .unwrap_or(false);
            if !matches {
                let base = align_up(image_end(&sections), section_alignment);
                let blob = directory_render::render_resources(root)?;
                let size = blob.len() as u32;
                sections.push(Section {
                    header: section_header_for(*b".persc\0\0", Rva(base), size as usize),
                    data: blob,
                });
                dirs[DataDirectoryIndex::Resource.to_usize()] = DataDirectory {
                    rva: Rva(base),
                    size,
                };
            }
        }
    }

    match &doc.relocations {
        None => dirs[DataDirectoryIndex::BaseReloc.to_usize()] = DataDirectory::default(),
        Some(table) => {
            let reloc_dir = dirs[DataDirectoryIndex::BaseReloc.to_usize()];
            let matches = reloc_dir.rva != Rva::NULL
                && parser::parse_relocations_from_doc(doc, reloc_dir)
                    .map(|t| &t == table)
                    .unwrap_or(false);
            if !matches {
                let base = align_up(image_end(&sections), section_alignment);
                let blob = directory_render::render_relocations(table);
                let size = blob.len() as u32;
                sections.push(Section {
                    header: section_header_for(*b".perel\0\0", Rva(base), size as usize),
                    data: blob,
                });
                dirs[DataDirectoryIndex::BaseReloc.to_usize()] = DataDirectory {
                    rva: Rva(base),
                    size,
                };
            }
        }
    }

    match &doc.tls {
        None => dirs[DataDirectoryIndex::Tls.to_usize()] = DataDirectory::default(),
        Some(tls) => {
            let tls_dir = dirs[DataDirectoryIndex::Tls.to_usize()];
            let matches = tls_dir.rva != Rva::NULL
                && parser::parse_tls_from_doc(doc, tls_dir)
                    .map(|t| t == *tls)
                    .unwrap_or(false);
            if !matches {
                let base = align_up(image_end(&sections), section_alignment);
                let blob = directory_render::render_tls(tls, doc.arch);
                let size = blob.len() as u32;
                sections.push(Section {
                    header: section_header_for(*b".petls\0\0", Rva(base), size as usize),
                    data: blob,
                });
                dirs[DataDirectoryIndex::Tls.to_usize()] = DataDirectory {
                    rva: Rva(base),
                    size,
                };
            }
        }
    }

    let optional_size = match &doc.optional {
        OptionalHeader::Bit32(_) => std::mem::size_of::<IMAGE_OPTIONAL_HEADER32>(),
        OptionalHeader::Bit64(_) => std::mem::size_of::<IMAGE_OPTIONAL_HEADER64>(),
    };
    let head_end = 64 + doc.dos.stub.len() + 4 + 20 + optional_size + 40 * sections.len();
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
    let h = IMAGE_DOS_HEADER {
        e_magic: dos.e_magic,
        e_cblp: dos.e_cblp,
        e_cp: dos.e_cp,
        e_crlc: dos.e_crlc,
        e_cparhdr: dos.e_cparhdr,
        e_minalloc: dos.e_minalloc,
        e_maxalloc: dos.e_maxalloc,
        e_ss: dos.e_ss,
        e_sp: dos.e_sp,
        e_csum: dos.e_csum,
        e_ip: dos.e_ip,
        e_cs: dos.e_cs,
        e_lfarlc: dos.e_lfarlc,
        e_ovno: dos.e_ovno,
        e_res: dos.e_res,
        e_oemid: dos.e_oemid,
        e_oeminfo: dos.e_oeminfo,
        e_res2: dos.e_res2,
        e_lfanew: (64 + dos.stub.len()) as i32,
    };
    let mut out = Vec::with_capacity(64 + dos.stub.len());
    write_struct(&mut out, &h);
    out.extend_from_slice(&dos.stub);
    out
}

fn encode_coff(
    coff: &CoffHeader,
    number_of_sections: u16,
    size_of_optional_header: u16,
) -> Vec<u8> {
    let h = IMAGE_FILE_HEADER {
        Machine: coff.machine.to_u16(),
        NumberOfSections: number_of_sections,
        TimeDateStamp: coff.time_date_stamp,
        PointerToSymbolTable: coff.pointer_to_symbol_table,
        NumberOfSymbols: coff.number_of_symbols,
        SizeOfOptionalHeader: size_of_optional_header,
        Characteristics: coff.characteristics,
    };
    let mut out = Vec::with_capacity(20);
    write_struct(&mut out, &h);
    out
}

fn encode_section_header(sh: &SectionHeader, size_of_raw_data: u32, ptr: RawOffset) -> Vec<u8> {
    let h = IMAGE_SECTION_HEADER {
        Name: sh.name,
        Misc: IMAGE_SECTION_HEADER_0 {
            VirtualSize: sh.virtual_size,
        },
        VirtualAddress: sh.virtual_address.get(),
        SizeOfRawData: size_of_raw_data,
        PointerToRawData: ptr.get(),
        PointerToRelocations: 0,
        PointerToLinenumbers: 0,
        NumberOfRelocations: 0,
        NumberOfLinenumbers: 0,
        Characteristics: sh.characteristics,
    };
    let mut out = Vec::with_capacity(40);
    write_struct(&mut out, &h);
    out
}

fn encode_optional(
    optional: &OptionalHeader,
    size_of_headers: u32,
    size_of_image: u32,
    dirs: &[DataDirectory],
) -> Vec<u8> {
    let mut out = Vec::new();
    match optional {
        OptionalHeader::Bit32(h) => {
            let oh = IMAGE_OPTIONAL_HEADER32 {
                Magic: h.magic,
                MajorLinkerVersion: h.major_linker_version,
                MinorLinkerVersion: h.minor_linker_version,
                SizeOfCode: h.size_of_code,
                SizeOfInitializedData: h.size_of_initialized_data,
                SizeOfUninitializedData: h.size_of_uninitialized_data,
                AddressOfEntryPoint: h.address_of_entry_point.get(),
                BaseOfCode: h.base_of_code.get(),
                BaseOfData: h.base_of_data.get(),
                ImageBase: h.image_base,
                SectionAlignment: h.section_alignment,
                FileAlignment: h.file_alignment,
                MajorOperatingSystemVersion: h.major_operating_system_version,
                MinorOperatingSystemVersion: h.minor_operating_system_version,
                MajorImageVersion: h.major_image_version,
                MinorImageVersion: h.minor_image_version,
                MajorSubsystemVersion: h.major_subsystem_version,
                MinorSubsystemVersion: h.minor_subsystem_version,
                Win32VersionValue: h.win32_version_value,
                SizeOfImage: size_of_image,
                SizeOfHeaders: size_of_headers,
                CheckSum: h.checksum,
                Subsystem: h.subsystem,
                DllCharacteristics: h.dll_characteristics,
                SizeOfStackReserve: h.size_of_stack_reserve,
                SizeOfStackCommit: h.size_of_stack_commit,
                SizeOfHeapReserve: h.size_of_heap_reserve,
                SizeOfHeapCommit: h.size_of_heap_commit,
                LoaderFlags: h.loader_flags,
                NumberOfRvaAndSizes: DataDirectoryIndex::COUNT as u32,
                DataDirectory: fill_dirs(dirs),
            };
            write_struct(&mut out, &oh);
        }
        OptionalHeader::Bit64(h) => {
            let oh = IMAGE_OPTIONAL_HEADER64 {
                Magic: h.magic,
                MajorLinkerVersion: h.major_linker_version,
                MinorLinkerVersion: h.minor_linker_version,
                SizeOfCode: h.size_of_code,
                SizeOfInitializedData: h.size_of_initialized_data,
                SizeOfUninitializedData: h.size_of_uninitialized_data,
                AddressOfEntryPoint: h.address_of_entry_point.get(),
                BaseOfCode: h.base_of_code.get(),
                ImageBase: h.image_base,
                SectionAlignment: h.section_alignment,
                FileAlignment: h.file_alignment,
                MajorOperatingSystemVersion: h.major_operating_system_version,
                MinorOperatingSystemVersion: h.minor_operating_system_version,
                MajorImageVersion: h.major_image_version,
                MinorImageVersion: h.minor_image_version,
                MajorSubsystemVersion: h.major_subsystem_version,
                MinorSubsystemVersion: h.minor_subsystem_version,
                Win32VersionValue: h.win32_version_value,
                SizeOfImage: size_of_image,
                SizeOfHeaders: size_of_headers,
                CheckSum: h.checksum,
                Subsystem: h.subsystem,
                DllCharacteristics: h.dll_characteristics,
                SizeOfStackReserve: h.size_of_stack_reserve,
                SizeOfStackCommit: h.size_of_stack_commit,
                SizeOfHeapReserve: h.size_of_heap_reserve,
                SizeOfHeapCommit: h.size_of_heap_commit,
                LoaderFlags: h.loader_flags,
                NumberOfRvaAndSizes: DataDirectoryIndex::COUNT as u32,
                DataDirectory: fill_dirs(dirs),
            };
            write_struct(&mut out, &oh);
        }
    }
    out
}

fn fill_dirs(dirs: &[DataDirectory]) -> [IMAGE_DATA_DIRECTORY; 16] {
    let mut arr = [IMAGE_DATA_DIRECTORY {
        VirtualAddress: 0,
        Size: 0,
    }; 16];
    for (i, slot) in arr.iter_mut().enumerate() {
        if let Some(dd) = dirs.get(i) {
            *slot = IMAGE_DATA_DIRECTORY {
                VirtualAddress: dd.rva.get(),
                Size: dd.size,
            };
        }
    }
    arr
}
