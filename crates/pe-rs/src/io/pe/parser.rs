//! Real PE parser: bytes → [`PeDocument`].
//!
//! On-disk structures are read through the official `windows-sys`
//! `IMAGE_*` definitions (`std::ptr::read_unaligned`), then converted into the
//! crate's rich domain types.

use crate::domain::PeDocument;
use crate::domain::coff::CoffHeader;
use crate::domain::data_directory::{DataDirectory, DataDirectoryIndex};
use crate::domain::dos::{DOS_MAGIC, DosHeader};
use crate::domain::export::{ExportSymbol, ExportTable};
use crate::domain::import::{ImportDescriptor, ImportFunction};
use crate::domain::optional::{
    OptionalHeader, OptionalHeader32, OptionalHeader64, PE32_MAGIC, PE32_PLUS_MAGIC,
};
use crate::domain::relocation::{RelocationBlock, RelocationEntry, RelocationTable};
use crate::domain::resource::{
    ResourceDataEntry, ResourceDirectory, ResourceEntry, ResourceEntryData, ResourceName,
};
use crate::domain::section::{Section, SectionHeader};
use crate::domain::tls::TlsDirectory;
use crate::domain::types::{Machine, RawOffset, Rva, ptr_size};
use crate::error::{PeError, Result};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64,
    IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_RESOURCE_DATA_ENTRY, IMAGE_RESOURCE_DIRECTORY, IMAGE_RESOURCE_DIRECTORY_ENTRY,
    IMAGE_TLS_DIRECTORY32, IMAGE_TLS_DIRECTORY64,
};

const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";
/// Upper bound for zero-padding a section to its virtual size; avoids unbounded
/// allocation on corrupt headers.
const MAX_SECTION_SIZE: usize = 0x1000_0000;
/// Guard against cyclic/runaway resource trees.
const MAX_RESOURCE_DEPTH: usize = 8;

fn take(bytes: &[u8], off: usize, n: usize) -> Result<&[u8]> {
    bytes.get(off..off + n).ok_or_else(|| {
        PeError::Malformed(format!(
            "truncated at file offset {off:#x} (need {n} bytes)"
        ))
    })
}

fn u16_at(bytes: &[u8], off: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(take(bytes, off, 2)?.try_into().unwrap()))
}

/// Read a `#[repr(C)]` structure from a byte slice at `off` (unaligned).
fn read_struct<T>(bytes: &[u8], off: usize) -> Result<T> {
    let size = std::mem::size_of::<T>();
    let end = off
        .checked_add(size)
        .ok_or_else(|| PeError::Malformed("structure size overflow".into()))?;
    let src = bytes.get(off..end).ok_or_else(|| {
        PeError::Malformed(format!(
            "truncated at file offset {off:#x} (need {size} bytes)"
        ))
    })?;
    // SAFETY: `T` is a plain `#[repr(C)]` structure of integers/arrays (never
    // pointers or references), and `src` points to `size` fully-initialized
    // bytes. This mirrors `bytemuck::pod_read_unaligned`.
    Ok(unsafe { src.as_ptr().cast::<T>().read_unaligned() })
}

/// Read a `#[repr(C)]` structure from the document's image at `rva`.
fn read_doc_struct<T>(doc: &PeDocument, rva: Rva) -> Result<T> {
    let size = std::mem::size_of::<T>();
    let src = doc.read(rva, size)?;
    // SAFETY: same as `read_struct` — `T` is a plain structure and `src` is
    // `size` initialized bytes.
    Ok(unsafe { src.as_ptr().cast::<T>().read_unaligned() })
}

/// Parse a PE file from raw bytes.
pub fn parse(bytes: &[u8]) -> Result<PeDocument> {
    let dos = parse_dos(bytes)?;
    if dos.e_magic != DOS_MAGIC {
        return Err(PeError::Malformed("bad DOS magic".into()));
    }
    let pe_off = dos.e_lfanew as usize;
    if take(bytes, pe_off, 4)? != PE_SIGNATURE {
        return Err(PeError::Malformed(format!(
            "missing PE signature at {pe_off:#x}"
        )));
    }

    let coff = parse_coff(bytes, pe_off + 4)?;
    let opt_off = pe_off + 4 + 20;
    let (optional, dir_array) =
        parse_optional(bytes, opt_off, coff.size_of_optional_header as usize)?;

    let section_off = opt_off + coff.size_of_optional_header as usize;
    let section_headers =
        parse_section_headers(bytes, section_off, coff.number_of_sections as usize)?;
    let mut sections = Vec::with_capacity(section_headers.len());
    for sh in &section_headers {
        sections.push(read_section(bytes, sh.clone())?);
    }

    let n = (optional.number_of_rva_and_sizes() as usize).min(DataDirectoryIndex::COUNT);
    let mut dirs = vec![DataDirectory::default(); DataDirectoryIndex::COUNT];
    for (i, slot) in dirs.iter_mut().take(n).enumerate() {
        *slot = DataDirectory {
            rva: Rva(dir_array[i].VirtualAddress),
            size: dir_array[i].Size,
        };
    }

    let mut doc = PeDocument {
        arch: optional.arch(),
        dos,
        coff,
        optional,
        sections,
        data_directories: dirs,
        imports: Vec::new(),
        exports: None,
        resources: None,
        relocations: None,
        tls: None,
    };

    // Rich directory parsing is lenient: a broken directory yields an empty
    // table instead of failing the whole file (viewer semantics).
    let import_dir = doc.data_directory(DataDirectoryIndex::Import).ok().copied();
    if let Some(dd) = import_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.imports = parse_imports_from_doc(&doc, dd.rva).unwrap_or_default();
    }
    let export_dir = doc.data_directory(DataDirectoryIndex::Export).ok().copied();
    if let Some(dd) = export_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.exports = parse_exports_from_doc(&doc, dd).ok().flatten();
    }
    let resource_dir = doc
        .data_directory(DataDirectoryIndex::Resource)
        .ok()
        .copied();
    if let Some(dd) = resource_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.resources = parse_resources_from_doc(&doc, dd).ok();
    }
    let reloc_dir = doc
        .data_directory(DataDirectoryIndex::BaseReloc)
        .ok()
        .copied();
    if let Some(dd) = reloc_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.relocations = parse_relocations_from_doc(&doc, dd).ok();
    }
    let tls_dir = doc.data_directory(DataDirectoryIndex::Tls).ok().copied();
    if let Some(dd) = tls_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.tls = parse_tls_from_doc(&doc, dd).ok();
    }

    Ok(doc)
}

fn parse_dos(bytes: &[u8]) -> Result<DosHeader> {
    let h: IMAGE_DOS_HEADER = read_struct(bytes, 0)?;
    let e_lfanew = h.e_lfanew as usize;
    let stub = bytes.get(64..e_lfanew).unwrap_or(&[]).to_vec();
    Ok(DosHeader {
        e_magic: h.e_magic,
        e_cblp: h.e_cblp,
        e_cp: h.e_cp,
        e_crlc: h.e_crlc,
        e_cparhdr: h.e_cparhdr,
        e_minalloc: h.e_minalloc,
        e_maxalloc: h.e_maxalloc,
        e_ss: h.e_ss,
        e_sp: h.e_sp,
        e_csum: h.e_csum,
        e_ip: h.e_ip,
        e_cs: h.e_cs,
        e_lfarlc: h.e_lfarlc,
        e_ovno: h.e_ovno,
        e_res: h.e_res,
        e_oemid: h.e_oemid,
        e_oeminfo: h.e_oeminfo,
        e_res2: h.e_res2,
        e_lfanew: h.e_lfanew as u32,
        stub,
    })
}

fn parse_coff(bytes: &[u8], off: usize) -> Result<CoffHeader> {
    let h: IMAGE_FILE_HEADER = read_struct(bytes, off)?;
    Ok(CoffHeader {
        machine: Machine::from_u16(h.Machine),
        number_of_sections: h.NumberOfSections,
        time_date_stamp: h.TimeDateStamp,
        pointer_to_symbol_table: h.PointerToSymbolTable,
        number_of_symbols: h.NumberOfSymbols,
        size_of_optional_header: h.SizeOfOptionalHeader,
        characteristics: h.Characteristics,
    })
}

fn parse_optional(
    bytes: &[u8],
    off: usize,
    size: usize,
) -> Result<(OptionalHeader, [IMAGE_DATA_DIRECTORY; 16])> {
    if size < 96 {
        return Err(PeError::Malformed("optional header too small".into()));
    }
    let magic = u16_at(bytes, off)?;
    match magic {
        PE32_MAGIC => {
            let h: IMAGE_OPTIONAL_HEADER32 = read_struct(bytes, off)?;
            Ok((
                OptionalHeader::Bit32(OptionalHeader32 {
                    magic: h.Magic,
                    major_linker_version: h.MajorLinkerVersion,
                    minor_linker_version: h.MinorLinkerVersion,
                    size_of_code: h.SizeOfCode,
                    size_of_initialized_data: h.SizeOfInitializedData,
                    size_of_uninitialized_data: h.SizeOfUninitializedData,
                    address_of_entry_point: Rva(h.AddressOfEntryPoint),
                    base_of_code: Rva(h.BaseOfCode),
                    base_of_data: Rva(h.BaseOfData),
                    image_base: h.ImageBase,
                    section_alignment: h.SectionAlignment,
                    file_alignment: h.FileAlignment,
                    major_operating_system_version: h.MajorOperatingSystemVersion,
                    minor_operating_system_version: h.MinorOperatingSystemVersion,
                    major_image_version: h.MajorImageVersion,
                    minor_image_version: h.MinorImageVersion,
                    major_subsystem_version: h.MajorSubsystemVersion,
                    minor_subsystem_version: h.MinorSubsystemVersion,
                    win32_version_value: h.Win32VersionValue,
                    size_of_image: h.SizeOfImage,
                    size_of_headers: h.SizeOfHeaders,
                    checksum: h.CheckSum,
                    subsystem: h.Subsystem,
                    dll_characteristics: h.DllCharacteristics,
                    size_of_stack_reserve: h.SizeOfStackReserve,
                    size_of_stack_commit: h.SizeOfStackCommit,
                    size_of_heap_reserve: h.SizeOfHeapReserve,
                    size_of_heap_commit: h.SizeOfHeapCommit,
                    loader_flags: h.LoaderFlags,
                    number_of_rva_and_sizes: h.NumberOfRvaAndSizes,
                }),
                h.DataDirectory,
            ))
        }
        PE32_PLUS_MAGIC => {
            let h: IMAGE_OPTIONAL_HEADER64 = read_struct(bytes, off)?;
            Ok((
                OptionalHeader::Bit64(OptionalHeader64 {
                    magic: h.Magic,
                    major_linker_version: h.MajorLinkerVersion,
                    minor_linker_version: h.MinorLinkerVersion,
                    size_of_code: h.SizeOfCode,
                    size_of_initialized_data: h.SizeOfInitializedData,
                    size_of_uninitialized_data: h.SizeOfUninitializedData,
                    address_of_entry_point: Rva(h.AddressOfEntryPoint),
                    base_of_code: Rva(h.BaseOfCode),
                    image_base: h.ImageBase,
                    section_alignment: h.SectionAlignment,
                    file_alignment: h.FileAlignment,
                    major_operating_system_version: h.MajorOperatingSystemVersion,
                    minor_operating_system_version: h.MinorOperatingSystemVersion,
                    major_image_version: h.MajorImageVersion,
                    minor_image_version: h.MinorImageVersion,
                    major_subsystem_version: h.MajorSubsystemVersion,
                    minor_subsystem_version: h.MinorSubsystemVersion,
                    win32_version_value: h.Win32VersionValue,
                    size_of_image: h.SizeOfImage,
                    size_of_headers: h.SizeOfHeaders,
                    checksum: h.CheckSum,
                    subsystem: h.Subsystem,
                    dll_characteristics: h.DllCharacteristics,
                    size_of_stack_reserve: h.SizeOfStackReserve,
                    size_of_stack_commit: h.SizeOfStackCommit,
                    size_of_heap_reserve: h.SizeOfHeapReserve,
                    size_of_heap_commit: h.SizeOfHeapCommit,
                    loader_flags: h.LoaderFlags,
                    number_of_rva_and_sizes: h.NumberOfRvaAndSizes,
                }),
                h.DataDirectory,
            ))
        }
        other => Err(PeError::Malformed(format!(
            "unknown optional header magic {other:#x}"
        ))),
    }
}

fn parse_section_headers(bytes: &[u8], off: usize, n: usize) -> Result<Vec<SectionHeader>> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let h: IMAGE_SECTION_HEADER = read_struct(bytes, off + i * 40)?;
        out.push(SectionHeader {
            name: h.Name,
            virtual_size: unsafe { h.Misc.VirtualSize },
            virtual_address: Rva(h.VirtualAddress),
            size_of_raw_data: h.SizeOfRawData,
            pointer_to_raw_data: RawOffset(h.PointerToRawData),
            characteristics: h.Characteristics,
        });
    }
    Ok(out)
}

fn read_section(bytes: &[u8], sh: SectionHeader) -> Result<Section> {
    let ptr = sh.pointer_to_raw_data.get() as usize;
    let raw = sh.size_of_raw_data as usize;
    let avail = bytes.len().saturating_sub(ptr);
    let n = raw.min(avail);
    let mut data = if n > 0 {
        bytes[ptr..ptr + n].to_vec()
    } else {
        Vec::new()
    };
    let vs = sh.virtual_size as usize;
    if vs != 0 {
        match data.len().cmp(&vs) {
            std::cmp::Ordering::Greater => data.truncate(vs),
            std::cmp::Ordering::Less if vs <= MAX_SECTION_SIZE => data.resize(vs, 0),
            _ => {}
        }
    }
    Ok(Section { header: sh, data })
}

/// Parse the import table starting at `dir_rva` from an in-memory document.
/// `pub(crate)` so the writer can check whether an existing directory still
/// matches the document's rich imports (and skip re-rendering when it does).
pub(crate) fn parse_imports_from_doc(
    doc: &PeDocument,
    dir_rva: Rva,
) -> Result<Vec<ImportDescriptor>> {
    let psize = ptr_size(doc.arch);
    let mut out = Vec::new();
    let mut i: usize = 0;
    loop {
        let desc_rva = match (dir_rva.get() as u64).checked_add(i as u64 * 20) {
            Some(v) if v <= u32::MAX as u64 => Rva(v as u32),
            _ => break,
        };
        let d: IMAGE_IMPORT_DESCRIPTOR = match read_doc_struct(doc, desc_rva) {
            Ok(d) => d,
            Err(_) => break, // past the table / unmapped
        };
        if unsafe { d.Anonymous.OriginalFirstThunk } == 0 && d.Name == 0 && d.FirstThunk == 0 {
            break;
        }
        let thunk_rva = if unsafe { d.Anonymous.OriginalFirstThunk } != 0 {
            unsafe { d.Anonymous.OriginalFirstThunk }
        } else {
            d.FirstThunk
        };
        if thunk_rva == 0 {
            break;
        }
        let name = read_cstring(doc, Rva(d.Name))?;
        let functions = parse_thunks(doc, Rva(thunk_rva), psize)?;
        out.push(ImportDescriptor { name, functions });
        i += 1;
    }
    Ok(out)
}

fn parse_thunks(doc: &PeDocument, thunk_rva: Rva, psize: usize) -> Result<Vec<ImportFunction>> {
    let mut out = Vec::new();
    let mut i: usize = 0;
    let high_bit = 1u64 << (psize * 8 - 1);
    loop {
        let rva = match (thunk_rva.get() as u64).checked_add(i as u64 * psize as u64) {
            Some(v) if v <= u32::MAX as u64 => Rva(v as u32),
            _ => break,
        };
        let (val, ordinal_flag) = if psize == 8 {
            match doc.read(rva, 8) {
                Ok(b) => {
                    let v = u64::from_le_bytes(b.try_into().unwrap());
                    (v, v & high_bit != 0)
                }
                Err(_) => break,
            }
        } else {
            match doc.read(rva, 4) {
                Ok(b) => {
                    let v = u32::from_le_bytes(b.try_into().unwrap()) as u64;
                    (v, v & high_bit != 0)
                }
                Err(_) => break,
            }
        };
        if val == 0 {
            break;
        }
        if ordinal_flag {
            out.push(ImportFunction::Ordinal {
                ordinal: (val & 0xffff) as u16,
            });
        } else {
            let name_rva = val as u32;
            let hint = u16::from_le_bytes(doc.read(Rva(name_rva), 2)?.try_into().unwrap());
            let name = read_cstring(
                doc,
                Rva(name_rva)
                    .checked_add(2)
                    .ok_or_else(|| PeError::Malformed("hint/name RVA overflow".into()))?,
            )?;
            out.push(ImportFunction::Name { hint, name });
        }
        i += 1;
    }
    Ok(out)
}

/// Parse the export table described by directory entry `dd`.
pub(crate) fn parse_exports_from_doc(
    doc: &PeDocument,
    dd: DataDirectory,
) -> Result<Option<ExportTable>> {
    let d: IMAGE_EXPORT_DIRECTORY = read_doc_struct(doc, dd.rva)?;
    let base = d.Base;
    let number_of_functions = d.NumberOfFunctions;
    let number_of_names = d.NumberOfNames;
    let addr_of_functions = d.AddressOfFunctions;
    let addr_of_names = d.AddressOfNames;
    let addr_of_name_ordinals = d.AddressOfNameOrdinals;
    let module_name_rva = d.Name;

    let module_name = read_cstring(doc, Rva(module_name_rva)).ok();
    let dd_end = dd.rva.get().saturating_add(dd.size);

    let mut symbols = Vec::new();
    for i in 0..number_of_names {
        let name_rva = u32::from_le_bytes(
            doc.read(
                Rva(addr_of_names)
                    .checked_add(i * 4)
                    .ok_or_else(|| PeError::Malformed("name pointer overflow".into()))?,
                4,
            )?
            .try_into()
            .unwrap(),
        );
        let ord_idx = u16::from_le_bytes(
            doc.read(
                Rva(addr_of_name_ordinals)
                    .checked_add(i * 2)
                    .ok_or_else(|| PeError::Malformed("name ordinal overflow".into()))?,
                2,
            )?
            .try_into()
            .unwrap(),
        );
        let func_rva = u32::from_le_bytes(
            doc.read(
                Rva(addr_of_functions)
                    .checked_add(ord_idx as u32 * 4)
                    .ok_or_else(|| PeError::Malformed("function address overflow".into()))?,
                4,
            )?
            .try_into()
            .unwrap(),
        );
        let name = read_cstring(doc, Rva(name_rva))?;
        // A forwarder is an RVA that points back into the export directory.
        let forwarder = if func_rva >= dd.rva.get() && func_rva < dd_end {
            Some(read_cstring(doc, Rva(func_rva))?)
        } else {
            None
        };
        let ordinal = base.checked_add(ord_idx as u32).unwrap_or(0);
        symbols.push(ExportSymbol {
            name: Some(name),
            ordinal: ordinal as u16,
            rva: Rva(func_rva),
            forwarder,
        });
    }

    Ok(Some(ExportTable {
        module_name,
        base,
        number_of_functions,
        symbols,
    }))
}

fn read_cstring(doc: &PeDocument, rva: Rva) -> Result<String> {
    let mut out = Vec::new();
    for i in 0..4096u32 {
        let byte = doc.read(
            rva.checked_add(i)
                .ok_or_else(|| PeError::Malformed("string RVA overflow".into()))?,
            1,
        )?;
        if byte[0] == 0 {
            break;
        }
        out.push(byte[0]);
    }
    if out.len() >= 4096 {
        return Err(PeError::Malformed("unterminated string".into()));
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Parse the resource directory tree rooted at `dd`.
pub(crate) fn parse_resources_from_doc(
    doc: &PeDocument,
    dd: DataDirectory,
) -> Result<ResourceDirectory> {
    parse_resource_directory(doc, dd.rva, dd.rva, 0)
}

fn parse_resource_directory(
    doc: &PeDocument,
    base: Rva,
    dir_rva: Rva,
    depth: usize,
) -> Result<ResourceDirectory> {
    if depth > MAX_RESOURCE_DEPTH {
        return Err(PeError::Malformed("resource directory too deep".into()));
    }
    let h: IMAGE_RESOURCE_DIRECTORY = read_doc_struct(doc, dir_rva)?;
    let n = h.NumberOfNamedEntries as usize + h.NumberOfIdEntries as usize;

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let entry_rva = dir_rva
            .checked_add(16 + i as u32 * 8)
            .ok_or_else(|| PeError::Malformed("resource entry overflow".into()))?;
        let e: IMAGE_RESOURCE_DIRECTORY_ENTRY = read_doc_struct(doc, entry_rva)?;

        let name = if unsafe { e.Anonymous1.Name } & 0x8000_0000 != 0 {
            ResourceName::Named(read_resource_name(
                doc,
                base,
                unsafe { e.Anonymous1.Name } & 0x7fff_ffff,
            )?)
        } else {
            ResourceName::Id(unsafe { e.Anonymous1.Name })
        };

        let data = if unsafe { e.Anonymous2.OffsetToData } & 0x8000_0000 != 0 {
            let sub = base
                .checked_add(unsafe { e.Anonymous2.OffsetToData } & 0x7fff_ffff)
                .ok_or_else(|| PeError::Malformed("resource subdir overflow".into()))?;
            ResourceEntryData::Directory(parse_resource_directory(doc, base, sub, depth + 1)?)
        } else {
            let data_rva = base
                .checked_add(unsafe { e.Anonymous2.OffsetToData })
                .ok_or_else(|| PeError::Malformed("resource data overflow".into()))?;
            let de: IMAGE_RESOURCE_DATA_ENTRY = read_doc_struct(doc, data_rva)?;
            ResourceEntryData::Leaf(ResourceDataEntry {
                rva: Rva(de.OffsetToData),
                size: de.Size,
                code_page: de.CodePage,
            })
        };
        entries.push(ResourceEntry { name, data });
    }
    Ok(ResourceDirectory { entries })
}

/// Read a `IMAGE_RESOURCE_DIR_STRING_U` (UTF-16LE length-prefixed) name.
fn read_resource_name(doc: &PeDocument, base: Rva, offset: u32) -> Result<String> {
    let rva = base
        .checked_add(offset)
        .ok_or_else(|| PeError::Malformed("resource name overflow".into()))?;
    let len = u16::from_le_bytes(doc.read(rva, 2)?.try_into().unwrap());
    if len > 0x1000 {
        return Err(PeError::Malformed("resource name too long".into()));
    }
    let bytes = doc.read(
        rva.checked_add(2)
            .ok_or_else(|| PeError::Malformed("resource name overflow".into()))?,
        len as usize * 2,
    )?;
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

/// Parse the base relocation table described by `dd`.
pub(crate) fn parse_relocations_from_doc(
    doc: &PeDocument,
    dd: DataDirectory,
) -> Result<RelocationTable> {
    let extent = if dd.size != 0 {
        dd.size as usize
    } else {
        0x1000
    };
    let mut blocks = Vec::new();
    let mut off = 0usize;
    loop {
        if off + 8 > extent {
            break;
        }
        let block_rva = dd
            .rva
            .checked_add(off as u32)
            .ok_or_else(|| PeError::Malformed("reloc block overflow".into()))?;
        let h: IMAGE_BASE_RELOCATION = read_doc_struct(doc, block_rva)?;
        let page = h.VirtualAddress;
        let size = h.SizeOfBlock;
        if page == 0 && size == 0 {
            break; // terminator block
        }
        if size < 8 {
            break; // malformed block
        }
        let entry_bytes = doc.read(
            block_rva
                .checked_add(8)
                .ok_or_else(|| PeError::Malformed("reloc block overflow".into()))?,
            size as usize - 8,
        )?;
        let count = (size as usize - 8) / 2;
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let v = u16::from_le_bytes(entry_bytes[i * 2..i * 2 + 2].try_into().unwrap());
            entries.push(RelocationEntry {
                reloc_type: (v >> 12) as u8,
                offset: v & 0x0fff,
            });
        }
        blocks.push(RelocationBlock {
            page_rva: Rva(page),
            entries,
        });
        off += size as usize;
    }
    Ok(RelocationTable { blocks })
}

/// Parse the TLS directory described by `dd`.
pub(crate) fn parse_tls_from_doc(doc: &PeDocument, dd: DataDirectory) -> Result<TlsDirectory> {
    if ptr_size(doc.arch) == 8 {
        let h: IMAGE_TLS_DIRECTORY64 = read_doc_struct(doc, dd.rva)?;
        Ok(TlsDirectory {
            start_address_of_raw_data: h.StartAddressOfRawData,
            end_address_of_raw_data: h.EndAddressOfRawData,
            address_of_index: h.AddressOfIndex,
            address_of_callbacks: h.AddressOfCallBacks,
            size_of_zero_fill: h.SizeOfZeroFill,
            characteristics: unsafe { h.Anonymous.Characteristics },
        })
    } else {
        let h: IMAGE_TLS_DIRECTORY32 = read_doc_struct(doc, dd.rva)?;
        Ok(TlsDirectory {
            start_address_of_raw_data: h.StartAddressOfRawData as u64,
            end_address_of_raw_data: h.EndAddressOfRawData as u64,
            address_of_index: h.AddressOfIndex as u64,
            address_of_callbacks: h.AddressOfCallBacks as u64,
            size_of_zero_fill: h.SizeOfZeroFill,
            characteristics: unsafe { h.Anonymous.Characteristics },
        })
    }
}
