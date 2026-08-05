//! Real PE parser: bytes → [`PeDocument`].

use crate::domain::coff::CoffHeader;
use crate::domain::data_directory::{DataDirectory, DataDirectoryIndex};
use crate::domain::dos::{DosHeader, DOS_MAGIC};
use crate::domain::export::{ExportSymbol, ExportTable};
use crate::domain::import::{ImportDescriptor, ImportFunction};
use crate::domain::optional::{
    OptionalHeader, OptionalHeader32, OptionalHeader64, PE32_MAGIC, PE32_PLUS_MAGIC,
};
use crate::domain::section::{Section, SectionHeader};
use crate::domain::types::{ptr_size, Machine, RawOffset, Rva};
use crate::domain::PeDocument;
use crate::error::{PeError, Result};

const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";
/// Upper bound for zero-padding a section to its virtual size; avoids unbounded
/// allocation on corrupt headers.
const MAX_SECTION_SIZE: usize = 0x1000_0000;

fn take(bytes: &[u8], off: usize, n: usize) -> Result<&[u8]> {
    bytes.get(off..off + n).ok_or_else(|| {
        PeError::Malformed(format!("truncated at file offset {off:#x} (need {n} bytes)"))
    })
}

fn u16_at(bytes: &[u8], off: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(take(bytes, off, 2)?.try_into().unwrap()))
}

fn u32_at(bytes: &[u8], off: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(take(bytes, off, 4)?.try_into().unwrap()))
}

fn u64_at(bytes: &[u8], off: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(take(bytes, off, 8)?.try_into().unwrap()))
}

/// Parse a PE file from raw bytes.
pub fn parse(bytes: &[u8]) -> Result<PeDocument> {
    let dos = parse_dos(bytes)?;
    if dos.e_magic != DOS_MAGIC {
        return Err(PeError::Malformed("bad DOS magic".into()));
    }
    let pe_off = dos.e_lfanew as usize;
    if take(bytes, pe_off, 4)? != PE_SIGNATURE {
        return Err(PeError::Malformed(format!("missing PE signature at {pe_off:#x}")));
    }

    let coff = parse_coff(bytes, pe_off + 4)?;
    let opt_off = pe_off + 4 + 20;
    let optional = parse_optional(bytes, opt_off, coff.size_of_optional_header as usize)?;

    let section_off = opt_off + coff.size_of_optional_header as usize;
    let section_headers = parse_section_headers(bytes, section_off, coff.number_of_sections as usize)?;
    let mut sections = Vec::with_capacity(section_headers.len());
    for sh in &section_headers {
        sections.push(read_section(bytes, sh.clone())?);
    }

    let (dirs_off, nrs) = match &optional {
        OptionalHeader::Bit32(_) => (opt_off + 96, optional.number_of_rva_and_sizes()),
        OptionalHeader::Bit64(_) => (opt_off + 112, optional.number_of_rva_and_sizes()),
    };
    let n = (nrs as usize).min(DataDirectoryIndex::COUNT);
    let mut dirs = vec![DataDirectory::default(); DataDirectoryIndex::COUNT];
    for (i, slot) in dirs.iter_mut().take(n).enumerate() {
        *slot = DataDirectory {
            rva: Rva(u32_at(bytes, dirs_off + i * 8)?),
            size: u32_at(bytes, dirs_off + i * 8 + 4)?,
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

    Ok(doc)
}

fn parse_dos(bytes: &[u8]) -> Result<DosHeader> {
    let h = take(bytes, 0, 64)?;
    let e_lfanew = u32_at(h, 0x3c)?;
    let stub = bytes.get(64..e_lfanew as usize).unwrap_or(&[]).to_vec();
    let res2 = std::array::from_fn(|i| u16_at(h, 0x28 + i * 2).unwrap());
    Ok(DosHeader {
        e_magic: u16_at(h, 0)?,
        e_cblp: u16_at(h, 0x02)?,
        e_cp: u16_at(h, 0x04)?,
        e_crlc: u16_at(h, 0x06)?,
        e_cparhdr: u16_at(h, 0x08)?,
        e_minalloc: u16_at(h, 0x0a)?,
        e_maxalloc: u16_at(h, 0x0c)?,
        e_ss: u16_at(h, 0x0e)?,
        e_sp: u16_at(h, 0x10)?,
        e_csum: u16_at(h, 0x12)?,
        e_ip: u16_at(h, 0x14)?,
        e_cs: u16_at(h, 0x16)?,
        e_lfarlc: u16_at(h, 0x18)?,
        e_ovno: u16_at(h, 0x1a)?,
        e_res: [
            u16_at(h, 0x1c)?,
            u16_at(h, 0x1e)?,
            u16_at(h, 0x20)?,
            u16_at(h, 0x22)?,
        ],
        e_oemid: u16_at(h, 0x24)?,
        e_oeminfo: u16_at(h, 0x26)?,
        e_res2: res2,
        e_lfanew,
        stub,
    })
}

fn parse_coff(bytes: &[u8], off: usize) -> Result<CoffHeader> {
    let h = take(bytes, off, 20)?;
    Ok(CoffHeader {
        machine: Machine::from_u16(u16_at(h, 0)?),
        number_of_sections: u16_at(h, 2)?,
        time_date_stamp: u32_at(h, 4)?,
        pointer_to_symbol_table: u32_at(h, 8)?,
        number_of_symbols: u32_at(h, 12)?,
        size_of_optional_header: u16_at(h, 16)?,
        characteristics: u16_at(h, 18)?,
    })
}

fn parse_optional(bytes: &[u8], off: usize, size: usize) -> Result<OptionalHeader> {
    if size < 96 {
        return Err(PeError::Malformed("optional header too small".into()));
    }
    let magic = u16_at(bytes, off)?;
    let major_linker = bytes.get(off + 2).copied().unwrap_or(0);
    let minor_linker = bytes.get(off + 3).copied().unwrap_or(0);
    match magic {
        PE32_MAGIC => Ok(OptionalHeader::Bit32(OptionalHeader32 {
            magic,
            major_linker_version: major_linker,
            minor_linker_version: minor_linker,
            size_of_code: u32_at(bytes, off + 4)?,
            size_of_initialized_data: u32_at(bytes, off + 8)?,
            size_of_uninitialized_data: u32_at(bytes, off + 12)?,
            address_of_entry_point: Rva(u32_at(bytes, off + 16)?),
            base_of_code: Rva(u32_at(bytes, off + 20)?),
            base_of_data: Rva(u32_at(bytes, off + 24)?),
            image_base: u32_at(bytes, off + 28)?,
            section_alignment: u32_at(bytes, off + 32)?,
            file_alignment: u32_at(bytes, off + 36)?,
            major_operating_system_version: u16_at(bytes, off + 40)?,
            minor_operating_system_version: u16_at(bytes, off + 42)?,
            major_image_version: u16_at(bytes, off + 44)?,
            minor_image_version: u16_at(bytes, off + 46)?,
            major_subsystem_version: u16_at(bytes, off + 48)?,
            minor_subsystem_version: u16_at(bytes, off + 50)?,
            win32_version_value: u32_at(bytes, off + 52)?,
            size_of_image: u32_at(bytes, off + 56)?,
            size_of_headers: u32_at(bytes, off + 60)?,
            checksum: u32_at(bytes, off + 64)?,
            subsystem: u16_at(bytes, off + 68)?,
            dll_characteristics: u16_at(bytes, off + 70)?,
            size_of_stack_reserve: u32_at(bytes, off + 72)?,
            size_of_stack_commit: u32_at(bytes, off + 76)?,
            size_of_heap_reserve: u32_at(bytes, off + 80)?,
            size_of_heap_commit: u32_at(bytes, off + 84)?,
            loader_flags: u32_at(bytes, off + 88)?,
            number_of_rva_and_sizes: u32_at(bytes, off + 92)?,
        })),
        PE32_PLUS_MAGIC => Ok(OptionalHeader::Bit64(OptionalHeader64 {
            magic,
            major_linker_version: major_linker,
            minor_linker_version: minor_linker,
            size_of_code: u32_at(bytes, off + 4)?,
            size_of_initialized_data: u32_at(bytes, off + 8)?,
            size_of_uninitialized_data: u32_at(bytes, off + 12)?,
            address_of_entry_point: Rva(u32_at(bytes, off + 16)?),
            base_of_code: Rva(u32_at(bytes, off + 20)?),
            image_base: u64_at(bytes, off + 24)?,
            section_alignment: u32_at(bytes, off + 32)?,
            file_alignment: u32_at(bytes, off + 36)?,
            major_operating_system_version: u16_at(bytes, off + 40)?,
            minor_operating_system_version: u16_at(bytes, off + 42)?,
            major_image_version: u16_at(bytes, off + 44)?,
            minor_image_version: u16_at(bytes, off + 46)?,
            major_subsystem_version: u16_at(bytes, off + 48)?,
            minor_subsystem_version: u16_at(bytes, off + 50)?,
            win32_version_value: u32_at(bytes, off + 52)?,
            size_of_image: u32_at(bytes, off + 56)?,
            size_of_headers: u32_at(bytes, off + 60)?,
            checksum: u32_at(bytes, off + 64)?,
            subsystem: u16_at(bytes, off + 68)?,
            dll_characteristics: u16_at(bytes, off + 70)?,
            size_of_stack_reserve: u64_at(bytes, off + 72)?,
            size_of_stack_commit: u64_at(bytes, off + 80)?,
            size_of_heap_reserve: u64_at(bytes, off + 88)?,
            size_of_heap_commit: u64_at(bytes, off + 96)?,
            loader_flags: u32_at(bytes, off + 104)?,
            number_of_rva_and_sizes: u32_at(bytes, off + 108)?,
        })),
        other => Err(PeError::Malformed(format!("unknown optional header magic {other:#x}"))),
    }
}

fn parse_section_headers(bytes: &[u8], off: usize, n: usize) -> Result<Vec<SectionHeader>> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let h = take(bytes, off + i * 40, 40)?;
        let mut name = [0u8; 8];
        name.copy_from_slice(&h[0..8]);
        out.push(SectionHeader {
            name,
            virtual_size: u32_at(h, 8)?,
            virtual_address: Rva(u32_at(h, 12)?),
            size_of_raw_data: u32_at(h, 16)?,
            pointer_to_raw_data: RawOffset(u32_at(h, 20)?),
            characteristics: u32_at(h, 36)?,
        });
    }
    Ok(out)
}

fn read_section(bytes: &[u8], sh: SectionHeader) -> Result<Section> {
    let ptr = sh.pointer_to_raw_data.get() as usize;
    let raw = sh.size_of_raw_data as usize;
    let avail = bytes.len().saturating_sub(ptr);
    let n = raw.min(avail);
    let mut data = if n > 0 { bytes[ptr..ptr + n].to_vec() } else { Vec::new() };
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
pub(crate) fn parse_imports_from_doc(doc: &PeDocument, dir_rva: Rva) -> Result<Vec<ImportDescriptor>> {
    let psize = ptr_size(doc.arch);
    let mut out = Vec::new();
    let mut i: usize = 0;
    loop {
        let desc_rva = match (dir_rva.get() as u64).checked_add(i as u64 * 20) {
            Some(v) if v <= u32::MAX as u64 => Rva(v as u32),
            _ => break,
        };
        let d = match doc.read(desc_rva, 20) {
            Ok(b) => b,
            Err(_) => break, // past the table / unmapped
        };
        if d.iter().all(|&b| b == 0) {
            break;
        }
        let oft = u32::from_le_bytes(d[0..4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(d[12..16].try_into().unwrap());
        let ft = u32::from_le_bytes(d[16..20].try_into().unwrap());
        let thunk_rva = if oft != 0 { oft } else { ft };
        if thunk_rva == 0 {
            break;
        }
        let name = read_cstring(doc, Rva(name_rva))?;
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
            out.push(ImportFunction::Ordinal { ordinal: (val & 0xffff) as u16 });
        } else {
            let name_rva = val as u32;
            let hint = u16::from_le_bytes(doc.read(Rva(name_rva), 2)?.try_into().unwrap());
            let name = read_cstring(doc, Rva(name_rva).checked_add(2).ok_or_else(|| {
                PeError::Malformed("hint/name RVA overflow".into())
            })?)?;
            out.push(ImportFunction::Name { hint, name });
        }
        i += 1;
    }
    Ok(out)
}

/// Parse the export table described by directory entry `dd`.
pub(crate) fn parse_exports_from_doc(doc: &PeDocument, dd: DataDirectory) -> Result<Option<ExportTable>> {
    let d = doc.read(dd.rva, 40)?;
    let base = u32::from_le_bytes(d[16..20].try_into().unwrap());
    let number_of_functions = u32::from_le_bytes(d[20..24].try_into().unwrap());
    let number_of_names = u32::from_le_bytes(d[24..28].try_into().unwrap());
    let addr_of_functions = u32::from_le_bytes(d[28..32].try_into().unwrap());
    let addr_of_names = u32::from_le_bytes(d[32..36].try_into().unwrap());
    let addr_of_name_ordinals = u32::from_le_bytes(d[36..40].try_into().unwrap());
    let module_name_rva = u32::from_le_bytes(d[12..16].try_into().unwrap());

    let module_name = read_cstring(doc, Rva(module_name_rva)).ok();
    let dd_end = dd.rva.get().saturating_add(dd.size);

    let mut symbols = Vec::new();
    for i in 0..number_of_names {
        let name_rva = u32::from_le_bytes(doc.read(Rva(addr_of_names).checked_add(i * 4).ok_or_else(|| {
            PeError::Malformed("name pointer overflow".into())
        })?, 4)?.try_into().unwrap());
        let ord_idx = u16::from_le_bytes(doc.read(Rva(addr_of_name_ordinals).checked_add(i * 2).ok_or_else(|| {
            PeError::Malformed("name ordinal overflow".into())
        })?, 2)?.try_into().unwrap());
        let func_rva = u32::from_le_bytes(doc.read(Rva(addr_of_functions).checked_add(ord_idx as u32 * 4).ok_or_else(|| {
            PeError::Malformed("function address overflow".into())
        })?, 4)?.try_into().unwrap());
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
        let byte = doc.read(rva.checked_add(i).ok_or_else(|| {
            PeError::Malformed("string RVA overflow".into())
        })?, 1)?;
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
