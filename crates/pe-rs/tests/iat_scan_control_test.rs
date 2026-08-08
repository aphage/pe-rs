//! Controlled "test DLL" for the IAT scanner: a tiny PE we build ourselves
//! (both x64 and x86) whose code section references a known IAT via direct
//! memory operands. Unlike the mock (x64 only) and the real Windows DLLs
//! (variable, OS-specific), this is a deterministic ground truth: the scan
//! must recover *exactly* the referenced slots, in order, on both
//! architectures, after a real serialize → parse file round-trip.

use pe_rs::api::{IatScanner, ImportResolver, ResolvedImport};
use pe_rs::domain::coff::IMAGE_FILE_EXECUTABLE_IMAGE;
use pe_rs::domain::data_directory::{DataDirectory, DataDirectoryIndex};
use pe_rs::domain::dos::{DOS_MAGIC, DosHeader};
use pe_rs::domain::optional::{
    OptionalHeader, OptionalHeader32, OptionalHeader64, PE32_MAGIC, PE32_PLUS_MAGIC,
};
use pe_rs::domain::section::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE, Section, SectionHeader,
};
use pe_rs::domain::{
    Arch, CoffHeader, ImportFunction, Machine, PeDocument, RawOffset, Rva, ScanMethod, ScanOptions,
};
use pe_rs::io::pe::{parse, serialize};

const IMAGE_BASE64: u64 = 0x1400_0000;
const IMAGE_BASE32: u32 = 0x0040_0000;
const TEXT_RVA: u32 = 0x1000;
const IDATA_RVA: u32 = 0x2000;
const IAT_OFFSET_IN_IDATA: usize = 0x80;

/// A resolver that resolves nothing: the code-reference scan runs with
/// `validate_slots = false`, isolating the reference-recovery behavior.
struct NoResolver;
impl pe_rs::api::ImportResolver for NoResolver {
    fn resolve(&self, _address: u64) -> Option<pe_rs::api::ResolvedImport> {
        None
    }
}

/// Resolves the control DLL's slot values (`0x1800_0000 + i * 0x100`, the
/// addresses `control_doc_with` writes into its IAT) to `control.dll!fn<i>`.
struct ControlResolver;
impl ImportResolver for ControlResolver {
    fn resolve(&self, address: u64) -> Option<ResolvedImport> {
        if address < 0x1800_0000 {
            return None;
        }
        let i = (address - 0x1800_0000) / 0x100;
        Some(ResolvedImport {
            module: "control.dll".to_string(),
            function: ImportFunction::by_name(format!("fn{i}")),
        })
    }
}

/// Build a `.text` whose instructions each reference `slots[i]` via an
/// arch-appropriate direct memory operand. x64 uses RIP-relative
/// call/jmp/mov/lea (`FF 15`, `FF 25`, `48 8B 0D`, `4C 8B 05`, `48 8D 05`,
/// `48 8B 05`); x86 uses absolute addressing (`FF 15`/`FF 25`, `A1` moffs,
/// `8B 05`, `8D 05`, `8B 15`).
fn control_text(arch: Arch, image_base: u64, slots: &[u32]) -> Vec<u8> {
    let mut data = vec![0x90u8; 0x100];
    for (i, &slot) in slots.iter().enumerate() {
        let insn_rva = TEXT_RVA + (i as u32) * 8;
        let off = i * 8;
        let (prefix, insn_len): (&[u8], usize) = match (arch, i % 6) {
            (Arch::Bit64, 0) => (&[0xFF, 0x15], 6), // call [rip+disp]
            (Arch::Bit64, 1) => (&[0xFF, 0x25], 6), // jmp  [rip+disp]
            (Arch::Bit64, 2) => (&[0x48, 0x8B, 0x0D], 7), // mov rcx, [rip+disp]
            (Arch::Bit64, 3) => (&[0x4C, 0x8B, 0x05], 7), // mov r8,  [rip+disp]
            (Arch::Bit64, 4) => (&[0x48, 0x8D, 0x05], 7), // lea rax, [rip+disp]
            (Arch::Bit64, 5) => (&[0x48, 0x8B, 0x05], 7), // mov rax, [rip+disp]
            (Arch::Bit32, 0) => (&[0xFF, 0x15], 6), // call dword [abs]
            (Arch::Bit32, 1) => (&[0xFF, 0x25], 6), // jmp  dword [abs]
            (Arch::Bit32, 2) => (&[0xA1], 5),       // mov eax, moffs
            (Arch::Bit32, 3) => (&[0x8B, 0x05], 6), // mov eax, dword [abs]
            (Arch::Bit32, 4) => (&[0x8D, 0x05], 6), // lea eax, dword [abs]
            (Arch::Bit32, 5) => (&[0x8B, 0x15], 6), // mov edx, dword [abs]
            _ => unreachable!("arch"),
        };
        let addr: u32 = match arch {
            // x64: disp is relative to the next instruction (in RVA space).
            Arch::Bit64 => (slot as i64 - (insn_rva as i64 + insn_len as i64)) as i32 as u32,
            // x86: the operand is an absolute VA.
            Arch::Bit32 => (image_base + slot as u64) as u32,
        };
        data[off..off + prefix.len()].copy_from_slice(prefix);
        data[off + prefix.len()..off + insn_len].copy_from_slice(&addr.to_le_bytes());
    }
    data
}

/// Build the controlled "test DLL" for `arch` in its "structure intact" shape:
/// a two-section PE (`.text` code referencing a known `.idata` IAT) with a
/// single contiguous IAT run and the IAT data directory present — i.e. a
/// compressor / plain unpacked binary, where the table is locatable through
/// the PE structure.
fn control_doc(arch: Arch) -> PeDocument {
    let psize: u32 = if arch == Arch::Bit64 { 8 } else { 4 };
    let slots: Vec<u32> = (0..6)
        .map(|i| IDATA_RVA + IAT_OFFSET_IN_IDATA as u32 + i * psize)
        .collect();
    control_doc_with(arch, &slots, false)
}

/// Build the controlled "test DLL" for `arch` with the given IAT slot RVAs.
///
/// `slots` may be contiguous (a normal IAT) or scattered across the data
/// section — the shape a protector leaves when it splits the IAT. With
/// `erase_iat_dir`, `DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]` is left zeroed
/// and no import descriptors exist, the shape a protector leaves when it
/// clears the import table: the IAT then exists only as the code references
/// that dereference it.
fn control_doc_with(arch: Arch, slots: &[u32], erase_iat_dir: bool) -> PeDocument {
    let psize: u32 = if arch == Arch::Bit64 { 8 } else { 4 };
    let image_base: u64 = if arch == Arch::Bit64 {
        IMAGE_BASE64
    } else {
        IMAGE_BASE32 as u64
    };
    let text_data = control_text(arch, image_base, slots);

    // `.idata`: the IAT pointer array, sized to hold every slot — a scattered
    // set therefore sits at widely separated, non-contiguous addresses.
    let idata_size = slots
        .iter()
        .map(|&s| (s - IDATA_RVA) as usize + psize as usize)
        .max()
        .unwrap_or(0x100);
    let mut idata_data = vec![0u8; idata_size];
    for (i, &slot) in slots.iter().enumerate() {
        let v = 0x1800_0000u64 + (i as u64) * 0x100;
        let off = (slot - IDATA_RVA) as usize;
        if psize == 8 {
            idata_data[off..off + 8].copy_from_slice(&v.to_le_bytes());
        } else {
            idata_data[off..off + 4].copy_from_slice(&(v as u32).to_le_bytes());
        }
    }

    let text = section_text(text_data);
    let idata = section_idata(idata_data);

    let mut dirs = vec![DataDirectory::default(); DataDirectoryIndex::COUNT];
    if !erase_iat_dir {
        dirs[DataDirectoryIndex::Iat.to_usize()] = DataDirectory {
            rva: Rva(slots[0]),
            size: slots.len() as u32 * psize,
        };
    }

    doc_shell(arch, text, idata, dirs)
}

/// Wrap the two test sections in a valid two-section PE document with headers
/// for `arch`. `.text` must be a code section at `TEXT_RVA`, `.idata` a data
/// section at `IDATA_RVA`; the optional-header sizes derive from them.
fn doc_shell(arch: Arch, text: Section, idata: Section, dirs: Vec<DataDirectory>) -> PeDocument {
    let text_len = text.data.len() as u32;
    let idata_len = idata.data.len() as u32;
    let optional = match arch {
        Arch::Bit64 => OptionalHeader::Bit64(OptionalHeader64 {
            magic: PE32_PLUS_MAGIC,
            major_linker_version: 14,
            minor_linker_version: 0,
            size_of_code: text_len,
            size_of_initialized_data: idata_len,
            size_of_uninitialized_data: 0,
            address_of_entry_point: Rva(TEXT_RVA),
            base_of_code: Rva(TEXT_RVA),
            image_base: IMAGE_BASE64,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            major_operating_system_version: 6,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 6,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: 0x4000,
            size_of_headers: 0x200,
            checksum: 0,
            subsystem: 2,
            dll_characteristics: 0,
            size_of_stack_reserve: 0x100000,
            size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 16,
        }),
        Arch::Bit32 => OptionalHeader::Bit32(OptionalHeader32 {
            magic: PE32_MAGIC,
            major_linker_version: 14,
            minor_linker_version: 0,
            size_of_code: text_len,
            size_of_initialized_data: idata_len,
            size_of_uninitialized_data: 0,
            address_of_entry_point: Rva(TEXT_RVA),
            base_of_code: Rva(TEXT_RVA),
            base_of_data: Rva(IDATA_RVA),
            image_base: IMAGE_BASE32,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            major_operating_system_version: 6,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 6,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: 0x4000,
            size_of_headers: 0x200,
            checksum: 0,
            subsystem: 2,
            dll_characteristics: 0,
            size_of_stack_reserve: 0x100000,
            size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 16,
        }),
    };

    PeDocument {
        arch,
        dos: DosHeader {
            e_magic: DOS_MAGIC,
            e_lfanew: 0x40,
            ..DosHeader::default()
        },
        coff: CoffHeader {
            machine: if arch == Arch::Bit64 {
                Machine::Amd64
            } else {
                Machine::I386
            },
            number_of_sections: 2,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: if arch == Arch::Bit64 { 0xF0 } else { 0xE0 },
            characteristics: IMAGE_FILE_EXECUTABLE_IMAGE,
        },
        optional,
        sections: vec![text, idata],
        data_directories: dirs,
        imports: Vec::new(),
        exports: None,
        resources: None,
        relocations: None,
        tls: None,
        load_config: None,
    }
}

/// A `.text` code section at `TEXT_RVA` holding `data`.
fn section_text(data: Vec<u8>) -> Section {
    Section {
        header: SectionHeader {
            name: *b".text\0\0\0",
            virtual_size: data.len() as u32,
            virtual_address: Rva(TEXT_RVA),
            size_of_raw_data: 0x200,
            pointer_to_raw_data: RawOffset(0x200),
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        },
        data,
    }
}

/// A `.idata` data section at `IDATA_RVA` holding `data`.
fn section_idata(data: Vec<u8>) -> Section {
    Section {
        header: SectionHeader {
            name: *b".idata\0\0",
            virtual_size: data.len() as u32,
            virtual_address: Rva(IDATA_RVA),
            size_of_raw_data: (data.len() as u32 + 0x1FF) & !0x1FF,
            pointer_to_raw_data: RawOffset(0x400),
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        },
        data,
    }
}

/// Write a little-endian `u32` into `buf` at `off`.
fn u32_w(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// The scan with `method` must recover exactly `expected` slots, in order.
fn assert_scan_recovers_with(doc: &PeDocument, expected: &[u32], method: ScanMethod) {
    let opts = ScanOptions {
        method,
        validate_slots: false,
        ..Default::default()
    };
    let scan = doc
        .scan(&NoResolver, &opts)
        .unwrap_or_else(|e| panic!("{method:?} scan should find the referenced slots: {e}"));
    let got: Vec<u32> = scan.entries.iter().map(|e| e.rva.get()).collect();
    assert_eq!(got, expected, "recovered IAT slots");
}

/// The code-reference scan must recover exactly `expected` slots, in order.
fn assert_scan_recovers(doc: &PeDocument, expected: &[u32]) {
    assert_scan_recovers_with(doc, expected, ScanMethod::CodeReference);
}

#[test]
fn control_x64_dll_references_are_recovered() {
    let psize = 8u32;
    let expected: Vec<u32> = (0..6)
        .map(|i| IDATA_RVA + IAT_OFFSET_IN_IDATA as u32 + i * psize)
        .collect();

    // In-memory document.
    assert_scan_recovers(&control_doc(Arch::Bit64), &expected);
    // The same content through the real writer → file → parser round-trip.
    let bytes = serialize(&control_doc(Arch::Bit64)).expect("serialize x64 control dll");
    let re = parse(&bytes).expect("parse x64 control dll");
    assert_scan_recovers(&re, &expected);
}

#[test]
fn control_x86_dll_references_are_recovered() {
    let psize = 4u32;
    let expected: Vec<u32> = (0..6)
        .map(|i| IDATA_RVA + IAT_OFFSET_IN_IDATA as u32 + i * psize)
        .collect();

    assert_scan_recovers(&control_doc(Arch::Bit32), &expected);
    let bytes = serialize(&control_doc(Arch::Bit32)).expect("serialize x86 control dll");
    let re = parse(&bytes).expect("parse x86 control dll");
    assert_scan_recovers(&re, &expected);
}

/// A protector-style shape: the same six references, but the IAT slots are
/// scattered to non-contiguous addresses (a split IAT) and the IAT data
/// directory is erased, so the import table exists only as code references.
fn assert_erased_split_recovers(arch: Arch) {
    let offsets = [0x40u32, 0x80, 0x1C0, 0x200, 0x280, 0x2C0];
    let expected: Vec<u32> = offsets.iter().map(|&o| IDATA_RVA + o).collect();

    let doc = control_doc_with(arch, &expected, true);
    assert_scan_recovers(&doc, &expected);
    // The same content through the real writer → file → parser round-trip.
    let bytes = serialize(&doc).expect("serialize split/erased dll");
    let re = parse(&bytes).expect("parse split/erased dll");
    assert_scan_recovers(&re, &expected);
}

#[test]
fn control_erased_split_x64_iat_recovered() {
    assert_erased_split_recovers(Arch::Bit64);
}

#[test]
fn control_erased_split_x86_iat_recovered() {
    assert_erased_split_recovers(Arch::Bit32);
}

/// `remap_iat_references` must repoint every code reference from the old
/// contiguous IAT slots to scattered new slots, so the code-reference scan then
/// recovers exactly the new slots. The document is built with the union of old
/// and new slots so `.idata` covers both locations.
#[test]
fn remap_iat_references_repoints_code_to_scattered_slots() {
    for arch in [Arch::Bit64, Arch::Bit32] {
        let psize: u32 = if arch == Arch::Bit64 { 8 } else { 4 };
        let old: Vec<u32> = (0..6)
            .map(|i| IDATA_RVA + IAT_OFFSET_IN_IDATA as u32 + i * psize)
            .collect();
        let new_offsets = [0x40u32, 0xC0, 0x180, 0x1C0, 0x240, 0x2C0];
        let new: Vec<u32> = new_offsets.iter().map(|&o| IDATA_RVA + o).collect();

        let mut all = old.clone();
        all.extend_from_slice(&new);
        let mut doc = control_doc_with(arch, &all, false);
        let mapping: Vec<(Rva, Rva)> = old
            .iter()
            .zip(&new)
            .map(|(&o, &n)| (Rva(o), Rva(n)))
            .collect();

        let patched = doc.remap_iat_references(&mapping).expect("remap refs");
        assert_eq!(patched, 6, "{arch:?}: every old reference rewritten");

        let scan = doc
            .scan(
                &NoResolver,
                &ScanOptions {
                    method: ScanMethod::CodeReference,
                    validate_slots: false,
                    ..Default::default()
                },
            )
            .unwrap();
        let got: Vec<u32> = scan.entries.iter().map(|e| e.rva.get()).collect();
        assert_eq!(
            got, new,
            "{arch:?}: code now references the scattered slots"
        );
    }
}

// ---------------------------------------------------------------------------
// Reflection shapes (docs/dump 情况分析和处理.md, the "相对正常的导入表"
// branches): a dumped PE whose import directory the loader overwrote.

/// The reflection scan must recover exactly `expected` slots, in order.
fn assert_reflection_recovers(doc: &PeDocument, expected: &[u32]) {
    assert_scan_recovers_with(doc, expected, ScanMethod::Reflection);
}

/// The control DLL slot RVAs for `reflect_1b_doc`: two NULL-separated
/// sub-arrays of two slots each.
fn reflect_1b_slots(arch: Arch) -> Vec<u32> {
    let psize: u32 = if arch == Arch::Bit64 { 8 } else { 4 };
    let iat_off = IAT_OFFSET_IN_IDATA as u32;
    [0u32, 1, 3, 4]
        .iter()
        .map(|&i| IDATA_RVA + iat_off + i * psize)
        .collect()
}

/// A dump whose import directory survives but whose descriptor's
/// `OriginalFirstThunk` was overwritten by the loader (`== 0`): the
/// `FirstThunk` array now holds loaded addresses and *is* the IAT.
fn reflect_1a_doc(arch: Arch) -> PeDocument {
    let psize: u32 = if arch == Arch::Bit64 { 8 } else { 4 };
    let image_base: u64 = if arch == Arch::Bit64 {
        IMAGE_BASE64
    } else {
        IMAGE_BASE32 as u64
    };
    let ft_off = IAT_OFFSET_IN_IDATA as u32;
    let slots: Vec<u32> = (0..3).map(|i| IDATA_RVA + ft_off + i * psize).collect();
    let text_data = control_text(arch, image_base, &slots);

    // `.idata`: import descriptors + DLL name + the FirstThunk/IAT array.
    let mut idata_data = vec![0u8; 0x100];
    // descriptor[0]: OriginalFirstThunk == 0 (overwritten, stays zero),
    // Name = name_rva, FirstThunk = ft_rva; descriptor[1] is the all-zero
    // terminator.
    u32_w(&mut idata_data, 12, IDATA_RVA + 0x40); // Name
    u32_w(&mut idata_data, 16, slots[0]); // FirstThunk
    idata_data[0x40..0x4C].copy_from_slice(b"control.dll\0");
    for (i, &slot) in slots.iter().enumerate() {
        let v = 0x1800_0000u64 + (i as u64) * 0x100;
        let off = (slot - IDATA_RVA) as usize;
        if psize == 8 {
            idata_data[off..off + 8].copy_from_slice(&v.to_le_bytes());
        } else {
            idata_data[off..off + 4].copy_from_slice(&(v as u32).to_le_bytes());
        }
    }

    let text = section_text(text_data);
    let idata = section_idata(idata_data);

    let mut dirs = vec![DataDirectory::default(); DataDirectoryIndex::COUNT];
    dirs[DataDirectoryIndex::Import.to_usize()] = DataDirectory {
        rva: Rva(IDATA_RVA),
        size: 0x40,
    };

    doc_shell(arch, text, idata, dirs)
}

/// A dump whose import directory is gone but whose IAT data directory survives
/// as NULL-separated per-module sub-arrays (the doc's Case B): two sub-arrays
/// of two slots, closed by the whole-table terminator double NULL.
fn reflect_1b_doc(arch: Arch) -> PeDocument {
    let psize: u32 = if arch == Arch::Bit64 { 8 } else { 4 };
    let image_base: u64 = if arch == Arch::Bit64 {
        IMAGE_BASE64
    } else {
        IMAGE_BASE32 as u64
    };
    let slots = reflect_1b_slots(arch);
    let text_data = control_text(arch, image_base, &slots);

    // `.idata`: [v0, v1, NULL, v2, v3, NULL, NULL] at the IAT offset — the
    // single NULLs and the final double NULL are the zero-initialized gaps.
    let mut idata_data = vec![0u8; 0x100];
    for (i, &slot) in slots.iter().enumerate() {
        let v = 0x1800_0000u64 + (i as u64) * 0x100;
        let off = (slot - IDATA_RVA) as usize;
        if psize == 8 {
            idata_data[off..off + 8].copy_from_slice(&v.to_le_bytes());
        } else {
            idata_data[off..off + 4].copy_from_slice(&(v as u32).to_le_bytes());
        }
    }

    let text = section_text(text_data);
    let idata = section_idata(idata_data);

    let mut dirs = vec![DataDirectory::default(); DataDirectoryIndex::COUNT];
    dirs[DataDirectoryIndex::Iat.to_usize()] = DataDirectory {
        rva: Rva(IDATA_RVA + IAT_OFFSET_IN_IDATA as u32),
        size: 7 * psize,
    };

    doc_shell(arch, text, idata, dirs)
}

#[test]
fn reflection_recovers_overwritten_oft_thunks() {
    for arch in [Arch::Bit64, Arch::Bit32] {
        let psize: u32 = if arch == Arch::Bit64 { 8 } else { 4 };
        let expected: Vec<u32> = (0..3)
            .map(|i| IDATA_RVA + IAT_OFFSET_IN_IDATA as u32 + i * psize)
            .collect();
        assert_reflection_recovers(&reflect_1a_doc(arch), &expected);
    }
}

#[test]
fn reflection_recovers_iat_dir_sub_arrays() {
    for arch in [Arch::Bit64, Arch::Bit32] {
        let doc = reflect_1b_doc(arch);
        assert_reflection_recovers(&doc, &reflect_1b_slots(arch));
    }
}

#[test]
fn recover_dump_imports_reflects_overwritten_oft() {
    for arch in [Arch::Bit64, Arch::Bit32] {
        let rec = reflect_1a_doc(arch)
            .recover_dump_imports(&ControlResolver)
            .expect("recover imports");
        assert_eq!(rec.descriptors.len(), 1, "{arch:?}");
        assert_eq!(rec.descriptors[0].name, "control.dll");
        assert_eq!(rec.descriptors[0].functions.len(), 3);
        assert!(rec.unresolved.is_empty(), "{arch:?}");
    }
}

#[test]
fn recover_dump_imports_reflects_iat_sub_arrays() {
    for arch in [Arch::Bit64, Arch::Bit32] {
        let rec = reflect_1b_doc(arch)
            .recover_dump_imports(&ControlResolver)
            .expect("recover imports");
        assert_eq!(rec.descriptors.len(), 1, "{arch:?}");
        assert_eq!(rec.descriptors[0].functions.len(), 4);
        assert!(rec.unresolved.is_empty(), "{arch:?}");
    }
}
