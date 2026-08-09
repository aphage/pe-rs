//! Direct-import handling (Scylla's `IATReferenceScan`).
//!
//! Some packers don't route every API call through the IAT: the code does a
//! direct `call`/`jmp` to the API's absolute address. [`scan_direct_imports`]
//! finds those instructions, [`add_direct_imports_to_doc`] adds the called APIs
//! to the image's import table so a rebuild resolves them, and
//! [`build_direct_import_jump_table`] + [`patch_direct_imports_to_jump_table`]
//! route the direct calls through a jump table in a new executable section,
//! whose entries `jmp [rip+0]` to the (rebuilt) IAT slots the loader fills.

use iced_x86::{Decoder, DecoderOptions, Instruction};
use pe_edit::api::ImportResolver;
use pe_edit::domain::section::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use pe_edit::domain::{ImportFunction, PeDocument, Rva};
use pe_edit::error::Result;

/// A direct branch to an API address that does not go through the IAT.
#[derive(Debug, Clone)]
pub struct DirectImport {
    /// RVA of the `call`/`jmp` instruction.
    pub insn_rva: Rva,
    /// The API address it calls directly.
    pub api_va: u64,
    pub module: String,
    pub function: ImportFunction,
}

/// Disassemble the executable sections and collect every direct `call`/`jmp`
/// whose target resolves to an API address (Scylla's direct-import scan).
pub fn scan_direct_imports(
    doc: &PeDocument,
    resolver: &dyn ImportResolver,
) -> Result<Vec<DirectImport>> {
    let bitness = match doc.arch {
        pe_edit::domain::Arch::Bit64 => 64,
        pe_edit::domain::Arch::Bit32 => 32,
    };
    let image_base = doc.optional.image_base();
    let mut out = Vec::new();
    for section in &doc.sections {
        if section.header.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) == 0 {
            continue;
        }
        let sec_start = section.header.virtual_address.get();
        // Decode at the image VA so a direct branch's target is the absolute
        // API address the resolver understands.
        let mut decoder = Decoder::with_ip(
            bitness,
            &section.data,
            image_base + sec_start as u64,
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            let insn = decoder.decode();
            if !is_direct_branch(&insn) {
                continue;
            }
            let target = insn.near_branch_target();
            if let Some(ri) = resolver.resolve(target) {
                out.push(DirectImport {
                    insn_rva: Rva((insn.ip() - image_base) as u32),
                    api_va: target,
                    module: ri.module,
                    function: ri.function,
                });
            }
        }
    }
    Ok(out)
}

/// Add every directly-called API to `doc.imports` (deduplicated per module),
/// so a subsequent import-table rebuild resolves it. Returns how many were new.
pub fn add_direct_imports_to_doc(doc: &mut PeDocument, direct: &[DirectImport]) -> Result<usize> {
    use pe_edit::api::ImportTableEditor;
    let mut added = 0;
    for d in direct {
        let before = doc
            .imports
            .iter()
            .find(|m| m.name == d.module)
            .map(|m| m.functions.len())
            .unwrap_or(0);
        doc.add_import(&d.module, std::slice::from_ref(&d.function))?;
        let after = doc
            .imports
            .iter()
            .find(|m| m.name == d.module)
            .map(|m| m.functions.len())
            .unwrap_or(0);
        if after > before {
            added += 1;
        }
    }
    Ok(added)
}

/// Size in bytes of one jump-table entry.
const ENTRY_SIZE: usize = 14; // `jmp [rip+0]` (6) + absolute target VA (8)

/// Append a new executable section containing one jump-table entry per direct
/// import: `jmp [rip+0]` followed by the IAT slot VA (`iat_slot_vas[k]`). The
/// loader fills those slots; a patched `call <entry>` lands on the jump, which
/// forwards to the slot's resolved address. Returns the section's RVA.
pub fn build_direct_import_jump_table(
    doc: &mut PeDocument,
    direct: &[DirectImport],
    iat_slot_vas: &[u64],
) -> Result<Rva> {
    if direct.is_empty() {
        return Err(pe_edit::error::PeError::InvalidArgument(
            "build_direct_import_jump_table: no direct imports".into(),
        ));
    }
    if direct.len() != iat_slot_vas.len() {
        return Err(pe_edit::error::PeError::InvalidArgument(
            "build_direct_import_jump_table: entry/slot count mismatch".into(),
        ));
    }
    let mut data = Vec::with_capacity(direct.len() * ENTRY_SIZE);
    for slot_va in iat_slot_vas {
        data.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // jmp [rip+0]
        data.extend_from_slice(&slot_va.to_le_bytes());
    }
    let rva = doc.alloc(data.len(), doc.optional.section_alignment().max(1))?;
    doc.write(rva, &data)?;
    // The jump table is called, so its section must be executable.
    if let Some(sec) = doc.sections.last_mut() {
        sec.header.characteristics |=
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    }
    Ok(rva)
}

/// Rewrite every direct `call`/`jmp` listed in `direct` to point at its
/// jump-table entry at `jump_table_rva` (Scylla's universal direct-import fix:
/// a `call rel32`/`jmp rel32` keeps its 5-byte length, so only the 4-byte
/// displacement changes). Returns how many instructions were patched.
pub fn patch_direct_imports_to_jump_table(
    doc: &mut PeDocument,
    direct: &[DirectImport],
    jump_table_rva: Rva,
) -> Result<usize> {
    let bitness = match doc.arch {
        pe_edit::domain::Arch::Bit64 => 64,
        pe_edit::domain::Arch::Bit32 => 32,
    };
    let image_base = doc.optional.image_base();
    let mut patched = 0usize;
    for si in 0..doc.sections.len() {
        let chars = doc.sections[si].header.characteristics;
        if chars & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) == 0 {
            continue;
        }
        let sec_start = doc.sections[si].header.virtual_address.get();
        let mut patches: Vec<(usize, i32)> = Vec::new();
        {
            let data = &doc.sections[si].data;
            let mut decoder = Decoder::with_ip(
                bitness,
                data,
                image_base + sec_start as u64,
                DecoderOptions::NONE,
            );
            while decoder.can_decode() {
                let pos = decoder.position();
                let insn = decoder.decode();
                if !is_direct_branch(&insn) || insn.len() != 5 {
                    continue; // only the rel32 forms keep their length
                }
                let insn_rva = (insn.ip() - image_base) as u32;
                let Some((k, _)) = direct
                    .iter()
                    .enumerate()
                    .find(|(_, d)| d.insn_rva.get() == insn_rva)
                else {
                    continue;
                };
                let entry_target =
                    image_base + jump_table_rva.get() as u64 + (k as u64 * ENTRY_SIZE as u64);
                // new rel32 = target - (ip + instruction length)
                let disp = entry_target as i64 - (insn.ip() + insn.len() as u64) as i64;
                patches.push((pos, disp as i32));
            }
        }
        let data = &mut doc.sections[si].data;
        for (pos, disp) in patches {
            data[pos + 1..pos + 5].copy_from_slice(&disp.to_le_bytes());
            patched += 1;
        }
    }
    Ok(patched)
}

/// Whether `insn` is a direct (relative) `call`/`jmp` branch.
fn is_direct_branch(insn: &Instruction) -> bool {
    use iced_x86::Mnemonic::{Call, Jmp};
    use iced_x86::OpKind::{NearBranch16, NearBranch32, NearBranch64};
    (insn.mnemonic() == Call || insn.mnemonic() == Jmp)
        && matches!(insn.op0_kind(), NearBranch16 | NearBranch32 | NearBranch64)
}
