//! IAT scanning.

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Encoder, Instruction, OpKind, Register};

use crate::api::resolver::ImportResolver;
use crate::domain::data_directory::{DataDirectory, DataDirectoryIndex};
use crate::domain::section::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE};
use crate::domain::types::ptr_size;
use crate::domain::{Arch, IatEntry, IatScan, PeDocument, Rva, ScanMethod, ScanOptions};
use crate::error::{PeError, Result};

/// Locates a candidate Import Address Table in a [`PeDocument`].
///
/// Two methods are available:
/// - [`ScanMethod::Resolver`] walks the image (or a `region` window) slot by
///   slot and keeps maximal runs whose stored value resolves through
///   [`ImportResolver`].
/// - [`ScanMethod::CodeReference`] disassembles the executable sections and
///   collects every slot dereferenced by a direct memory operand
///   (`call/jmp/mov/lea [rip+disp]` on x64, absolute addressing on x86),
///   validates each slot's content through the resolver, and returns the full
///   referenced-slot set (Scylla's reference-scan model).
pub trait IatScanner {
    fn scan(&self, resolver: &dyn ImportResolver, options: &ScanOptions) -> Result<IatScan>;
}

impl IatScanner for PeDocument {
    fn scan(&self, resolver: &dyn ImportResolver, options: &ScanOptions) -> Result<IatScan> {
        match options.method {
            ScanMethod::Resolver => self.scan_by_resolver(resolver, options),
            ScanMethod::CodeReference => self.scan_by_code_reference(resolver, options),
            ScanMethod::Reflection => self.scan_by_reflection(resolver, options),
        }
    }
}

struct Run {
    base: Rva,
    entries: Vec<IatEntry>,
}

impl PeDocument {
    fn scan_by_resolver(
        &self,
        resolver: &dyn ImportResolver,
        options: &ScanOptions,
    ) -> Result<IatScan> {
        let psize = ptr_size(self.arch);
        let (start, len) = self.scan_window(options)?;

        // Zero slots are per-module NULL separators: a run continues across
        // them as long as the next resolvable slot is within `max_null_gap`.
        // Non-zero but unresolvable slots end the run.
        let mut current: Option<Run> = None;
        let mut best: Option<Run> = None;
        let mut gap = 0usize;

        for off in (0..len).step_by(psize) {
            let Some(slot_rva) = start.checked_add(off as u32) else {
                break;
            };
            let slot = self
                .read(slot_rva, psize)
                .ok()
                .map(|b| read_thunk(b, psize));
            match slot {
                Some(v) if resolver.resolve(v).is_some() => {
                    let run = current.get_or_insert_with(|| Run {
                        base: slot_rva,
                        entries: Vec::new(),
                    });
                    run.entries.push(IatEntry {
                        rva: slot_rva,
                        value: v,
                    });
                    gap = 0;
                }
                Some(0) => {
                    gap += 1;
                    if gap > options.max_null_gap
                        && let Some(run) = current.take()
                    {
                        consider(run, options.min_entries, &mut best);
                    }
                }
                _ => {
                    if let Some(run) = current.take() {
                        consider(run, options.min_entries, &mut best);
                    }
                    gap = 0;
                }
            }
        }
        if let Some(run) = current.take() {
            consider(run, options.min_entries, &mut best);
        }

        match best {
            Some(run) => Ok(IatScan {
                base_rva: run.base,
                size: run.entries.len(),
                entries: run.entries,
            }),
            None => Err(PeError::NotFound(format!(
                "no IAT run with >= {} resolvable entries found",
                options.min_entries
            ))),
        }
    }

    /// Locate IAT slots referenced by code, using iced-x86 to disassemble each
    /// executable section. Keeps the target of every instruction that
    /// dereferences a direct memory address — a RIP/EIP-relative operand (x64)
    /// or an absolute address (x86) — validates each slot's content through the
    /// resolver (unless `validate_slots` is off for protected dumps). The full
    /// set of referenced slots is returned; it may span several segments (e.g.
    /// normal + delay-load thunks), so curate with `IatTable` when rebuilding.
    fn scan_by_code_reference(
        &self,
        resolver: &dyn ImportResolver,
        options: &ScanOptions,
    ) -> Result<IatScan> {
        let psize = ptr_size(self.arch);
        let image_base = self.optional.image_base();
        let bitness = match self.arch {
            Arch::Bit64 => 64,
            Arch::Bit32 => 32,
        };
        let (start, len) = self.scan_window(options)?;
        let window_end = start.get().saturating_add(len as u32);

        // 1. Disassemble each code section and collect the slots referenced by
        //    direct memory operands, validated by the resolver.
        let mut slots: HashMap<Rva, u64> = HashMap::new();
        for section in &self.sections {
            let chars = section.header.characteristics;
            if chars & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) == 0 {
                continue;
            }
            let sec_start = section.header.virtual_address.get();
            let sec_end = sec_start.saturating_add(section.data.len() as u32);
            let lo = sec_start.max(start.get());
            let hi = sec_end.min(window_end);
            if hi <= lo {
                continue;
            }
            let base_off = (lo - sec_start) as usize;
            let data = &section.data[base_off..base_off + (hi - lo) as usize];
            // Decode from RVA `lo` so RIP-relative targets land in RVA space.
            let mut decoder = Decoder::with_ip(bitness, data, lo as u64, DecoderOptions::NONE);
            while decoder.can_decode() {
                let insn = decoder.decode();
                if !is_iat_reference_insn(&insn) {
                    continue;
                }
                let slot_rva = if insn.is_ip_rel_memory_operand() {
                    // Target of a RIP/EIP-relative operand, already an RVA.
                    let t = insn.ip_rel_memory_address();
                    if t > u32::MAX as u64 {
                        continue;
                    }
                    Rva(t as u32)
                } else if is_absolute_memory_operand(&insn) {
                    // x86 absolute addressing: the displacement is a VA.
                    let va = insn.memory_displacement64();
                    if va < image_base || va - image_base > u32::MAX as u64 {
                        continue;
                    }
                    Rva((va - image_base) as u32)
                } else {
                    continue;
                };
                // An IAT slot is pointer-aligned and never lives in code:
                // drop unaligned references (data / struct fields) and
                // references into executable sections.
                if slot_rva.get() % psize as u32 != 0 || !self.slot_in_data(slot_rva) {
                    continue;
                }
                if let Ok(bytes) = self.read(slot_rva, psize) {
                    let v = read_thunk(bytes, psize);
                    // In signature mode (`validate_slots = false`) the slot
                    // content is not required to resolve — the code reference
                    // itself marks the slot as IAT-like.
                    if !options.validate_slots || resolver.resolve(v).is_some() {
                        slots.insert(slot_rva, v);
                    }
                }
            }
        }

        if slots.is_empty() {
            return Err(PeError::NotFound(
                "no IAT slot referenced by code (and resolvable)".into(),
            ));
        }

        // 2. Sort by RVA: the full referenced-slot set is the candidate IAT.
        //    It may span several segments (e.g. normal + delay-load thunks);
        //    curate with `IatTable` when rebuilding.
        let mut entries: Vec<IatEntry> = slots
            .into_iter()
            .map(|(rva, value)| IatEntry { rva, value })
            .collect();
        entries.sort_by_key(|e| e.rva);
        if entries.len() < options.min_entries {
            return Err(PeError::NotFound(format!(
                "only {} IAT slots referenced by code (need >= {})",
                entries.len(),
                options.min_entries
            )));
        }

        Ok(IatScan {
            base_rva: entries[0].rva,
            size: entries.len(),
            entries,
        })
    }

    /// Reflect the IAT from the PE structure itself, following Scylla's dump
    /// handling (docs/dump 情况分析和处理.md): when the loader has overwritten
    /// an import descriptor's `OriginalFirstThunk` (`== 0` or `== FirstThunk`),
    /// the `FirstThunk` array now holds loaded *addresses* and *is* the IAT —
    /// collect its slots. If the import directory is gone but the IAT data
    /// directory remains, walk its NULL-separated per-module sub-arrays (a
    /// double NULL closes the whole table). The reflected slots are returned
    /// unresolved; feed them to `IatFixer::fix_iat` to resolve and rebuild.
    fn scan_by_reflection(
        &self,
        _resolver: &dyn ImportResolver,
        _options: &ScanOptions,
    ) -> Result<IatScan> {
        let psize = ptr_size(self.arch);

        // 1. An intact import directory: reflect the descriptors whose
        //    OriginalFirstThunk the loader overwrote.
        if let Some(dd) = self.non_null_dir(DataDirectoryIndex::Import) {
            let mut entries = Vec::new();
            let mut i = 0u32;
            while let Some(desc_rva) = dd.rva.checked_add(i * 20) {
                let Ok(desc) = self.read(desc_rva, 20) else {
                    break;
                };
                let oft = u32_at(desc, 0);
                let name_rva = u32_at(desc, 12);
                let ft = u32_at(desc, 16);
                // A NULL descriptor terminates the array.
                if oft == 0 && name_rva == 0 && ft == 0 {
                    break;
                }
                // OriginalFirstThunk destroyed *and* FirstThunk destroyed:
                // nothing to reflect — Scylla logs an error and exits.
                if oft == 0 && ft == 0 {
                    break;
                }
                if (oft == 0 || oft == ft) && ft != 0 {
                    collect_thunk_array(self, Rva(ft), psize, &mut entries);
                }
                i += 1;
            }
            if !entries.is_empty() {
                return Ok(entries_to_scan(entries));
            }
            return Err(PeError::NotFound(
                "no import descriptor with an overwritten OriginalFirstThunk to reflect".into(),
            ));
        }

        // 2. Import directory gone, but the IAT data directory remains: walk
        //    its NULL-separated per-module sub-arrays.
        if let Some(dd) = self.non_null_dir(DataDirectoryIndex::Iat) {
            let mut entries = Vec::new();
            collect_iat_dir_entries(self, dd, psize, &mut entries);
            if !entries.is_empty() {
                return Ok(entries_to_scan(entries));
            }
            return Err(PeError::NotFound(
                "no non-empty IAT sub-array in the IAT data directory".into(),
            ));
        }

        Err(PeError::NotFound(
            "neither an import directory nor an IAT data directory to reflect".into(),
        ))
    }

    /// The data directory `idx` when present (its RVA is non-zero).
    fn non_null_dir(&self, idx: DataDirectoryIndex) -> Option<DataDirectory> {
        self.data_directory(idx)
            .ok()
            .copied()
            .filter(|d| d.rva != Rva::NULL)
    }

    /// Whether `rva` falls inside a non-executable section — a plausible data
    /// location for an IAT slot.
    fn slot_in_data(&self, rva: Rva) -> bool {
        self.sections.iter().any(|s| {
            let s0 = s.header.virtual_address.get();
            s0 <= rva.get()
                && rva.get() < s0 + s.data.len() as u32
                && s.header.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) == 0
        })
    }

    /// The byte window to scan: the `region` from the options, or the whole
    /// image extent.
    fn scan_window(&self, options: &ScanOptions) -> Result<(Rva, usize)> {
        if let Some((rva, len)) = options.region {
            return Ok((rva, len));
        }
        let (s0, e0) = self
            .sections
            .iter()
            .fold((u32::MAX, 0u32), |(s0, e0), sec| {
                let s = sec.header.virtual_address.get();
                let e = s.saturating_add(sec.data.len() as u32);
                (s0.min(s), e0.max(e))
            });
        if e0 <= s0 {
            return Err(PeError::NotFound("image has no mappable data".into()));
        }
        Ok((Rva(s0), (e0 - s0) as usize))
    }

    /// Rewrite the direct-memory code references in the executable sections
    /// whose target slot RVA is a key of `mapping` to point at the mapped new
    /// slot RVA instead — the code side of relocating (scattering) an IAT.
    /// After this, code that dereferenced the old slots dereferences the new
    /// ones. Only the displacement is changed, so each rewritten instruction
    /// keeps its byte length; an instruction whose re-encoding would change
    /// length is left untouched (it would desynchronize the decoder). Returns
    /// the number of instructions rewritten. On x64 the references are
    /// RIP-relative (base-independent), so no `.reloc` entries are involved.
    pub fn remap_iat_references(&mut self, mapping: &[(Rva, Rva)]) -> Result<usize> {
        if mapping.is_empty() {
            return Ok(0);
        }
        let map: HashMap<u32, u32> = mapping.iter().map(|&(o, n)| (o.get(), n.get())).collect();
        let image_base = self.optional.image_base();
        let bitness = match self.arch {
            Arch::Bit64 => 64,
            Arch::Bit32 => 32,
        };
        let mut patched = 0usize;

        for si in 0..self.sections.len() {
            let chars = self.sections[si].header.characteristics;
            if chars & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) == 0 {
                continue;
            }
            let sec_start = self.sections[si].header.virtual_address.get();

            // Pass 1: decode and re-encode the references to rewrite. Decoding
            // borrows the section data, so collect the (offset, bytes) patches
            // first and apply them afterwards.
            let mut patches: Vec<(usize, Vec<u8>)> = Vec::new();
            {
                let data = &self.sections[si].data;
                let mut decoder =
                    Decoder::with_ip(bitness, data, sec_start as u64, DecoderOptions::NONE);
                while decoder.can_decode() {
                    let start = decoder.position();
                    let insn = decoder.decode();
                    if !is_iat_reference_insn(&insn) {
                        continue;
                    }
                    let old_rva: u32 = if insn.is_ip_rel_memory_operand() {
                        let t = insn.ip_rel_memory_address();
                        if t > u32::MAX as u64 {
                            continue;
                        }
                        t as u32
                    } else if is_absolute_memory_operand(&insn) {
                        let va = insn.memory_displacement64();
                        if va < image_base || va - image_base > u32::MAX as u64 {
                            continue;
                        }
                        (va - image_base) as u32
                    } else {
                        continue;
                    };
                    let Some(&new_rva) = map.get(&old_rva) else {
                        continue;
                    };

                    let mut new_insn = insn;
                    let target = if new_insn.is_ip_rel_memory_operand() {
                        new_rva as u64
                    } else {
                        image_base + new_rva as u64
                    };
                    new_insn.set_memory_displacement64(target);
                    let mut encoder = Encoder::new(bitness);
                    let rip = sec_start as u64 + start as u64;
                    if encoder.encode(&new_insn, rip).is_err() {
                        continue;
                    }
                    let bytes = encoder.take_buffer();
                    if bytes.len() != insn.len() {
                        continue; // encoding changed length: would desync the section
                    }
                    patches.push((start, bytes));
                }
            }

            // Pass 2: apply the rewritten instruction bytes.
            let data = &mut self.sections[si].data;
            for (start, bytes) in patches {
                data[start..start + bytes.len()].copy_from_slice(&bytes);
                patched += 1;
            }
        }

        Ok(patched)
    }
}

fn read_thunk(bytes: &[u8], psize: usize) -> u64 {
    if psize == 8 {
        u64::from_le_bytes(bytes.try_into().unwrap())
    } else {
        u32::from_le_bytes(bytes.try_into().unwrap()) as u64
    }
}

fn consider(run: Run, min_entries: usize, best: &mut Option<Run>) {
    if run.entries.len() >= min_entries
        && best
            .as_ref()
            .is_none_or(|b| run.entries.len() > b.entries.len())
    {
        *best = Some(run);
    }
}

/// Read a `u32` from `bytes` at `off`, or 0 when out of bounds.
pub(crate) fn u32_at(bytes: &[u8], off: usize) -> u32 {
    bytes
        .get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0)
}

/// Collect the non-zero thunk slots of the `[IMAGE_THUNK_DATA, NULL]` array at
/// `ft_rva` into `out`. Shared by the reflection scan and dump-import recovery.
pub(crate) fn collect_thunk_array(
    doc: &PeDocument,
    ft_rva: Rva,
    psize: usize,
    out: &mut Vec<IatEntry>,
) {
    let mut off = 0u32;
    while let Some(rva) = ft_rva.checked_add(off) {
        let Ok(bytes) = doc.read(rva, psize) else {
            break;
        };
        let v = read_thunk(bytes, psize);
        if v == 0 {
            break;
        }
        out.push(IatEntry { rva, value: v });
        off += psize as u32;
    }
}

/// Collect every entry of the IAT data directory `dd`, walked as NULL-separated
/// per-module sub-arrays: a NULL closes a sub-array, a second NULL closes the
/// whole table, and the directory `size` bounds the walk.
pub(crate) fn collect_iat_dir_entries(
    doc: &PeDocument,
    dd: DataDirectory,
    psize: usize,
    out: &mut Vec<IatEntry>,
) {
    let end = dd.size.min(u32::MAX - dd.rva.get());
    let mut off = 0u32;
    while off < end {
        let Some(slot_rva) = dd.rva.checked_add(off) else {
            break;
        };
        let Ok(bytes) = doc.read(slot_rva, psize) else {
            break;
        };
        let v = read_thunk(bytes, psize);
        if v == 0 {
            // NULL closes a sub-array; a second NULL closes the whole table.
            off += psize as u32;
            if off >= end {
                break;
            }
            let Some(next_rva) = dd.rva.checked_add(off) else {
                break;
            };
            let Ok(next) = doc.read(next_rva, psize) else {
                break;
            };
            if read_thunk(next, psize) == 0 {
                break;
            }
            continue;
        }
        out.push(IatEntry {
            rva: slot_rva,
            value: v,
        });
        off += psize as u32;
    }
}

/// Sort the reflected entries by RVA and wrap them in an [`IatScan`].
fn entries_to_scan(mut entries: Vec<IatEntry>) -> IatScan {
    entries.sort_by_key(|e| e.rva);
    IatScan {
        base_rva: entries[0].rva,
        size: entries.len(),
        entries,
    }
}

/// True when `insn` dereferences a direct absolute address — a memory operand
/// with neither a base nor an index register (x86 `[disp32]`, `moffs`).
fn is_absolute_memory_operand(insn: &Instruction) -> bool {
    insn.op_kinds().any(|k| k == OpKind::Memory)
        && insn.memory_base() == Register::None
        && insn.memory_index() == Register::None
}

/// Whether `insn` is one of the IAT-reference instruction families Scylla
/// accepts in `IATReferenceScan::isIatReferenceOpcodes`: `call`/`jmp`/`push`
/// (opcode FF), `mov` (8B/89/A0-A3/C6/C7) and `lea` (8D). Narrow and
/// arithmetic / SIMD memory operands (movzx/movsx, add/sub/cmp, movaps, ...)
/// are excluded, so global-data references contribute less noise.
fn is_iat_reference_insn(insn: &Instruction) -> bool {
    use iced_x86::Mnemonic::{Call, Jmp, Lea, Mov, Push};
    matches!(insn.mnemonic(), Call | Jmp | Push | Mov | Lea)
}
