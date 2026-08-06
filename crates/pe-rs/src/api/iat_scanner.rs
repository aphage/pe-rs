//! IAT scanning.

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

use crate::api::resolver::ImportResolver;
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
