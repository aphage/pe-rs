//! IAT scanning.

use std::collections::HashMap;

use crate::api::resolver::ImportResolver;
use crate::domain::types::ptr_size;
use crate::domain::{Arch, IatEntry, IatScan, PeDocument, Rva, ScanMethod, ScanOptions};
use crate::error::{PeError, Result};

/// Locates a candidate Import Address Table in a [`PeDocument`].
///
/// Two methods are available:
/// - [`ScanMethod::Resolver`] walks the image (or a `region` window) slot by
///   slot and keeps maximal runs whose stored value resolves through
///   [`ImportResolver`].
/// - [`ScanMethod::OpcodePattern`] scans code bytes for instructions that
///   dereference a memory address (`call/jmp/mov/lea [addr]`), computes the
///   referenced slot RVAs, validates each slot's content through the resolver,
///   and groups the consecutive slots into runs.
pub trait IatScanner {
    fn scan(&self, resolver: &dyn ImportResolver, options: &ScanOptions) -> Result<IatScan>;
}

impl IatScanner for PeDocument {
    fn scan(&self, resolver: &dyn ImportResolver, options: &ScanOptions) -> Result<IatScan> {
        match options.method {
            ScanMethod::Resolver => self.scan_by_resolver(resolver, options),
            ScanMethod::OpcodePattern => self.scan_by_opcode(resolver, options),
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

    fn scan_by_opcode(
        &self,
        resolver: &dyn ImportResolver,
        options: &ScanOptions,
    ) -> Result<IatScan> {
        let psize = ptr_size(self.arch);
        let image_base = self.optional.image_base();
        let (start, len) = self.scan_window(options)?;
        let window_end = start.get().saturating_add(len as u32);

        // 1. Collect referenced slots from opcode patterns, validated by the
        //    resolver (the slot's stored value must resolve to an import).
        let patterns = opcode_patterns(self.arch);
        let mut slots: HashMap<Rva, u64> = HashMap::new();
        for section in &self.sections {
            let sec_start = section.header.virtual_address.get();
            let sec_end = sec_start.saturating_add(section.data.len() as u32);
            let lo = sec_start.max(start.get());
            let hi = sec_end.min(window_end);
            if hi <= lo {
                continue;
            }
            let base_off = (lo - sec_start) as usize;
            let data = &section.data[base_off..base_off + (hi - lo) as usize];
            let sec_base = section.header.virtual_address;

            for pat in patterns {
                for (i, _) in data
                    .windows(pat.bytes.len())
                    .enumerate()
                    .filter(|(_, w)| *w == pat.bytes)
                {
                    let insn_rva = sec_base
                        .get()
                        .saturating_add(base_off as u32)
                        .saturating_add(i as u32);
                    let target = if pat.rip_relative {
                        // x64 rip-relative: target = next instruction + disp32
                        let disp = i32::from_le_bytes(
                            data[i + pat.disp_off..i + pat.disp_off + 4]
                                .try_into()
                                .unwrap(),
                        );
                        let next = insn_rva as i64 + pat.insn_len as i64;
                        let t = next + disp as i64;
                        if t < 0 || t > u32::MAX as i64 {
                            continue;
                        }
                        Rva(t as u32)
                    } else {
                        // x86 absolute: the field is an absolute VA
                        let abs = u32::from_le_bytes(
                            data[i + pat.disp_off..i + pat.disp_off + 4]
                                .try_into()
                                .unwrap(),
                        ) as u64;
                        if abs < image_base {
                            continue;
                        }
                        let r = abs - image_base;
                        if r > u32::MAX as u64 {
                            continue;
                        }
                        Rva(r as u32)
                    };
                    if let Ok(bytes) = self.read(target, psize) {
                        let v = read_thunk(bytes, psize);
                        // In signature mode (`validate_slots = false`) the slot
                        // content is not required to resolve — the code
                        // reference itself marks the slot as IAT-like.
                        if !options.validate_slots || resolver.resolve(v).is_some() {
                            slots.insert(target, v);
                        }
                    }
                }
            }
        }

        if slots.is_empty() {
            return Err(PeError::NotFound(
                "no IAT slot referenced by code patterns (and resolvable)".into(),
            ));
        }

        // 2. Sort the unique slots and group runs: a slot continues a run when
        //    it is within `max_null_gap + 1` pointer widths of the previous
        //    referenced slot, so split IAT chunks still merge.
        let mut ordered: Vec<Rva> = slots.keys().copied().collect();
        ordered.sort_unstable();
        let max_span = psize as u32 * (options.max_null_gap as u32 + 1);
        let mut current: Option<Run> = None;
        let mut best: Option<Run> = None;
        for &rva in &ordered {
            let is_next = current.as_ref().is_none_or(|r| {
                let last = r
                    .entries
                    .last()
                    .map(|e| e.rva.get())
                    .unwrap_or(r.base.get());
                rva.get() > last && rva.get() - last <= max_span
            });
            if is_next {
                let run = current.get_or_insert_with(|| Run {
                    base: rva,
                    entries: Vec::new(),
                });
                run.entries.push(IatEntry {
                    rva,
                    value: slots[&rva],
                });
            } else {
                if let Some(run) = current.take() {
                    consider(run, options.min_entries, &mut best);
                }
                current = Some(Run {
                    base: rva,
                    entries: vec![IatEntry {
                        rva,
                        value: slots[&rva],
                    }],
                });
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
                "no IAT referenced run with >= {} entries",
                options.min_entries
            ))),
        }
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

/// A code pattern that dereferences a memory address, with the byte offset of
/// its 32-bit address field and the total instruction length.
struct Pattern {
    bytes: &'static [u8],
    disp_off: usize,
    insn_len: usize,
    rip_relative: bool,
}

static X64_PATTERNS: [Pattern; 4] = [
    // call/jmp qword ptr [rip+disp]
    Pattern {
        bytes: &[0xFF, 0x15],
        disp_off: 2,
        insn_len: 6,
        rip_relative: true,
    },
    Pattern {
        bytes: &[0xFF, 0x25],
        disp_off: 2,
        insn_len: 6,
        rip_relative: true,
    },
    // mov/lea rax, [rip+disp]
    Pattern {
        bytes: &[0x48, 0x8B, 0x05],
        disp_off: 3,
        insn_len: 7,
        rip_relative: true,
    },
    Pattern {
        bytes: &[0x48, 0x8D, 0x05],
        disp_off: 3,
        insn_len: 7,
        rip_relative: true,
    },
];

static X86_PATTERNS: [Pattern; 4] = [
    // call/jmp dword ptr [abs]
    Pattern {
        bytes: &[0xFF, 0x15],
        disp_off: 2,
        insn_len: 6,
        rip_relative: false,
    },
    Pattern {
        bytes: &[0xFF, 0x25],
        disp_off: 2,
        insn_len: 6,
        rip_relative: false,
    },
    // mov eax, [abs]
    Pattern {
        bytes: &[0x8B, 0x05],
        disp_off: 2,
        insn_len: 6,
        rip_relative: false,
    },
    Pattern {
        bytes: &[0xA1],
        disp_off: 1,
        insn_len: 5,
        rip_relative: false,
    },
];

fn opcode_patterns(arch: Arch) -> &'static [Pattern] {
    match arch {
        Arch::Bit64 => &X64_PATTERNS,
        Arch::Bit32 => &X86_PATTERNS,
    }
}
