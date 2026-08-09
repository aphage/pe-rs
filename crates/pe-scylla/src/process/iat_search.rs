//! IAT autosearch in a live process's memory (Scylla's `IATSearch`).
//!
//! [`search_iat`] finds the Import Address Table of a running process without
//! knowing its address: starting from the OEP (or any address), it disassembles
//! the code, finds a `call`/`jmp` that dereferences a memory slot whose content
//! is a valid API address (so the slot is an IAT slot), then derives the IAT's
//! start and size around it. The `advanced` variant disassembles the whole
//! executable memory region and takes the span of every such slot.

use iced_x86::{Decoder, DecoderOptions, OpKind, Register};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, VirtualQueryEx,
};

use crate::process::{ProcessResolver, read_memory};
use pe_edit::api::ImportResolver;
use pe_edit::domain::Arch;
use pe_edit::domain::types::ptr_size;
use pe_edit::error::Result;

/// How far past the last executable region to keep scanning (bounds the
/// address-space walk).
const MAX_ADVANCED_SCAN: u64 = 0x1000_0000; // 256 MB
/// Bytes of code disassembled from the start address in the normal search.
const NORMAL_CODE_SCAN: usize = 0x200;
/// Window read around a found IAT slot to derive its start/size.
const IAT_WINDOW: usize = 0x10000;

/// Find the IAT of the live process `pid` as `(address, size)`, starting the
/// search at `start_va` (typically the OEP). Returns `Ok(None)` when no IAT
/// could be located.
pub fn search_iat(pid: u32, start_va: u64, advanced: bool) -> Result<Option<(u64, usize)>> {
    let resolver = ProcessResolver::for_process(pid)?;
    let psize = ptr_size(resolver.target_arch());
    let found = if advanced {
        search_advanced(pid, &resolver, start_va, psize)
    } else {
        search_normal(pid, &resolver, start_va, psize)
    };
    Ok(found)
}

fn search_normal(
    pid: u32,
    resolver: &ProcessResolver,
    start_va: u64,
    psize: usize,
) -> Option<(u64, usize)> {
    let slot = find_first_iat_slot(pid, resolver, start_va, psize)?;
    iat_start_and_size(pid, resolver, slot, psize)
}

fn search_advanced(
    pid: u32,
    resolver: &ProcessResolver,
    start_va: u64,
    psize: usize,
) -> Option<(u64, usize)> {
    let handle = super::open_process(pid).ok()?;
    let mut targets: Vec<u64> = Vec::new();
    let mut addr = start_va;
    let scan_end = start_va.saturating_add(MAX_ADVANCED_SCAN);
    while addr < scan_end {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let n = unsafe {
            VirtualQueryEx(
                handle,
                addr as *const core::ffi::c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if n == 0 {
            break;
        }
        let region_base = mbi.BaseAddress as u64;
        let region_end = region_base + mbi.RegionSize as u64;
        if mbi.State == MEM_COMMIT
            && is_executable(mbi.Protect)
            && let Ok(bytes) = read_memory(pid, region_base, mbi.RegionSize as usize)
        {
            collect_slots(pid, resolver, region_base, &bytes, psize, &mut targets);
        }
        if region_end <= addr {
            break;
        }
        addr = region_end;
    }
    unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
    let (min, max) = (targets.iter().min()?, targets.iter().max()?);
    Some((*min, (*max - *min) as usize + psize))
}

/// Disassemble `bytes` (mapped at `base`) and collect the direct-memory slot
/// targets of every `call`/`jmp` whose slot content resolves to a valid API.
fn collect_slots(
    pid: u32,
    resolver: &ProcessResolver,
    base: u64,
    bytes: &[u8],
    psize: usize,
    out: &mut Vec<u64>,
) {
    let bitness = if resolver.target_arch() == Arch::Bit64 {
        64
    } else {
        32
    };
    let mut decoder = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    while decoder.can_decode() {
        let insn = decoder.decode();
        if !is_call_jmp_mem(&insn) {
            continue;
        }
        if let Some(target) = mem_target(&insn)
            && slot_value_resolves(pid, resolver, target, psize)
        {
            out.push(target);
        }
    }
}

/// Disassemble `NORMAL_CODE_SCAN` bytes from `start_va` and return the target of
/// the first `call`/`jmp` with a direct memory operand whose slot content is a
/// valid API address (Scylla's `findAPIAddressInIAT` + `isIATPointerValid`).
fn find_first_iat_slot(
    pid: u32,
    resolver: &ProcessResolver,
    start_va: u64,
    psize: usize,
) -> Option<u64> {
    let bytes = read_memory(pid, start_va, NORMAL_CODE_SCAN).ok()?;
    let bitness = if resolver.target_arch() == Arch::Bit64 {
        64
    } else {
        32
    };
    let mut decoder = Decoder::with_ip(bitness, &bytes, start_va, DecoderOptions::NONE);
    while decoder.can_decode() {
        let insn = decoder.decode();
        if !is_call_jmp_mem(&insn) {
            continue;
        }
        if let Some(target) = mem_target(&insn)
            && slot_value_resolves(pid, resolver, target, psize)
        {
            return Some(target);
        }
    }
    None
}

/// Derive the IAT's start and size around a known IAT slot (Scylla's
/// `findIATStartAndSize`): read a window around the slot and walk backward to
/// the first slot of the run and forward to its end. A run is bounded by two
/// consecutive "invalid for IAT" slots (NULL or a value that resolves to no
/// API) followed by a slot that is not a valid API.
fn iat_start_and_size(
    pid: u32,
    resolver: &ProcessResolver,
    slot: u64,
    psize: usize,
) -> Option<(u64, usize)> {
    let window_base = slot & !0xFFF; // page-align down so the window starts readable
    let window = read_memory(pid, window_base, IAT_WINDOW).ok()?;
    if window.len() < psize * 2 {
        return None;
    }
    let n_slots = window.len() / psize;
    let read_slot = |i: usize| -> Option<u64> {
        let off = i * psize;
        let b = window.get(off..off + psize)?;
        Some(if psize == 8 {
            u64::from_le_bytes(b.try_into().unwrap())
        } else {
            u32::from_le_bytes(b.try_into().unwrap()) as u64
        })
    };
    let invalid_for_iat = |v: u64| v == 0 || resolver.resolve(v).is_none();

    // Walk backward from the found slot to the IAT start.
    let found = ((slot - window_base) / psize as u64).min(n_slots as u64 - 1) as usize;
    let mut start_idx = 0usize;
    for i in (0..=found).rev() {
        let bad_cur = read_slot(i).map(invalid_for_iat).unwrap_or(true);
        let bad_prev = i
            .checked_sub(1)
            .and_then(&read_slot)
            .map(invalid_for_iat)
            .unwrap_or(true);
        let good_prev2 = i
            .checked_sub(2)
            .and_then(&read_slot)
            .map(|v| resolver.resolve(v).is_some())
            .unwrap_or(false);
        if bad_cur && bad_prev && !good_prev2 {
            start_idx = i;
            break;
        }
    }

    // Walk forward to the IAT end.
    let mut end_idx = n_slots - 1;
    for i in start_idx..n_slots.saturating_sub(2) {
        let bad_cur = read_slot(i).map(invalid_for_iat).unwrap_or(true);
        let bad_next = read_slot(i + 1).map(invalid_for_iat).unwrap_or(true);
        let good_next2 = read_slot(i + 2)
            .map(|v| resolver.resolve(v).is_some())
            .unwrap_or(false);
        if bad_cur && bad_next && !good_next2 {
            end_idx = i;
            break;
        }
    }

    let start = window_base + (start_idx * psize) as u64;
    let size = (end_idx - start_idx + 1) * psize;
    if start < slot && size >= psize * 2 {
        Some((start, size))
    } else {
        Some((slot, psize))
    }
}

/// Whether the value stored at `slot` in `pid` resolves to a valid API.
fn slot_value_resolves(pid: u32, resolver: &ProcessResolver, slot: u64, psize: usize) -> bool {
    let Ok(bytes) = read_memory(pid, slot, psize) else {
        return false;
    };
    let value = if psize == 8 {
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    } else {
        u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64
    };
    resolver.resolve(value).is_some()
}

/// Whether `insn` is a `call`/`jmp` that dereferences a direct memory address.
fn is_call_jmp_mem(insn: &iced_x86::Instruction) -> bool {
    use iced_x86::Mnemonic::{Call, Jmp};
    (insn.mnemonic() == Call || insn.mnemonic() == Jmp)
        && (insn.is_ip_rel_memory_operand() || is_absolute_memory_operand(insn))
}

/// The direct memory target of `insn`: a RIP-relative address (x64) or an
/// absolute address (x86), as an absolute VA.
fn mem_target(insn: &iced_x86::Instruction) -> Option<u64> {
    if insn.is_ip_rel_memory_operand() {
        Some(insn.ip_rel_memory_address())
    } else if is_absolute_memory_operand(insn) {
        Some(insn.memory_displacement64())
    } else {
        None
    }
}

/// True when `insn` dereferences a direct absolute address — a memory operand
/// with neither a base nor an index register (x86 `[disp32]`, `moffs`).
fn is_absolute_memory_operand(insn: &iced_x86::Instruction) -> bool {
    insn.op_kinds().any(|k| k == OpKind::Memory)
        && insn.memory_base() == Register::None
        && insn.memory_index() == Register::None
}

fn is_executable(protect: u32) -> bool {
    matches!(
        protect & 0xFF,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}
