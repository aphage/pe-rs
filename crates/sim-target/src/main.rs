//! The simulation **target**: a minimal-runtime Windows executable (no CRT, no
//! `std` runtime, no heap) that corrupts its own in-memory PE image on demand,
//! reproducing the scenarios of `docs/dump 情况分析和处理.md`, then **pauses
//! itself** (like being stopped by a debugger) so a *standalone* pe dump tool
//! (`cargo run -p pe-rs --example dump -- <pid> ...`) can dump and fix it.
//!
//! A deliberately minimal runtime matters: `std`/CRT programs lazily write
//! absolute function pointers into `.data` at startup, so a dump of them can't
//! re-run (the loader re-relocates those slots as if they were image pointers).
//! This target keeps `.data` clean, like a freshly-unpacked packed program.
//!
//! Modes (parsed from the command line):
//! - `sim-target` / `sim-target verify` — run normally, print `SIM_TARGET_OK`,
//!   exit 0. This is what a *fixed* dump is launched with to prove it works.
//! - `sim-target corrupt <scenario>` — corrupt self per scenario, print
//!   `SIM_TARGET_READY:<pid>`, then suspend the current thread (paused, like a
//!   debugger break) until terminated by the dump tool.
//!
//! Scenarios (`normal|oft|iatdir|erased`, aliases `a|b|c|d`):
//! - `normal` (A): no corruption — a plain running process.
//! - `oft` (B): overwrite every import descriptor's `OriginalFirstThunk` with 0.
//! - `iatdir` (C): zero the Import data directory, keep the IAT directory.
//! - `erased` (D): zero both directories *and* scatter the IAT — each module's
//!   thunk block is copied to a non-contiguous region of a scratch buffer and
//!   every RIP-relative code reference to the old slots is repointed.

#![cfg_attr(not(test), no_std)] // std is only used by the (test) build harness
#![no_main]
#![windows_subsystem = "console"]
#![allow(clippy::missing_safety_doc)] // compiler-runtime helpers, not public API

use core::ffi::c_void;

// ---------------------------------------------------------------------------
// Compiler runtime helpers (no CRT is linked).
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            *dst.add(i) = *src.add(i);
        }
    }
    dst
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dst < src as *mut u8 {
        unsafe { memcpy(dst, src, n) }
    } else {
        for i in (0..n).rev() {
            unsafe {
                *dst.add(i) = *src.add(i);
            }
        }
        dst
    }
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            *dst.add(i) = c as u8;
        }
    }
    dst
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let x = unsafe { *a.add(i) };
        let y = unsafe { *b.add(i) };
        if x != y {
            return (x as i32) - (y as i32);
        }
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ---------------------------------------------------------------------------
// CRT symbols the linker expects (we link no default library).
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

/// MSVC's stack-probe helper for large stack frames. Windows commits stack
/// pages on demand via the guard page, so a no-op is safe for our frame sizes.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn __chkstk() {}

/// The SEH frame handler referenced by the x64 unwind tables; never invoked
/// for code without C++ exceptions.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn __CxxFrameHandler3() -> i32 {
    0
}

// ---------------------------------------------------------------------------
// Win32 FFI (kernel32 only — a small, clean import table).
// ---------------------------------------------------------------------------

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *const c_void;
    fn GetCommandLineW() -> *const u16;
    fn GetStdHandle(kind: u32) -> *mut c_void;
    fn WriteFile(
        file: *mut c_void,
        buf: *const c_void,
        n: u32,
        written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn GetCurrentProcessId() -> u32;
    fn GetTickCount() -> u32;
    fn GetSystemDirectoryW(buf: *mut u16, size: u32) -> u32;
    fn SetLastError(e: u32);
    fn GetLastError() -> u32;
    fn VirtualProtect(addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
    fn FlushInstructionCache(process: *mut c_void, base: *const c_void, size: usize) -> i32;
    fn SuspendThread(thread: *mut c_void) -> u32;
    fn GetCurrentThread() -> *mut c_void;
    fn ExitProcess(code: u32) -> !;
}

const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
const PAGE_READWRITE: u32 = 0x04;
const CURRENT_PROCESS: *mut c_void = usize::MAX as *mut c_void;

/// Scratch buffer for the scattered IAT (scenario D). A non-zero initializer
/// forces `.data` (writable and captured by a dump) rather than a `.bss` tail.
static mut SCRATCH: [u64; SCRATCH_SLOTS] = [0xDEAD_CAFE_0000_0001; SCRATCH_SLOTS];
const SCRATCH_SLOTS: usize = 2048;
const GAP: usize = 8; // slots of padding between per-module scatter blocks

// ---------------------------------------------------------------------------
// Console output (no std formatting).
// ---------------------------------------------------------------------------

struct Out(*mut c_void);

impl Out {
    fn new() -> Self {
        Out(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) })
    }
    fn write(&self, bytes: &[u8]) {
        let mut written = 0u32;
        unsafe {
            WriteFile(
                self.0,
                bytes.as_ptr() as *const c_void,
                bytes.len() as u32,
                &mut written,
                core::ptr::null_mut(),
            );
        }
    }
    fn write_str(&self, s: &str) {
        self.write(s.as_bytes());
    }
    fn write_u32(&self, mut v: u32) {
        let mut buf = [0u8; 10];
        let mut n = 0;
        if v == 0 {
            self.write(b"0");
            return;
        }
        while v > 0 {
            buf[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
        }
        for i in (0..n).rev() {
            self.write(&buf[i..i + 1]);
        }
    }
}

// ---------------------------------------------------------------------------
// Command-line parsing (wide, quote-aware).
// ---------------------------------------------------------------------------

const MAX_TOKENS: usize = 8;
const MAX_TOKEN_LEN: usize = 64;

fn parse_argv() -> (usize, [[u16; MAX_TOKEN_LEN]; MAX_TOKENS]) {
    let mut toks = [[0u16; MAX_TOKEN_LEN]; MAX_TOKENS];
    let mut n = 0usize;
    let cmd = unsafe { GetCommandLineW() };
    let mut pos = 0usize;
    while n < MAX_TOKENS {
        // Skip leading whitespace.
        while unsafe { *cmd.add(pos) } != 0 {
            let c = unsafe { *cmd.add(pos) };
            if c != b' ' as u16 && c != b'\t' as u16 {
                break;
            }
            pos += 1;
        }
        if unsafe { *cmd.add(pos) } == 0 {
            break;
        }
        // Collect one token (quote-aware).
        let mut j = 0usize;
        let mut quoted = false;
        while unsafe { *cmd.add(pos) } != 0 {
            let c = unsafe { *cmd.add(pos) };
            if c == b'"' as u16 {
                quoted = !quoted;
                pos += 1;
                continue;
            }
            if c == b' ' as u16 && !quoted {
                break;
            }
            if j < MAX_TOKEN_LEN - 1 {
                toks[n][j] = c;
                j += 1;
            }
            pos += 1;
        }
        toks[n][j] = 0;
        n += 1;
        // Consume the separator (space or tab).
        let c = unsafe { *cmd.add(pos) };
        if c == b' ' as u16 || c == b'\t' as u16 {
            pos += 1;
        }
    }
    (n, toks)
}

fn tok_eq(tok: &[u16; MAX_TOKEN_LEN], lit: &str) -> bool {
    let bytes = lit.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if tok[i] != c as u16 {
            return false;
        }
    }
    tok[bytes.len()] == 0
}

// ---------------------------------------------------------------------------
// Self-PE access (raw header walking).
// ---------------------------------------------------------------------------

fn base() -> u64 {
    unsafe { GetModuleHandleW(core::ptr::null()) as u64 }
}

fn u16_off(addr: u64) -> u16 {
    unsafe { (addr as *const u16).read_unaligned() }
}

fn u32_at(addr: u64) -> u32 {
    unsafe { (addr as *const u32).read_unaligned() }
}

fn u64_at(addr: u64) -> u64 {
    unsafe { (addr as *const u64).read_unaligned() }
}

/// Pointer to the data-directory array inside the optional header.
fn dirs(base: u64) -> *const u8 {
    let pe_off = u32_at(base + 0x3c) as u64;
    let opt = base + pe_off + 4 + 20;
    let magic = u16_off(opt);
    let dd = if magic == 0x20B { 112 } else { 96 };
    (opt + dd) as *const u8
}

fn poke(addr: u64, bytes: &[u8]) {
    let mut old = 0u32;
    unsafe {
        VirtualProtect(addr as *mut c_void, bytes.len(), PAGE_READWRITE, &mut old);
        for (i, &b) in bytes.iter().enumerate() {
            (addr as *mut u8).add(i).write(b);
        }
        VirtualProtect(addr as *mut c_void, bytes.len(), old, &mut old);
    }
}

fn zero_dir(dirs: *const u8, index: usize) {
    poke(dirs as u64 + (index * 8) as u64, &[0u8; 8]);
}

/// Iterate the import descriptors: `f(desc_rva, oft, name, ft) -> continue?`.
fn for_each_descriptor(base: u64, dirs: *const u8, mut f: impl FnMut(u32, u32, u32, u32) -> bool) {
    let import_rva = u32_at(dirs as u64 + 8);
    if import_rva == 0 {
        return;
    }
    let mut i = 0u32;
    loop {
        let desc_rva = import_rva.wrapping_add(i * 20);
        let d = base + desc_rva as u64;
        let oft = u32_at(d);
        let name = u32_at(d + 12);
        let ft = u32_at(d + 16);
        if oft == 0 && name == 0 && ft == 0 {
            break;
        }
        if !f(desc_rva, oft, name, ft) {
            break;
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// Scenarios.
// ---------------------------------------------------------------------------

/// B: the loader "overwrote" OriginalFirstThunk (0), so FirstThunk is the IAT.
fn zero_oft(base: u64, dirs: *const u8) {
    for_each_descriptor(base, dirs, |desc_rva, _o, _n, _f| {
        poke(base + desc_rva as u64, &[0u8; 4]); // OriginalFirstThunk = 0
        true
    });
}

/// D: erase both directories and scatter the IAT into a non-contiguous scratch
/// region, repointing every RIP-relative code reference.
fn erased(base: u64, dirs: *const u8) -> bool {
    // 1. Collect each module's FirstThunk run (resolved addresses).
    #[derive(Clone, Copy)]
    struct ModSlots {
        n: usize,
        slots: [(u32, u64); 64], // (slot rva, resolved address)
    }
    let mut mods: [(u32, ModSlots); 16] = [(
        0,
        ModSlots {
            n: 0,
            slots: [(0, 0); 64],
        },
    ); 16];
    let mut nmods = 0usize;
    for_each_descriptor(base, dirs, |_desc, _o, _n, ft| {
        if nmods >= 16 {
            return false;
        }
        let mut k = 0u32;
        loop {
            let slot = base + (ft + k * 8) as u64;
            let v = u64_at(slot);
            if v == 0 || k as usize >= 64 {
                break;
            }
            mods[nmods].1.slots[k as usize] = (ft + k * 8, v);
            k += 1;
        }
        mods[nmods].0 = ft;
        mods[nmods].1.n = k as usize;
        nmods += 1;
        true
    });
    let total: usize = mods[..nmods].iter().map(|m| m.1.n).sum();
    if total == 0 || total >= SCRATCH_SLOTS {
        return false;
    }

    // 2. Write resolved addresses into scratch blocks (scattered, with gaps)
    //    and build the old-slot → new-slot mapping.
    let scratch_va = core::ptr::addr_of!(SCRATCH) as usize as u64;
    let scratch_rva = scratch_va - base;
    let mut off = 0usize;
    let mut old_to_new: [(u32, u32); 512] = [(0, 0); 512];
    let mut mapping_len = 0usize;
    for m in &mods[..nmods] {
        let slots = &m.1.slots[..m.1.n];
        for (k, &(old_rva, v)) in slots.iter().enumerate() {
            let new_rva = (scratch_rva + (off + k) as u64 * 8) as u32;
            unsafe {
                core::ptr::addr_of_mut!(SCRATCH)
                    .cast::<u64>()
                    .add(off + k)
                    .write(v);
            }
            if mapping_len < old_to_new.len() {
                old_to_new[mapping_len] = (old_rva, new_rva);
                mapping_len += 1;
            }
        }
        off += slots.len() + GAP;
    }
    if off > SCRATCH_SLOTS {
        return false;
    }
    if mapping_len == 0 {
        return false;
    }

    // 3. Repoint every RIP-relative reference in the executable sections and
    //    write the patched code back into live memory.
    let mut patched = 0usize;
    let pe_off = u32_at(base + 0x3c) as u64;
    let opt = base + pe_off + 4 + 20;
    // COFF header sits just before the optional header: number_of_sections at
    // coff+2 (= opt-18), size_of_optional_header at coff+16 (= opt-4).
    let nsec = u16_off(opt - 18) as usize;
    let optsize = u16_off(opt - 4) as usize;
    let mut sec = opt + optsize as u64;
    for _ in 0..nsec {
        let chars = u32_at(sec + 36);
        if chars & 0x2000_0000 != 0 {
            // MEM_EXECUTE
            let va = u32_at(sec + 12);
            let vsize = u32_at(sec + 8);
            let rawsize = u32_at(sec + 16);
            let size = if vsize != 0 { vsize } else { rawsize } as usize;
            let mut old = 0u32;
            unsafe {
                VirtualProtect(
                    (base + va as u64) as *mut c_void,
                    size,
                    PAGE_READWRITE,
                    &mut old,
                );
            }
            patched += patch_text(base + va as u64, size, va, &old_to_new[..mapping_len]);
            unsafe {
                VirtualProtect((base + va as u64) as *mut c_void, size, old, &mut old);
                FlushInstructionCache(CURRENT_PROCESS, (base + va as u64) as *const c_void, size);
            }
        }
        sec += 40;
    }
    patched > 0
}

/// Scan one executable section for the RIP-relative IAT-reference patterns
/// (`FF 15`/`FF 25`/`FF 35` call/jmp/push, and the rex/`8B`/`8D` mov/lea
/// forms) whose target is an old slot, and rewrite the displacement.
fn patch_text(text: u64, len: usize, text_rva: u32, map: &[(u32, u32)]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i + 6 <= len {
        let b0 = unsafe { (text as *const u8).add(i).read() };
        let b1 = unsafe { (text as *const u8).add(i + 1).read() };
        let (insn_len, disp_off) = match (b0, b1) {
            (0xFF, 0x15 | 0x25 | 0x35) => (6usize, 2usize),
            (0x48 | 0x4C, 0xFF) => {
                let b2 = unsafe { (text as *const u8).add(i + 2).read() };
                match b2 {
                    0x15 | 0x25 | 0x35 => (7usize, 3usize),
                    _ => (0, 0),
                }
            }
            (0x48 | 0x4C, 0x8B | 0x8D) => {
                let b2 = unsafe { (text as *const u8).add(i + 2).read() };
                match b2 & 0xC7 {
                    0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => (7usize, 3usize),
                    _ => (0, 0),
                }
            }
            (0x8B | 0x8D, 0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D) => {
                (6usize, 2usize)
            }
            _ => (0, 0),
        };
        if insn_len == 0 || i + insn_len > len {
            i += 1;
            continue;
        }
        let disp = unsafe {
            (text as *const u8)
                .add(i + disp_off)
                .cast::<u32>()
                .read_unaligned()
        };
        let target = text_rva as u64 + i as u64 + insn_len as u64 + disp as u64;
        for &(old_rva, new_rva) in map {
            if old_rva as u64 == target {
                let new_disp = (new_rva as u64)
                    .wrapping_sub(text_rva as u64 + i as u64 + insn_len as u64)
                    as u32;
                unsafe {
                    (text as *mut u8)
                        .add(i + disp_off)
                        .cast::<u32>()
                        .write_unaligned(new_disp);
                }
                count += 1;
                break;
            }
        }
        i += 1;
    }
    count
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "system" fn mainCRTStartup() -> ! {
    let out = Out::new();
    let (argc, argv) = parse_argv();

    let mut scenario: Option<&[u8]> = None;
    let mut mode: &[u8] = b"run";
    if argc >= 3 && tok_eq(&argv[1], "corrupt") {
        mode = b"corrupt";
        for (name, s) in [
            ("normal", &b"normal"[..]),
            ("a", &b"normal"[..]),
            ("oft", &b"oft"[..]),
            ("b", &b"oft"[..]),
            ("iatdir", &b"iatdir"[..]),
            ("c", &b"iatdir"[..]),
            ("erased", &b"erased"[..]),
            ("d", &b"erased"[..]),
        ] {
            if tok_eq(&argv[2], name) {
                scenario = Some(s);
                break;
            }
        }
    } else if argc >= 2 && tok_eq(&argv[1], "verify") {
        mode = b"verify";
    }

    match mode {
        b"run" | b"verify" => run(&out),
        b"corrupt" => corrupt(scenario.unwrap_or(b"normal"), &out),
        _ => unreachable!(),
    }
}

fn run(out: &Out) -> ! {
    let pid = unsafe { GetCurrentProcessId() };
    let tick = unsafe { GetTickCount() };
    let mut sys = [0u16; 260];
    let sys_n = unsafe { GetSystemDirectoryW(sys.as_mut_ptr(), sys.len() as u32) };
    unsafe { SetLastError(0x5) };
    let err = unsafe { GetLastError() };

    out.write_str("SIM_TARGET_OK pid=");
    out.write_u32(pid);
    out.write_str(" tick=");
    out.write_u32(tick);
    out.write_str(" err=");
    out.write_u32(err);
    out.write_str(" sysdir_len=");
    out.write_u32(sys_n);
    out.write(b"\n");
    unsafe { ExitProcess(0) }
}

fn corrupt(scenario: &[u8], out: &Out) -> ! {
    let base = base();
    let dirs = dirs(base);

    match scenario {
        b"normal" => {}
        b"oft" => zero_oft(base, dirs),
        b"iatdir" => zero_dir(dirs, 1),
        b"erased" => {
            zero_dir(dirs, 1);
            zero_dir(dirs, 12);
            let scattered = erased(base, dirs);
            if !scattered {
                // degraded to erasure-only
            }
        }
        _ => {}
    }

    let pid = unsafe { GetCurrentProcessId() };
    out.write_str("SIM_TARGET_READY:");
    out.write_u32(pid);
    out.write(b"\n");

    // Simulate being paused by a debugger: freeze this thread so a standalone
    // pe dump tool reads a stable image. The target never runs again — a real
    // dump tool attaches to the paused process, reads it, and terminates it.
    unsafe {
        SuspendThread(GetCurrentThread());
    }
    // Only reached if something resumes the thread; spin rather than busy-loop.
    loop {
        core::hint::spin_loop();
    }
}
