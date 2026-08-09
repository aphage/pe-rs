//! A plain `std` program that reproduces the runtime-written-pointer problem
//! `pe_scylla::feature::rebase_dump` addresses: `CACHED` is a `.data` slot whose
//! initializer points into the image (so the linker registers a relocation
//! entry), and at runtime the program overwrites it with an *external* absolute
//! pointer (`GetProcAddress("GetTickCount")`).
//!
//! **Known limitation**: unlike the no_std `sim-target`, a *full* `std` Rust
//! program's dump cannot currently be made to re-run — even with `--rebase`,
//! the Rust runtime's own `lang_start` init (TLS/allocator/panic state in
//! `.data`) crashes on the re-run, independent of the `CACHED` slot. This
//! binary is kept as the reproduction for debugging that in WinDbg; the
//! `rebase_dump` end-to-end validation lives in `sim-target`'s `pollute`
//! scenario, which is runtime-clean so the fix is observable.
//!
//! Modes:
//! - `std-target` — write the external pointer into `CACHED`, print
//!   `STD_TARGET_READY:<pid>` and suspend (paused, like a debugger break).
//! - `std-target verify` — if `CACHED` is null resolve it again, call through
//!   it, print `STD_TARGET_OK` and exit 0.

use std::ffi::c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn SuspendThread(thread: *mut c_void) -> u32;
    fn GetCurrentThread() -> *mut c_void;
}

/// Image-internal initializer → the linker registers a relocation entry for
/// this slot. Runtime overwrites it with an external address.
static DUMMY: u8 = 0xAA;
static mut CACHED: *const u8 = &DUMMY;

fn resolve_get_tick_count() -> *const u8 {
    let kernel32: Vec<u16> = "kernel32.dll".encode_utf16().collect();
    let module = unsafe { GetModuleHandleW(kernel32.as_ptr()) };
    let name = c"GetTickCount";
    unsafe { GetProcAddress(module, name.as_ptr().cast()) as *const u8 }
}

fn call_get_tick_count() -> u32 {
    let f: unsafe extern "system" fn() -> u32 = unsafe { std::mem::transmute(CACHED) };
    unsafe { f() }
}

fn main() {
    let verify = std::env::args().skip(1).any(|a| a == "verify");
    if verify {
        // The fixed dump: rebase cleared CACHED (it held an external pointer),
        // so resolve it lazily again and call through it.
        if unsafe { CACHED.is_null() } {
            unsafe { CACHED = resolve_get_tick_count() };
        }
        let tick = call_get_tick_count();
        println!("STD_TARGET_OK pid={} tick={tick}", std::process::id());
        return;
    }

    // First run: write an external absolute pointer into the .reloc-covered
    // slot, then pause for the dump tool.
    unsafe { CACHED = resolve_get_tick_count() };
    println!("STD_TARGET_READY:{}", std::process::id());
    unsafe { SuspendThread(GetCurrentThread()) };
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
