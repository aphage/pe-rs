//! Inline hook tracer test (ignored: hooks our own process to verify the
//! mechanism).
//!
//! The hooked "function" is a hand-written x64 machine-code routine whose first
//! 14 bytes are exactly whole, position-independent instructions ending on an
//! instruction boundary (two nops), so the trampoline forwards cleanly.

use std::ffi::c_void;

use pe_scylla::process::tracer::Tracer;
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

/// `arg1 + arg2`:
/// ```text
/// push rbp              55
/// mov rbp, rsp          48 89 E5
/// sub rsp, 8            48 83 EC 08
/// mov [rbp-8], rcx      48 89 4D F8
/// nop nop               90 90            <- 14-byte instruction boundary
/// mov [rbp-16], rdx     48 89 55 F0
/// mov rax, [rbp-8]      48 8B 45 F8
/// add rax, [rbp-16]     48 03 45 F0
/// add rsp, 8            48 83 C4 08
/// pop rbp               5D
/// ret                   C3
/// ```
const TRACED_FN_CODE: [u8; 40] = [
    0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x89, 0x4D, 0xF8, 0x90, 0x90, 0x48, 0x89,
    0x55, 0xF0, 0x48, 0x8B, 0x45, 0xF8, 0x48, 0x03, 0x45, 0xF0, 0x48, 0x83, 0xC4, 0x08, 0x5D, 0xC3,
    0, 0, 0, 0, 0, 0, 0, 0,
];

static mut TRACED_FN_CODE_RWX: [u8; 40] = TRACED_FN_CODE;

#[test]
#[ignore]
fn tracer_self_hook_logs_and_forwards() {
    unsafe {
        let code_ptr = std::ptr::addr_of_mut!(TRACED_FN_CODE_RWX) as *mut c_void;
        let mut old = 0u32;
        assert_ne!(
            VirtualProtect(code_ptr, 40, PAGE_EXECUTE_READWRITE, &mut old),
            0,
            "VirtualProtect failed"
        );
        let fn_addr = code_ptr as u64;
        let f: unsafe extern "C" fn(u64, u64) -> u64 = std::mem::transmute(fn_addr as usize);

        let mut tracer = Tracer::attach(std::process::id()).expect("attach");
        assert_eq!(f(7, 2), 9); // before hooking

        let id = tracer.install_hook("traced_fn", fn_addr).expect("install");
        assert_eq!(tracer.hooked(), vec!["traced_fn".to_string()]);

        // Calls after hooking must forward to the original body.
        assert_eq!(f(7, 2), 9);
        assert_eq!(f(10, 3), 13);
        let _ = f(1, 1);

        let trace = tracer.read_trace().expect("read trace");
        assert_eq!(trace.len(), 3);
        assert!(trace.iter().all(|e| e.hook_id == id));
        assert_eq!(trace[0].arg1, 7);
        assert_eq!(trace[0].arg2, 2);
        assert_eq!(trace[1].arg1, 10);
        assert_eq!(trace[1].arg2, 3);

        // Uninstall restores the original prologue; no further calls are traced.
        tracer.uninstall().expect("uninstall");
        assert_eq!(f(7, 2), 9);
        let trace2 = tracer.read_trace().expect("read trace 2");
        assert_eq!(trace2.len(), 3);
    }
}
