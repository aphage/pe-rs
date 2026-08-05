//! Inline API-hook tracer (Scylla's "Tracer").
//!
//! Installs an x64 inline hook on a function inside a (possibly remote)
//! process: the first 14 bytes of the function are replaced with an absolute
//! jump to a stub we allocate, the stub logs the call (hook id + first four
//! arguments) into a shared buffer, then jumps to a trampoline that executes
//! the original prologue bytes and jumps back past the patch. This forwards
//! every call to the original, so the hooked process keeps working while we
//! record which APIs it invokes.
//!
//! Limitation: the trampoline copies the original prologue verbatim, so it is
//! only valid when those bytes are position-independent (no RIP-relative
//! addressing in the first 14 bytes) and instruction-aligned. This is the case
//! for the common `push rbp / mov rbp,rsp / sub rsp,..` prologue.

use std::ffi::c_void;

use crate::error::{PeError, Result};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx, VirtualProtectEx,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

/// Size of the log entry: hook id + four arguments.
const LOG_ENTRY: usize = 40;
/// Maximum number of traced calls held in the shared log.
const LOG_CAP: usize = 4096;
/// The absolute jump we write over the function prologue.
const PATCH_LEN: usize = 14;
/// Stub region layout: stub at 0, trampoline after the stub.
const STUB_LEN: usize = 0x100;
const TRAMPOLINE_LEN: usize = 0x40;

/// One recorded API call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEntry {
    pub hook_id: u64,
    pub name: String,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
}

/// A hooked function.
struct Hook {
    id: u64,
    name: String,
    function_addr: u64,
    /// The original prologue bytes we overwrote (for restoring).
    original: [u8; PATCH_LEN],
}

/// Attaches to a process and installs/reads inline hooks.
pub struct Tracer {
    pid: u32,
    handle: HANDLE,
    /// Shared call log in the target: `[index u64][entries…]`.
    log_base: u64,
    hooks: Vec<Hook>,
    unhooked: bool,
}

impl Tracer {
    /// Open `pid` for reading, writing and patching its memory.
    pub fn attach(pid: u32) -> Result<Self> {
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_INFORMATION
                    | PROCESS_VM_OPERATION
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE,
                0,
                pid,
            );
            if handle.is_null() {
                return Err(PeError::Io(std::io::Error::last_os_error()));
            }
            let mut tracer = Self {
                pid,
                handle,
                log_base: 0,
                hooks: Vec::new(),
                unhooked: false,
            };
            tracer.log_base = tracer.alloc(8 + LOG_CAP * LOG_ENTRY)?;
            Ok(tracer)
        }
    }

    /// Install an inline hook on `function_addr`. Returns the hook id.
    pub fn install_hook(&mut self, name: &str, function_addr: u64) -> Result<u64> {
        if self.log_base == 0 {
            self.log_base = self.alloc(8 + LOG_CAP * LOG_ENTRY)?;
        }
        let id = self.hooks.len() as u64 + 1;

        // Save the original prologue.
        let original: [u8; PATCH_LEN] = self
            .read(function_addr, PATCH_LEN)?
            .try_into()
            .map_err(|_| PeError::InvalidArgument("cannot read hook prologue".into()))?;

        // Allocate one RWX region for the stub + trampoline.
        let region = self.alloc(STUB_LEN + TRAMPOLINE_LEN)?;
        let stub = build_hook_stub(self.log_base, id, region + STUB_LEN as u64);
        let trampoline = build_trampoline(&original, function_addr);
        self.write(region, &stub)?;
        self.write(region + STUB_LEN as u64, &trampoline)?;

        // Patch the target function with an absolute jump to the stub.
        let mut patch = [0u8; PATCH_LEN];
        patch[..6].copy_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // jmp [rip+0]
        patch[6..].copy_from_slice(&region.to_le_bytes());
        let mut old = 0u32;
        self.protect(function_addr, PATCH_LEN, PAGE_EXECUTE_READWRITE, &mut old)?;
        self.write(function_addr, &patch)?;
        self.protect(function_addr, PATCH_LEN, old, &mut 0u32)?;

        self.hooks.push(Hook {
            id,
            name: name.to_string(),
            function_addr,
            original,
        });
        Ok(id)
    }

    /// Read back the recorded calls.
    pub fn read_trace(&self) -> Result<Vec<TraceEntry>> {
        if self.log_base == 0 {
            return Ok(Vec::new());
        }
        let idx_bytes = self.read(self.log_base, 8)?;
        let idx = u64::from_le_bytes(idx_bytes[..8].try_into().unwrap()) as usize;
        let idx = idx.min(LOG_CAP);
        let bytes = self.read(self.log_base + 8, idx * LOG_ENTRY)?;
        let mut out = Vec::with_capacity(idx);
        for i in 0..idx {
            let off = i * LOG_ENTRY;
            let hook_id = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            let name = self
                .hooks
                .iter()
                .find(|h| h.id == hook_id)
                .map(|h| h.name.clone())
                .unwrap_or_default();
            out.push(TraceEntry {
                hook_id,
                name,
                arg1: u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap()),
                arg2: u64::from_le_bytes(bytes[off + 16..off + 24].try_into().unwrap()),
                arg3: u64::from_le_bytes(bytes[off + 24..off + 32].try_into().unwrap()),
                arg4: u64::from_le_bytes(bytes[off + 32..off + 40].try_into().unwrap()),
            });
        }
        Ok(out)
    }

    /// Restore the original prologue of every hooked function.
    pub fn uninstall(&mut self) -> Result<()> {
        if self.unhooked {
            return Ok(());
        }
        for hook in &self.hooks {
            let mut old = 0u32;
            self.protect(
                hook.function_addr,
                PATCH_LEN,
                PAGE_EXECUTE_READWRITE,
                &mut old,
            )?;
            self.write(hook.function_addr, &hook.original)?;
            let mut _discard = 0u32;
            self.protect(hook.function_addr, PATCH_LEN, old, &mut _discard)?;
        }
        self.hooks.clear();
        self.unhooked = true;
        Ok(())
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn hooked(&self) -> Vec<String> {
        self.hooks.iter().map(|h| h.name.clone()).collect()
    }

    fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        unsafe {
            let mut buf = vec![0u8; size];
            let mut read = 0usize;
            let ok = ReadProcessMemory(
                self.handle,
                addr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                size,
                &mut read,
            );
            if ok == 0 {
                return Err(PeError::Io(std::io::Error::last_os_error()));
            }
            buf.truncate(read);
            Ok(buf)
        }
    }

    fn write(&self, addr: u64, bytes: &[u8]) -> Result<()> {
        unsafe {
            let mut written = 0usize;
            let ok = WriteProcessMemory(
                self.handle,
                addr as *const c_void,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                &mut written,
            );
            if ok == 0 {
                return Err(PeError::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        }
    }

    fn alloc(&self, size: usize) -> Result<u64> {
        unsafe {
            let p = VirtualAllocEx(
                self.handle,
                std::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if p.is_null() {
                return Err(PeError::Io(std::io::Error::last_os_error()));
            }
            Ok(p as u64)
        }
    }

    fn protect(&self, addr: u64, size: usize, new_prot: u32, old: &mut u32) -> Result<()> {
        unsafe {
            let ok = VirtualProtectEx(self.handle, addr as *const c_void, size, new_prot, old);
            if ok == 0 {
                return Err(PeError::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        }
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        let _ = self.uninstall();
        unsafe { CloseHandle(self.handle) };
    }
}

/// Build the hook stub that logs the call and forwards to `trampoline_addr`.
fn build_hook_stub(log_base: u64, hook_id: u64, trampoline_addr: u64) -> Vec<u8> {
    let mut b = Vec::new();
    // save args + rax
    b.extend_from_slice(&[0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x50]); // push rcx rdx r8 r9 rax
    // mov rax, imm64(log_base)
    b.extend_from_slice(&[0x48, 0xB8]);
    let log_off = b.len();
    b.extend_from_slice(&[0; 8]);
    // mov r10, [rax]              ; r10 = log index
    b.extend_from_slice(&[0x4C, 0x8B, 0x10]);
    // lea r11, [r10 + r10*4]      ; r11 = r10 * 5
    b.extend_from_slice(&[0x4F, 0x8D, 0x1C, 0x92]);
    // lea r11, [rax + r11*8 + 8]  ; r11 = log_base + 8 + r10*40 (entry addr)
    b.extend_from_slice(&[0x4E, 0x8D, 0x5C, 0xD8, 0x08]);
    // mov rdx, imm64(hook_id)
    b.extend_from_slice(&[0x48, 0xBA]);
    let id_off = b.len();
    b.extend_from_slice(&[0; 8]);
    // mov [r11], rdx              ; entry.hook_id
    b.extend_from_slice(&[0x49, 0x89, 0x13]);
    // store the four args (saved on the stack)
    b.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x20, 0x49, 0x89, 0x4B, 0x08]); // [rsp+32]->arg1
    b.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x18, 0x49, 0x89, 0x4B, 0x10]); // [rsp+24]->arg2
    b.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x10, 0x49, 0x89, 0x4B, 0x18]); // [rsp+16]->arg3
    b.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x08, 0x49, 0x89, 0x4B, 0x20]); // [rsp+8]->arg4
    // inc r10 ; mov [rax], r10     ; index += 1
    b.extend_from_slice(&[0x49, 0xFF, 0xC2, 0x4C, 0x89, 0x10]);
    // restore
    b.extend_from_slice(&[0x58, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59]); // pop rax r9 r8 rdx rcx
    // jmp qword ptr [rip+0]
    b.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    let tramp_off = b.len();
    b.extend_from_slice(&[0; 8]);

    patch_u64(&mut b, log_off, log_base);
    patch_u64(&mut b, id_off, hook_id);
    patch_u64(&mut b, tramp_off, trampoline_addr);
    b
}

/// Build the trampoline: the original prologue bytes followed by a jump back to
/// `function_addr + PATCH_LEN`.
fn build_trampoline(original: &[u8; PATCH_LEN], function_addr: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(original);
    b.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // jmp [rip+0]
    b.extend_from_slice(&(function_addr + PATCH_LEN as u64).to_le_bytes());
    b
}

fn patch_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
