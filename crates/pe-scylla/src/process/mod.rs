//! Windows process-level features: reading a live process's image and resolving
//! IAT addresses against its loaded modules. Compiled only on Windows.
//!
//! This is the process side of Scylla's workflow: [`dump`] produces a
//! [`PeDocument`] from a running process's main module by reading its image
//! from memory, and [`ProcessResolver`] resolves absolute addresses to
//! `(module, function)` so the IAT scanner / fixer can operate on the dump.
//! [`tracer`] installs inline API hooks to trace calls in a target process.

pub mod tracer;

use std::collections::HashMap;
use std::ffi::c_void;

use pe_edit::api::resolver::{ImportResolver, ResolvedImport};
use pe_edit::domain::data_directory::{DataDirectory, DataDirectoryIndex};
use pe_edit::domain::dos::DOS_MAGIC;
use pe_edit::domain::import::ImportFunction;
use pe_edit::domain::optional::PE32_MAGIC;
use pe_edit::domain::types::Rva;
use pe_edit::domain::{PeDocument, Section};
use pe_edit::error::{PeError, Result};
use pe_edit::io::pe::parser::{
    parse_coff, parse_dos, parse_exports_from_doc, parse_imports_from_doc,
    parse_load_config_from_doc, parse_optional, parse_relocations_from_doc,
    parse_resources_from_doc, parse_section_headers, parse_tls_from_doc,
};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{DebugActiveProcessStop, ReadProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModules, GetModuleBaseNameW, GetModuleInformation, MODULEINFO,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, TerminateProcess,
};

fn open_process(pid: u32) -> Result<HANDLE> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return Err(PeError::Io(std::io::Error::last_os_error()));
        }
        Ok(handle)
    }
}

/// Read `size` bytes of a process's memory at `base`.
pub fn read_memory(pid: u32, base: u64, size: usize) -> Result<Vec<u8>> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return Err(PeError::Io(std::io::Error::last_os_error()));
        }
        let mut buf = vec![0u8; size];
        let mut read = 0usize;
        let ok = ReadProcessMemory(
            handle,
            base as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            size,
            &mut read,
        );
        CloseHandle(handle);
        if ok == 0 {
            return Err(PeError::Io(std::io::Error::last_os_error()));
        }
        buf.truncate(read);
        Ok(buf)
    }
}

/// The base address and size of a process's main (executable) module.
pub fn module_range(pid: u32) -> Result<(u64, u32)> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(PeError::Io(std::io::Error::last_os_error()));
        }
        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return Err(PeError::Io(std::io::Error::last_os_error()));
        }
        let base = entry.modBaseAddr as usize as u64;
        let size = entry.modBaseSize;
        CloseHandle(snapshot);
        Ok((base, size))
    }
}

/// A module (main exe or loaded DLL) inside a process.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Short module name (file name, e.g. `kernel32.dll`). The first entry is
    /// the process's main module.
    pub name: String,
    pub base: u64,
    pub size: u32,
}

/// List the process's loaded modules (main executable first, then DLLs).
pub fn list_modules(pid: u32) -> Result<Vec<ModuleInfo>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(PeError::Io(std::io::Error::last_os_error()));
        }
        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        let mut out = Vec::new();
        let mut ok = Module32FirstW(snapshot, &mut entry);
        while ok != 0 {
            let len = entry
                .szModule
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szModule.len());
            let full = String::from_utf16_lossy(&entry.szModule[..len]);
            let name = full
                .rsplit(['\\', '/'])
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or(&full)
                .to_string();
            out.push(ModuleInfo {
                name,
                base: entry.modBaseAddr as usize as u64,
                size: entry.modBaseSize,
            });
            ok = Module32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
        Ok(out)
    }
}

/// A running process (PID + executable name), for the GUI's process picker.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

/// List running processes via a ToolHelp snapshot. Access-denied entries are
/// simply omitted; a failed snapshot itself is a [`PeError`].
pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(PeError::Io(std::io::Error::last_os_error()));
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut out = Vec::new();
        let mut ok = Process32FirstW(snapshot, &mut entry);
        while ok != 0 {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            out.push(ProcessInfo {
                pid: entry.th32ProcessID,
                name: String::from_utf16_lossy(&entry.szExeFile[..len]),
            });
            ok = Process32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
        Ok(out)
    }
}

/// Build a [`PeDocument`] from a running process's **main** module, reading its
/// image from process memory (each section at `image_base + virtual_address`).
pub fn dump(pid: u32) -> Result<PeDocument> {
    let (base, _size) = module_range(pid)?;
    dump_at(pid, base)
}

/// A process created with [`spawn_paused`]: fully loaded by the OS and paused at
/// its **entry point**, before any of the program's own code has run — the ideal
/// state to dump. Dropping the handle terminates the process and detaches the
/// debugger.
pub struct PausedProcess {
    process: HANDLE,
    thread: HANDLE,
    pub pid: u32,
    /// RVA of the entry point, whose byte was temporarily replaced by a
    /// breakpoint while paused.
    entry_rva: Option<u32>,
    /// The original entry-point byte, to restore into the dump.
    original_entry_byte: Option<u8>,
}

impl PausedProcess {
    /// Restore the entry-point byte that was temporarily replaced by a
    /// breakpoint, so a dump taken while paused at the entry has intact code.
    pub fn restore_entry_byte(&self, doc: &mut PeDocument) -> Result<()> {
        if let (Some(rva), Some(byte)) = (self.entry_rva, self.original_entry_byte) {
            doc.write(Rva(rva), &[byte])?;
        }
        Ok(())
    }
}

impl Drop for PausedProcess {
    fn drop(&mut self) {
        unsafe {
            TerminateProcess(self.process, 0);
            DebugActiveProcessStop(self.pid);
            CloseHandle(self.process);
            CloseHandle(self.thread);
        }
    }
}

/// Create `exe` (with `args`) as a debuggee and wait until the OS loader has
/// fully initialized it — image mapped, relocations applied, imports resolved,
/// TLS set up, `.data`/`.bss` in their initial state — and it is paused at its
/// **entry point**, before any program code has run. This is the clean, correct
/// moment to dump (Scylla's "attach, break at entry, fix").
///
/// The debugger arms a breakpoint at the entry (`INT 3`); every earlier event
/// (process creation, DLL loads, the loader's own attach break) is continued
/// until that breakpoint. [`PausedProcess::restore_entry_byte`] puts the
/// original entry byte back into a dump.
pub fn spawn_paused(exe: &str, args: &[String]) -> Result<PausedProcess> {
    use windows_sys::Win32::Foundation::{DBG_CONTINUE, EXCEPTION_BREAKPOINT};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CREATE_PROCESS_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
        WaitForDebugEvent, WriteProcessMemory,
    };
    use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtectEx};
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DEBUG_ONLY_THIS_PROCESS, DEBUG_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let mut cmdline: Vec<u16> = exe.encode_utf16().collect();
    for a in args {
        cmdline.push(b' ' as u16);
        cmdline.extend(a.encode_utf16());
    }
    cmdline.push(0);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmdline.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(PeError::Io(std::io::Error::last_os_error()));
    }
    let pid = pi.dwProcessId;
    let process = pi.hProcess;
    let thread = pi.hThread;

    let mut entry_va: Option<u64> = None;
    let mut entry_rva: Option<u32> = None;
    let mut original_entry_byte: Option<u8> = None;
    loop {
        let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        if unsafe { WaitForDebugEvent(&mut ev, 10_000) } == 0 {
            break;
        }
        match ev.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let base = unsafe { ev.u.CreateProcessInfo.lpBaseOfImage } as u64;
                // Compute the entry point VA from the main module's headers.
                if let Ok(dos) = read_memory(pid, base, 64) {
                    let pe_off = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
                    if let Ok(nt) = read_memory(pid, base + pe_off, 24 + 0x100) {
                        let rva = u32::from_le_bytes(nt[40..44].try_into().unwrap());
                        entry_rva = Some(rva);
                        entry_va = Some(base + rva as u64);
                    }
                }
                // Arm a breakpoint at the entry: save the original byte, write
                // an `INT 3`, so the loader's remaining init runs and the
                // process stops at the entry — loaded, but not run.
                if let Some(va) = entry_va {
                    let mut orig = [0u8; 1];
                    let mut read = 0usize;
                    let ok = unsafe {
                        ReadProcessMemory(
                            process,
                            va as *const c_void,
                            orig.as_mut_ptr() as *mut c_void,
                            1,
                            &mut read,
                        )
                    };
                    if ok != 0 && read == 1 {
                        original_entry_byte = Some(orig[0]);
                        let mut old = 0u32;
                        unsafe {
                            VirtualProtectEx(
                                process,
                                va as *const c_void,
                                1,
                                PAGE_READWRITE,
                                &mut old,
                            );
                            let cc = [0xCCu8];
                            let mut written = 0usize;
                            WriteProcessMemory(
                                process,
                                va as *const c_void,
                                cc.as_ptr() as *const c_void,
                                1,
                                &mut written,
                            );
                            VirtualProtectEx(process, va as *const c_void, 1, old, &mut old);
                        }
                    }
                }
                unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
            }
            EXCEPTION_DEBUG_EVENT => {
                let code = unsafe { ev.u.Exception.ExceptionRecord.ExceptionCode };
                let addr = unsafe { ev.u.Exception.ExceptionRecord.ExceptionAddress } as u64;
                if code == EXCEPTION_BREAKPOINT && Some(addr) == entry_va {
                    // Paused at the entry point: fully loaded, nothing run.
                    return Ok(PausedProcess {
                        process,
                        thread,
                        pid,
                        entry_rva,
                        original_entry_byte,
                    });
                }
                unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
            }
            _ => unsafe {
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            },
        }
    }

    // Failed to reach the entry point: clean up.
    unsafe {
        TerminateProcess(process, 0);
        DebugActiveProcessStop(pid);
        CloseHandle(process);
        CloseHandle(thread);
    }
    Err(PeError::NotFound(
        "paused process did not reach its entry point".into(),
    ))
}

/// Build a [`PeDocument`] from **any** loaded module of a process (e.g. a DLL
/// in the process, not just the main executable). `base` comes from
/// [`list_modules`].
pub fn dump_module(pid: u32, base: u64) -> Result<PeDocument> {
    dump_at(pid, base)
}

/// Read the PE image at `base` in `pid`'s address space into a [`PeDocument`].
fn dump_at(pid: u32, base: u64) -> Result<PeDocument> {
    let dos_bytes = read_memory(pid, base, 64)?;
    let dos = parse_dos(&dos_bytes)?;
    if dos.e_magic != DOS_MAGIC {
        return Err(PeError::Malformed("bad DOS magic".into()));
    }
    let pe_off = dos.e_lfanew as usize;

    let sig_coff = read_memory(pid, base + pe_off as u64, 24)?;
    if &sig_coff[0..4] != b"PE\0\0" {
        return Err(PeError::Malformed("missing PE signature".into()));
    }
    let coff = parse_coff(&sig_coff, 4)?;
    let opt_size = coff.size_of_optional_header as usize;
    let nsec = coff.number_of_sections as usize;

    let headers = read_memory(pid, base + pe_off as u64 + 24, opt_size + nsec * 40)?;
    let (optional, dir_array) = parse_optional(&headers, 0, opt_size)?;
    // `size_of_optional_header` already includes the data-directory array, so
    // the section table starts right after it.
    let section_headers = parse_section_headers(&headers, opt_size, nsec)?;

    let mut sections = Vec::with_capacity(section_headers.len());
    for sh in &section_headers {
        let va = sh.virtual_address.get() as u64;
        let size = if sh.virtual_size != 0 {
            sh.virtual_size as usize
        } else {
            sh.size_of_raw_data as usize
        };
        let data = read_memory(pid, base + va, size)?;
        sections.push(Section {
            header: sh.clone(),
            data,
        });
    }

    let n = (optional.number_of_rva_and_sizes() as usize).min(DataDirectoryIndex::COUNT);
    let mut dirs = vec![DataDirectory::default(); DataDirectoryIndex::COUNT];
    for (i, slot) in dirs.iter_mut().take(n).enumerate() {
        *slot = DataDirectory {
            rva: Rva(dir_array[i].VirtualAddress),
            size: dir_array[i].Size,
        };
    }

    let mut doc = PeDocument {
        arch: optional.arch(),
        dos,
        coff,
        optional,
        sections,
        data_directories: dirs,
        imports: Vec::new(),
        exports: None,
        resources: None,
        relocations: None,
        tls: None,
        load_config: None,
    };

    let import_dir = doc.data_directory(DataDirectoryIndex::Import).ok().copied();
    if let Some(dd) = import_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.imports = parse_imports_from_doc(&doc, dd.rva).unwrap_or_default();
    }
    let export_dir = doc.data_directory(DataDirectoryIndex::Export).ok().copied();
    if let Some(dd) = export_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.exports = parse_exports_from_doc(&doc, dd).ok().flatten();
    }
    let resource_dir = doc
        .data_directory(DataDirectoryIndex::Resource)
        .ok()
        .copied();
    if let Some(dd) = resource_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.resources = parse_resources_from_doc(&doc, dd).ok();
    }
    let reloc_dir = doc
        .data_directory(DataDirectoryIndex::BaseReloc)
        .ok()
        .copied();
    if let Some(dd) = reloc_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.relocations = parse_relocations_from_doc(&doc, dd).ok();
    }
    let tls_dir = doc.data_directory(DataDirectoryIndex::Tls).ok().copied();
    if let Some(dd) = tls_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.tls = parse_tls_from_doc(&doc, dd).ok();
    }
    let lc_dir = doc
        .data_directory(DataDirectoryIndex::LoadConfig)
        .ok()
        .copied();
    if let Some(dd) = lc_dir.filter(|dd| dd.rva != Rva::NULL) {
        doc.load_config = parse_load_config_from_doc(&doc, dd).ok();
    }

    Ok(doc)
}

/// Resolves IAT addresses against a live process's loaded modules, reading each
/// module's export table from process memory. This is the resolver a GUI would
/// use to scan / fix the IAT of a dumped process.
pub struct ProcessResolver {
    pid: u32,
    modules: Vec<ModuleExports>,
    /// Code fingerprint of every named export of the system-loaded modules,
    /// used to resolve addresses in *memory-loaded* (manually mapped) modules
    /// that the OS module list does not report. Empty unless
    /// [`ProcessResolver::with_fingerprints`] was called.
    fingerprints: HashMap<u64, Vec<FingerprintCandidate>>,
}

struct ModuleExports {
    base: u64,
    size: u32,
    name: String,
    /// Offset within the module → exported function.
    functions: HashMap<u32, ImportFunction>,
}

/// An export's first 16 code bytes, for matching memory-loaded modules.
struct FingerprintCandidate {
    module: String,
    function: ImportFunction,
    prefix: [u8; 16],
}

impl ProcessResolver {
    /// Enumerate `pid`'s loaded modules and read their exports.
    pub fn for_process(pid: u32) -> Result<Self> {
        let handle = open_process(pid)?;
        let modules = unsafe { enumerate_modules(handle, pid)? };
        unsafe { CloseHandle(handle) };
        Ok(Self {
            pid,
            modules,
            fingerprints: HashMap::new(),
        })
    }

    /// Also record the code fingerprint of every export, enabling resolution
    /// of addresses in memory-loaded (manually mapped) modules via
    /// [`ProcessResolver::resolve_fingerprint`].
    pub fn with_fingerprints(mut self) -> Result<Self> {
        self.fingerprints = build_fingerprints(self.pid, &self.modules);
        Ok(self)
    }

    /// The names of all loaded modules (for diagnostics).
    pub fn module_names(&self) -> Vec<String> {
        self.modules.iter().map(|m| m.name.clone()).collect()
    }

    /// Resolve `address` by matching its code bytes against the exports of the
    /// system-loaded modules. This works for **memory-loaded** (manually
    /// mapped) modules that `EnumProcessModules` does not report — their code
    /// is byte-identical to the system copy, even if the PE header was erased.
    /// Requires [`ProcessResolver::with_fingerprints`].
    pub fn resolve_fingerprint(&self, address: u64) -> Option<ResolvedImport> {
        let bytes = read_memory(self.pid, address, 16).ok()?;
        if bytes.len() < 16 {
            return None;
        }
        let key = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let candidates = self.fingerprints.get(&key)?;
        for c in candidates {
            if c.prefix[8..] == bytes[8..] {
                return Some(ResolvedImport {
                    module: c.module.clone(),
                    function: c.function.clone(),
                });
            }
        }
        None
    }
}

impl ImportResolver for ProcessResolver {
    fn resolve(&self, address: u64) -> Option<ResolvedImport> {
        // Fast path: the address is inside an OS-loaded module.
        for m in &self.modules {
            if address >= m.base && address < m.base + m.size as u64 {
                let off = (address - m.base) as u32;
                return m.functions.get(&off).map(|f| ResolvedImport {
                    module: m.name.clone(),
                    function: f.clone(),
                });
            }
        }
        // Fallback: a memory-loaded module (manual mapping) not reported by the
        // OS — resolve by matching the code against the system-loaded copy.
        self.resolve_fingerprint(address)
    }
}

/// Read the first 16 code bytes of every named export of each loaded module
/// and index them by their leading 8 bytes.
fn build_fingerprints(
    pid: u32,
    modules: &[ModuleExports],
) -> HashMap<u64, Vec<FingerprintCandidate>> {
    let mut map: HashMap<u64, Vec<FingerprintCandidate>> = HashMap::new();
    for m in modules {
        for (off, function) in &m.functions {
            let Ok(bytes) = read_memory(pid, m.base + *off as u64, 16) else {
                continue;
            };
            if bytes.len() < 16 {
                continue;
            }
            let mut prefix = [0u8; 16];
            prefix.copy_from_slice(&bytes[..16]);
            map.entry(u64::from_le_bytes(prefix[0..8].try_into().unwrap()))
                .or_default()
                .push(FingerprintCandidate {
                    module: m.name.clone(),
                    function: function.clone(),
                    prefix,
                });
        }
    }
    map
}

/// SAFETY: calls into `EnumProcessModules` / `GetModuleInformation` /
/// `GetModuleBaseNameW` and reads exports via `read_memory`.
unsafe fn enumerate_modules(handle: HANDLE, pid: u32) -> Result<Vec<ModuleExports>> {
    unsafe {
        let mut needed = 0u32;
        if EnumProcessModules(handle, std::ptr::null_mut(), 0, &mut needed) == 0 {
            return Err(PeError::Io(std::io::Error::last_os_error()));
        }
        let count = needed as usize / std::mem::size_of::<HANDLE>();
        let mut modules = vec![std::ptr::null_mut::<c_void>(); count.max(1)];
        if EnumProcessModules(handle, modules.as_mut_ptr(), needed, &mut needed) == 0 {
            return Err(PeError::Io(std::io::Error::last_os_error()));
        }

        let mut out = Vec::with_capacity(count);
        for &hmodule in &modules {
            if hmodule.is_null() {
                continue;
            }
            let mut info: MODULEINFO = std::mem::zeroed();
            if GetModuleInformation(
                handle,
                hmodule,
                &mut info,
                std::mem::size_of::<MODULEINFO>() as u32,
            ) == 0
            {
                continue;
            }
            let base = info.lpBaseOfDll as usize as u64;
            let size = info.SizeOfImage;
            let mut name_buf = [0u16; 256];
            let len = GetModuleBaseNameW(
                handle,
                hmodule,
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
            );
            let name = String::from_utf16_lossy(&name_buf[..len as usize]);
            let functions = read_module_exports(pid, base);
            out.push(ModuleExports {
                base,
                size,
                name,
                functions,
            });
        }
        Ok(out)
    }
}

/// Read a module's export table from process memory into an
/// `offset-in-module → function` map. Any read failure yields an empty map
/// (that module simply contributes no resolutions).
fn read_module_exports(pid: u32, base: u64) -> HashMap<u32, ImportFunction> {
    let Ok(dos) = read_memory(pid, base, 64) else {
        return HashMap::new();
    };
    if u16::from_le_bytes(dos[0..2].try_into().unwrap()) != DOS_MAGIC {
        return HashMap::new();
    }
    let pe_off = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
    let Ok(nt) = read_memory(pid, base + pe_off, 24 + 0x100) else {
        return HashMap::new();
    };
    let magic = u16::from_le_bytes(nt[24..26].try_into().unwrap());
    let dirs_off = if magic == PE32_MAGIC {
        24 + 96
    } else {
        24 + 112
    };
    let Ok(dirs) = read_memory(pid, base + pe_off + dirs_off, 16 * 8) else {
        return HashMap::new();
    };
    let export_rva = u32::from_le_bytes(dirs[0..4].try_into().unwrap());
    let export_size = u32::from_le_bytes(dirs[4..8].try_into().unwrap());
    if export_rva == 0 || export_size == 0 {
        return HashMap::new();
    }
    let Ok(region) = read_memory(pid, base + export_rva as u64, export_size as usize) else {
        return HashMap::new();
    };
    let rel = |rva: u32| -> usize { rva.wrapping_sub(export_rva) as usize };
    let exp = &region[..region.len().min(40)];
    let n = u32_at(exp, 24);
    let addr_funcs = u32_at(exp, 28);
    let addr_names = u32_at(exp, 32);
    let addr_ords = u32_at(exp, 36);

    let mut map = HashMap::new();
    for i in 0..n {
        let name_rva = u32_at(&region, rel(addr_names) + i as usize * 4);
        let ord = u16_at(&region, rel(addr_ords) + i as usize * 2);
        let func_rva = u32_at(&region, rel(addr_funcs) + ord as usize * 4);
        let start = rel(name_rva);
        let tail = &region[start..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        let name = String::from_utf8_lossy(&tail[..end]).into_owned();
        if !name.is_empty() {
            map.insert(func_rva, ImportFunction::by_name(name));
        }
    }
    map
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0)
}

fn u16_at(buf: &[u8], off: usize) -> u16 {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_processes_includes_current_process() {
        let procs = list_processes().expect("toolhelp snapshot");
        let me = std::process::id();
        let mine = procs
            .iter()
            .find(|p| p.pid == me)
            .expect("current process should be listed");
        assert!(!mine.name.is_empty(), "current process has a name");
    }
}
