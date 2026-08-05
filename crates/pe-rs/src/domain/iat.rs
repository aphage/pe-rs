//! Import Address Table (IAT) scanning and fixing types.

use crate::domain::types::Rva;

/// One slot of an IAT: its location and the target address stored there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IatEntry {
    /// RVA of the thunk slot within the image.
    pub rva: Rva,
    /// Value stored at the slot: usually an absolute API address.
    pub value: u64,
}

/// The result of scanning for an IAT: a contiguous run of entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatScan {
    /// RVA of the first entry.
    pub base_rva: Rva,
    /// Number of entries in `entries`.
    pub size: usize,
    pub entries: Vec<IatEntry>,
}

/// How the IAT scanner locates candidate slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanMethod {
    /// Keep slots whose stored value resolves via [`crate::api::ImportResolver`].
    #[default]
    Resolver,
    /// Heuristic x86/x64 opcode patterns (`push`/`call`) — reserved for later.
    OpcodePattern,
}

/// Options controlling [`crate::api::IatScanner::scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOptions {
    /// Restrict scanning to a `(rva, len)` window; `None` scans the whole image.
    pub region: Option<(Rva, usize)>,
    pub method: ScanMethod,
    /// Minimum number of consecutive valid entries a candidate must have.
    pub min_entries: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { region: None, method: ScanMethod::Resolver, min_entries: 4 }
    }
}

/// Options controlling [`crate::api::IatFixer::fix_iat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IatFixOptions {
    /// Rewrite the original IAT slots in place so they point at the newly
    /// built thunks (Scylla's "redirect IAT").
    pub redirect_iat: bool,
}

impl Default for IatFixOptions {
    fn default() -> Self {
        Self { redirect_iat: true }
    }
}

/// Outcome of an IAT fix operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IatFixReport {
    /// Number of modules written into the new import table.
    pub imports_built: usize,
    /// Total number of IAT entries processed.
    pub total_entries: usize,
    /// Entries that could not be resolved to a module/function.
    pub unresolved: Vec<IatEntry>,
    /// RVA of the newly built import table, if any.
    pub new_import_rva: Option<Rva>,
    /// Size in bytes of the newly built import table.
    pub new_import_size: usize,
}

/// Outcome of rebuilding the physical import table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuiltImportTable {
    /// RVA of the new descriptor array.
    pub rva: Rva,
    /// Size in bytes of the new import table.
    pub size: u32,
    /// RVA of the first FirstThunk (IAT) array.
    pub iat_rva: Rva,
    /// Combined size in bytes of all FirstThunk arrays.
    pub iat_size: u32,
    /// New thunk value for each function, in descriptor order. This is the
    /// value that belongs in the (redirected) IAT slot for that function.
    pub thunk_values: Vec<u64>,
}
