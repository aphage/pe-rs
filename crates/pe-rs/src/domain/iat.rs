//! Import Address Table (IAT) scanning and fixing types.

use crate::domain::import::ImportDescriptor;
use crate::domain::types::Rva;

/// One slot of an IAT: its location and the target address stored there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IatEntry {
    /// RVA of the thunk slot within the image.
    pub rva: Rva,
    /// Value stored at the slot: usually an absolute API address.
    pub value: u64,
}

/// The result of scanning for an IAT. For the [`ScanMethod::Resolver`] scan
/// this is one contiguous run; for [`ScanMethod::CodeReference`] it is the
/// full referenced-slot set (possibly spanning several segments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatScan {
    /// RVA of the first entry.
    pub base_rva: Rva,
    /// Number of entries in `entries`.
    pub size: usize,
    pub entries: Vec<IatEntry>,
}

/// A manually-constructed IAT: a mutable set of `(rva, value)` slots that may
/// come from several **non-contiguous** regions.
///
/// Protectors (e.g. VMProtect with memory-loaded modules) can erase and split
/// the IAT across separate segments that the automatic scan only partially
/// recovers. Build a table from the automatic scan and curate it — add missed
/// regions with [`IatTable::add_region`], drop false positives — then rebuild
/// with [`IatFixer::fix_iat_table`](crate::api::IatFixer::fix_iat_table). The
/// rebuilt import table is a normal contiguous, per-module NULL-separated
/// array.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IatTable {
    entries: Vec<IatEntry>,
}

impl IatTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from an automatic scan so it can be curated.
    pub fn from_scan(scan: &IatScan) -> Self {
        Self {
            entries: scan.entries.clone(),
        }
    }

    pub fn from_entries(entries: Vec<IatEntry>) -> Self {
        Self { entries }
    }

    /// Append every slot in `[rva, rva + size)` (size in bytes), reading one
    /// pointer per slot from the document. Lets you add IAT regions the
    /// automatic scan missed.
    pub fn add_region(
        &mut self,
        doc: &crate::domain::PeDocument,
        rva: Rva,
        size: usize,
    ) -> crate::error::Result<()> {
        let psize = crate::domain::types::ptr_size(doc.arch);
        for off in (0..size).step_by(psize) {
            let slot_rva = rva.checked_add(off as u32).ok_or_else(|| {
                crate::error::PeError::InvalidArgument("add_region: region RVA overflow".into())
            })?;
            let bytes = doc.read(slot_rva, psize)?;
            let value = if psize == 8 {
                u64::from_le_bytes(bytes.try_into().unwrap())
            } else {
                u32::from_le_bytes(bytes.try_into().unwrap()) as u64
            };
            self.entries.push(IatEntry {
                rva: slot_rva,
                value,
            });
        }
        Ok(())
    }

    pub fn add(&mut self, entry: IatEntry) {
        self.entries.push(entry);
    }

    pub fn add_many(&mut self, entries: &[IatEntry]) {
        self.entries.extend_from_slice(entries);
    }

    /// Remove the first entry at `rva`.
    pub fn remove(&mut self, rva: Rva) {
        if let Some(i) = self.entries.iter().position(|e| e.rva == rva) {
            self.entries.remove(i);
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn entries(&self) -> &[IatEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries sorted by RVA with duplicates removed.
    pub fn to_scan(&self) -> IatScan {
        let mut entries = self.entries.clone();
        entries.sort_by_key(|e| e.rva);
        entries.dedup_by_key(|e| e.rva);
        IatScan {
            base_rva: entries.first().map(|e| e.rva).unwrap_or(Rva::NULL),
            size: entries.len(),
            entries,
        }
    }
}

/// How the IAT scanner locates candidate slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanMethod {
    /// Keep slots whose stored value resolves via [`crate::api::ImportResolver`].
    #[default]
    Resolver,
    /// Disassemble the code sections and return every slot dereferenced by a
    /// direct memory operand (`call/jmp/mov/lea [rip+disp]` on x64, absolute
    /// addressing on x86) that lands in a data section.
    CodeReference,
    /// Reflect the IAT from the PE structure itself (Scylla's dump handling
    /// for a loader-overwritten import directory): collect the `FirstThunk`
    /// arrays of import descriptors whose `OriginalFirstThunk` is gone
    /// (`== 0` or `== FirstThunk`), or — when the import directory is absent
    /// but the IAT data directory remains — every entry of its NULL-separated
    /// per-module sub-arrays. Returns the raw slots; resolve and rebuild with
    /// [`IatFixer::fix_iat`](crate::api::IatFixer::fix_iat).
    Reflection,
}

/// Options controlling [`crate::api::IatScanner::scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOptions {
    /// Restrict scanning to a `(rva, len)` window; `None` scans the whole image.
    pub region: Option<(Rva, usize)>,
    pub method: ScanMethod,
    /// Minimum number of consecutive valid entries a candidate must have.
    pub min_entries: usize,
    /// Resolver scan: maximum consecutive zero slots allowed inside a run (the
    /// per-module NULL separators of a real IAT). Larger gaps end the run.
    pub max_null_gap: usize,
    /// Code-reference scan: require each referenced slot's content to resolve
    /// through the [`ImportResolver`](crate::api::ImportResolver). Disable for
    /// protected dumps (erased / split IAT, e.g. VMProtect) where the slot
    /// content does not resolve — the code references alone locate the IAT.
    pub validate_slots: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            region: None,
            method: ScanMethod::Resolver,
            min_entries: 4,
            max_null_gap: 4,
            validate_slots: true,
        }
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

/// Outcome of recovering a dumped process's import table via
/// [`PeDocument::recover_dump_imports`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DumpImportRecovery {
    /// Recovered imports: descriptors with an intact `OriginalFirstThunk`
    /// parsed by name, plus descriptors reflected from overwritten thunk
    /// arrays and resolved through the resolver.
    pub descriptors: Vec<ImportDescriptor>,
    /// Reflected slots whose value could not be resolved to a module/function.
    pub unresolved: Vec<IatEntry>,
}
