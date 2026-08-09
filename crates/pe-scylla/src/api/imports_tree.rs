//! Get Imports / Fix Dump import tree (Scylla's module → function tree).
//!
//! [`get_imports`] reads a live process's IAT (at a caller-supplied or
//! autosearched address) and resolves every thunk into a per-module tree where
//! each import is *valid*, *suspect* (the address is shared by several exports
//! and scoring was not decisive — e.g. kernel32's forwarded `EncodePointer` /
//! `DecodePointer`) or *invalid* (unresolvable). The user curates the tree
//! (drop invalid / suspect entries, fix a module/API by hand), then
//! [`fix_iat_from_tree`] rebuilds a dumped image's import table from it.

use pe_edit::domain::types::ptr_size;
use pe_edit::domain::{
    IatFixOptions, IatFixReport, ImportDescriptor, ImportFunction, PeDocument, Rva,
};
use pe_edit::error::{PeError, Result};

use crate::api::iat_fixer::rebuild_from_descriptors_with_slots;
use crate::process::{ProcessResolver, read_memory};

/// Status of one resolved IAT slot, mirroring Scylla's valid / invalid /
/// suspect flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportStatus {
    /// Resolved uniquely (or a clear scored winner) — the import is correct.
    Valid,
    /// The slot value could not be resolved to any (module, function).
    Invalid,
    /// Several exports share the slot value and scoring did not pick a clear
    /// winner — the import may be wrong, worth a manual look.
    Suspect,
}

/// One resolved (or unresolvable) IAT slot.
#[derive(Debug, Clone)]
pub struct ImportEntry {
    /// Absolute address of the IAT slot (in the target process).
    pub slot_va: u64,
    /// RVA of the IAT slot (relative to the image base).
    pub slot_rva: u32,
    /// The value stored in the slot — the API address it pointed to.
    pub api_address: u64,
    /// The resolved function (None when the slot is invalid).
    pub function: Option<ImportFunction>,
    /// The resolved module (empty when invalid).
    pub module: String,
    pub status: ImportStatus,
}

impl ImportEntry {
    /// Human label for the tree row: the function name/ordinal, or the raw
    /// address when unresolvable.
    pub fn label(&self) -> String {
        match &self.function {
            Some(f) => f.display_name(),
            None => format!("{:#x}", self.api_address),
        }
    }
}

/// One module's imports, in slot order (Scylla's `ImportModuleThunk`).
#[derive(Debug, Clone)]
pub struct ImportModule {
    pub name: String,
    /// VA of this module's first thunk slot.
    pub first_thunk: u64,
    pub entries: Vec<ImportEntry>,
}

/// The resolved + curated import tree (Scylla's moduleList).
#[derive(Debug, Clone, Default)]
pub struct ImportsTree {
    pub modules: Vec<ImportModule>,
}

impl ImportsTree {
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    pub fn total(&self) -> usize {
        self.modules.iter().map(|m| m.entries.len()).sum()
    }

    pub fn valid(&self) -> usize {
        self.count(ImportStatus::Valid)
    }

    pub fn invalid(&self) -> usize {
        self.count(ImportStatus::Invalid)
    }

    pub fn suspect(&self) -> usize {
        self.count(ImportStatus::Suspect)
    }

    fn count(&self, status: ImportStatus) -> usize {
        self.modules
            .iter()
            .flat_map(|m| &m.entries)
            .filter(|e| e.status == status)
            .count()
    }
}

/// Read the IAT of the live process `pid` at `iat_va` (for `iat_size` bytes)
/// and resolve each thunk into a per-module [`ImportsTree`]. Zero slots (the
/// per-module separators of a normal IAT) are skipped. This is Scylla's
/// "Get Imports".
pub fn get_imports(
    pid: u32,
    resolver: &ProcessResolver,
    iat_va: u64,
    iat_size: usize,
) -> Result<ImportsTree> {
    if iat_size == 0 {
        return Err(PeError::InvalidArgument("get_imports: empty IAT".into()));
    }
    let psize = ptr_size(resolver.target_arch());
    // Read the IAT in page-sized chunks, stopping at the first unreadable page
    // (like Scylla's `readMemoryPartlyFromProcess`): the caller's size may
    // overrun into guard/stack pages, and a real IAT ends at a NULL terminator
    // anyway.
    let mut bytes: Vec<u8> = Vec::new();
    let mut off = 0usize;
    while off < iat_size {
        let chunk = (iat_size - off).min(0x1000);
        match read_memory(pid, iat_va + off as u64, chunk) {
            Ok(mut part) => {
                let n = part.len();
                bytes.append(&mut part);
                if n < chunk {
                    break; // partial page: nothing readable past here
                }
            }
            Err(_) => break,
        }
        off += chunk;
    }
    if bytes.len() < psize {
        return Err(PeError::NotFound(
            "get_imports: could not read the IAT from the process".into(),
        ));
    }

    let mut modules: Vec<ImportModule> = Vec::new();
    let mut unknown: Vec<ImportEntry> = Vec::new();
    let mut off = 0usize;
    while off + psize <= bytes.len() {
        let value = if psize == 8 {
            u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
        } else {
            u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as u64
        };
        off += psize;
        if value == 0 {
            continue; // per-module NULL separator (or terminator)
        }
        let slot_va = iat_va + (off - psize) as u64;
        let slot_rva = slot_va.saturating_sub(resolver.image_base) as u32;
        let entry = ImportEntry {
            slot_va,
            slot_rva,
            api_address: value,
            function: None,
            module: String::new(),
            status: ImportStatus::Invalid,
        };
        match resolver.resolve_scored(value) {
            Some(a) => {
                let mut entry = entry;
                entry.function = Some(a.resolved.function.clone());
                entry.module = a.resolved.module.clone();
                entry.status = if a.suspect {
                    ImportStatus::Suspect
                } else {
                    ImportStatus::Valid
                };
                push_entry(&mut modules, entry);
            }
            None => unknown.push(entry),
        }
    }

    if !unknown.is_empty() {
        // Unresolvable slots group under an "<unknown>" module so nothing is
        // silently dropped before the user curates it.
        let first_va = unknown[0].slot_va;
        modules.push(ImportModule {
            name: "<unknown>".to_string(),
            first_thunk: first_va,
            entries: unknown,
        });
    }

    Ok(ImportsTree { modules })
}

fn push_entry(modules: &mut Vec<ImportModule>, entry: ImportEntry) {
    let module = entry.module.clone();
    match modules.iter_mut().find(|m| m.name == module) {
        Some(m) => m.entries.push(entry),
        None => modules.push(ImportModule {
            name: module,
            first_thunk: entry.slot_va,
            entries: vec![entry],
        }),
    }
}

/// Rebuild a dumped image's import table from a curated [`ImportsTree`],
/// applying the same in-place / code-reference-remap logic as
/// [`crate::api::IatFixer::fix_iat`] but using the tree's *curated*
/// `(module, function, slot)` data directly (the user may have changed a
/// module/API by hand). Invalid entries are dropped. When `oep_rva` is given,
/// the image's entry point is set to it (Scylla's "fix IAT and OEP").
pub fn fix_iat_from_tree(
    doc: &mut PeDocument,
    tree: &ImportsTree,
    options: &IatFixOptions,
    oep_rva: Option<u32>,
) -> Result<IatFixReport> {
    if tree.is_empty() {
        return Err(PeError::InvalidArgument(
            "fix_iat_from_tree: empty tree".into(),
        ));
    }
    let mut descriptors_with_slots = Vec::new();
    for module in &tree.modules {
        let kept: Vec<&ImportEntry> = module
            .entries
            .iter()
            .filter(|e| e.status != ImportStatus::Invalid)
            .collect();
        if kept.is_empty() {
            continue;
        }
        let functions: Vec<ImportFunction> = kept
            .iter()
            .map(|e| {
                e.function
                    .clone()
                    .unwrap_or_else(|| ImportFunction::by_ordinal(0))
            })
            .collect();
        let slots: Vec<Rva> = kept.iter().map(|e| Rva(e.slot_rva)).collect();
        descriptors_with_slots.push((
            ImportDescriptor {
                name: module.name.clone(),
                functions,
            },
            slots,
        ));
    }
    if descriptors_with_slots.is_empty() {
        return Err(PeError::NotFound(
            "fix_iat_from_tree: no resolvable import left in the tree".into(),
        ));
    }
    if let Some(rva) = oep_rva {
        doc.optional.set_address_of_entry_point(Rva(rva));
    }
    let all_resolved = !tree
        .modules
        .iter()
        .flat_map(|m| &m.entries)
        .any(|e| e.status == ImportStatus::Invalid);
    rebuild_from_descriptors_with_slots(
        doc,
        &descriptors_with_slots,
        options,
        all_resolved,
        tree.total(),
    )
}
