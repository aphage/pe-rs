//! IAT fixing (import table rebuilding, "Fix Dump") on a dumped process's
//! [`PeDocument`].

use crate::api::iat_scanner::{
    collect_iat_dir_entries, collect_thunk_array, remap_iat_references, u32_at,
};
use pe_edit::api::importer::ImportTableEditor;
use pe_edit::api::resolver::ImportResolver;
use pe_edit::domain::data_directory::DataDirectoryIndex;
use pe_edit::domain::types::ptr_size;
use pe_edit::domain::{
    DumpImportRecovery, IatEntry, IatFixOptions, IatFixReport, IatScan, IatTable, ImportDescriptor,
    PeDocument, Rva,
};
use pe_edit::error::{PeError, Result};
use pe_edit::io::pe::parser::{parse_thunks, read_cstring};

/// Rebuilds a PE's import table from the addresses found in its IAT.
///
/// This is Scylla's core "Fix Dump" operation: every thunk value is resolved
/// to a `(module, function)` pair and a fresh import directory (descriptors +
/// thunk arrays + name strings) is written into the image.
pub trait IatFixer {
    /// Resolve the entries of `scan` and rebuild the import table from them.
    fn fix_iat(
        &mut self,
        scan: &IatScan,
        resolver: &dyn ImportResolver,
        options: &IatFixOptions,
    ) -> Result<IatFixReport>;

    /// Manually add a caller-supplied array of IAT entries, then rebuild.
    fn add_iat_array(
        &mut self,
        entries: &[IatEntry],
        resolver: &dyn ImportResolver,
        options: &IatFixOptions,
    ) -> Result<IatFixReport>;

    /// Rebuild the import table from a manually-curated [`IatTable`] — an
    /// automatic scan merged with regions added by hand (for dumps whose IAT
    /// was erased / split into non-contiguous segments). The rebuilt import
    /// directory is a normal contiguous, per-module NULL-separated array.
    fn fix_iat_table(
        &mut self,
        table: &IatTable,
        resolver: &dyn ImportResolver,
        options: &IatFixOptions,
    ) -> Result<IatFixReport> {
        if table.is_empty() {
            return Err(PeError::InvalidArgument(
                "fix_iat_table: empty table".into(),
            ));
        }
        let scan = table.to_scan();
        self.fix_iat(&scan, resolver, options)
    }
}

impl IatFixer for PeDocument {
    fn fix_iat(
        &mut self,
        scan: &IatScan,
        resolver: &dyn ImportResolver,
        options: &IatFixOptions,
    ) -> Result<IatFixReport> {
        // Group resolved entries into import descriptors, first-seen order,
        // keeping the original slot RVA of every function (one function entry
        // per slot, so the in-place FirstThunk arrays line up 1:1).
        let (descriptors_with_slots, unresolved) =
            group_resolved_with_slots(&scan.entries, resolver);
        if descriptors_with_slots.is_empty() {
            return Err(PeError::NotFound(
                "fix_iat: no IAT entry could be resolved to an import".into(),
            ));
        }
        let mut report = rebuild_from_descriptors_with_slots(
            self,
            &descriptors_with_slots,
            options,
            unresolved.is_empty(),
            scan.entries.len(),
        )?;
        report.unresolved = unresolved;
        Ok(report)
    }

    fn add_iat_array(
        &mut self,
        entries: &[IatEntry],
        resolver: &dyn ImportResolver,
        options: &IatFixOptions,
    ) -> Result<IatFixReport> {
        if entries.is_empty() {
            return Err(PeError::InvalidArgument(
                "add_iat_array: empty entries".into(),
            ));
        }
        let scan = IatScan {
            base_rva: entries[0].rva,
            size: entries.len(),
            entries: entries.to_vec(),
        };
        self.fix_iat(&scan, resolver, options)
    }
}

/// Shared "rebuild the import table from per-module `(descriptor, slot run)`
/// pairs" logic, used by both `fix_iat` (a resolved scan) and
/// `fix_iat_from_tree` (a curated import tree). Places the new import directory
/// in place at the original slot RVAs when each module's run is contiguous
/// (`reuse_iat_slots`); otherwise appends a fresh `.peimp`-style table and
/// rewrites every code reference from the old slots to the new ones.
pub(crate) fn rebuild_from_descriptors_with_slots(
    doc: &mut PeDocument,
    descriptors_with_slots: &[(ImportDescriptor, Vec<Rva>)],
    options: &IatFixOptions,
    all_resolved: bool,
    total_entries: usize,
) -> Result<IatFixReport> {
    let mut report = IatFixReport {
        total_entries,
        ..IatFixReport::default()
    };
    let descriptors: Vec<ImportDescriptor> = descriptors_with_slots
        .iter()
        .map(|(d, _)| d.clone())
        .collect();
    let psize = ptr_size(doc.arch) as u32;
    let flat_slots: Vec<Rva> = descriptors_with_slots
        .iter()
        .flat_map(|(_, s)| s.iter().copied())
        .collect();

    // In-place rebuild: when every module's slot run is contiguous, point
    // each rebuilt descriptor's FirstThunk at the original slots so the
    // loader resolves imports into the slots the code references — the
    // shape that makes a fixed dump runnable. Otherwise fall back to the
    // new table's own IAT arrays.
    let contiguous = descriptors_with_slots
        .iter()
        .all(|(_, slots)| slots.windows(2).all(|w| w[1].get() == w[0].get() + psize));
    let use_in_place = options.redirect_iat && options.reuse_iat_slots && contiguous;

    let rebuilt = if use_in_place {
        let slots: Vec<Vec<Rva>> = descriptors_with_slots
            .iter()
            .map(|(_, s)| s.clone())
            .collect();
        doc.rebuild_import_table_in_place(&descriptors, &slots)?
    } else {
        doc.rebuild_import_table(&descriptors)?
    };
    report.imports_built = descriptors.len();
    report.iat_reused = use_in_place;
    report.new_import_rva = Some(rebuilt.rva);
    report.new_import_size = rebuilt.size as usize;

    // Redirect: overwrite the original IAT slots with the new thunk values,
    // so code that calls through the old IAT still lands on a loader-fixable
    // table. Only safe when every entry resolved. In the in-place case the
    // rebuilt FirstThunk arrays already live at those slots; in the fallback
    // case this repoints the old slots at the new table.
    if options.redirect_iat && all_resolved {
        let psize = ptr_size(doc.arch);
        for (k, slot) in flat_slots.iter().enumerate() {
            let thunk = rebuilt.thunk_values[k];
            if psize == 8 {
                doc.write(*slot, &thunk.to_le_bytes())?;
            } else {
                doc.write(*slot, &(thunk as u32).to_le_bytes())?;
            }
        }
    }

    // Runnable-dump guarantee: when the FirstThunk arrays could not be placed
    // at the original slots (in-place requires each module's slots to be
    // contiguous), rewrite every code reference from the old IAT slot to its
    // new slot in the rebuilt table. The loader then resolves imports into
    // the new IAT and the rewritten code calls through it — the fixed dump
    // runs standalone even for scattered/noisy IAT layouts. The new slot of
    // each function is read from the rebuilt descriptor's FirstThunk (the
    // renderer interleaves INT/IAT arrays per module), so the remap always
    // matches the actual layout.
    if !use_in_place && options.redirect_iat && all_resolved {
        let psize = ptr_size(doc.arch) as u32;
        let mut mapping = Vec::with_capacity(flat_slots.len());
        let mut fi = 0usize; // flattened function index into `flat_slots`
        for (m, (desc, _)) in descriptors_with_slots.iter().enumerate() {
            let desc_rva = rebuilt
                .rva
                .get()
                .checked_add(m as u32 * 20)
                .ok_or_else(|| PeError::InvalidArgument("descriptor RVA overflow".into()))?;
            let desc_bytes = doc.read(Rva(desc_rva), 20)?;
            let ft = u32::from_le_bytes(desc_bytes[16..20].try_into().unwrap());
            for k in 0..desc.functions.len() {
                let new_slot = ft
                    .checked_add(k as u32 * psize)
                    .ok_or_else(|| PeError::InvalidArgument("new IAT slot RVA overflow".into()))?;
                mapping.push((flat_slots[fi], Rva(new_slot)));
                fi += 1;
            }
        }
        remap_iat_references(doc, &mapping)?;
    }

    Ok(report)
}

/// Recover a dumped process's import table, following Scylla's dump handling
/// (docs/dump 情况分析和处理.md): import descriptors whose `OriginalFirstThunk`
/// the loader overwrote (`== 0` or `== FirstThunk`) are *reflected* — their
/// `FirstThunk` array now holds loaded addresses, resolved here through
/// `resolver` into `(module, function)` names — while descriptors with an
/// intact `OriginalFirstThunk` keep their original hint/name pairs. When the
/// import directory is gone but the IAT data directory remains, its
/// NULL-separated per-module sub-arrays are reflected the same way. Reflected
/// values that cannot be resolved are reported in
/// [`DumpImportRecovery::unresolved`].
pub fn recover_dump_imports(
    doc: &PeDocument,
    resolver: &dyn ImportResolver,
) -> Result<DumpImportRecovery> {
    let psize = ptr_size(doc.arch);
    let mut out = DumpImportRecovery::default();

    let import_dir = doc.data_directory(DataDirectoryIndex::Import).ok().copied();
    if let Some(dd) = import_dir.filter(|d| d.rva != Rva::NULL) {
        let mut i = 0u32;
        while let Some(desc_rva) = dd.rva.checked_add(i * 20) {
            let Ok(desc) = doc.read(desc_rva, 20) else {
                break;
            };
            let oft = u32_at(desc, 0);
            let name_rva = u32_at(desc, 12);
            let ft = u32_at(desc, 16);
            if oft == 0 && name_rva == 0 && ft == 0 {
                break; // terminator descriptor
            }
            if oft == 0 && ft == 0 {
                break; // FirstThunk destroyed (Scylla logs an error, exits)
            }
            if oft == 0 || oft == ft {
                // OriginalFirstThunk was used as the IAT: reflect the loaded
                // addresses in FirstThunk.
                let mut entries = Vec::new();
                collect_thunk_array(doc, Rva(ft), psize, &mut entries);
                let (mut descs, mut unresolved) = group_resolved(&entries, resolver);
                out.descriptors.append(&mut descs);
                out.unresolved.append(&mut unresolved);
            } else {
                // OriginalFirstThunk intact: parse hint/name pairs as usual.
                let name = read_cstring(doc, Rva(name_rva))?;
                let functions = parse_thunks(doc, Rva(oft), psize)?;
                out.descriptors.push(ImportDescriptor { name, functions });
            }
            i += 1;
        }
    } else if let Some(dd) = doc
        .data_directory(DataDirectoryIndex::Iat)
        .ok()
        .copied()
        .filter(|d| d.rva != Rva::NULL)
    {
        // Import directory gone but the IAT directory remains: reflect
        // every NULL-separated sub-array.
        let mut entries = Vec::new();
        collect_iat_dir_entries(doc, dd, psize, &mut entries);
        let (mut descs, mut unresolved) = group_resolved(&entries, resolver);
        out.descriptors.append(&mut descs);
        out.unresolved.append(&mut unresolved);
    } else {
        return Err(PeError::NotFound(
            "no import or IAT data directory to recover imports from".into(),
        ));
    }

    if out.descriptors.is_empty() && out.unresolved.is_empty() {
        return Err(PeError::NotFound(
            "no import table could be recovered from the dump".into(),
        ));
    }
    Ok(out)
}

/// Resolve raw IAT slots into per-module import descriptors, keeping the
/// original slot RVA of every function (one function entry per slot, in slot
/// order). Returns the `(descriptor, slots)` pairs plus the slots that could
/// not be resolved.
fn group_resolved_with_slots(
    entries: &[IatEntry],
    resolver: &dyn ImportResolver,
) -> (Vec<(ImportDescriptor, Vec<Rva>)>, Vec<IatEntry>) {
    let mut descriptors: Vec<(ImportDescriptor, Vec<Rva>)> = Vec::new();
    let mut unresolved = Vec::new();
    for entry in entries {
        match resolver.resolve(entry.value) {
            Some(ri) => match descriptors.iter_mut().find(|(d, _)| d.name == ri.module) {
                Some((d, slots)) => {
                    d.functions.push(ri.function.clone());
                    slots.push(entry.rva);
                }
                None => descriptors.push((
                    ImportDescriptor {
                        name: ri.module.clone(),
                        functions: vec![ri.function.clone()],
                    },
                    vec![entry.rva],
                )),
            },
            None => unresolved.push(*entry),
        }
    }
    (descriptors, unresolved)
}

/// Resolve raw IAT slots into per-module import descriptors, returning the
/// descriptors plus the slots that could not be resolved.
fn group_resolved(
    entries: &[IatEntry],
    resolver: &dyn ImportResolver,
) -> (Vec<ImportDescriptor>, Vec<IatEntry>) {
    let mut descriptors: Vec<ImportDescriptor> = Vec::new();
    let mut unresolved = Vec::new();
    for entry in entries {
        match resolver.resolve(entry.value) {
            Some(ri) => match descriptors.iter_mut().find(|d| d.name == ri.module) {
                Some(d) => {
                    if !d.functions.contains(&ri.function) {
                        d.functions.push(ri.function.clone());
                    }
                }
                None => descriptors.push(ImportDescriptor {
                    name: ri.module.clone(),
                    functions: vec![ri.function.clone()],
                }),
            },
            None => unresolved.push(*entry),
        }
    }
    (descriptors, unresolved)
}
