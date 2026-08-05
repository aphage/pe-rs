//! IAT fixing (import table rebuilding, "Fix Dump").

use crate::api::importer::ImportTableEditor;
use crate::api::resolver::ImportResolver;
use crate::domain::types::ptr_size;
use crate::domain::{
    IatEntry, IatFixOptions, IatFixReport, IatScan, ImportDescriptor, PeDocument,
};
use crate::error::{PeError, Result};

/// Rebuilds a PE's import table from the addresses found in its IAT.
///
/// This is Scylla's core "Fix Dump" operation, exposed in file terms:
/// every thunk value is resolved to a `(module, function)` pair and a fresh
/// import directory (descriptors + thunk arrays + name strings) is written
/// into the image.
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
}

impl IatFixer for PeDocument {
    fn fix_iat(
        &mut self,
        scan: &IatScan,
        resolver: &dyn ImportResolver,
        options: &IatFixOptions,
    ) -> Result<IatFixReport> {
        let mut report = IatFixReport {
            total_entries: scan.entries.len(),
            ..IatFixReport::default()
        };

        // Group resolved entries into import descriptors, first-seen order.
        let mut descriptors: Vec<ImportDescriptor> = Vec::new();
        for entry in &scan.entries {
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
                None => report.unresolved.push(*entry),
            }
        }

        if descriptors.is_empty() {
            return Err(PeError::NotFound(
                "fix_iat: no IAT entry could be resolved to an import".into(),
            ));
        }

        let rebuilt = self.rebuild_import_table(&descriptors)?;
        report.imports_built = descriptors.len();
        report.new_import_rva = Some(rebuilt.rva);
        report.new_import_size = rebuilt.size as usize;

        // Redirect: overwrite the original IAT slots with the new thunk values,
        // so code that calls through the old IAT still lands on a loader-fixable
        // table. Only safe when every entry resolved.
        if options.redirect_iat && report.unresolved.is_empty() {
            let psize = ptr_size(self.arch);
            for (k, entry) in scan.entries.iter().enumerate() {
                let thunk = rebuilt.thunk_values[k];
                if psize == 8 {
                    self.write(entry.rva, &thunk.to_le_bytes())?;
                } else {
                    self.write(entry.rva, &(thunk as u32).to_le_bytes())?;
                }
            }
        }

        Ok(report)
    }

    fn add_iat_array(
        &mut self,
        entries: &[IatEntry],
        resolver: &dyn ImportResolver,
        options: &IatFixOptions,
    ) -> Result<IatFixReport> {
        if entries.is_empty() {
            return Err(PeError::InvalidArgument("add_iat_array: empty entries".into()));
        }
        let scan = IatScan {
            base_rva: entries[0].rva,
            size: entries.len(),
            entries: entries.to_vec(),
        };
        self.fix_iat(&scan, resolver, options)
    }
}
