//! IAT fixing (import table rebuilding, "Fix Dump").

use crate::domain::{IatEntry, IatFixOptions, IatFixReport, IatScan};
use crate::error::Result;
use crate::api::resolver::ImportResolver;

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
