//! IAT scanning.

use crate::domain::{IatScan, ScanOptions};
use crate::error::Result;

/// Locates a candidate Import Address Table in a [`PeDocument`].
///
/// Implemented in Phase 6 (resolver-based scan over the document image).
pub trait IatScanner {
    fn scan(&self, options: &ScanOptions) -> Result<IatScan>;
}
