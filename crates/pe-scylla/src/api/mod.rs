//! IAT scan / fix on a dumped process's [`PeDocument`]. These traits are
//! implemented here for pe-edit's image model (a local trait on a foreign
//! type), keeping the process/dump side of the API in this crate.

pub mod iat_fixer;
pub mod iat_scanner;

pub use iat_fixer::IatFixer;
pub use iat_scanner::IatScanner;
// The image-model traits the scan/fix code drives, re-exported from pe-edit so
// consumers can use a single `pe_scylla::api::*` surface.
pub use pe_edit::api::{ImportResolver, PeViewer, ResolvedImport};
