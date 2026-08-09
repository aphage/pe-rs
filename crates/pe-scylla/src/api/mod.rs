//! IAT scan / fix on a dumped process's [`PeDocument`]. These traits are
//! implemented here for pe-edit's image model (a local trait on a foreign
//! type), keeping the process/dump side of the API in this crate.

pub mod direct_imports;
pub mod iat_fixer;
pub mod iat_scanner;
pub mod imports_tree;

pub use direct_imports::{
    DirectImport, add_direct_imports_to_doc, build_direct_import_jump_table,
    patch_direct_imports_to_jump_table, scan_direct_imports,
};
pub use iat_fixer::IatFixer;
pub use iat_scanner::IatScanner;
pub use imports_tree::{
    ImportEntry, ImportModule, ImportStatus, ImportsTree, fix_iat_from_tree, get_imports,
};
// The image-model traits the scan/fix code drives, re-exported from pe-edit so
// consumers can use a single `pe_scylla::api::*` surface.
pub use pe_edit::api::{ImportResolver, PeViewer, ResolvedImport};
