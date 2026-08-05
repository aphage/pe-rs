//! The **outer layer** of the library: capability traits that a GUI (or any
//! consumer) drives directly. Implementations operate on
//! [`crate::domain::PeDocument`], so they work identically for mock- and
//! real-parser-backed documents.

pub mod editor;
pub mod iat_fixer;
pub mod iat_scanner;
pub mod importer;
pub mod resolver;
pub mod viewer;

pub use editor::PeEditor;
pub use iat_fixer::IatFixer;
pub use iat_scanner::IatScanner;
pub use importer::ImportTableEditor;
pub use resolver::{ImportResolver, ResolvedImport};
pub use viewer::PeViewer;
