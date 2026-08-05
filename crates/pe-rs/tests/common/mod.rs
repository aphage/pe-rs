//! Shared test helpers: build documents through the mock (and later through the
//! real parser) so every contract test runs against both paths.

use pe_rs::domain::PeDocument;
use pe_rs::io::{MockSource, PeFile};

/// A document built by the mock adapter (no real parsing).
pub fn doc_via_mock() -> PeDocument {
    MockSource::document()
}

/// A [`PeFile`] facade backed by the mock adapter.
pub fn file_via_mock() -> PeFile {
    PeFile::from_source(MockSource::new()).expect("mock source loads")
}
