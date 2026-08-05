//! Shared test helpers: build documents through the mock and through the real
//! parser (mock → serialize → re-parse) so every contract test runs against
//! both paths.
#![allow(dead_code)]

use pe_rs::domain::PeDocument;
use pe_rs::io::pe::{parse, serialize};
use pe_rs::io::{MockSource, PeFile};

/// A document built by the mock adapter (no real parsing).
pub fn doc_via_mock() -> PeDocument {
    MockSource::document()
}

/// The mock document serialized by the real writer and re-parsed by the real
/// parser — i.e. the same content coming through the real implementation.
pub fn doc_via_real() -> PeDocument {
    let bytes = serialize(&doc_via_mock()).expect("serialize mock doc");
    parse(&bytes).expect("parse serialized mock doc")
}

/// Run `f` against both the mock and the real-parser document.
pub fn both<F: FnMut(&mut PeDocument)>(mut f: F) {
    f(&mut doc_via_mock());
    f(&mut doc_via_real());
}

/// A [`PeFile`] facade backed by the mock adapter.
pub fn file_via_mock() -> PeFile {
    PeFile::from_source(MockSource::new()).expect("mock source loads")
}

/// A [`PeFile`] facade backed by real bytes (mock doc written and re-read).
pub fn file_via_real() -> PeFile {
    let bytes = serialize(&doc_via_mock()).expect("serialize mock doc");
    PeFile::from_bytes(bytes).expect("real source loads")
}
