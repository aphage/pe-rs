//! Adapters (ports) between bytes/disk and the domain model.
//!
//! The only place where the *mock* and *real* implementations differ:
//! - `MockSource` fabricates a deterministic in-memory `PeDocument` (no real parsing).
//! - `ByteSource` / `FileSource` parse real PE bytes and serialize documents back.

pub mod mock;
pub mod pe;
pub mod source;

pub use mock::{
    MOCK_APIS_BASE, MOCK_IAT_RVA, MOCK_IDATA_RVA, MOCK_IMAGE_BASE, MOCK_TEXT_RVA, MockResolver,
    MockSource,
};
pub use source::{ByteSource, FileSource, PeFile, PeSource};
