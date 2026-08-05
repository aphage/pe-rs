//! Adapters (ports) between bytes/disk and the domain model.
//!
//! The only place where the *mock* and *real* implementations differ:
//! - `MockSource` fabricates a deterministic in-memory `PeDocument` (no real parsing).
//! - `ByteSource` / `FileSource` parse real PE bytes and serialize documents back.
//!
//! Filled in during Phase 1 (outer API + domain types).
