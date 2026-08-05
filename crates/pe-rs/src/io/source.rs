//! The persistence port of the library: getting a [`PeDocument`] from bytes /
//! disk and writing it back. Mock and real differ only here.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use crate::domain::PeDocument;
use crate::error::Result;

/// Loads and saves a PE document. The only adapter point that differs between
/// the mock and the real implementation.
pub trait PeSource {
    fn load(&self) -> Result<PeDocument>;
    fn save(&self, doc: &PeDocument) -> Result<()>;
}

/// A PE held entirely in memory.
pub struct ByteSource {
    bytes: Vec<u8>,
    saved: RefCell<Vec<u8>>,
}

impl ByteSource {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, saved: RefCell::new(Vec::new()) }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes produced by the last `save()` (empty if never saved).
    pub fn saved_bytes(&self) -> Vec<u8> {
        self.saved.borrow().clone()
    }
}

impl PeSource for ByteSource {
    fn load(&self) -> Result<PeDocument> {
        crate::io::pe::parse(&self.bytes)
    }

    fn save(&self, doc: &PeDocument) -> Result<()> {
        *self.saved.borrow_mut() = crate::io::pe::serialize(doc)?;
        Ok(())
    }
}

/// A PE on disk.
pub struct FileSource {
    path: PathBuf,
}

impl FileSource {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl PeSource for FileSource {
    fn load(&self) -> Result<PeDocument> {
        let bytes = std::fs::read(&self.path)?;
        crate::io::pe::parse(&bytes)
    }

    fn save(&self, doc: &PeDocument) -> Result<()> {
        let bytes = crate::io::pe::serialize(doc)?;
        std::fs::write(&self.path, bytes)?;
        Ok(())
    }
}

/// High-level facade combining a [`PeSource`] (how to persist) with a loaded
/// [`PeDocument`] (the object being viewed/edited).
pub struct PeFile {
    source: Box<dyn PeSource>,
    doc: PeDocument,
}

impl PeFile {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let source = FileSource::new(path);
        let doc = source.load()?;
        Ok(Self { source: Box::new(source), doc })
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let source = ByteSource::new(bytes);
        let doc = source.load()?;
        Ok(Self { source: Box::new(source), doc })
    }

    /// Open from an arbitrary source (e.g. `MockSource` in tests).
    pub fn from_source<S: PeSource + 'static>(source: S) -> Result<Self> {
        let doc = source.load()?;
        Ok(Self { source: Box::new(source), doc })
    }

    pub fn doc(&self) -> &PeDocument {
        &self.doc
    }

    pub fn doc_mut(&mut self) -> &mut PeDocument {
        &mut self.doc
    }

    pub fn save(&mut self) -> Result<()> {
        self.source.save(&self.doc)
    }
}
