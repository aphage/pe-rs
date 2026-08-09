//! Resolution of an IAT thunk address to a concrete import.

use crate::domain::ImportFunction;

/// A thunk address resolved to a module plus the function it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImport {
    pub module: String,
    pub function: ImportFunction,
}

/// Resolves an absolute address (as stored in an IAT slot) to a concrete
/// module/function. In a file-only library this mapping is caller-provided
/// (e.g. from a symbol map or a live process's loaded modules); the mock
/// provides a fixed map.
pub trait ImportResolver {
    fn resolve(&self, address: u64) -> Option<ResolvedImport>;
}
