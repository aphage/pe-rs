//! Export table domain model.

use crate::domain::types::Rva;

/// A single exported symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSymbol {
    /// Export name, or `None` when exported only by ordinal.
    pub name: Option<String>,
    pub ordinal: u16,
    pub rva: Rva,
    /// Forwarder string such as `"ntdll.RtlpAllocateReadOnlyMemory"`.
    pub forwarder: Option<String>,
}

/// The parsed export table of a PE.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportTable {
    pub module_name: Option<String>,
    pub base: u32,
    pub number_of_functions: u32,
    pub symbols: Vec<ExportSymbol>,
}
