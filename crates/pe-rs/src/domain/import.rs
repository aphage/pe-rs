//! Import table domain model.

/// A single imported function: by ordinal or by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportFunction {
    Ordinal { ordinal: u16 },
    Name { hint: u16, name: String },
}

impl ImportFunction {
    pub fn by_name(name: impl Into<String>) -> Self {
        Self::Name { hint: 0, name: name.into() }
    }

    pub fn by_ordinal(ordinal: u16) -> Self {
        Self::Ordinal { ordinal }
    }

    /// The symbol this import refers to: the name, or `#<ordinal>` for ordinal imports.
    pub fn display_name(&self) -> String {
        match self {
            Self::Ordinal { ordinal } => format!("#{ordinal}"),
            Self::Name { name, .. } => name.clone(),
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Name { name, .. } => Some(name),
            _ => None,
        }
    }

    pub fn ordinal(&self) -> Option<u16> {
        match self {
            Self::Ordinal { ordinal } => Some(*ordinal),
            _ => None,
        }
    }
}

/// One import descriptor: a module plus the functions imported from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDescriptor {
    pub name: String,
    pub functions: Vec<ImportFunction>,
}

impl ImportDescriptor {
    pub fn new(name: impl Into<String>, functions: Vec<ImportFunction>) -> Self {
        Self { name: name.into(), functions }
    }
}
