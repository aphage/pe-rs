//! Data directory table (`IMAGE_DATA_DIRECTORY`).

use crate::domain::types::Rva;

/// Index into the data directory array as defined by the PE spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataDirectoryIndex {
    Export,
    Import,
    Resource,
    Exception,
    Security,
    BaseReloc,
    Debug,
    Architecture,
    GlobalPtr,
    Tls,
    LoadConfig,
    BoundImport,
    Iat,
    DelayImport,
    ComDescriptor,
}

impl DataDirectoryIndex {
    /// The size of a full data directory array (16 entries).
    pub const COUNT: usize = 16;

    pub fn to_usize(self) -> usize {
        match self {
            DataDirectoryIndex::Export => 0,
            DataDirectoryIndex::Import => 1,
            DataDirectoryIndex::Resource => 2,
            DataDirectoryIndex::Exception => 3,
            DataDirectoryIndex::Security => 4,
            DataDirectoryIndex::BaseReloc => 5,
            DataDirectoryIndex::Debug => 6,
            DataDirectoryIndex::Architecture => 7,
            DataDirectoryIndex::GlobalPtr => 8,
            DataDirectoryIndex::Tls => 9,
            DataDirectoryIndex::LoadConfig => 10,
            DataDirectoryIndex::BoundImport => 11,
            DataDirectoryIndex::Iat => 12,
            DataDirectoryIndex::DelayImport => 13,
            DataDirectoryIndex::ComDescriptor => 14,
        }
    }

    pub fn from_usize(i: usize) -> Option<Self> {
        Some(match i {
            0 => Self::Export,
            1 => Self::Import,
            2 => Self::Resource,
            3 => Self::Exception,
            4 => Self::Security,
            5 => Self::BaseReloc,
            6 => Self::Debug,
            7 => Self::Architecture,
            8 => Self::GlobalPtr,
            9 => Self::Tls,
            10 => Self::LoadConfig,
            11 => Self::BoundImport,
            12 => Self::Iat,
            13 => Self::DelayImport,
            14 => Self::ComDescriptor,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Export => "Export",
            Self::Import => "Import",
            Self::Resource => "Resource",
            Self::Exception => "Exception",
            Self::Security => "Security",
            Self::BaseReloc => "BaseReloc",
            Self::Debug => "Debug",
            Self::Architecture => "Architecture",
            Self::GlobalPtr => "GlobalPtr",
            Self::Tls => "TLS",
            Self::LoadConfig => "LoadConfig",
            Self::BoundImport => "BoundImport",
            Self::Iat => "IAT",
            Self::DelayImport => "DelayImport",
            Self::ComDescriptor => "COM descriptor",
        }
    }
}

/// One entry of the data directory array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataDirectory {
    pub rva: Rva,
    pub size: u32,
}
