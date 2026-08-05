//! Resource directory tree (`IMAGE_RESOURCE_DIRECTORY`).

use crate::domain::types::Rva;

/// The name of a resource: an integer ID or a named string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceName {
    Id(u32),
    Named(String),
}

/// A leaf node: where the actual resource bytes live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceDataEntry {
    pub rva: Rva,
    pub size: u32,
    pub code_page: u32,
}

/// What a resource directory entry points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceEntryData {
    Directory(ResourceDirectory),
    Leaf(ResourceDataEntry),
}

/// One entry of a resource directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEntry {
    pub name: ResourceName,
    pub data: ResourceEntryData,
}

/// A node of the resource tree.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceDirectory {
    pub entries: Vec<ResourceEntry>,
}

/// Standard resource type IDs.
pub const RT_CURSOR: u32 = 1;
pub const RT_BITMAP: u32 = 2;
pub const RT_ICON: u32 = 3;
pub const RT_MENU: u32 = 4;
pub const RT_DIALOG: u32 = 5;
pub const RT_STRING: u32 = 6;
pub const RT_FONTDIR: u32 = 7;
pub const RT_FONT: u32 = 8;
pub const RT_ACCELERATOR: u32 = 9;
pub const RT_RCDATA: u32 = 10;
pub const RT_MESSAGETABLE: u32 = 11;
pub const RT_GROUP_CURSOR: u32 = 12;
pub const RT_GROUP_ICON: u32 = 14;
pub const RT_VERSION: u32 = 16;
pub const RT_MANIFEST: u32 = 24;
