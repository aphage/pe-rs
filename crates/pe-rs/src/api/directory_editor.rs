//! Editing of the resource / relocation / TLS directories.
//!
//! Edits are applied to the document's rich forms; the writer re-renders the
//! affected data directory on save (see `io::pe::writer`), so mutations here
//! persist through `serialize`/`save`.

use crate::domain::resource::{
    ResourceDataEntry, ResourceDirectory, ResourceEntry, ResourceEntryData, ResourceName,
};
use crate::domain::{
    LoadConfigDirectory, PeDocument, RelocationBlock, RelocationEntry, RelocationTable, Rva,
    TlsDirectory,
};
use crate::error::{PeError, Result};

/// Operations on the rich resource / relocation / TLS directories.
pub trait DirectoryEditor {
    // TLS ----------------------------------------------------------------
    fn set_tls(&mut self, tls: Option<TlsDirectory>);
    fn tls_mut(&mut self) -> Option<&mut TlsDirectory>;

    // Relocations --------------------------------------------------------
    fn set_relocations(&mut self, table: Option<RelocationTable>);
    fn relocations_mut(&mut self) -> Option<&mut RelocationTable>;
    fn add_relocation_block(&mut self, page_rva: Rva, entries: Vec<RelocationEntry>) -> Result<()>;
    fn remove_relocation_block(&mut self, index: usize) -> Result<()>;

    // Resources ----------------------------------------------------------
    fn set_resources(&mut self, root: Option<ResourceDirectory>);
    fn resources_mut(&mut self) -> Option<&mut ResourceDirectory>;
    /// Add (or replace) a resource of `type_id` / `name` / `lang` with `data`.
    /// The content is written into the image immediately; returns its RVA.
    fn add_resource_data(
        &mut self,
        type_id: u32,
        name: ResourceName,
        lang: u16,
        data: Vec<u8>,
    ) -> Result<Rva>;
    /// Remove every resource of `name` under type `type_id` (and the type
    /// itself once it is empty).
    fn remove_resource(&mut self, type_id: u32, name: &ResourceName) -> Result<()>;

    // LoadConfig ----------------------------------------------------------
    fn set_load_config(&mut self, lc: Option<LoadConfigDirectory>);
    fn load_config_mut(&mut self) -> Option<&mut LoadConfigDirectory>;
}

impl DirectoryEditor for PeDocument {
    fn set_tls(&mut self, tls: Option<TlsDirectory>) {
        self.tls = tls;
    }

    fn tls_mut(&mut self) -> Option<&mut TlsDirectory> {
        self.tls.as_mut()
    }

    fn set_relocations(&mut self, table: Option<RelocationTable>) {
        self.relocations = table;
    }

    fn relocations_mut(&mut self) -> Option<&mut RelocationTable> {
        self.relocations.as_mut()
    }

    fn add_relocation_block(&mut self, page_rva: Rva, entries: Vec<RelocationEntry>) -> Result<()> {
        let table = self
            .relocations
            .get_or_insert_with(RelocationTable::default);
        table.blocks.push(RelocationBlock { page_rva, entries });
        Ok(())
    }

    fn remove_relocation_block(&mut self, index: usize) -> Result<()> {
        let Some(table) = self.relocations.as_mut() else {
            return Err(PeError::NotFound("no relocation table".into()));
        };
        if index >= table.blocks.len() {
            return Err(PeError::InvalidArgument(format!(
                "remove_relocation_block: no block #{index}"
            )));
        }
        table.blocks.remove(index);
        Ok(())
    }

    fn set_resources(&mut self, root: Option<ResourceDirectory>) {
        self.resources = root;
    }

    fn resources_mut(&mut self) -> Option<&mut ResourceDirectory> {
        self.resources.as_mut()
    }

    fn add_resource_data(
        &mut self,
        type_id: u32,
        name: ResourceName,
        lang: u16,
        data: Vec<u8>,
    ) -> Result<Rva> {
        if data.is_empty() {
            return Err(PeError::InvalidArgument(
                "add_resource_data: empty data".into(),
            ));
        }
        let rva = self.alloc(data.len(), 4)?;
        self.write(rva, &data)?;

        let root = self
            .resources
            .get_or_insert_with(ResourceDirectory::default);
        let type_dir = ensure_subdir(root, ResourceName::Id(type_id))?;
        let name_dir = ensure_subdir(type_dir, name)?;
        set_leaf(
            name_dir,
            ResourceName::Id(lang as u32),
            ResourceDataEntry {
                rva,
                size: data.len() as u32,
                code_page: 0,
            },
        )?;
        Ok(rva)
    }

    fn remove_resource(&mut self, type_id: u32, name: &ResourceName) -> Result<()> {
        let Some(root) = self.resources.as_mut() else {
            return Err(PeError::NotFound("no resource table".into()));
        };
        let Some(type_idx) = root
            .entries
            .iter()
            .position(|e| e.name == ResourceName::Id(type_id))
        else {
            return Err(PeError::NotFound(format!(
                "resource type {type_id} not found"
            )));
        };
        let ResourceEntryData::Directory(type_dir) = &mut root.entries[type_idx].data else {
            return Err(PeError::InvalidArgument(
                "resource type entry is a leaf".into(),
            ));
        };
        let before = type_dir.entries.len();
        type_dir.entries.retain(|e| e.name != *name);
        if type_dir.entries.len() == before {
            return Err(PeError::NotFound(format!(
                "resource {name:?} not found under type {type_id}"
            )));
        }
        if type_dir.entries.is_empty() {
            root.entries.remove(type_idx);
        }
        Ok(())
    }

    fn set_load_config(&mut self, lc: Option<LoadConfigDirectory>) {
        self.load_config = lc;
    }

    fn load_config_mut(&mut self) -> Option<&mut LoadConfigDirectory> {
        self.load_config.as_mut()
    }
}

/// Find the subdirectory named `name`, creating it (with an empty directory)
/// if missing. Errors if the name is already a leaf.
fn ensure_subdir(
    dir: &mut ResourceDirectory,
    name: ResourceName,
) -> Result<&mut ResourceDirectory> {
    if let Some(idx) = dir.entries.iter().position(|e| e.name == name) {
        return match &mut dir.entries[idx].data {
            ResourceEntryData::Directory(d) => Ok(d),
            _ => Err(PeError::InvalidArgument(
                "resource name already a leaf".into(),
            )),
        };
    }
    dir.entries.push(ResourceEntry {
        name,
        data: ResourceEntryData::Directory(ResourceDirectory::default()),
    });
    let idx = dir.entries.len() - 1;
    match &mut dir.entries[idx].data {
        ResourceEntryData::Directory(d) => Ok(d),
        _ => unreachable!(),
    }
}

/// Set the leaf entry named `name`, replacing an existing leaf or adding a new
/// entry.
fn set_leaf(
    dir: &mut ResourceDirectory,
    name: ResourceName,
    leaf: ResourceDataEntry,
) -> Result<()> {
    if let Some(idx) = dir.entries.iter().position(|e| e.name == name) {
        match &mut dir.entries[idx].data {
            ResourceEntryData::Leaf(l) => {
                *l = leaf;
                Ok(())
            }
            _ => Err(PeError::InvalidArgument(
                "resource name already a directory".into(),
            )),
        }
    } else {
        dir.entries.push(ResourceEntry {
            name,
            data: ResourceEntryData::Leaf(leaf),
        });
        Ok(())
    }
}
