//! Editing of the (rich) import table.

use crate::domain::{ImportDescriptor, ImportFunction, Rva};
use crate::error::{PeError, Result};

/// Operations on the parsed import table of a [`PeDocument`].
///
/// `add_import` / `remove_import` edit the rich form directly. The physical
/// import directory is rebuilt by `rebuild_import_table`, which writes fresh
/// descriptor / thunk / name arrays into the image and updates the data
/// directory (this is what an IAT fix ultimately calls).
pub trait ImportTableEditor {
    /// Add a module import (merging functions if the module already exists).
    fn add_import(&mut self, module: &str, functions: &[ImportFunction]) -> Result<()>;
    fn remove_import(&mut self, module: &str) -> Result<()>;
    /// Rebuild the physical import directory for `descriptors` and return its RVA.
    fn rebuild_import_table(&mut self, descriptors: &[ImportDescriptor]) -> Result<Rva>;
}

impl ImportTableEditor for crate::domain::PeDocument {
    fn add_import(&mut self, module: &str, functions: &[ImportFunction]) -> Result<()> {
        if module.is_empty() {
            return Err(PeError::InvalidArgument("add_import: empty module name".into()));
        }
        match self.imports.iter_mut().find(|d| d.name == module) {
            Some(desc) => {
                for f in functions {
                    if !desc.functions.contains(f) {
                        desc.functions.push(f.clone());
                    }
                }
            }
            None => {
                self.imports.push(ImportDescriptor {
                    name: module.to_string(),
                    functions: functions.to_vec(),
                });
            }
        }
        Ok(())
    }

    fn remove_import(&mut self, module: &str) -> Result<()> {
        let before = self.imports.len();
        self.imports.retain(|d| d.name != module);
        if self.imports.len() == before {
            return Err(PeError::InvalidArgument(format!("remove_import: no import '{module}'")));
        }
        Ok(())
    }

    fn rebuild_import_table(&mut self, _descriptors: &[ImportDescriptor]) -> Result<Rva> {
        Err(PeError::NotImplemented("ImportTableEditor::rebuild_import_table"))
    }
}
