//! Editing of the (rich) import table.

use crate::api::PeEditor;
use crate::domain::types::align_up;
use crate::domain::{
    DataDirectoryIndex, ImportDescriptor, ImportFunction, RebuiltImportTable, Rva,
};
use crate::error::{PeError, Result};
use crate::io::pe::import_render::render_import_table;

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
    /// Rebuild the physical import directory for `descriptors`, updating the
    /// rich form and the data directory, and return the result.
    fn rebuild_import_table(
        &mut self,
        descriptors: &[ImportDescriptor],
    ) -> Result<RebuiltImportTable>;
}

impl ImportTableEditor for crate::domain::PeDocument {
    fn add_import(&mut self, module: &str, functions: &[ImportFunction]) -> Result<()> {
        if module.is_empty() {
            return Err(PeError::InvalidArgument(
                "add_import: empty module name".into(),
            ));
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
            return Err(PeError::InvalidArgument(format!(
                "remove_import: no import '{module}'"
            )));
        }
        Ok(())
    }

    fn rebuild_import_table(
        &mut self,
        descriptors: &[ImportDescriptor],
    ) -> Result<RebuiltImportTable> {
        if descriptors.is_empty() {
            return Err(PeError::InvalidArgument(
                "rebuild_import_table: no descriptors".into(),
            ));
        }
        let alignment = self.optional.section_alignment().max(1);
        let image_end = self
            .sections
            .iter()
            .map(|s| {
                s.header
                    .virtual_address
                    .get()
                    .saturating_add(s.data.len() as u32)
            })
            .max()
            .unwrap_or(0);
        let base = align_up(image_end, alignment);
        let rendered = render_import_table(descriptors, self.arch, Rva(base))?;
        let rva = self.alloc(rendered.blob.len(), alignment)?;
        self.write(rva, &rendered.blob)?;
        self.set_data_directory(
            DataDirectoryIndex::Import,
            Rva(rendered.dir_rva),
            rendered.size,
        )?;
        self.set_data_directory(
            DataDirectoryIndex::Iat,
            Rva(rendered.iat_rva),
            rendered.iat_size,
        )?;
        self.imports = descriptors.to_vec();
        Ok(RebuiltImportTable {
            rva,
            size: rendered.size,
            iat_rva: Rva(rendered.iat_rva),
            iat_size: rendered.iat_size,
            thunk_values: rendered.thunk_values,
        })
    }
}
