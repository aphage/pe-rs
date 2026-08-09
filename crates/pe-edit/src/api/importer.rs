//! Editing of the (rich) import table.

use crate::api::PeEditor;
use crate::domain::section::IMAGE_SCN_MEM_WRITE;
use crate::domain::types::{align_up, ptr_size};
use crate::domain::{
    DataDirectoryIndex, ImportDescriptor, ImportFunction, PeDocument, RebuiltImportTable, Rva,
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

impl PeDocument {
    /// Rebuild the physical import table for `descriptors`, then place each
    /// descriptor's `FirstThunk` array **in place** at the caller-supplied
    /// original IAT slot RVAs (`iat_slots[m]` holds `descriptors[m]`'s slot
    /// RVAs, one per function, in order). The new thunk values are written into
    /// those slots and the IAT data directory is repointed at the first one.
    ///
    /// This is the shape a fixed *dump* needs to be runnable: the loader
    /// resolves the rebuilt names straight into the slots the code already
    /// references, so `call [rip+disp]` land on loader-populated addresses.
    /// The containing section(s) are marked writable so the loader can write
    /// even when the original IAT sat in a read-only section (e.g. `.rdata`).
    pub fn rebuild_import_table_in_place(
        &mut self,
        descriptors: &[ImportDescriptor],
        iat_slots: &[Vec<Rva>],
    ) -> Result<RebuiltImportTable> {
        if descriptors.is_empty() {
            return Err(PeError::InvalidArgument(
                "rebuild_import_table_in_place: no descriptors".into(),
            ));
        }
        if descriptors.len() != iat_slots.len() {
            return Err(PeError::InvalidArgument(
                "rebuild_import_table_in_place: descriptor/slot count mismatch".into(),
            ));
        }
        let psize = ptr_size(self.arch) as u32;

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

        // Repoint each descriptor's FirstThunk at its original slot run, and
        // write the new thunk values into those slots (the loader overwrites
        // them with resolved addresses on load).
        let mut fi = 0usize; // flattened function index into `thunk_values`
        for (m, slots) in iat_slots.iter().enumerate() {
            let desc_field = rva
                .get()
                .checked_add((m * 20 + 16) as u32)
                .ok_or_else(|| PeError::InvalidArgument("descriptor field RVA overflow".into()))?;
            self.write(Rva(desc_field), &slots[0].get().to_le_bytes())?;
            for &slot in slots {
                let thunk = rendered.thunk_values[fi];
                if psize == 8 {
                    self.write(slot, &thunk.to_le_bytes())?;
                } else {
                    self.write(slot, &(thunk as u32).to_le_bytes())?;
                }
                fi += 1;
            }
        }

        // Ensure the loader may write the IAT, even if the original section
        // (typically `.rdata`) was marked read-only.
        for slot in iat_slots.iter().flatten() {
            if let Some((i, _)) = self.section_containing_rva(*slot) {
                self.sections[i].header.characteristics |= IMAGE_SCN_MEM_WRITE;
            }
        }

        let first_iat = iat_slots[0][0];
        let iat_size = iat_slots
            .iter()
            .map(|s| s.len() as u32 * psize)
            .sum::<u32>();
        self.set_data_directory(
            DataDirectoryIndex::Import,
            Rva(rendered.dir_rva),
            rendered.size,
        )?;
        self.set_data_directory(DataDirectoryIndex::Iat, first_iat, iat_size)?;
        self.imports = descriptors.to_vec();
        Ok(RebuiltImportTable {
            rva,
            size: rendered.size,
            iat_rva: first_iat,
            iat_size,
            thunk_values: rendered.thunk_values,
        })
    }
}
