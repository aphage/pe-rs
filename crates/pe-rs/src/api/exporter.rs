//! Editing of the (rich) export table.

use crate::domain::export::{ExportSymbol, ExportTable};
use crate::error::{PeError, Result};

/// Operations on the parsed export table of a [`PeDocument`].
///
/// `add_export` / `remove_export` / `set_exports` edit the rich form directly.
/// The physical export directory is rebuilt at serialization time by the
/// writer (a fresh `.peexp` section when the existing directory no longer
/// matches the rich form), so no immediate write-back is needed.
pub trait ExportTableEditor {
    /// Replace the whole export table; `None` clears it.
    fn set_exports(&mut self, exports: Option<ExportTable>) -> Result<()>;
    /// Add `symbol`, or replace the existing symbol with the same ordinal.
    /// Auto-creates the export table when the document has none (base 0,
    /// empty module name).
    fn add_export(&mut self, symbol: ExportSymbol) -> Result<()>;
    /// Remove the symbol at `ordinal`; error when it is absent. Removing the
    /// last symbol clears the export table.
    fn remove_export(&mut self, ordinal: u16) -> Result<()>;
}

impl ExportTableEditor for crate::domain::PeDocument {
    fn set_exports(&mut self, exports: Option<ExportTable>) -> Result<()> {
        self.exports = exports;
        Ok(())
    }

    fn add_export(&mut self, symbol: ExportSymbol) -> Result<()> {
        let table = self.exports.get_or_insert_with(Default::default);
        match table
            .symbols
            .iter_mut()
            .find(|s| s.ordinal == symbol.ordinal)
        {
            Some(slot) => *slot = symbol,
            None => table.symbols.push(symbol),
        }
        table.number_of_functions = table.symbols.len() as u32;
        Ok(())
    }

    fn remove_export(&mut self, ordinal: u16) -> Result<()> {
        let Some(table) = self.exports.as_mut() else {
            return Err(PeError::NotFound("remove_export: no export table".into()));
        };
        let before = table.symbols.len();
        table.symbols.retain(|s| s.ordinal != ordinal);
        if table.symbols.len() == before {
            return Err(PeError::NotFound(format!(
                "remove_export: no export at ordinal {ordinal}"
            )));
        }
        if table.symbols.is_empty() {
            // The last symbol is gone: no exports left, clear the table so the
            // writer zeroes the export directory.
            self.exports = None;
        } else {
            table.number_of_functions = table.symbols.len() as u32;
        }
        Ok(())
    }
}
