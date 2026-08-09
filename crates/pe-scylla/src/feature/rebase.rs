//! Rebase a process dump so it can be re-run standalone.
//!
//! A dump of a running process carries two kinds of value in its relocation
//! slots (`DataDirectory[IMAGE_BASE_RELOCATION]`, parsed as
//! [`RelocationTable`]):
//!
//! - **image-internal pointers**, which the loader already relocated to the
//!   process's actual base. Dumping them and re-loading is self-consistent:
//!   the loader's second relocation adds `LoadBase - ImageBase`, and because
//!   the dump's `ImageBase` *is* the actual base, `actual + rva + (LoadBase -
//!   actual) = LoadBase + rva`. They don't need to be touched at all.
//! - **runtime-written absolute pointers** (e.g. `GetProcAddress` results,
//!   heap handles) that `std`/CRT programs lazily store into `.data` at
//!   startup. Those slots are still covered by a relocation entry, so on a
//!   re-load the loader re-relocates them as if they were image pointers and
//!   they turn into garbage — the reason a dump of a normal program crashes.
//!
//! [`rebase_dump`] classifies every relocation slot by its stored value
//! (inside the image range → image-internal; outside → runtime-written), then
//! rebuilds the table: image-internal pointers are rebased to `preferred_base`
//! (and `ImageBase` set to it, so the output is a standard file-consistent
//! image), while runtime-written slots are zeroed and **dropped from the
//! table** — the loader leaves them alone and the program re-initializes them
//! at load (the lazy-init path sees a null and resolves fresh).

use pe_edit::domain::data_directory::DataDirectoryIndex;
use pe_edit::domain::relocation::{
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, RelocationBlock,
    RelocationTable,
};
use pe_edit::domain::{PeDocument, Rva};
use pe_edit::error::{PeError, Result};
use pe_edit::io::pe::parser::{parse_load_config_from_doc, parse_tls_from_doc};

/// Outcome of [`rebase_dump`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RebaseReport {
    /// Image-internal pointers rewritten to the (new) preferred base.
    pub rebased: usize,
    /// Runtime-written external slots zeroed and removed from the table.
    pub cleared: usize,
}

/// Rebase `doc` (a process dump) to `preferred_base` and rebuild its relocation
/// table, so a fixed dump runs standalone even when the original program's
/// runtime wrote absolute pointers into `.data`.
///
/// If the relocation table contains relocation types other than DIR64/HIGHLOW,
/// the dump is not rebased to a new base — `ImageBase` stays the actual load
/// base (image-internal pointers are self-consistent there) and only the
/// runtime-written external slots are cleared and dropped.
pub fn rebase_dump(doc: &mut PeDocument, preferred_base: u64) -> Result<RebaseReport> {
    let actual = doc.optional.image_base();
    let image_end = actual + doc.optional.size_of_image() as u64;
    let mut report = RebaseReport::default();

    let Some(table) = doc.relocations.clone() else {
        // No absolute pointers to reconcile; just pick the requested base.
        doc.optional.set_image_base(preferred_base);
        return Ok(report);
    };

    // Rebase to a new base only when every entry is one we understand; exotic
    // types would otherwise be relocated against the wrong base.
    let all_standard = table.blocks.iter().flat_map(|b| &b.entries).all(|e| {
        matches!(
            e.reloc_type,
            IMAGE_REL_BASED_ABSOLUTE | IMAGE_REL_BASED_HIGHLOW | IMAGE_REL_BASED_DIR64
        )
    });
    let target_base = if all_standard { preferred_base } else { actual };

    let mut rebuilt = RelocationTable::default();
    for block in &table.blocks {
        let mut entries = Vec::new();
        for e in &block.entries {
            match e.reloc_type {
                // Padding / no-op: leave the slot alone, keep the entry.
                IMAGE_REL_BASED_ABSOLUTE => entries.push(*e),
                IMAGE_REL_BASED_DIR64 | IMAGE_REL_BASED_HIGHLOW => {
                    let n = if e.reloc_type == IMAGE_REL_BASED_DIR64 {
                        8
                    } else {
                        4
                    };
                    let Some(slot_rva) = block.page_rva.checked_add(e.offset as u32) else {
                        continue;
                    };
                    let Ok(bytes) = doc.read(slot_rva, n) else {
                        entries.push(*e); // unreadable slot: leave it be
                        continue;
                    };
                    let value = if n == 8 {
                        u64::from_le_bytes(bytes.try_into().unwrap())
                    } else {
                        u32::from_le_bytes(bytes.try_into().unwrap()) as u64
                    };
                    if value == 0 {
                        continue; // empty slot: nothing to reconcile, drop the entry
                    } else if (actual..image_end).contains(&value) {
                        // Image-internal pointer. Rebase when changing base;
                        // otherwise it is already self-consistent.
                        if target_base != actual {
                            let new = target_base + (value - actual);
                            write_pointer(doc, slot_rva, n, new)?;
                            report.rebased += 1;
                        }
                        entries.push(*e);
                    } else {
                        // Runtime-written external pointer: clear it and drop the
                        // relocation entry so the loader doesn't touch it and the
                        // program re-initializes it at load.
                        write_pointer(doc, slot_rva, n, 0)?;
                        report.cleared += 1;
                    }
                }
                // Exotic type: preserve the entry and slot untouched.
                _ => entries.push(*e),
            }
        }
        if !entries.is_empty() {
            rebuilt.blocks.push(RelocationBlock {
                page_rva: block.page_rva,
                entries,
            });
        }
    }

    doc.relocations = Some(rebuilt);
    doc.optional.set_image_base(target_base);

    // Rebase rewrote the raw slots of every directory whose values are absolute
    // pointers, but their parsed rich forms still hold the pre-rebase values.
    // Re-parse them so the writer's reuse-or-rebuild keeps the rebased slots
    // instead of re-rendering stale pointers into a fresh section.
    if let Some(tls_dir) = doc
        .data_directory(DataDirectoryIndex::Tls)
        .ok()
        .filter(|d| d.rva != Rva::NULL)
    {
        doc.tls = parse_tls_from_doc(doc, *tls_dir).ok();
    }
    if let Some(lc_dir) = doc
        .data_directory(DataDirectoryIndex::LoadConfig)
        .ok()
        .filter(|d| d.rva != Rva::NULL)
    {
        doc.load_config = parse_load_config_from_doc(doc, *lc_dir).ok();
    }

    Ok(report)
}

fn write_pointer(
    doc: &mut PeDocument,
    rva: pe_edit::domain::Rva,
    n: usize,
    value: u64,
) -> Result<()> {
    match n {
        8 => doc.write(rva, &value.to_le_bytes()),
        4 => doc.write(rva, &(value as u32).to_le_bytes()),
        _ => Err(PeError::InvalidArgument("unsupported pointer width".into())),
    }
}
