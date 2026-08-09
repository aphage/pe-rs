//! PE rebuild of a **disk** file (Scylla's `PeRebuild` / "PE Rebuild"): parse
//! the file, optionally remove the DOS stub, re-align the section table and
//! re-fix the headers, optionally recompute the PE header checksum, optionally
//! keep a `.bak` backup, and write it back.

use std::path::Path;

use pe_edit::domain::PeDocument;
use pe_edit::feature::rebuild_section_table;
use pe_edit::io::pe::{parse, serialize};

use crate::{PeError, Result};

/// Options for [`pe_rebuild`].
#[derive(Debug, Clone, Copy, Default)]
pub struct PeRebuildOptions {
    /// Zero out the DOS stub (the bytes between the DOS header and the NT
    /// headers) before re-aligning.
    pub remove_dos_stub: bool,
    /// Recompute and write the optional-header checksum.
    pub update_checksum: bool,
    /// Copy the original file to `<path>.bak` first.
    pub create_backup: bool,
}

/// Outcome of [`pe_rebuild`].
#[derive(Debug, Clone, Copy)]
pub struct PeRebuildReport {
    pub old_size: usize,
    pub new_size: usize,
}

/// Rebuild `path` in place (Scylla's PE Rebuild): realign sections, optionally
/// drop the DOS stub / update the checksum / keep a backup.
pub fn pe_rebuild(path: &Path, options: &PeRebuildOptions) -> Result<PeRebuildReport> {
    let bytes = std::fs::read(path).map_err(PeError::Io)?;
    if options.create_backup {
        let mut bak = path.as_os_str().to_os_string();
        bak.push(".bak");
        std::fs::copy(path, &bak).map_err(PeError::Io)?;
    }
    let mut doc = parse(&bytes)?;
    if options.remove_dos_stub {
        doc.dos.stub = Vec::new();
    }
    rebuild_section_table(&mut doc)?;
    let mut out = serialize(&doc)?;
    if options.update_checksum {
        let off = checksum_offset(&doc);
        if off + 4 <= out.len() {
            out[off..off + 4].fill(0);
            let cs = pe_checksum(&out);
            out[off..off + 4].copy_from_slice(&cs.to_le_bytes());
        }
    }
    std::fs::write(path, &out).map_err(PeError::Io)?;
    Ok(PeRebuildReport {
        old_size: bytes.len(),
        new_size: out.len(),
    })
}

/// Byte offset of the optional-header `CheckSum` field (its 8th DWORD, at
/// offset 0x40 within the optional header for both PE32 and PE32+).
fn checksum_offset(doc: &PeDocument) -> usize {
    let e_lfanew = doc.dos.e_lfanew as usize;
    e_lfanew + 4 + 20 + 64
}

/// The Windows PE checksum: sum of all 16-bit words plus the file size, with
/// carry folding. The checksum field must be zeroed before computing.
fn pe_checksum(data: &[u8]) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_le_bytes([data[i], data[i + 1]]) as u64;
        i += 2;
    }
    if i < data.len() {
        sum += data[i] as u64;
    }
    sum += data.len() as u64;
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u32
}
