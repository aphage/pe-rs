# pe-edit

A Rust library for **viewing and editing PE (Portable Executable) files on disk**
— the *disk file editing* paradigm (CFF-Explorer style). It parses a PE file into a
rich [`PeDocument`] (headers, sections, data directories, and the
import/export/resource/reloc/TLS/LoadConfig rich forms), lets you edit it through
the capability traits in `pe_edit::api`, and serializes it back to bytes.

It has **no process dependency** — everything operates on files on disk. The
companion crate [`pe-scylla`] builds the *process-dump* paradigm (Scylla
benchmark) on top of this shared image model.

[`PeDocument`]: https://docs.rs/pe-edit/latest/pe_edit/domain/struct.PeDocument.html
[`pe-scylla`]: https://crates.io/crates/pe-scylla

## Features

- Parse real on-disk PE files through the official `windows-sys` `IMAGE_*`
  definitions, mapped into rich domain types.
- View / edit: headers, data directories, sections (add / remove / merge /
  rebuild), import table, export table, and the resource / reloc / TLS /
  LoadConfig directories.
- Built *outside-in*: a stable public API (domain model + capability traits),
  backed by a mock (for contract tests) or the real parser/writer.
- `feature::VaConverter` — RVA / VA / raw-offset conversion;
  `feature::rebuild_section_table` / `merge_sections`.
- Full round-trip guarantees: `parse(serialize(doc))` preserves the document.

## Usage

```rust
use pe_edit::io::pe::{parse, serialize};

// Parse a PE file from disk.
let bytes = std::fs::read("app.exe")?;
let mut doc = parse(&bytes)?;   // -> pe_edit::domain::PeDocument

// Inspect / edit through the capability traits in pe_edit::api:
//   PeViewer (read), PeEditor (headers / sections / write-alloc),
//   ImportTableEditor, ExportTableEditor, DirectoryEditor.

// Serialize back to bytes.
let out = serialize(&doc)?;
std::fs::write("app-edited.exe", &out)?;
# Ok::<(), pe_edit::PeError>(())
```

## License

MIT
