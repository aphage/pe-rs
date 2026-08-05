# pe-rs

A Rust library for **viewing and editing PE (Portable Executable) files**,
covering the *file-level* feature set of [Scylla](https://github.com/NtQuery/Scylla):
header/section viewing & editing, import/export tables, **IAT scanning**,
**IAT fixing** (import table rebuilding, a.k.a. "Fix Dump") and **manual IAT
array** addition. It is the library a future GUI PE editor will be built on
(the `pe-rs-gui` crate is the placeholder consumer).

## Feature overview

**Viewing**
- DOS / COFF / Optional (PE32 & PE32+) headers
- Section table and data directories
- Import table (by name or ordinal) and export table
- Raw ↔ RVA ↔ VA conversion (including non-aligned dumps) via `VaConverter`

**Editing**
- Header fields, data directories, add/remove sections
- Add / remove imports; `write`/`alloc` arbitrary bytes into the image

**Scylla-style, file-level**
- `IatScanner` — locate the IAT in the image (resolver-based, with region and
  min-entries options)
- `IatFixer::fix_iat` — resolve IAT entries to `(module, function)`, rebuild the
  import directory (descriptors + INT/IAT arrays + name strings) and optionally
  **redirect** the original IAT slots to the new thunks
- `IatFixer::add_iat_array` — manually feed a caller-supplied array of IAT
  entries and rebuild from it
- `rebuild_section_table` / `merge_sections` — section table rebuild and merge

## Architecture

Built *outside-in*: the outer public API (domain model + capability traits) is
fixed first and backed by a **mock** so contract tests run before the real
parser/writer exists; the same tests then run against the real implementation.

```
crates/pe-rs/src/
├── api/        trait "ports": PeViewer, PeEditor, ImportTableEditor,
│               IatScanner, IatFixer, ImportResolver
├── domain/     pure-data model: PeDocument + header/section/import/export/IAT types
├── feature/    standalone utilities: VaConverter, section rebuild/merge
└── io/         adapters between bytes/disk and the model:
    ├── mock/       MockSource + MockResolver (fabricated, deterministic)
    ├── pe/         real parser + writer + import/export table renderers
    └── source.rs   PeSource trait + PeFile facade + Byte/FileSource
```

The real parser reads every on-disk structure (DOS/COFF/Optional/section
headers, import/export/resource/reloc/TLS directories) through the official
`windows-sys` `IMAGE_*` definitions, then converts them into the crate's rich
domain types. The domain model and every capability trait are shared; mock and
real differ only in how a `PeDocument` is produced (fabricated vs. parsed).
Contract tests run against both paths (see `tests/common`).

## Usage

```rust,no_run
use pe_rs::api::{IatFixer, IatScanner, PeViewer};
use pe_rs::domain::ScanOptions;
use pe_rs::io::{MockResolver, PeFile};

fn fix_dump(path: &str) -> Result<(), pe_rs::PeError> {
    let mut file = PeFile::open(path)?;
    let resolver = MockResolver::new(); // any ImportResolver

    let scan = file.doc().scan(&resolver, &ScanOptions::default())?;
    let report = file.doc_mut().fix_iat(&scan, &resolver, &Default::default())?;
    println!(
        "rebuilt {} imports ({} entries), {} unresolved",
        report.imports_built,
        report.total_entries,
        report.unresolved.len(),
    );
    file.save()
}
```

## Roadmap

- [x] Phase 0–5 — scaffold, outer API + domain model, mock, contract tests, real parser/writer (round-trip stable)
- [x] Phase 6–8 — IAT scanner (resolver + opcode-pattern), IAT fixer (import table rebuild + redirect), manual IAT array
- [x] Phase 9 — Raw↔VA conversion, section table rebuild/merge
- [x] Opcode-pattern IAT scan (`ScanMethod::OpcodePattern`)
- [x] Resource / relocation / TLS directory parsing (view)
- [x] Resource / relocation / TLS directory editing (`DirectoryEditor`)
- [ ] LoadConfig directory parsing
- [ ] Section merging across non-contiguous ranges (RVA remap)
- [ ] Process-level features for the GUI (dump live process, inline hooks, tracer, ScyllaHide)
- [ ] GUI application (crates/pe-rs-gui)

## Development

One git commit per stage/feature (outside-in: API → mock → tests → real impl).
Check before committing:

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --check
```
