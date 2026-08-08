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
  min-entries options, grouping across the per-module NULL separators of a real
  IAT), by `ScanMethod::CodeReference` (disassembles the code sections with
  iced-x86, keeps the direct memory operands of Scylla's IAT-reference opcode
  set — call/jmp/push/mov/lea — and returns the full referenced-slot set for
  curation with `IatTable`; signature scan for protected dumps with
  `validate_slots: false`), or by `ScanMethod::Reflection` (dump handling when
  the loader overwrote `OriginalFirstThunk`: collect the `FirstThunk` arrays of
  those descriptors, or the NULL-separated sub-arrays of the IAT data directory
  when the import directory is gone)
- `recover_dump_imports` — recover a dumped process's import table per Scylla's
  dump handling: descriptors with an intact `OriginalFirstThunk` keep their
  hint/name pairs, overwritten ones are reflected (their `FirstThunk` holds
  loaded addresses, resolved through the resolver into names)
- `IatFixer::fix_iat` — resolve IAT entries to `(module, function)`, rebuild the
  import directory (descriptors + INT/IAT arrays + name strings) and optionally
  **redirect** the original IAT slots to the new thunks. The rebuilt table is
  placed **in place** at the original IAT slot RVAs when they are contiguous (so
  the loader resolves imports into the slots the code references — the shape
  that makes a fixed dump runnable); otherwise every code reference is rewritten
  to the new table (`remap_iat_references`)
- `IatFixer::add_iat_array` — manually feed a caller-supplied array of IAT
  entries and rebuild from it
- `IatTable` / `IatFixer::fix_iat_table` — curate an IAT by hand: add
  non-contiguous regions (`add_region`, for erased / split IATs e.g. VMProtect),
  drop false positives, then rebuild a normal contiguous import table
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

## Simulation test (dump → fix → re-run)

`crates/sim-target` simulates the real Scylla workflow end-to-end: a
minimal-runtime Windows executable **corrupts its own in-memory PE image** per
the scenarios of `docs/dump 情况分析和处理.md`, then **pauses itself** (like a
debugger break). A *standalone* pe dump tool (`pe-rs`'s `dump` example) then
dumps the paused process, scans its IAT with the per-scenario method, fixes the
imports, writes a rebuilt executable, and the fixed dump is **re-run** to prove
it works standalone.

```text
cargo build -p sim-target

# 1. start the target: corrupt per scenario, then pause (prints SIM_TARGET_READY:<pid>)
./target/debug/sim-target.exe corrupt erased

# 2. standalone pe dump tool: dump + fix + save (knows nothing about the target)
cargo run -p pe-rs --example dump -- <pid> fixed.exe --method code

# 3. run the fixed dump
./fixed.exe verify          # -> SIM_TARGET_OK, exit 0
```

| scenario | in-memory corruption | scan (`--method`) | fixed dump runs |
|---|---|---|---|
| `normal` (A) | none | `code` | ✓ |
| `oft` (B) | `OriginalFirstThunk` zeroed | `reflection` | ✓ |
| `iatdir` (C) | Import directory erased, IAT kept | `reflection` | ✓ |
| `erased` (D) | both erased + IAT scattered, code repointed | `code` | ✓ |

The four scenarios are also driven automatically (spawn → pause → dump+fix →
re-run, using pe-rs the way the standalone tool does):

```text
cargo test -p sim-target -- --ignored
```

The target is `no_std` (no CRT, no heap) on purpose: `std` programs lazily write
absolute function pointers into `.data`, so a dump of them can't re-run (the
loader re-relocates those slots as if they were image pointers). A clean runtime
behaves like a freshly-unpacked packed program. See `docs/simulation.md`.

## Roadmap

- [x] Phase 0–5 — scaffold, outer API + domain model, mock, contract tests, real parser/writer (round-trip stable)
- [x] Phase 6–8 — IAT scanner (resolver + disassembly code-reference), IAT fixer (import table rebuild + redirect), manual IAT array
- [x] Phase 9 — Raw↔VA conversion, section table rebuild/merge
- [x] Disassembly-based IAT reference scan (`ScanMethod::CodeReference`, iced-x86)
- [x] Resource / relocation / TLS directory parsing (view)
- [x] Resource / relocation / TLS directory editing (`DirectoryEditor`)
- [x] LoadConfig directory parsing (view, CFG fields)
- [x] LoadConfig directory editing
- [x] Section merging across non-contiguous ranges (RVA remap)
- [x] Process dump + IAT resolution (`pe_rs::process`: `dump`, `ProcessResolver` — dump a live process and scan/fix its IAT; `with_fingerprints` resolves addresses in **memory-loaded** (manually mapped) modules by matching code against the system-loaded copy, for protectors that erase or split the IAT)
- [x] Runnable fixed dumps (`fix_iat` rebuilds the import table in place at the
  original IAT slot RVAs, or rewrites code references to the new table; the
  writer preserves the raw/bss split so dumped uninitialized tails are
  re-zeroed) + a **simulation test** (`crates/sim-target`: a self-corrupting
  `no_std` target whose dump is fixed and re-run for all four dump scenarios)
- [x] Process hooks / tracer (`pe_rs::process::tracer` — inline API hooks with
  trampoline forwarding, trace log readback, self-hook verified)
- [ ] ScyllaHide (anti-anti-debug)
- [x] GUI application (crates/pe-rs-gui: view headers/sections/imports/exports/
  directories, dump a process, scan & fix its IAT, save)

## Development

One git commit per stage/feature (outside-in: API → mock → tests → real impl).
Check before committing:

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --check
```
