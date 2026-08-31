# pe-rs

A Rust workspace with **two independent PE tools**, split along the two
underlying paradigms:

| Tool | Paradigm | Benchmark | Surface |
|---|---|---|---|
| **pe-edit** | disk PE **file editing** | CFF Explorer | parse a file → edit headers/sections/tables → write back. Memory layout 4K (`SectionAlignment`) vs disk layout 512 (`FileAlignment`). |
| **pe-scylla** | **process dump / IAT fix** | [Scylla](https://github.com/NtQuery/Scylla) | attach to a debugged process → dump its image → find the IAT (3 scan lines) → rebuild the import table → save the fixed dump. |

Each tool ships a **CLI** and a **GUI** (`*-cli` / `*-gui` crates). The two
libraries share the PE *image model* (`pe-edit` provides `PeDocument` +
`parse`/`serialize`; `pe-scylla` operates on it and adds the process side).

```
crates/pe-edit        lib A — disk PE editing API + image model
crates/pe-edit-cli    CLI A — `pe-edit` (show / set-entry / add-section / add-import / merge / rebuild)
crates/pe-edit-gui    GUI A — CFF-Explorer-style editor (12-node structure tree: DOS/COFF/Optional/Directories/Sections/Imports/Exports/Resources/Relocs/TLS/LoadConfig/Converter)
crates/pe-scylla      lib B — process operation + dump API (depends on pe-edit)
crates/pe-scylla-cli  CLI B — `pe-scylla` (dump → scan → fix → save)
crates/pe-scylla-gui  GUI B — Scylla-style tool (process picker → dump → IAT → fix → save)
crates/sim-target     self-corrupting no_std target that validates pe-scylla end-to-end
crates/std-target     std program reproducing the documented dump limitation
crates/pe-gui-common  shared GUI utilities: i18n (rust-i18n locales + CJK fonts + persisted language)
```

Both GUIs are bilingual (简体中文 / English): the `Language` menu switches at
runtime, the choice is persisted, and the first run auto-detects the system
language. Strings live in `pe-gui-common/locales/` (`en.yml` / `zh-CN.yml`).

## pe-scylla: dump → fix a process

The Scylla workflow. Dump a (typically paused / debugged) process, scan its
IAT against the process's loaded modules with the right scan line, rebuild the
import table, write a fixed dump.

```text
cargo run -p pe-scylla-cli -- <pid> fixed.exe --method code --rebase
```

- `IatScanner` — locate the IAT by `ScanMethod::Resolver` (values that resolve
  through the process modules), `CodeReference` (disassemble the code sections,
  keep Scylla's IAT-reference opcode set — call/jmp/push/mov/lea — and return
  the full referenced-slot set for curation with `IatTable`), or `Reflection`
  (recover the IAT from the PE structure: an overwritten `OriginalFirstThunk`,
  or the NULL-separated sub-arrays of the IAT data directory).
- `IatFixer::fix_iat` — resolve IAT entries to `(module, function)`, rebuild
  the import directory (descriptors + INT/IAT arrays + name strings) and
  redirect the original IAT slots. The rebuilt table is placed **in place** at
  the original slot RVAs when they are contiguous (the shape that makes a fixed
  dump runnable); otherwise every code reference is rewritten to the new table
  (`remap_iat_references`).
- `recover_dump_imports` — recover a dumped process's import table per Scylla's
  dump handling (intact OFT keeps hint/name pairs, overwritten ones are
  reflected and resolved through the resolver).
- `rebase_dump` — rebuild the base relocation table so a dump whose runtime
  wrote absolute pointers into `.data` re-runs standalone.
- `process::spawn_paused` — create a process paused at its **entry point**
  (fully loaded, nothing run) — the clean, correct moment to dump.
- `process::tracer` — inline API-hook tracing.

### Scylla interaction model (Get Imports / Fix Dump)

The GUI (and `pe-scylla-cli`'s `get-imports` / `fix-tree`) drive Scylla's
interaction model end-to-end:

- **OEP / IAT address+size fields** (typed or filled by `Scan IAT` /
  **IAT Autosearch** — `process::search_iat` disassembles the live process
  from the OEP, finds a resolving call/jmp slot, and derives the IAT
  start/size; `--advanced` disassembles the whole executable region).
- **Get Imports** — `get_imports(pid, resolver, iat_va, iat_size)` reads the
  live IAT and resolves every thunk into a per-module tree with **valid /
  suspect / invalid** status. `ProcessResolver` scores duplicate exports
  (kernel32 high priority; `EncodePointer`/`DecodePointer`-style aliases are
  flagged suspect).
- **Fix Dump from tree** — `fix_iat_from_tree(doc, tree, options, oep)`
  rebuilds the dump's imports from the curated tree and writes the OEP.
  `IatFixOptions` gains `write_oft` (OriginalFirstThunk) and
  `new_iat_in_section`.
- **Direct imports** (`api::direct_imports`) — scan for `call`/`jmp` that
  target an API directly (not through the IAT), add them as imports, and route
  them through a jump table (`build_direct_import_jump_table` +
  `patch_direct_imports_to_jump_table`).
- **Process** — `suspend`/`resume` (dump without racing the target),
  `dump_memory(pid, va, size)`, `dump_section(pid, index)`,
  `dump_with_oep(pid, oep)`.
- **Save/Load import tree** (`io::tree`) — the curated tree + OEP/IAT metadata
  as **XML or JSON**.
- **PE Rebuild** (`feature::pe_rebuild`) — realign a disk PE, optionally drop
  the DOS stub / update the checksum / keep a `.bak`.
- **GUI** — process picker, imports tree with status icons, a log panel, an
  Options dialog (suspend / advanced search), and a Disassembler view.

## pe-edit: edit a disk PE file

The CFF-Explorer paradigm. A PE file is parsed into a rich `PeDocument`
(headers, sections, data directories, import/export/resource/reloc/TLS/
LoadConfig rich forms), edited through the `pe-edit` capability traits, and
serialized back.

```text
cargo run -p pe-edit-cli -- show C:\Windows\System32\kernel32.dll
cargo run -p pe-edit-gui
```

Editing surface (`pe_edit::api`): `PeViewer` (read), `PeEditor` (headers /
data directories / add-remove sections / write-alloc), `ImportTableEditor`,
`ExportTableEditor`, `DirectoryEditor` (resource / reloc / TLS / LoadConfig),
plus `feature::{VaConverter, rebuild_section_table, merge_sections}`.

The **GUI** (`pe-edit-gui`) is a bright, bilingual CFF-Explorer-style editor:
all DOS/COFF/Optional header fields editable in place (writer-derived fields —
`e_lfanew`, section/optional sizes, raw offsets, the 7 rich-form directories —
are shown read-only and re-rendered on save), a File/Memory (512/4K) layout
toggle, a virtualized section hex view with right-click jump and byte find,
an editable section table (name/VA/VSize/Characteristics) with overlapping-VA
warnings, add/remove sections, import/export editing, a resource tree with
leaf byte preview, relocation / TLS / load-config viewers, an RVA/VA/raw
address converter, a snapshot undo/redo stack (Ctrl+Z / Ctrl+Y, one step
per edit gesture), and a cross-tree search box (sections / imports / exports /
resources, results jump to the matching node). Unsaved edits are guarded on
Open/Save-As/close.

## Architecture

Both libraries are built *outside-in*: a stable public API (domain model +
capability traits) fixed first, then backed by a **mock** so contract tests run
before the real parser/writer exists; the same tests then run against the real
implementation.

```
crates/pe-edit/src/
├── api/        capability traits: PeViewer, PeEditor, ImportTableEditor,
│               ExportTableEditor, DirectoryEditor, ImportResolver
├── domain/     pure-data model: PeDocument + header/section/directory/import/export/IAT types
├── feature/    VaConverter, section rebuild/merge
└── io/         adapters: mock/, pe/{parser, writer, *render}, source.rs

crates/pe-scylla/src/
├── api/        IatScanner, IatFixer (impl for pe_edit::PeDocument)
├── process/    dump, list_*, ProcessResolver (+ fingerprints), spawn_paused, tracer
└── feature/    rebase_dump
```

The real parser reads every on-disk structure through the official `windows-sys`
`IMAGE_*` definitions, then converts them into the crate's rich domain types.
Contract tests run against both the mock and the real path (see `tests/common`).

## Simulation test (dump → fix → re-run)

`crates/sim-target` validates the Scylla workflow end-to-end: a minimal-runtime
Windows executable **corrupts its own in-memory PE image** per the scenarios of
`docs/dump 情况分析和处理.md`, then **pauses itself** (like a debugger break).
`pe-scylla` then dumps the paused process, scans its IAT with the per-scenario
method, fixes the imports, writes a rebuilt executable, and the fixed dump is
**re-run** to prove it works standalone.

```text
cargo build -p sim-target

# 1. start the target: corrupt per scenario, then pause (prints SIM_TARGET_READY:<pid>)
./target/debug/sim-target.exe corrupt erased

# 2. standalone pe dump tool: dump + fix + save (knows nothing about the target)
#    --rebase additionally rebuilds the base relocation table so a dump whose
#    runtime wrote absolute pointers into .data re-runs
cargo run -p pe-scylla-cli -- <pid> fixed.exe --method code --rebase

# 3. run the fixed dump
./fixed.exe verify          # -> SIM_TARGET_OK, exit 0
```

| scenario | in-memory corruption | scan (`--method`) | fixed dump runs |
|---|---|---|---|
| `normal` (A) | none | `code` | ✓ |
| `oft` (B) | `OriginalFirstThunk` zeroed | `reflection` | ✓ |
| `iatdir` (C) | Import directory erased, IAT kept | `reflection` | ✓ |
| `erased` (D) | both erased + IAT scattered, code repointed | `code` | ✓ |
| `pollute` | an external pointer written into a `.reloc`-covered `.data` slot | `code` | only with `--rebase` |

The scenarios are also driven automatically (spawn → pause → dump+fix → re-run):

```text
cargo test -p sim-target -- --ignored
```

See `docs/simulation.md` for the details (why the target is `no_std`, how a
fixed dump is made runnable, and the documented std-program limitation).

## Development

Check before committing:

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --check
```

## Roadmap

- [x] Two-paradigm split (this reorg): pe-edit (disk edit) + pe-scylla (process dump), each CLI + GUI
- [x] pe-scylla aligned with Scylla: OEP/IAT fields, Get Imports tree (valid/suspect/invalid),
      API scoring, IAT autosearch, suspend/resume, dump memory/section, fix options
      (OFT, new IAT in section, direct imports), save/load tree (XML+JSON), PE rebuild,
      GUI log/options/disassembler
- [x] pe-edit: memory-view (4K) / disk-view (512) toggle in the editor (CFF Explorer File/Memory dual view)
- [x] pe-edit: snapshot undo/redo (Ctrl+Z / Ctrl+Y), section VA-overlap warnings
- [x] pe-edit: cross-tree search (sections / imports / exports / resources with jump-to-node)
- [ ] pe-scylla: auto-trace to find OEP/IAT (Scylla AutoTrace); per-tool feature pass,
      one git commit per feature
