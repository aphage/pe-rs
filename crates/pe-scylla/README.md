# pe-scylla

A Rust library for the **process-dump / IAT-fix** paradigm (Scylla benchmark):
attach to a (typically paused / debugged) process, read its PE image out of
memory into `pe_edit::PeDocument`, scan the IAT with one of three scan lines
(resolver / code-reference / reflection), rebuild the import table ("Fix Dump"),
and save a fixed, runnable dump.

It depends on [`pe-edit`] for the image model and disk-level parse/serialize;
everything in this crate is process-oriented.

> **Windows-only.** The process code lives under `#[cfg(target_os = "windows")]`.
> On other targets the crate compiles but the process API is unavailable.

[`pe-edit`]: https://crates.io/crates/pe-edit

## Features

- `process::dump` — read a live process's PE image into `PeDocument`.
- `IatScanner` — locate the IAT by `ScanMethod::Resolver`,
  `ScanMethod::CodeReference`, or `ScanMethod::Reflection`.
- `IatFixer::fix_iat` — resolve IAT entries to `(module, function)`, rebuild the
  import directory (descriptors + INT/IAT arrays + name strings), and redirect
  the original IAT slots — placed **in place** when contiguous, otherwise every
  code reference is rewritten (`remap_iat_references`).
- `recover_dump_imports` — recover a dumped process's import table per Scylla's
  dump handling.
- `rebase_dump` — rebuild the base relocation table so a dump whose runtime
  wrote absolute pointers into `.data` re-runs standalone.
- `process::spawn_paused` — create a process paused at its **entry point**
  (fully loaded, nothing run) — the clean moment to dump.
- `process::tracer` — inline API-hook tracing.
- `io::tree` — save/load a curated import tree as **XML or JSON**.

## Usage

```rust,no_run
use pe_scylla::{process, IatFixOptions, ScanMethod, ScanOptions};
use pe_edit::io::pe::serialize;

// Create a process paused at its entry point (Drop terminates it when done).
let paused = process::spawn_paused("app.exe", &[])?;
let pid = paused.pid;

// Dump its PE image, restore the entry-point byte, scan and fix the IAT.
let mut doc = process::dump(pid)?;
paused.restore_entry_byte(&mut doc)?;

let resolver = process::ProcessResolver::for_process(pid)?;
let scan = doc.scan(&resolver, &ScanOptions { method: ScanMethod::CodeReference, ..Default::default() })?;
doc.fix_iat(&scan, &resolver, &IatFixOptions::default())?;

let bytes = serialize(&doc)?;
std::fs::write("fixed.exe", &bytes)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## License

MIT
