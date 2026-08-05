# pe-rs

A Rust library for **viewing and editing PE (Portable Executable) files**, covering the
*file-level* feature set of [Scylla](https://github.com/NtQuery/Scylla) — including
IAT scanning, **IAT fixing** (import table rebuilding, a.k.a. "Fix Dump") and **manual
IAT array** addition — to be consumed by a future GUI PE editor.

> Scaffolded. Architecture and roadmap are being written up in Phase 10.

## Workspace layout

```
pe-rs/
├── crates/pe-rs/       the library (this project's deliverable)
└── crates/pe-rs-gui/   placeholder GUI consumer
```

## Development approach

Outside-in: fix the outer public API (domain model + capability traits) first, back it
with a mock for tests, then implement the real PE parser/writer behind the same API.
One git commit per stage/feature.
