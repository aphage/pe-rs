//! Force a rebuild when the locale files change.
//!
//! `rust-i18n` reads `locales/*.yml` inside the `i18n!` proc-macro, and cargo
//! does not track that file dependency on its own. Without this, editing a
//! locale file could leave stale translations baked into the binary — a
//! missing key then silently falls back to the raw key at runtime.

use std::path::Path;

fn main() {
    let dir = Path::new("locales");
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().is_file() {
                println!("cargo:rerun-if-changed={}", entry.path().display());
            }
        }
    }
    // Watch the directory itself so adding/removing a locale file also
    // triggers a rebuild.
    println!("cargo:rerun-if-changed={}", dir.display());
}
