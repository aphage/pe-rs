//! Shared GUI utilities for the pe-rs editors.
//!
//! Two things the disk editor (`pe-edit-gui`) and the process dumper
//! (`pe-scylla-gui`) both need and would otherwise duplicate:
//!
//! * **i18n** — translation strings live in `locales/` as `rust-i18n` locale
//!   files (one YAML per language) with a runtime global locale. The [`t!`]
//!   macro generated here is exported at the crate root, so both GUIs
//!   translate with `t!("key", name = value)` from a single set of files.
//! * **fonts** — egui's bundled fonts have no CJK glyphs, so Chinese UI text
//!   renders as boxes without a Windows system CJK fallback family.
//! * **config** — the chosen UI language is persisted across restarts.

pub mod config;
pub mod fonts;
pub mod lang;
pub mod theme;

// Declare the locale resources (under `locales/`, defaulting to English when a
// key is missing). This generates the `t!` macro at the crate root.
rust_i18n::i18n!("locales");

#[cfg(test)]
mod tests {
    use rust_i18n::t;
    use std::collections::BTreeSet;
    use std::sync::{Mutex, OnceLock};

    /// rust-i18n's locale is process-global, so tests that call `set_locale`
    /// must be serialized or they race under `cargo test`'s parallel runner.
    static LOCALE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    pub(crate) fn lock_locale() -> std::sync::MutexGuard<'static, ()> {
        LOCALE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Flatten the two-space-indented YAML maps we write by hand into dotted
    /// keys (e.g. `menu.file`), mirroring how `t!` looks them up.
    fn flatten_yaml(yaml: &str) -> Vec<String> {
        let mut keys = Vec::new();
        // Stack of (indent, prefix) for open map nodes.
        let mut stack: Vec<(usize, String)> = Vec::new();
        for line in yaml.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            let Some(colon) = trimmed.find(':') else {
                continue;
            };
            let key = trimmed[..colon].trim().trim_matches('"').to_owned();
            let rest = trimmed[colon + 1..].trim();
            while let Some(&(d, _)) = stack.last() {
                if d >= indent {
                    stack.pop();
                } else {
                    break;
                }
            }
            let prefix = stack.last().map(|(_, p)| p.as_str()).unwrap_or("");
            let full = if prefix.is_empty() {
                key
            } else {
                format!("{prefix}.{key}")
            };
            if rest.is_empty() {
                stack.push((indent, full));
            } else {
                keys.push(full);
            }
        }
        keys
    }

    fn locale_keys(locale: &str) -> BTreeSet<String> {
        let yaml = match locale {
            "en" => include_str!("../locales/en.yml"),
            "zh-CN" => include_str!("../locales/zh-CN.yml"),
            _ => unreachable!(),
        };
        flatten_yaml(yaml).into_iter().collect()
    }

    /// Every key defined in English must exist in Chinese (and vice versa), so
    /// a string can never silently fall back to the other language.
    #[test]
    fn locales_cover_the_same_keys() {
        let en = locale_keys("en");
        let zh = locale_keys("zh-CN");
        assert_eq!(en, zh, "en.yml and zh-CN.yml must define the same keys");
        assert!(
            en.len() > 50,
            "expected a substantial key set, got {}",
            en.len()
        );
    }

    /// The core mechanism: `t!` resolves a dotted key in the current locale
    /// and `set_locale` switches the language.
    #[test]
    fn t_resolves_and_switches_locale() {
        let _guard = lock_locale();
        rust_i18n::set_locale("en");
        assert_eq!(t!("menu.file"), "File");
        assert_eq!(
            t!("status.saved", len = 12, path = "a.bin"),
            "saved 12 bytes to a.bin"
        );
        rust_i18n::set_locale("zh-CN");
        assert_eq!(t!("menu.file"), "文件");
        assert_eq!(
            t!("status.saved", len = 12, path = "a.bin"),
            "已保存 12 字节到 a.bin"
        );
        rust_i18n::set_locale("en");
    }

    /// The runtime-key path used by `lang::set_lang` for the window title: a
    /// `t!` with the key passed as a variable, evaluated after switching.
    #[test]
    fn t_resolves_runtime_key() {
        let _guard = lock_locale();
        rust_i18n::set_locale("en");
        let key = "app.title_scylla";
        assert_eq!(t!(key).into_owned(), "Scylla Dumper");
        rust_i18n::set_locale("zh-CN");
        assert_eq!(t!(key).into_owned(), "Scylla 转储器");
        rust_i18n::set_locale("en");
    }

    /// `set_lang`'s exact call shape: the key arrives as a `&'static str`
    /// *parameter*, not a local. Verify the macro handles that identically.
    fn title_for(title_key: &'static str) -> String {
        t!(title_key).into_owned()
    }

    #[test]
    fn t_resolves_key_from_param() {
        let _guard = lock_locale();
        rust_i18n::set_locale("zh-CN");
        assert_eq!(title_for("app.title_scylla"), "Scylla 转储器");
        rust_i18n::set_locale("en");
        assert_eq!(title_for("app.title_scylla"), "Scylla Dumper");
        rust_i18n::set_locale("en");
    }
}
