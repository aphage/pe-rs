//! Tiny persisted settings: the chosen UI language. Hand-rolled (no serde): a
//! single `lang` file holding the locale code, so the choice survives
//! restarts. Written only on an explicit user switch — never on startup, so a
//! later OS-language change isn't masked by a stale file.

use std::path::PathBuf;

/// Directory for this project's config files (`%APPDATA%\pe-rs` on Windows,
/// `$XDG_CONFIG_HOME`/`~/.config` elsewhere, current dir as a last resort).
fn config_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("pe-rs")
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."))
            .join("pe-rs")
    }
}

fn config_path() -> PathBuf {
    config_dir().join("lang")
}

/// The saved language code (`"en"` / `"zh-CN"`), if the config file holds one
/// we support. `None` when missing, unreadable, or stale.
pub fn load_lang() -> Option<String> {
    let s = std::fs::read_to_string(config_path()).ok()?;
    let code = s.trim();
    if matches!(code, "en" | "zh-CN") {
        Some(code.to_owned())
    } else {
        None
    }
}

/// Persist the chosen language code (best-effort).
pub fn save_lang(code: &str) {
    let dir = config_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let _ = std::fs::write(dir.join("lang"), code);
}
