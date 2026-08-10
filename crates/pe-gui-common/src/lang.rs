//! Runtime language handling: system-language auto-detect on first run, a
//! persisted override, and the egui menu to switch at runtime.

use crate::config;
use rust_i18n::t;

/// Locale code for Simplified Chinese.
pub const ZH: &str = "zh-CN";
/// Locale code for English.
pub const EN: &str = "en";

/// The currently active locale code (`"en"` or `"zh-CN"`).
pub fn current() -> String {
    rust_i18n::locale().to_string()
}

/// Normalize an OS locale string (e.g. `"zh-Hans-CN"`, `"en-US"`) to one of
/// the supported locale codes: anything Chinese → `zh-CN`, everything else
/// → `en`.
fn normalize(locale: &str) -> &'static str {
    if locale.to_ascii_lowercase().starts_with("zh") {
        ZH
    } else {
        EN
    }
}

/// Detect the system UI language, ignoring any saved config.
fn detect() -> &'static str {
    sys_locale::get_locale()
        .as_deref()
        .map(normalize)
        .unwrap_or(EN)
}

/// Choose the startup language — the persisted choice if any, otherwise the
/// system language — set it as the global locale, and return its code. Called
/// before the GUI is built so the initial window title is already localized.
pub fn init_lang() -> &'static str {
    let code = config::load_lang()
        .as_deref()
        .map(|s| if s == ZH { ZH } else { EN })
        .unwrap_or_else(detect);
    rust_i18n::set_locale(code);
    code
}

/// Switch the runtime language and persist the choice. `title_key` is the
/// locale key for the main window title, which must be re-read *after* the
/// locale changes — translated titles are recomputed here, not by the caller,
/// so a switch always lands in the new language.
pub fn set_lang(ctx: &egui::Context, code: &'static str, title_key: &'static str) {
    if &*rust_i18n::locale() == code {
        return;
    }
    rust_i18n::set_locale(code);
    config::save_lang(code);
    ctx.send_viewport_cmd(egui::ViewportCommand::Title(t!(title_key).into_owned()));
    ctx.request_repaint();
}

/// The `Language` menu (English / 中文) shown in the menu bar. Options are
/// rendered in their own native name; the current one is highlighted. `title_key`
/// is forwarded to [`set_lang`] when the user switches.
pub fn lang_menu(ui: &mut egui::Ui, title_key: &'static str) {
    let current = &*rust_i18n::locale();
    ui.menu_button(t!("menu.language"), |ui| {
        for (code, name) in [(EN, t!("menu.lang_en")), (ZH, t!("menu.lang_zh"))] {
            if ui.selectable_label(current == code, name).clicked() {
                set_lang(ui.ctx(), code, title_key);
                ui.close();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn normalize_maps_to_supported_codes() {
        assert_eq!(normalize("zh-CN"), "zh-CN");
        assert_eq!(normalize("zh-Hans-CN"), "zh-CN");
        assert_eq!(normalize("zh-TW"), "zh-CN");
        assert_eq!(normalize("en-US"), "en");
        assert_eq!(normalize("en"), "en");
        assert_eq!(normalize(""), "en");
    }
}
