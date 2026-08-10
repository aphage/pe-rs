//! CJK-capable font setup for egui.

use egui::FontData;

/// egui's bundled fonts have no CJK glyphs, so Chinese UI text renders as
/// boxes. Install a Windows system CJK font as a fallback family.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    for path in [
        "C:/Windows/Fonts/msyh.ttc",   // Microsoft YaHei (collection)
        "C:/Windows/Fonts/simhei.ttf", // SimHei
        "C:/Windows/Fonts/Deng.ttf",   // DengXian
    ] {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        fonts.font_data.insert(
            "cjk".to_owned(),
            std::sync::Arc::new(FontData::from_owned(bytes)),
        );
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push("cjk".to_owned());
        }
        break;
    }
    ctx.set_fonts(fonts);
}
