//! Bright (light) visual theme shared by the pe-rs GUIs.
//!
//! egui's default theme is dark. This module installs a clean, bright light
//! theme with a blue accent. It lives in `pe-gui-common` so the disk editor
//! (`pe-edit-gui`) and the process dumper (`pe-scylla-gui`) can share it.
//!
//! Usage (in each GUI's `main`):
//!
//! ```ignore
//! pe_gui_common::fonts::install_fonts(&cc.egui_ctx);
//! pe_gui_common::theme::install_bright_theme(&cc.egui_ctx);
//! ```

use egui::{
    Color32, CornerRadius, Stroke, Visuals,
    style::{Selection, TextCursorStyle, WidgetVisuals, Widgets},
};

/// The blue accent used for selection, active widgets and links.
const ACCENT: Color32 = Color32::from_rgb(0, 106, 224);
/// Slightly darker blue for pressed state / borders.
const ACCENT_DARK: Color32 = Color32::from_rgb(0, 76, 168);
/// Very light blue tint used as the hover background.
const ACCENT_SOFT: Color32 = Color32::from_rgb(228, 239, 255);

/// Background of the side / tool panels (a gentle gray, distinct from the
/// bright central content).
pub const PANEL_FILL: Color32 = Color32::from_rgb(240, 242, 247);
/// Background of the central content area (bright, near-white).
pub const CENTER_FILL: Color32 = Color32::from_rgb(252, 253, 255);

/// Install the bright theme as the default for the whole app.
pub fn install_bright_theme(ctx: &egui::Context) {
    ctx.set_visuals(bright_visuals());
}

/// A clean, bright light theme with a blue accent.
pub fn bright_visuals() -> Visuals {
    let mut v = Visuals::light();

    v.dark_mode = false;

    // --- Surfaces -----------------------------------------------------------
    v.panel_fill = PANEL_FILL;
    v.window_fill = CENTER_FILL;
    v.extreme_bg_color = Color32::WHITE; // text-edit / scrollbar background
    v.text_edit_bg_color = Some(Color32::WHITE);
    v.code_bg_color = Color32::from_rgb(233, 237, 243); // monospace snippets
    v.faint_bg_color = Color32::from_rgb(245, 247, 251); // striped grid rows

    v.window_stroke = Stroke::new(1.0, Color32::from_rgb(205, 211, 221));
    v.window_corner_radius = CornerRadius::same(6);
    v.menu_corner_radius = CornerRadius::same(6);

    // --- Text & links -------------------------------------------------------
    v.hyperlink_color = ACCENT;
    v.weak_text_alpha = 0.55;
    v.text_cursor = TextCursorStyle {
        stroke: Stroke::new(2.0, ACCENT_DARK),
        ..Default::default()
    };
    v.warn_fg_color = Color32::from_rgb(202, 92, 0);
    v.error_fg_color = Color32::from_rgb(214, 34, 44);

    // --- Selection (selected tree rows, selected text, …) --------------------
    v.selection = Selection {
        bg_fill: ACCENT,
        stroke: Stroke::new(1.0, Color32::WHITE),
    };

    // --- Widget states ------------------------------------------------------
    v.widgets = Widgets {
        noninteractive: WidgetVisuals {
            weak_bg_fill: Color32::from_rgb(246, 247, 250),
            bg_fill: Color32::from_rgb(246, 247, 250),
            bg_stroke: Stroke::new(1.0, Color32::from_rgb(214, 219, 228)),
            fg_stroke: Stroke::new(1.0, Color32::from_rgb(70, 76, 88)),
            corner_radius: CornerRadius::same(4),
            expansion: 0.0,
        },
        inactive: WidgetVisuals {
            weak_bg_fill: Color32::WHITE, // button background
            bg_fill: Color32::WHITE,      // checkbox background
            bg_stroke: Stroke::new(1.0, Color32::from_rgb(210, 215, 225)),
            fg_stroke: Stroke::new(1.0, Color32::from_rgb(40, 46, 58)),
            corner_radius: CornerRadius::same(4),
            expansion: 0.0,
        },
        hovered: WidgetVisuals {
            weak_bg_fill: ACCENT_SOFT,
            bg_fill: ACCENT_SOFT,
            bg_stroke: Stroke::new(1.0, Color32::from_rgb(150, 186, 240)),
            fg_stroke: Stroke::new(1.5, Color32::from_rgb(16, 42, 84)),
            corner_radius: CornerRadius::same(4),
            expansion: 0.0,
        },
        active: WidgetVisuals {
            weak_bg_fill: ACCENT,
            bg_fill: ACCENT,
            bg_stroke: Stroke::new(1.0, ACCENT_DARK),
            fg_stroke: Stroke::new(2.0, Color32::WHITE),
            corner_radius: CornerRadius::same(4),
            expansion: 0.0,
        },
        open: WidgetVisuals {
            weak_bg_fill: Color32::from_rgb(222, 234, 252),
            bg_fill: Color32::from_rgb(237, 244, 255),
            bg_stroke: Stroke::new(1.0, Color32::from_rgb(160, 188, 235)),
            fg_stroke: Stroke::new(1.0, Color32::from_rgb(20, 50, 90)),
            corner_radius: CornerRadius::same(4),
            expansion: 0.0,
        },
    };

    v.striped = true;
    v.button_frame = true;
    v.collapsing_header_frame = true;
    v.slider_trailing_fill = true;

    v
}

/// A `Frame` for the left-hand structure tree pane: a light gray background
/// (distinct from the bright central content) and no own border (the panel's
/// separator line already marks the edge).
pub fn sidebar_frame() -> egui::Frame {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(8, 2))
        .fill(PANEL_FILL)
}
