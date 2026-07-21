//! Color palettes for the TUI dashboard.
//!
//! Nine themes ship, matching the website / explorer / wallet's
//! `data-theme` palette name-for-name so a user moving between
//! surfaces sees one CoinCync, not nine. Cycle order matches the
//! website's switcher: `Brass → Dark → Midnight → Forge → Vault →
//! Mono → Paper → Cream → Contrast → Brass`. Hot-cycle with `t`.
//!
//! Truecolor RGB throughout; on legacy terminals ratatui will
//! gracefully degrade to the nearest 256-color palette. Colors
//! are picked so each theme's *accent* is unambiguously distinct
//! at the 256-color level — gold vs. silver vs. orange vs. olive vs.
//! white — so even on a degraded terminal the user can tell which
//! theme is active. Body and muted colors are picked to read on
//! any terminal background (light or dark); we never force-paint a
//! background in the TUI.

use ratatui::style::Color;

/// One palette's worth of named colors. Every TUI widget reads from
/// here — do not hardcode `Color::Rgb(...)` outside this module.
#[derive(Clone, Copy)]
pub struct Theme {
    /// Display name in the keybinding hint. Matches the website's
    /// `data-theme` attribute value.
    pub name: &'static str,
    /// Primary brand accent — the eye snaps here first. Each theme's
    /// accent is unambiguously distinct from every other theme's,
    /// so cycling produces visible changes even on terminals that
    /// can't render subtle RGB shifts.
    pub accent: Color,
    /// Same hue as `accent` but ~60% intensity; for dim accents and
    /// progress-bar trails.
    pub accent_dim: Color,
    /// Default body text. Picked for contrast on both light and
    /// dark terminal backgrounds.
    pub body: Color,
    /// Subdued text — labels, secondary stats, log timestamps.
    pub muted: Color,
    /// Border color for panels and stat cards.
    pub border: Color,
    /// Healthy / mining / accepted state.
    pub success: Color,
    /// Stale tip / overdue / WARN log level.
    pub warn: Color,
    /// Rejected block / disconnected / ERROR log level.
    pub danger: Color,
    /// Page background. Most terminals will composite this against
    /// the user's terminal bg; we don't force-paint it.
    /// Reserved for a future `--paint-bg` flag.
    #[allow(dead_code)]
    pub bg: Color,
}

// ─── 9 themes, matching the website's data-theme palette ────────────

/// Brand gold on warm body — the default. Matches website's `--ac2`
/// at #d4a059 and the wallet/explorer accent.
pub const BRASS: Theme = Theme {
    name: "Brass",
    accent: Color::Rgb(212, 160, 89), // #d4a059
    accent_dim: Color::Rgb(140, 105, 55),
    body: Color::Rgb(220, 210, 195),
    muted: Color::Rgb(140, 132, 118),
    border: Color::Rgb(95, 88, 76),
    success: Color::Rgb(127, 184, 121),
    warn: Color::Rgb(228, 175, 78),
    danger: Color::Rgb(216, 99, 99),
    bg: Color::Reset,
};

/// Same gold as Brass, but with a darker neutral palette — the
/// website's primary `dark` theme.
pub const DARK: Theme = Theme {
    name: "Dark",
    accent: Color::Rgb(212, 160, 89), // #d4a059 — same gold
    accent_dim: Color::Rgb(140, 105, 55),
    body: Color::Rgb(245, 240, 232),  // #f5f0e8
    muted: Color::Rgb(138, 133, 125), // #8a857d
    border: Color::Rgb(37, 36, 31),   // #25241f
    success: Color::Rgb(126, 184, 124),
    warn: Color::Rgb(228, 175, 78),
    danger: Color::Rgb(196, 92, 79),
    bg: Color::Reset,
};

/// Cool blue-tinted dark with the same gold accent. For night
/// shifts.
pub const MIDNIGHT: Theme = Theme {
    name: "Midnight",
    accent: Color::Rgb(212, 160, 89),
    accent_dim: Color::Rgb(140, 105, 55),
    body: Color::Rgb(232, 228, 240), // cool off-white
    muted: Color::Rgb(160, 160, 184),
    border: Color::Rgb(30, 32, 48),
    success: Color::Rgb(126, 184, 124),
    warn: Color::Rgb(228, 175, 78),
    danger: Color::Rgb(196, 92, 79),
    bg: Color::Reset,
};

/// Warm orange accent — distinctive and unmistakable. From website's
/// `forge` theme.
pub const FORGE: Theme = Theme {
    name: "Forge",
    accent: Color::Rgb(224, 120, 64), // #e07840 — burnt orange
    accent_dim: Color::Rgb(140, 75, 40),
    body: Color::Rgb(240, 232, 224),
    muted: Color::Rgb(180, 152, 132),
    border: Color::Rgb(48, 40, 40),
    success: Color::Rgb(126, 184, 124),
    warn: Color::Rgb(232, 168, 80),
    danger: Color::Rgb(208, 64, 64),
    bg: Color::Reset,
};

/// Olive accent — distinct from gold and orange. From website's
/// `vault` theme.
pub const VAULT: Theme = Theme {
    name: "Vault",
    accent: Color::Rgb(160, 176, 96), // #a0b060 — olive
    accent_dim: Color::Rgb(112, 128, 64),
    body: Color::Rgb(224, 232, 220),
    muted: Color::Rgb(168, 176, 160),
    border: Color::Rgb(34, 40, 32),
    success: Color::Rgb(126, 184, 124),
    warn: Color::Rgb(232, 200, 96),
    danger: Color::Rgb(196, 92, 79),
    bg: Color::Reset,
};

/// High-contrast monochrome — accessibility-friendly, copies cleanly
/// over screen-share tools that downsample color.
pub const MONO: Theme = Theme {
    name: "Mono",
    accent: Color::Rgb(245, 240, 232),     // bright off-white
    accent_dim: Color::Rgb(168, 164, 152), // #a8a498
    body: Color::Rgb(232, 228, 220),
    muted: Color::Rgb(120, 117, 112),
    border: Color::Rgb(40, 40, 38),
    success: Color::Rgb(184, 184, 184),
    warn: Color::Rgb(216, 216, 216),
    danger: Color::Rgb(248, 248, 248),
    bg: Color::Reset,
};

/// Light-background theme — for users with light terminals. Inverts
/// the contrast direction; body text is dark.
pub const PAPER: Theme = Theme {
    name: "Paper",
    accent: Color::Rgb(212, 160, 89), // gold accent
    accent_dim: Color::Rgb(158, 122, 62),
    body: Color::Rgb(74, 72, 68), // #4a4844 — dark body
    muted: Color::Rgb(138, 133, 125),
    border: Color::Rgb(216, 212, 202), // #d8d4ca
    success: Color::Rgb(74, 138, 72),
    warn: Color::Rgb(180, 130, 50),
    danger: Color::Rgb(196, 92, 79),
    bg: Color::Reset,
};

/// Soft warm light theme — alternative to Paper with a brown accent
/// instead of gold.
pub const CREAM: Theme = Theme {
    name: "Cream",
    accent: Color::Rgb(90, 74, 48), // #5a4a30 — deep tan
    accent_dim: Color::Rgb(58, 51, 40),
    body: Color::Rgb(58, 51, 40), // #3a3328 — dark cocoa
    muted: Color::Rgb(138, 125, 109),
    border: Color::Rgb(216, 208, 192),
    success: Color::Rgb(74, 138, 72),
    warn: Color::Rgb(180, 130, 50),
    danger: Color::Rgb(176, 48, 48),
    bg: Color::Reset,
};

/// Maximum contrast — pure black background assumed, max-bright
/// accent. For users who want zero ambiguity.
pub const CONTRAST: Theme = Theme {
    name: "Contrast",
    accent: Color::Rgb(255, 184, 64), // #ffb840 — bright amber
    accent_dim: Color::Rgb(184, 128, 32),
    body: Color::Rgb(255, 255, 255),
    muted: Color::Rgb(204, 204, 204),
    border: Color::Rgb(80, 80, 80),
    success: Color::Rgb(80, 232, 80),
    warn: Color::Rgb(255, 184, 64),
    danger: Color::Rgb(255, 64, 64),
    bg: Color::Reset,
};

/// Cycle order for the `t` key. Brass is default (index 0); cycle
/// matches the website's theme picker.
pub const THEMES: &[Theme] = &[
    BRASS, DARK, MIDNIGHT, FORGE, VAULT, MONO, PAPER, CREAM, CONTRAST,
];

/// Resolve the next theme in the cycle from the current index.
pub fn next_theme(idx: usize) -> usize {
    (idx + 1) % THEMES.len()
}
