//! Color palettes for the TUI dashboard.
//!
//! Three themes ship: **Brass** (default — CoinCync brand gold on deep ink),
//! **Moon** (cool slate + soft silver, easy on the eyes at night), and
//! **Mono** (high-contrast monochrome for accessibility / e-ink-like
//! terminals). The user cycles them with `t`. The TUI looks up every
//! color via this struct so a theme swap is one assignment, not a hunt
//! through every widget.
//!
//! Truecolor RGB is used throughout — on ancient terminals (`TERM=xterm`)
//! ratatui will gracefully degrade to the nearest 256-color palette. We
//! don't paper over that with conditionals; the theme intent stays
//! readable in the source.
//!
//! Color choices echo the website + explorer + wallet so a user moving
//! between surfaces sees one CoinCync, not five.

use ratatui::style::Color;

/// One palette's worth of named colors. Every TUI widget reads from
/// here — do not hardcode `Color::Rgb(...)` outside this module.
#[derive(Clone, Copy)]
pub struct Theme {
    /// Display name in the keybinding hint.
    pub name: &'static str,
    /// Primary brand accent. Hashrate digits, hero numbers, found-block
    /// celebration flash. The eye snaps here first.
    pub accent: Color,
    /// Same hue as `accent` but ~60% intensity; for dim accents and
    /// progress-bar trails.
    pub accent_dim: Color,
    /// Default body text.
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
    /// Page background. Most terminals will composite this against the
    /// user's terminal bg; we don't force-paint it for first-run polish.
    /// Reserved for a future `--paint-bg` flag.
    #[allow(dead_code)]
    pub bg: Color,
}

/// Brand gold on deep ink — the default. Matches the website + wallet's
/// `--ac2: #d4a059` accent.
pub const BRASS: Theme = Theme {
    name: "Brass",
    accent: Color::Rgb(212, 160, 89),
    accent_dim: Color::Rgb(140, 105, 55),
    body: Color::Rgb(245, 238, 221),
    muted: Color::Rgb(140, 132, 118),
    border: Color::Rgb(95, 88, 76),
    success: Color::Rgb(127, 184, 121),
    warn: Color::Rgb(228, 175, 78),
    danger: Color::Rgb(216, 99, 99),
    bg: Color::Reset,
};

/// Cool moon-silver on slate, for night-shift miners.
pub const MOON: Theme = Theme {
    name: "Moon",
    accent: Color::Rgb(180, 195, 220),
    accent_dim: Color::Rgb(110, 125, 150),
    body: Color::Rgb(225, 230, 240),
    muted: Color::Rgb(120, 128, 145),
    border: Color::Rgb(70, 78, 95),
    success: Color::Rgb(140, 200, 175),
    warn: Color::Rgb(220, 200, 130),
    danger: Color::Rgb(220, 140, 145),
    bg: Color::Reset,
};

/// High-contrast monochrome — accessibility-friendly, copies cleanly
/// over screen-share tools that downsample color.
pub const MONO: Theme = Theme {
    name: "Mono",
    accent: Color::Rgb(245, 245, 245),
    accent_dim: Color::Rgb(170, 170, 170),
    body: Color::Rgb(230, 230, 230),
    muted: Color::Rgb(140, 140, 140),
    border: Color::Rgb(110, 110, 110),
    success: Color::Rgb(220, 220, 220),
    warn: Color::Rgb(200, 200, 200),
    danger: Color::Rgb(255, 255, 255),
    bg: Color::Reset,
};

/// Cycle order for the `t` key. Brass → Moon → Mono → Brass.
pub const THEMES: &[Theme] = &[BRASS, MOON, MONO];

/// Resolve the next theme in the cycle from the current index.
pub fn next_theme(idx: usize) -> usize {
    (idx + 1) % THEMES.len()
}
