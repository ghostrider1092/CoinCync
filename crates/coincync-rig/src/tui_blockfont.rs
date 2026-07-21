//! 5-row block-character font for the hero hashrate display.
//!
//! Each glyph is rendered as a 5-line array of strings using the full
//! block character `█` and U+0020 space. Width per glyph varies (digits
//! are 5, the dot is 1, space is 2). The render function below takes a
//! string of supported chars and returns five lines of text already
//! kerned with single-space gaps between glyphs.
//!
//! The font intentionally only supports characters we actually render
//   in the hero: digits 0-9, '.', ',', and the 'H', '/', 's' letters
//! for the unit suffix. Adding more would just bloat the binary.
//!
//! ## Why hand-rolled instead of `figlet-rs`?
//!
//! `figlet-rs` is great but pulls in a bunch of font-file plumbing for
//! a feature we use exactly once. A 50-line constant table compiles
//! faster and ships smaller, and we get to pick a font that matches
//! the brand's narrow geometric feel rather than figlet's defaults.

/// Glyph height in lines. All entries in [`GLYPHS`] must have this many
/// rows or `render` will panic.
pub const HEIGHT: usize = 5;

/// Look up a 5-row glyph for `c`, falling back to a blank space-glyph
/// for anything unsupported (so we never panic on user input we didn't
/// anticipate, e.g. a stray scientific-notation 'e' in a future format).
pub fn glyph(c: char) -> &'static [&'static str; HEIGHT] {
    match c {
        '0' => &G0,
        '1' => &G1,
        '2' => &G2,
        '3' => &G3,
        '4' => &G4,
        '5' => &G5,
        '6' => &G6,
        '7' => &G7,
        '8' => &G8,
        '9' => &G9,
        '.' => &GDOT,
        ',' => &GCOMMA,
        'H' => &GH,
        '/' => &GSLASH,
        's' => &GS_LOWER,
        'K' => &GK,
        'M' => &GM,
        'G' => &GG,
        ' ' => &GSPACE,
        _ => &GSPACE,
    }
}

/// Render `text` as five strings — one per row of the block-letter
/// font. Glyphs are joined with one column of empty space for kerning.
/// Caller is responsible for any horizontal alignment / centering.
pub fn render(text: &str) -> [String; HEIGHT] {
    let mut rows: [String; HEIGHT] = Default::default();
    for (i, c) in text.chars().enumerate() {
        let g = glyph(c);
        if i > 0 {
            for r in 0..HEIGHT {
                rows[r].push(' ');
            }
        }
        for r in 0..HEIGHT {
            rows[r].push_str(g[r]);
        }
    }
    rows
}

// ─── Glyph table ────────────────────────────────────────────────────
// 5×4 (5×5 for some) bitmap-style. Visual-by-eye design, keep at fixed
// width per glyph and let `render` insert kerning gaps.

const G0: [&str; HEIGHT] = ["████", "█  █", "█  █", "█  █", "████"];
const G1: [&str; HEIGHT] = ["  █", " ██", "  █", "  █", "███"];
const G2: [&str; HEIGHT] = ["████", "   █", "████", "█   ", "████"];
const G3: [&str; HEIGHT] = ["████", "   █", " ███", "   █", "████"];
const G4: [&str; HEIGHT] = ["█  █", "█  █", "████", "   █", "   █"];
const G5: [&str; HEIGHT] = ["████", "█   ", "████", "   █", "████"];
const G6: [&str; HEIGHT] = ["████", "█   ", "████", "█  █", "████"];
const G7: [&str; HEIGHT] = ["████", "   █", "  █ ", " █  ", " █  "];
const G8: [&str; HEIGHT] = ["████", "█  █", "████", "█  █", "████"];
const G9: [&str; HEIGHT] = ["████", "█  █", "████", "   █", "████"];
const GDOT: [&str; HEIGHT] = [" ", " ", " ", " ", "█"];
const GCOMMA: [&str; HEIGHT] = [" ", " ", " ", "█", "█"];
const GH: [&str; HEIGHT] = ["█  █", "█  █", "████", "█  █", "█  █"];
const GSLASH: [&str; HEIGHT] = ["   █", "  █ ", " █  ", "█   ", "█   "];
const GS_LOWER: [&str; HEIGHT] = ["███", "█  ", "███", "  █", "███"];
const GK: [&str; HEIGHT] = ["█  █", "█ █ ", "██  ", "█ █ ", "█  █"];
const GM: [&str; HEIGHT] = ["█   █", "██ ██", "█ █ █", "█   █", "█   █"];
const GG: [&str; HEIGHT] = ["████", "█   ", "█ ██", "█  █", "████"];
const GSPACE: [&str; HEIGHT] = ["  ", "  ", "  ", "  ", "  "];

/// Format a hashrate (raw H/s) as a hero-display string.
/// Auto-scales:
///   <10000          → "1234 H/s"   (no decimal)
///   <10000000       → "12.3 KH/s"  (one decimal)
///   <10000000000    → "12.3 MH/s"  (one decimal)
///   else            → "12.3 GH/s"  (one decimal)
/// Returns `(digits_string, unit_suffix)` so the caller can render the
/// unit at a smaller scale beside the hero digits.
pub fn format_hashrate(hps: u64) -> (String, &'static str) {
    if hps < 10_000 {
        (format!("{}", hps), "H/s")
    } else if hps < 10_000_000 {
        (format!("{:.1}", hps as f64 / 1_000.0), "KH/s")
    } else if hps < 10_000_000_000 {
        (format!("{:.1}", hps as f64 / 1_000_000.0), "MH/s")
    } else {
        (format!("{:.1}", hps as f64 / 1_000_000_000.0), "GH/s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_produces_five_rows() {
        let rows = render("123");
        assert_eq!(rows.len(), HEIGHT);
        for r in &rows {
            assert!(!r.is_empty());
        }
    }

    #[test]
    fn render_inserts_kerning_gap() {
        let rows = render("11");
        // Two '1' glyphs (each 3 wide) + 1 kerning column = 7 chars.
        assert_eq!(rows[0].chars().count(), 7);
    }

    #[test]
    fn unsupported_char_falls_back_to_space() {
        // Should not panic; emits the space-glyph instead.
        let rows = render("e");
        assert_eq!(rows.len(), HEIGHT);
    }

    #[test]
    fn format_hashrate_small() {
        assert_eq!(format_hashrate(57), ("57".into(), "H/s"));
        assert_eq!(format_hashrate(9_999), ("9999".into(), "H/s"));
    }

    #[test]
    fn format_hashrate_kilo() {
        assert_eq!(format_hashrate(54_000), ("54.0".into(), "KH/s"));
    }

    #[test]
    fn format_hashrate_mega() {
        assert_eq!(format_hashrate(54_000_000), ("54.0".into(), "MH/s"));
    }
}
