//! Theme engine — parses btop's own `.theme` files and precomputes 101-step
//! gradients, exactly like btop's `Theme` (src/btop_theme.cpp). Colours may be
//! `#RRGGBB`, `#BW` (2-char greyscale) or `R G B` decimal. Gradients are built
//! from `<name>_start` / `_mid` / `_end`: one colour if only start, a two-stop
//! ramp with start+end, a three-stop ramp with all three.
//!
//! The built-in Default theme is embedded in the same `.theme` text format and
//! parsed by the same code path, so there is a single source of truth.

use std::collections::HashMap;

use ratatui::style::Color;

/// btop's built-in "Default" theme, in `.theme` syntax (values from
/// src/btop_theme.cpp). Parsed by `Theme::from_str`, same as a user theme.
pub const DEFAULT_THEME: &str = r##"
theme[main_bg]="#00"
theme[main_fg]="#cc"
theme[title]="#ee"
theme[hi_fg]="#b54040"
theme[selected_bg]="#6a2f2f"
theme[selected_fg]="#ee"
theme[inactive_fg]="#40"
theme[graph_text]="#60"
theme[meter_bg]="#40"
theme[proc_misc]="#0de756"
theme[cpu_box]="#556d59"
theme[mem_box]="#6c6c4b"
theme[net_box]="#5c588d"
theme[proc_box]="#805252"
theme[div_line]="#30"
theme[temp_start]="#4897d4"
theme[temp_mid]="#5474e8"
theme[temp_end]="#ff40b6"
theme[cpu_start]="#77ca9b"
theme[cpu_mid]="#cbc06c"
theme[cpu_end]="#dc4c4c"
theme[free_start]="#384f21"
theme[free_mid]="#b5e685"
theme[free_end]="#dcff85"
theme[cached_start]="#163350"
theme[cached_mid]="#74e6fc"
theme[cached_end]="#26c5ff"
theme[available_start]="#4e3f0e"
theme[available_mid]="#ffd77a"
theme[available_end]="#ffb814"
theme[used_start]="#592b26"
theme[used_mid]="#d9626d"
theme[used_end]="#ff4769"
theme[download_start]="#291f75"
theme[download_mid]="#4f43a3"
theme[download_end]="#b0a9de"
theme[upload_start]="#620665"
theme[upload_mid]="#7d4180"
theme[upload_end]="#dcafde"
theme[process_start]="#80d0a3"
theme[process_mid]="#dcd179"
theme[process_end]="#d45454"
"##;

/// Gradient bases we precompute into 101-step ramps.
const GRADIENTS: &[&str] = &[
    "cpu", "used", "free", "available", "cached", "download", "upload", "process", "temp",
];

#[derive(Clone)]
pub struct Theme {
    colors: HashMap<String, Color>,
    grads: HashMap<String, Vec<Color>>, // 101 entries each (index 0..=100)
}

impl Theme {
    /// The built-in Default theme.
    pub fn default_theme() -> Self {
        Self::parse(DEFAULT_THEME, false)
    }

    /// Parse a `.theme` file's text. Unknown/missing keys fall back to Default
    /// so a partial theme still renders.
    pub fn from_str(text: &str) -> Self {
        Self::parse(text, true)
    }

    fn parse(text: &str, fill_defaults: bool) -> Self {
        let mut colors = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // theme[key]="value"
            let Some(rest) = line.strip_prefix("theme[") else { continue };
            let Some((key, after)) = rest.split_once(']') else { continue };
            let val = after.trim_start_matches('=').trim().trim_matches('"');
            if let Some(c) = parse_color(val) {
                colors.insert(key.trim().to_string(), c);
            }
        }
        // Fill missing roles from Default (unless we ARE building Default).
        if fill_defaults {
            let def = Self::default_theme();
            for (k, v) in def.colors.iter() {
                colors.entry(k.clone()).or_insert(*v);
            }
        }
        // btop fallbacks: meter_bg→inactive_fg, graph_text→inactive_fg,
        // process→cpu when unset.
        for (miss, src) in [("meter_bg", "inactive_fg"), ("graph_text", "inactive_fg")] {
            if !colors.contains_key(miss) {
                if let Some(c) = colors.get(src).copied() {
                    colors.insert(miss.into(), c);
                }
            }
        }

        let mut grads = HashMap::new();
        for base in GRADIENTS {
            let start = colors.get(&format!("{base}_start")).copied();
            let mid = colors.get(&format!("{base}_mid")).copied();
            let end = colors.get(&format!("{base}_end")).copied();
            grads.insert((*base).to_string(), build_gradient(start, mid, end));
        }
        // process gradient falls back to cpu's if unset.
        if !grads.contains_key("process") || grads["process"].iter().all(|c| *c == Color::Reset) {
            if let Some(cpu) = grads.get("cpu").cloned() {
                grads.insert("process".into(), cpu);
            }
        }

        Theme { colors, grads }
    }

    /// A named colour role (falls back to main_fg, then white).
    pub fn c(&self, name: &str) -> Color {
        self.colors
            .get(name)
            .copied()
            .or_else(|| self.colors.get("main_fg").copied())
            .unwrap_or(Color::White)
    }

    /// A gradient colour at `pct` (0..=100) for a base name (cpu/used/…).
    pub fn g(&self, name: &str, pct: f64) -> Color {
        let i = pct.clamp(0.0, 100.0).round() as usize;
        self.grads
            .get(name)
            .and_then(|v| v.get(i).copied())
            .unwrap_or_else(|| self.c("main_fg"))
    }
}

/// Parse a btop colour token: `#RRGGBB`, `#BW` (2-char greyscale), or
/// `R G B` decimal. Empty string → None (used to detect absent gradient stops).
fn parse_color(s: &str) -> Option<Color> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix('#') {
        match hex.len() {
            6 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                return Some(Color::Rgb(r, g, b));
            }
            2 => {
                let v = u8::from_str_radix(hex, 16).ok()?;
                return Some(Color::Rgb(v, v, v));
            }
            _ => return None,
        }
    }
    // "R G B" decimal
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() == 3 {
        let r = parts[0].parse().ok()?;
        let g = parts[1].parse().ok()?;
        let b = parts[2].parse().ok()?;
        return Some(Color::Rgb(r, g, b));
    }
    None
}

fn rgb(c: Color) -> (u8, u8, u8) {
    match c {
        Color::Rgb(r, g, b) => (r, g, b),
        _ => (0xcc, 0xcc, 0xcc),
    }
}

fn lerp(a: u8, b: u8, t: f64) -> u8 {
    (a as f64 + (b as f64 - a as f64) * t).round().clamp(0.0, 255.0) as u8
}

fn lerp_c(a: Color, b: Color, t: f64) -> Color {
    let (ar, ag, ab) = rgb(a);
    let (br, bg, bb) = rgb(b);
    Color::Rgb(lerp(ar, br, t), lerp(ag, bg, t), lerp(ab, bb, t))
}

/// Build a 101-entry gradient ramp from up to three stops, btop-style.
fn build_gradient(start: Option<Color>, mid: Option<Color>, end: Option<Color>) -> Vec<Color> {
    let Some(start) = start else {
        return vec![Color::Reset; 101];
    };
    match (mid, end) {
        (None, None) => vec![start; 101],
        (None, Some(end)) => (0..=100).map(|i| lerp_c(start, end, i as f64 / 100.0)).collect(),
        (Some(mid), None) => (0..=100).map(|i| lerp_c(start, mid, i as f64 / 100.0)).collect(),
        (Some(mid), Some(end)) => (0..=100)
            .map(|i| {
                if i <= 50 {
                    lerp_c(start, mid, i as f64 / 50.0)
                } else {
                    lerp_c(mid, end, (i - 50) as f64 / 50.0)
                }
            })
            .collect(),
    }
}
