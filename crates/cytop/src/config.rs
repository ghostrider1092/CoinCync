//! Persistent config — a tiny `key = value` file (no TOML dep). CLI flags take
//! precedence over the file, which takes precedence over built-in defaults. The
//! active theme / rpc / log / refresh are written back on exit so `t` and the
//! other settings survive restarts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_RPC: &str = "http://127.0.0.1:28121";
pub const DEFAULT_REFRESH_MS: u64 = 1000;

#[derive(Clone, Default)]
pub struct Config {
    pub rpc: Option<String>,
    pub log: Option<String>,
    pub theme: Option<String>,
    pub refresh_ms: Option<u64>,
}

impl Config {
    /// Load from a `key = value` file; a missing/unreadable file yields empties.
    pub fn load(path: &Path) -> Config {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Config::default();
        };
        let mut kv: HashMap<String, String> = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let v = v.trim().trim_matches('"');
                if !v.is_empty() {
                    kv.insert(k.trim().to_lowercase(), v.to_string());
                }
            }
        }
        Config {
            rpc: kv.get("rpc").cloned(),
            log: kv.get("log").cloned(),
            theme: kv.get("theme").cloned(),
            refresh_ms: kv.get("refresh_ms").and_then(|s| s.parse().ok()),
        }
    }

    /// Write the resolved settings back (creates the parent directory).
    pub fn save(path: &Path, rpc: &str, log: Option<&str>, theme: &str, refresh_ms: u64) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let mut out = String::from("# cytop config — edit freely; rewritten on exit.\n");
        out.push_str(&format!("rpc = \"{rpc}\"\n"));
        if let Some(log) = log {
            out.push_str(&format!("log = \"{log}\"\n"));
        }
        out.push_str(&format!("theme = \"{theme}\"\n"));
        out.push_str(&format!("refresh_ms = {refresh_ms}\n"));
        let _ = std::fs::write(path, out);
    }
}

/// `%APPDATA%\cytop\cytop.conf` on Windows, else `$HOME/.config/cytop/cytop.conf`.
pub fn default_path() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata).join("cytop").join("cytop.conf");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("cytop").join("cytop.conf")
}
