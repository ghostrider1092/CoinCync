//! Build script — critical file integrity verification.
//!
//! At the start of every build, this script recomputes SHA-256 hashes for
//! the consensus-critical files listed below and compares them against
//! `critical_files.lock`. If any hash doesn't match, the build fails with
//! a clear error naming the file(s) that drifted.
//!
//! The goal is to make it impossible to quietly ship a binary that changed
//! `MIN_RING_SIZE`, the emission curve, the supply cap, the PoW verifier,
//! the genesis timestamp, or the Constitution itself. Those files are
//! consensus rules — a silent change forks the chain.
//!
//! To refresh after an INTENTIONAL change:
//!
//!     COINCYNC_REGEN_LOCK=1 cargo run --bin update-critical-hashes
//!
//! The refresher lives at `src/bin/update_critical_hashes.rs` and uses a
//! byte-identical SHA-256 implementation to the one in this file; changes
//! to either must stay in lock-step or the build breaks with no real drift.
//!
//! Line endings are normalized (CRLF → LF) before hashing so the lockfile
//! values match on Windows, Linux, and macOS checkouts of the same commit.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Files whose hashes are verified at build time. Kept in lock-step with
/// `CRITICAL_FILES` in `src/bin/update_critical_hashes.rs`.
const CRITICAL_FILES: &[&str] = &[
    "CONSTITUTION.md",
    "docs/BILL_OF_RIGHTS.md",
    "src/testnet.rs",
    "src/constants.rs",
    "src/consensus/difficulty.rs",
    "src/consensus/pow.rs",
    "src/consensus/validation.rs",
    "src/emission/curve.rs",
];

fn main() {
    // ── Standard cargo reruns ────────────────────────────────────────
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=critical_files.lock");
    println!("cargo:rerun-if-changed=src/mainnet.rs");
    for file in CRITICAL_FILES {
        println!("cargo:rerun-if-changed={}", file);
    }
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=COINCYNC_REGEN_LOCK");

    // Register cfg(kani) so the compiler doesn't warn when it sees
    // `#[cfg(kani)]` gated proof modules in src/. Kani itself sets
    // this cfg when it runs; normal cargo builds leave it unset and
    // the gated code never compiles.
    println!("cargo:rustc-check-cfg=cfg(kani)");

    emit_build_metadata();

    // An integrity gate you can disable by deleting a file is not a gate.
    // The intentional re-lock path (which must build the updater binary and
    // therefore re-run this script) sets COINCYNC_REGEN_LOCK=1, which relaxes
    // both the missing-lock and hash-mismatch checks to warnings so that
    // `update-critical-hashes` can regenerate the lockfile. Every OTHER build
    // treats a missing or mismatched lock as a hard failure.
    let regen_lock = std::env::var_os("COINCYNC_REGEN_LOCK").is_some();

    // ── Load the lockfile ────────────────────────────────────────────
    let lockfile = Path::new("critical_files.lock");
    if !lockfile.exists() {
        if regen_lock {
            println!(
                "cargo:warning=critical_files.lock absent + COINCYNC_REGEN_LOCK set — \
                 skipping the integrity check so update-critical-hashes can regenerate it."
            );
            return;
        }
        panic!(
            "\n\ncritical_files.lock is MISSING — the consensus integrity gate cannot run.\n\
             A missing lock is a HARD FAILURE: it must not silently permit the build, or the \
             gate could be bypassed by deleting one file. To (re)generate it after an \
             intentional consensus change, run:\n\
             \n    COINCYNC_REGEN_LOCK=1 cargo run --bin update-critical-hashes\n\n\
             then commit the regenerated critical_files.lock alongside the change.\n"
        );
    }

    let expected = parse_lockfile(lockfile);
    let mut failures = Vec::new();

    // ── Verify every file listed in CRITICAL_FILES ───────────────────
    //
    // We iterate CRITICAL_FILES rather than `expected`'s keys so a file
    // that was dropped from the lockfile (or never added) still fails
    // the check with a clear "MISSING FROM LOCKFILE" message instead of
    // being silently skipped.
    for file_path in CRITICAL_FILES {
        let path = Path::new(file_path);

        if !path.exists() {
            failures.push(format!("  MISSING ON DISK: {}", file_path));
            continue;
        }

        let expected_hash = match expected.get(*file_path) {
            Some(h) => h,
            None => {
                failures.push(format!(
                    "  MISSING FROM LOCKFILE: {} \
                     (run `COINCYNC_REGEN_LOCK=1 cargo run --bin update-critical-hashes`)",
                    file_path
                ));
                continue;
            }
        };

        let actual_hash = sha256_file(path);
        if &actual_hash != expected_hash {
            failures.push(format!(
                "  CHANGED: {}\n    expected: {}\n    actual:   {}",
                file_path, expected_hash, actual_hash
            ));
        }
    }

    if !failures.is_empty() {
        if regen_lock {
            println!(
                "cargo:warning=critical files changed + COINCYNC_REGEN_LOCK set — \
                 skipping the mismatch failure so update-critical-hashes can refresh the lock."
            );
            return;
        }
        panic!(
            "\n\n\
             ╔══════════════════════════════════════════════════════════════╗\n\
             ║  CRITICAL FILE INTEGRITY CHECK FAILED                        ║\n\
             ║  Consensus-critical files have been modified!               ║\n\
             ╚══════════════════════════════════════════════════════════════╝\n\
             \n\
             The following files do not match their locked hashes:\n\
             \n\
             {}\n\
             \n\
             If these changes are INTENTIONAL:\n\
                 1. Review the changes carefully — they affect consensus.\n\
                 2. Run: COINCYNC_REGEN_LOCK=1 cargo run --bin update-critical-hashes\n\
                 3. Commit the updated critical_files.lock alongside the change.\n\
             \n\
             If these changes are NOT intentional:\n\
                 1. Run: git diff <file>\n\
                 2. Revert with: git checkout -- <file>\n\
                 3. Rebuild.\n\
             \n",
            failures.join("\n")
        );
    }
}

fn emit_build_metadata() {
    let git_sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let git_dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|out| out.status.success() && !out.stdout.is_empty())
        .unwrap_or(false);

    let build_profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=COINCYNC_BUILD_GIT_SHA={}", git_sha);
    println!(
        "cargo:rustc-env=COINCYNC_BUILD_GIT_DIRTY={}",
        if git_dirty { "1" } else { "0" }
    );
    println!("cargo:rustc-env=COINCYNC_BUILD_PROFILE={}", build_profile);
}

// ─────────────────────────────────────────────────────────────────────
// Lockfile parsing
// ─────────────────────────────────────────────────────────────────────

fn parse_lockfile(path: &Path) -> HashMap<String, String> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read critical_files.lock: {}", e));

    let mut map = HashMap::new();
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            map.insert(key.trim().to_string(), val.trim().to_string());
        }
    }
    map
}

// ─────────────────────────────────────────────────────────────────────
// File hashing — normalizes CRLF → LF so Windows and Linux agree.
// ─────────────────────────────────────────────────────────────────────

fn sha256_file(path: &Path) -> String {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot open critical file {}: {}", path.display(), e));
    let normalized = contents.replace("\r\n", "\n");
    let digest = sha256(normalized.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in &digest {
        use std::fmt::Write;
        write!(hex, "{:02x}", byte).unwrap();
    }
    hex
}

// ─────────────────────────────────────────────────────────────────────
// Minimal inline SHA-256 — no external deps.
//
// Kept byte-identical to `sha256` in `src/bin/update_critical_hashes.rs`.
// If you change one, change the other — otherwise the build will fail on
// hashes that the refresher considers valid.
// ─────────────────────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut r = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        r[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    r
}
