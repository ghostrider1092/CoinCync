//! Invariant → everything pipeline.
//!
//! Declare a consensus invariant ONCE (in the `invariants!{ }` block) and get
//! three things for free, so they can never drift apart:
//!   1. a derived unit test that asserts it on a fixture chain,
//!   2. a `CATALOG` entry the `simkit` multi-node harness registers as a live
//!      runtime MONITOR (checked after every delivery round),
//!   3. a `docs/audit/invariants.json` manifest the section-coverage tool
//!      ingests (so each invariant shows up as an audited section with its
//!      proving test), via `build_section_heatmap.py --invariants`.
//!
//! One source of truth for "what must always be true" → test + monitor + audit.

#[path = "common/mining.rs"]
mod mining;
#[path = "common/simkit.rs"]
mod simkit;

use coincync::chain::Blockchain;
use coincync::emission::calculate_block_reward;
use simkit::Sim;

/// A fresh genesis chain — the default fixture the derived tests run against.
fn fixture() -> Blockchain {
    let c = Blockchain::new();
    c.init_genesis().expect("genesis");
    let g = c.get_block_by_height(0).expect("genesis block");
    c.restore_state(0, g.hash(), 1).expect("seed base");
    c
}

// ── invariant check functions (the only bespoke code per invariant) ──────────
fn chk_supply_conservation(c: &Blockchain) -> Result<(), String> {
    let s = c.stats();
    let expected: u128 = (0..=c.height())
        .map(|h| calculate_block_reward(h).as_atomic() as u128)
        .sum();
    if s.total_supply + s.total_burned != expected {
        return Err(format!(
            "supply {} + burned {} != Σ reward(0..={}) {}",
            s.total_supply, s.total_burned, c.height(), expected
        ));
    }
    Ok(())
}

fn chk_work_positive(c: &Blockchain) -> Result<(), String> {
    if c.stats().total_difficulty == 0 {
        return Err("cumulative work is zero".into());
    }
    Ok(())
}

fn chk_height_tip_agree(c: &Blockchain) -> Result<(), String> {
    // The reported height must match the tip block's own height (the split-state
    // bug class: stats.height and tip.height drifting apart).
    let tip = c.get_block_by_height(c.height()).ok_or("no block at reported height")?;
    if tip.header.height != c.height() {
        return Err(format!("stats height {} != tip block height {}", c.height(), tip.header.height));
    }
    Ok(())
}

/// `invariants! { id, "statement", [tags], check_fn; … }`
/// Declares each ONCE and expands to a `CATALOG` + one `#[test]` per invariant.
macro_rules! invariants {
    ($($id:ident, $stmt:literal, [$($tag:literal),* $(,)?], $check:path);+ $(;)?) => {
        /// (id, plain-English statement, incident tags, check fn) — consumed by
        /// the runtime monitor and the JSON manifest export below.
        pub const CATALOG: &[(&str, &str, &[&str], fn(&Blockchain) -> Result<(), String>)] = &[
            $(( stringify!($id), $stmt, &[$($tag),*], $check )),+
        ];
        $(
            #[test]
            fn $id() {
                let c = fixture();
                ($check)(&c).unwrap_or_else(|e|
                    panic!("invariant `{}` failed on fixture: {e}", stringify!($id)));
            }
        )+
    };
}

invariants! {
    supply_conservation, "total_supply + total_burned == Σ block reward over the canonical chain (no inflation, no lost coins)", ["C-2"], chk_supply_conservation;
    work_positive, "cumulative chain work is always strictly positive", [], chk_work_positive;
    height_tip_agreement, "the reported chain height equals the tip block's own height (no split-state)", [], chk_height_tip_agree;
}

/// The SAME catalog, registered as live monitors on a multi-node `Sim` — one
/// declaration, now enforced across nodes after every delivery round.
#[test]
fn catalog_registers_as_simkit_monitors() {
    let mut sim = Sim::new(3);
    for (id, _stmt, _tags, check) in CATALOG {
        sim = sim.with_invariant(id, *check);
    }
    // Runs every catalogued invariant against every node.
    sim.check_invariants().expect("all catalogued invariants hold on genesis");
    assert_eq!(CATALOG.len(), 3);
}

/// Export the catalog as the machine-readable manifest the coverage tool reads.
/// (`build_section_heatmap.py --invariants docs/audit/invariants.json`.)
#[test]
fn export_invariants_manifest() {
    let mut items = Vec::new();
    for (id, stmt, tags, _check) in CATALOG {
        let tags_json = tags.iter().map(|t| format!("\"{t}\"")).collect::<Vec<_>>().join(",");
        items.push(format!(
            "  {{\"id\":\"{id}\",\"statement\":{},\"tags\":[{tags_json}],\"test\":\"{id}\"}}",
            serde_json_string(stmt)
        ));
    }
    let json = format!("[\n{}\n]\n", items.join(",\n"));
    std::fs::create_dir_all("docs/audit").ok();
    std::fs::write("docs/audit/invariants.json", json).expect("write manifest");
}

/// Minimal JSON string escaper (avoids a serde dep in this test binary).
fn serde_json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}
