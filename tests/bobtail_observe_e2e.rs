#![cfg(feature = "bobtail")]
//! End-to-end Observe-path run with **real RandomX shares — no mocks**.
//!
//! Drives the actual Bobtail code the way a user's node would in the Observe
//! phase: a miner grinds proof-shares (`collect_shares`, the real send-side),
//! they cross as a `ProofShareBatch` (the borsh wire type), a receiving node
//! admits them through the real admission path (`admit_batch`), and the real
//! Observe telemetry (`observe`) + CYNC-POW diagnostic report on the pool.
//!
//! Run locally — the live testnet cannot run gated, unaudited consensus code:
//!   cargo test --features bobtail --test bobtail_observe_e2e -- --nocapture

use coincync::consensus::bobtail::{self, Admit, ProofShareBatch, SharePool};
use coincync::consensus::{compute_pow_hash, PowAlgorithm};
use coincync::primitives::{Hash, PublicKey};

/// The real share hasher: `RandomX(prev ‖ nonce ‖ pubkey)` at the block epoch,
/// exactly what the node's dispatch handler + miner use (no mock).
fn real_hasher(height: u64) -> impl Fn(&bobtail::ShareProof, &Hash) -> Hash {
    move |s, prev| {
        let pk = Hash::from_bytes(*s.miner_pubkey.as_bytes());
        compute_pow_hash(PowAlgorithm::RandomX, prev, s.nonce, &pk, height)
            .unwrap_or_else(|_| Hash::from_bytes([0xFF; 32]))
    }
}

#[test]
fn bobtail_observe_end_to_end_with_real_randomx() {
    let k = bobtail::BOBTAIL_K;
    let c = bobtail::BOBTAIL_C_SHARE;
    let height = 1000u64;
    let epoch = height + 1;
    let prev = Hash::from_bytes([0x11; 32]); // a regtest-like parent tip
    // A target chosen so tau_share = C*K*T admits ~half the samples — enough to
    // reach K from a small grind budget (real RandomX in WSL light mode is slow).
    let target = Hash::from_difficulty(128);
    let tau = bobtail::tau_share_target(&target, k, c);
    let hasher = real_hasher(epoch);
    const BUDGET: u64 = 64;

    println!("\n=== Bobtail Observe end-to-end (real RandomX, no mocks) ===");
    println!("K={k}  C_SHARE={c}  parent=0x{}  height={height}", &prev.to_hex()[..12]);
    println!("tau_share target = 0x{}…", &tau.to_hex()[..16]);

    // --- Miner A grinds + would-gossip shares (the real send-side) ---
    let pk_a = PublicKey::from_bytes([0xA1; 32]);
    let a_shares = bobtail::collect_shares(&prev, pk_a, 0, BUDGET, &tau, &hasher);
    println!(
        "\n[miner A] grinded {BUDGET} nonces -> {} shares below tau_share",
        a_shares.len()
    );
    assert!(!a_shares.is_empty(), "A must find shares at this target");

    // A second miner B so the pool has more than one owner.
    let pk_b = PublicKey::from_bytes([0xB2; 32]);
    let b_shares = bobtail::collect_shares(&prev, pk_b, 0, BUDGET, &tau, &hasher);
    println!("[miner B] grinded {BUDGET} nonces -> {} shares", b_shares.len());

    // Cap each batch to the wire limit (a real miner gossips its lowest).
    let mut a_shares = a_shares;
    a_shares.truncate(200);
    let mut b_shares = b_shares;
    b_shares.truncate(200);
    let batch_a = ProofShareBatch { prev_hash: prev, shares: a_shares };
    let batch_b = ProofShareBatch { prev_hash: prev, shares: b_shares };
    assert!(batch_a.is_well_formed() && batch_b.is_well_formed(), "wire-valid batches");
    println!("\n[wire] two ProofShareBatch gossip messages, both well-formed");

    // --- Node C receives + admits both batches (the real inbound path) ---
    let mut pool = SharePool::new(prev, k, c);
    let va = pool.admit_batch(&batch_a, &tau, &hasher);
    let vb = pool.admit_batch(&batch_b, &tau, &hasher);
    let accepted = va
        .iter()
        .chain(&vb)
        .filter(|v| matches!(v, Admit::Accepted { .. }))
        .count();
    println!(
        "[node C] admitted {accepted} shares (pool now holds {}, cap {})",
        pool.len(),
        bobtail::max_pool_size(k, c)
    );
    assert!(pool.len() >= k, "pool must reach K to form a candidate");

    // --- Observe telemetry on the real pool ---
    let obs = pool.observe(&target);
    let h = obs.health.as_ref().expect("a full pool carries health");
    println!("\n--- Observe: what a Bobtail block would be right now ---");
    println!("  canonical K-lowest set : {} shares", obs.canonical_set.len());
    println!("  clears k-mean bar      : {}", obs.meets_bar);
    if let Some(p) = obs.proposer {
        println!("  proposer (global min)  : 0x{}", &p.to_hex()[..8]);
    }
    println!("  fallback lottery slot  : {:?}", obs.lottery_winner);
    println!(
        "  distinct owners        : {}   (max {} / {} slots to one miner)",
        h.distinct_owners, h.max_owner_slots, k
    );
    println!("  bar fill               : {} bps (10000 = exactly at tau)", h.bar_fill_bps);

    // --- CYNC-POW diagnostics on the real observation ---
    match bobtail::diagnostics::concentration_report(&obs) {
        Some(r) => println!("\n[CYNC-POW] concentration diagnostic FIRED:\n{r}"),
        None => println!("\n[CYNC-POW-004] not fired — pool adequately decentralized"),
    }

    // --- Solo miner: shows the concentration diagnostic correctly fires ---
    let mut solo = SharePool::new(prev, k, c);
    solo.admit_batch(&batch_a, &tau, &hasher); // miner A only
    if solo.len() >= k {
        let solo_obs = solo.observe(&target);
        let sh = solo_obs.health.as_ref().unwrap();
        println!(
            "\n[solo miner A] distinct owners = {}  ->  concentration diagnostic:",
            sh.distinct_owners
        );
        match bobtail::diagnostics::concentration_report(&solo_obs) {
            Some(r) => println!("{r}"),
            None => panic!("solo miner should trip CYNC-POW-004"),
        }
    }

    println!("\n=== Observe path verified end-to-end with real RandomX ===\n");
}

// --- Inlined RNG so this demo needs no extra dep ---
fn xorshift01(s: &mut u64) -> f64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    (*s >> 11) as f64 / (1u64 << 53) as f64
}
fn normal(s: &mut u64, mean: f64, std: f64) -> f64 {
    let u1 = xorshift01(s).max(1e-12);
    let u2 = xorshift01(s);
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    mean + std * z
}

/// Monte-Carlo demonstration that the share-informed hashrate estimate is far
/// smoother than a block-interval one: shares arrive ~C_SHARE*K× more often, so
/// the estimate's spread (CV ∝ 1/√N) is ~√(C_SHARE*K) tighter. This is the
/// evidence a share-informed difficulty retarget would be smoother + lower-lag.
#[test]
fn share_vs_block_difficulty_is_smoother() {
    let k = bobtail::BOBTAIL_K as f64;
    let c = bobtail::BOBTAIL_C_SHARE as f64;
    let window = 1200.0; // 10 block intervals
    let lambda_block = window / 120.0; // ~10 blocks/window
    let lambda_share = lambda_block * c * k; // ~600 shares/window

    let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
    let trials = 4000;
    let (mut blk, mut shr) = (Vec::with_capacity(trials), Vec::with_capacity(trials));
    for _ in 0..trials {
        // count ~ Normal(λ, √λ) (Poisson for large λ), floored at 0.
        blk.push(normal(&mut rng, lambda_block, lambda_block.sqrt()).max(0.0));
        shr.push(normal(&mut rng, lambda_share, lambda_share.sqrt()).max(0.0));
    }
    let cv = |v: &[f64]| {
        let m = v.iter().sum::<f64>() / v.len() as f64;
        let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / v.len() as f64;
        var.sqrt() / m
    };
    let (cvb, cvs) = (cv(&blk), cv(&shr));

    println!("\n=== Share- vs block-based hashrate estimate (smoothness) ===");
    println!(
        "window {window:.0}s: ~{lambda_block:.0} blocks  vs  ~{lambda_share:.0} shares per window"
    );
    println!("  block-based estimate CV : {:.1}%", cvb * 100.0);
    println!("  share-based estimate CV : {:.1}%", cvs * 100.0);
    println!(
        "  measured smoothness gain: {:.1}× tighter  (predicted √{:.0} = {:.1}×)",
        cvb / cvs,
        c * k,
        (c * k).sqrt()
    );
    println!("  => a share-informed retarget tracks hashrate with ~that much less noise/lag\n");

    assert!(cvs < cvb * 0.3, "share-based estimate must be much tighter (got {cvs} vs {cvb})");
}
