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
