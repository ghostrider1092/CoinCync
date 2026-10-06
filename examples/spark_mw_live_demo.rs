//! # Live demo — Lelantus Spark spend proof + MimbleWimble cut-through
//!
//! Runs the REAL (now-fixed) Spark and MW cut-through code as a standalone
//! program with real cryptographic operations, printing each step. This is a
//! demonstration harness, NOT the consensus node: CoinCync's chain is
//! RingCT/CLSAG, and these two modules are experimental/alternative privacy
//! schemes that are feature-gated off and not integrated into the transaction
//! format — so they cannot run inside the live node. This binary exercises the
//! same fixed algorithms end-to-end.
//!
//! Run:
//!   cargo run --release --example spark_mw_live_demo --features sketch-lelantus-spark
//!
//! (The MW cut-through section runs in the default build; the Spark section
//! needs the `sketch-lelantus-spark` feature.)

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::rngs::OsRng;
use rand::RngCore;

use coincync::constants::MW_CUTTHROUGH_DEPTH;
use coincync::crypto::generator_h;
use coincync::crypto::mw_cutthrough::{
    build_signed_kernel, verify_kernel_signature, CutThroughEngine, MwKernel,
};

fn rnd() -> Scalar {
    let mut b = [0u8; 64];
    OsRng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

fn rule(title: &str) {
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("  {title}");
    println!("═══════════════════════════════════════════════════════════════");
}

fn ok(cond: bool) -> &'static str {
    if cond {
        "✅"
    } else {
        "❌"
    }
}

fn mw_cutthrough_demo() {
    rule("MimbleWimble cut-through — LIVE (excess-signature fix)");

    // 1. Build a real, balanced, SIGNED kernel: x = r_out - r_in = 0 (single
    //    self-balanced tx), so excess = 0*G + fee*H and the aggregate check
    //    sum(excess) == fee*H holds.
    let r = rnd();
    let fee = 1000u64;
    let kernel = build_signed_kernel(&[r], &[r], fee, 10);
    println!(
        "1. built signed kernel: fee={} height={} sig_len={} bytes",
        kernel.fee,
        kernel.height,
        kernel.signature.len()
    );
    let sig_ok = verify_kernel_signature(&kernel);
    println!("   kernel excess signature verifies: {} {}", sig_ok, ok(sig_ok));

    // 2. Aggregate kernel-set verification (signature + balance) accepts it.
    let set_ok = CutThroughEngine::verify_kernel_set(&[kernel.clone()]).is_ok();
    println!("2. verify_kernel_set(balanced, signed): {} {}", set_ok, ok(set_ok));

    // 3. Cut-through engine: register a spend whose input commitment equals the
    //    spent output commitment, then process past the confirmation depth →
    //    the pair becomes prunable, only the kernel remains.
    let mut engine = CutThroughEngine::new();
    let commitment = (generator_h() * Scalar::from(500u64)).compress().to_bytes();
    let created_at = 5u64;
    let spent_at = 10u64;
    engine.register_spend(commitment, commitment, created_at, spent_at, kernel.clone());
    println!(
        "3. registered cut-through candidate (pending={})",
        engine.stats().pending_candidates
    );
    let prunable = engine.process(spent_at + MW_CUTTHROUGH_DEPTH);
    let st = engine.stats();
    println!(
        "   processed at height {} (depth {}): pruned {} commitment(s), kept {} kernel(s), bytes_saved={} {}",
        spent_at + MW_CUTTHROUGH_DEPTH,
        MW_CUTTHROUGH_DEPTH,
        prunable.len(),
        st.kernels_kept,
        st.bytes_saved,
        ok(prunable.len() == 2 && st.kernels_kept == 1)
    );

    // 4. THE FIX — hidden-value inflation is rejected. Two kernels carry
    //    canceling +v*H / -v*H components: they still SUM to fee_sum*H (so the
    //    old aggregate-only check would pass), but neither can be signed because
    //    excess - fee*H has a leftover H component with no G discrete log.
    let h = generator_h();
    let hidden = Scalar::from(5u64);
    let (fee_a, fee_b) = (10u64, 20u64);
    let excess_a = h * (Scalar::from(fee_a) + hidden); // (fee_a + hidden)*H
    let excess_b = h * (Scalar::from(fee_b) - hidden); // (fee_b - hidden)*H
    let balanced =
        (excess_a + excess_b).compress() == (h * Scalar::from(fee_a + fee_b)).compress();
    println!(
        "4. crafted inflation kernels balance in aggregate (fools old check): {} {}",
        balanced,
        ok(balanced)
    );
    let attack = [
        MwKernel { excess: excess_a.compress().to_bytes(), signature: vec![], fee: fee_a, height: 1 },
        MwKernel { excess: excess_b.compress().to_bytes(), signature: vec![], fee: fee_b, height: 2 },
    ];
    let rejected = CutThroughEngine::verify_kernel_set(&attack).is_err();
    println!(
        "   verify_kernel_set(inflation attack): {} {}",
        if rejected { "REJECTED" } else { "ACCEPTED — BUG!" },
        ok(rejected)
    );
}

#[cfg(feature = "sketch-lelantus-spark")]
fn spark_demo() {
    use coincync::config::NetworkType;
    use coincync::crypto::lelantus_spark::{
        prove_spark_spend, spark_commit, verify_spark_spend, SparkNote,
    };
    use coincync::crypto::privacy_connector::{connect_spark_spend, ConnectorGate};
    use coincync::storage::{SparkCoinEntry, SparkStore};

    rule("Lelantus Spark — LIVE (public value-hiding verifier + double-spend fix)");

    // Build a real anonymity set of INDEPENDENT coins: every decoy has its own
    // value, serial and blinding — none shared with the real coin. The real coin
    // sits at `real_index`. Verification uses ONLY the public commitments, so
    // there is nothing secret to reconstruct: this is the completed public
    // verifier, and it hides value.
    let n = 8usize;
    let real_index = 3usize;
    let real_value = 1000u64;
    let real_serial = rnd();
    let real_randomness = rnd();

    let mut decoy_values = Vec::new();
    let anon: Vec<RistrettoPoint> = (0..n)
        .map(|i| {
            if i == real_index {
                spark_commit(real_value, &real_serial, &real_randomness)
            } else {
                let v = 100 + i as u64 * 37; // deliberately distinct per decoy
                decoy_values.push(v);
                spark_commit(v, &rnd(), &rnd())
            }
        })
        .collect();

    let note = SparkNote {
        commitment: anon[real_index].compress().to_bytes(),
        value: real_value,
        serial: real_serial.to_bytes(),
        randomness: real_randomness.to_bytes(),
        diversifier: [0u8; 11],
        height: 1,
        coin_id: real_index as u64,
    };
    let indices: Vec<u64> = (0..n as u64).collect();
    let message = [7u8; 32];

    println!("   anonymity set size: {n}, real coin at index {real_index}");
    println!(
        "   real value = {real_value}, decoy values = {decoy_values:?} (all distinct — value is hidden)"
    );

    // ── Regtest chain state: a connector gate + a Spark accumulator ──────────
    // ConnectorGate(Regtest, height 100, activated at 50) is a live regtest
    // validation context. The SparkStore is the on-chain accumulator; we mint
    // every anon-set coin into it (coin_id == position), exactly as a node would
    // as blocks arrive.
    let mut gate = ConnectorGate::new(NetworkType::Regtest, 100, Some(50));
    let store = SparkStore::new();
    for (i, c) in anon.iter().enumerate() {
        store.add_coin(SparkCoinEntry {
            coin_id: i as u64,
            commitment: c.compress().to_bytes(),
            height: 1,
        });
    }
    println!("   minted {n} coins into the regtest Spark accumulator (root committed)");

    // 1. Honest spend, verified against the PUBLIC commitments alone (no v/r).
    let proof = prove_spark_spend(&note, &anon, &indices, real_index, &message, &mut OsRng)
        .expect("prove");
    let accept = verify_spark_spend(&proof, &anon).is_ok();
    println!(
        "1. honest spend verifies against public commitments: {} {}   (serial tag {}…)",
        accept,
        ok(accept),
        &hex::encode(proof.serial_tag)[..16]
    );

    // 2. Route it through the connector as a node would: gate → resolve the
    //    anon-set indices to on-chain commitments from the store → verify →
    //    record the serial tag. The connector is handed NO secret — it looks the
    //    commitments up itself.
    let connected = connect_spark_spend(&mut gate, &store, &proof).is_ok();
    println!(
        "2. connector accepts the spend (public data only) + burns the coin: {} {}",
        connected,
        ok(connected)
    );

    // 3. Double-spend: a second spend of the SAME coin yields the SAME serial
    //    tag, and the connector rejects it against the recorded nullifier.
    let proof2 = prove_spark_spend(&note, &anon, &indices, real_index, &message, &mut OsRng)
        .expect("prove2");
    let same_tag = proof.serial_tag == proof2.serial_tag;
    let ds_rejected = connect_spark_spend(&mut gate, &store, &proof2).is_err();
    println!(
        "3. re-spend → identical tag ({}) and connector REJECTS the double-spend: {} {}",
        same_tag,
        ds_rejected,
        ok(same_tag && ds_rejected)
    );

    // 4. Forged serial tag (H-1): an attacker swaps in T' != s*G to dodge the
    //    double-spend nullifier. The tag is now bound inside every ring link, so
    //    verification fails.
    let mut forged = proof.clone();
    forged.serial_tag[0] ^= 0x01;
    let forge_rejected = verify_spark_spend(&forged, &anon).is_err();
    println!(
        "4. spend with altered serial tag: {} {}",
        if forge_rejected { "REJECTED" } else { "ACCEPTED — BUG!" },
        ok(forge_rejected)
    );

    // 5. Wrong anonymity set: the set digest binds the exact ordered commitment
    //    vector, so verifying against a different/permuted set fails.
    let mut permuted = anon.clone();
    permuted.swap(0, n - 1);
    let set_rejected = verify_spark_spend(&proof, &permuted).is_err();
    println!(
        "5. verify against a permuted commitment set: {} {}",
        if set_rejected { "REJECTED" } else { "ACCEPTED — BUG!" },
        ok(set_rejected)
    );
}

#[cfg(not(feature = "sketch-lelantus-spark"))]
fn spark_demo() {
    rule("Lelantus Spark — SKIPPED");
    println!("   Build with --features sketch-lelantus-spark to run the Spark demo.");
}

fn main() {
    println!("CoinCync — live demo of the Spark + MW cut-through soundness fixes");
    println!("(standalone harness; these schemes are NOT part of the RingCT consensus chain)");
    mw_cutthrough_demo();
    spark_demo();
    println!("\nDone.");
}
