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
    use coincync::crypto::lelantus_spark::{
        prove_spark_spend, spark_commit, spark_pubkey, verify_spark_spend, SparkNote,
    };

    rule("Lelantus Spark — LIVE (serial-tag double-spend fix, H-1)");

    // Build a real anonymity set of Spark coins sharing (value, randomness) so a
    // single reconstructed pubkey vector verifies all of them; the real coin
    // sits at `real_index` with its own secret serial.
    let value = 1000u64;
    let randomness = rnd();
    let n = 8usize;
    let real_index = 3usize;
    let real_serial = rnd();

    let anon: Vec<RistrettoPoint> = (0..n)
        .map(|i| {
            let serial = if i == real_index { real_serial } else { rnd() };
            spark_commit(value, &serial, &randomness)
        })
        .collect();
    let pubkeys: Vec<RistrettoPoint> =
        anon.iter().map(|c| spark_pubkey(c, value, &randomness)).collect();

    let note = SparkNote {
        commitment: anon[real_index].compress().to_bytes(),
        value,
        serial: real_serial.to_bytes(),
        randomness: randomness.to_bytes(),
        diversifier: [0u8; 11],
        height: 1,
        coin_id: real_index as u64,
    };
    let indices: Vec<u64> = (0..n as u64).collect();
    let message = [7u8; 32];

    println!("   anonymity set size: {n}, real coin at index {real_index}");

    // 1. Honest spend proof verifies.
    let proof = prove_spark_spend(&note, &anon, &indices, real_index, &message, &mut OsRng)
        .expect("prove");
    let accept = verify_spark_spend(&proof, &pubkeys).is_ok();
    println!(
        "1. honest spend proof verifies: {} {}   (serial tag {}…)",
        accept,
        ok(accept),
        &hex::encode(proof.serial_tag)[..16]
    );

    // 2. Double-spend DETECTION: a second spend of the SAME coin produces the
    //    SAME serial tag → a serial-set lookup catches the reuse.
    let proof2 = prove_spark_spend(&note, &anon, &indices, real_index, &message, &mut OsRng)
        .expect("prove2");
    let same_tag = proof.serial_tag == proof2.serial_tag;
    println!(
        "2. re-spend of same coin yields identical serial tag (detectable): {} {}",
        same_tag,
        ok(same_tag)
    );

    // 3. THE FIX — the serial tag is cryptographically bound. Tampering it (an
    //    attacker trying to present a different tag to dodge double-spend
    //    detection) causes verification to fail.
    let mut forged = proof.clone();
    forged.serial_tag[0] ^= 0x01;
    let rejected = verify_spark_spend(&forged, &pubkeys).is_err();
    println!(
        "3. spend with altered serial tag: {} {}",
        if rejected { "REJECTED" } else { "ACCEPTED — BUG!" },
        ok(rejected)
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
