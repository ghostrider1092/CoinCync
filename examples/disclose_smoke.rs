use coincync::crypto::{
    create_balance_proof, verify_balance_proof,
    PedersenCommitment, BlindingFactor, DisclosureBalanceProof,
};
use rand::rngs::OsRng;

fn main() {
    let value = 5_000_000_000_000u64; // 5 CYNC
    let threshold = 1_000_000_000_000u64; // prove >= 1 CYNC
    let blinding = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(value, &blinding);

    let proof = create_balance_proof(value, &blinding, &commitment, threshold)
        .expect("create_balance_proof");
    let json = serde_json::to_vec(&proof).unwrap();
    let hex_str = hex::encode(&json);
    println!("balance proof: {} bytes hex", hex_str.len());

    let bytes = hex::decode(&hex_str).unwrap();
    let decoded: DisclosureBalanceProof = serde_json::from_slice(&bytes).unwrap();
    let ok = verify_balance_proof(&decoded).expect("verify");
    assert!(ok);
    println!("VALID round-trip balance proof: threshold={}, original_commitment={}",
        decoded.threshold, hex::encode(decoded.original_commitment));

    // Bad threshold (above value) should fail at create-time
    let bad = create_balance_proof(value, &blinding, &commitment, value + 1);
    assert!(bad.is_err(), "expected error for threshold > value");
    println!("Correctly rejected threshold > value: {:?}", bad.err());
}
