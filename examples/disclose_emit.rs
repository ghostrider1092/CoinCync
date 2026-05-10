use coincync::crypto::{
    create_balance_proof, PedersenCommitment, BlindingFactor,
};
use rand::rngs::OsRng;

fn main() {
    let value = 5_000_000_000_000u64;
    let threshold = 1_000_000_000_000u64;
    let blinding = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(value, &blinding);
    let proof = create_balance_proof(value, &blinding, &commitment, threshold)
        .expect("create_balance_proof");
    let json = serde_json::to_vec(&proof).unwrap();
    print!("{}", hex::encode(&json));
}
