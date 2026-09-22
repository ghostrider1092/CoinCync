//! Transaction types for CoinCync 1.0 (single-asset — asset layer stripped).

use crate::primitives::{hash_concat, Amount, Hash, KeyImage, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum TxType {
    Coinbase,
    Transfer,
    Churn,
    /// Shielded (Lelantus-Spark) private spend — CIP-Shielded. A spend proves
    /// membership in the Spark accumulator with a serial-tag double-spend guard
    /// instead of a CLSAG ring over transparent UTXOs. Borsh discriminant `3`:
    /// adding it is a WIRE HARD FORK, gated by `SHIELDED_TX_ACTIVATION_HEIGHT`
    /// (disabled by default). Fail-closed until activation + a real verifier is
    /// wired. See docs/design/cip-shielded-txtype.md.
    Shielded,
}

/// Ring member for ring signatures.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RingMemberRef {
    pub public_key: PublicKey,
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TxInput {
    pub key_image: KeyImage,
    pub ring_members: Vec<RingMemberRef>,
    pub signature: crate::crypto::ClsagSignature,
    /// Pseudo-output commitment for balance verification.
    /// Used in balance equation: sum(pseudo_outputs) = sum(outputs) + fee_commitment.
    pub pseudo_output_commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TxOutput {
    pub stealth_address: PublicKey,
    pub tx_public_key: PublicKey,
    pub commitment: [u8; 32],
    pub encrypted_amount: Vec<u8>,
    pub view_tag: u8,
    /// Optional time lock: output cannot be spent until this block height.
    pub lock_height: Option<u64>,
    /// ECDH-encrypted memo (max 256 + 28 overhead = 284 bytes).
    pub encrypted_memo: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    pub version: u8,
    pub tx_type: TxType,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: Amount,
    pub range_proof: Vec<u8>,
    pub extra: Vec<u8>,
}

impl Transaction {
    /// Compute the transaction hash (txid) as `blake3(borsh(self))`.
    ///
    /// Fails closed on the (practically impossible) borsh error. The previous
    /// fallback computed a DIFFERENT, non-injective hash from a subset of
    /// fields — a consensus footgun: if two nodes ever disagreed on whether the
    /// error path was taken they would compute different txids for the same tx
    /// → merkle-root mismatch → chain split. `borsh::to_vec` into a `Vec` is
    /// infallible in practice, so a failure here means memory corruption and we
    /// halt rather than silently diverge.
    pub fn hash(&self) -> Hash {
        let data = borsh::to_vec(self)
            .expect("Transaction borsh serialization is infallible into a Vec; a failure indicates memory corruption");
        hash_concat(&[&data])
    }

    /// Serialized transaction size in bytes. Fails closed on the (impossible)
    /// borsh error rather than returning a divergent size — a wrong size feeds
    /// fee/congestion math that must be identical across nodes.
    pub fn size(&self) -> usize {
        // Count serialized bytes without allocating a temporary transaction buffer.
        borsh::object_length(self).expect("Transaction borsh length calculation failed")
    }

    pub fn is_coinbase(&self) -> bool {
        self.tx_type == TxType::Coinbase
    }
    /// True for a shielded (Spark) private spend. These do NOT use the CLSAG
    /// ring / transparent-UTXO model, so the ring/range/balance validation and
    /// the UTXO-set apply paths must branch on this.
    pub fn is_shielded(&self) -> bool {
        self.tx_type == TxType::Shielded
    }
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    pub fn key_images(&self) -> Vec<KeyImage> {
        self.inputs.iter().map(|i| i.key_image).collect()
    }

    /// Compute the signing hash — the preimage binding every field of the
    /// transaction *except* the ring signatures themselves. Used as the CLSAG
    /// message, so any malleability here means a signature that validates on
    /// a different transaction.
    ///
    /// The preimage is prefixed with the domain-separation tag
    /// [`TX_SIGN_DOMAIN_TAG`] so this hash can never collide with any other
    /// hash in the protocol.
    ///
    /// ## Field coverage
    ///
    /// Every field of `Transaction`, `TxInput` (except `signature`) and
    /// `TxOutput` is included. Variable-length fields are length-prefixed to
    /// prevent prefix-collision / reshuffle attacks.
    ///
    /// Callers building a transaction before the CLSAG signatures exist must
    /// use [`Transaction::compute_signing_hash`] with the same arguments to
    /// guarantee byte-identical preimage.
    pub fn signing_hash(&self) -> Hash {
        Self::compute_signing_hash(
            self.version,
            self.tx_type,
            self.fee,
            self.inputs.iter().map(SigningInputView::from_txinput),
            &self.outputs,
            &self.range_proof,
            &self.extra,
        )
    }

    /// Canonical signing-hash preimage, usable before signatures exist.
    ///
    /// This is the single source of truth for the CLSAG signing message.
    /// Both [`Transaction::signing_hash`] (verifier path) and
    /// `TransactionBuilder::build_with_proofs` (signer path) funnel through
    /// here so the preimage bytes are identical.
    pub fn compute_signing_hash<'a, I>(
        version: u8,
        tx_type: TxType,
        fee: Amount,
        inputs: I,
        outputs: &[TxOutput],
        range_proof: &[u8],
        extra: &[u8],
    ) -> Hash
    where
        I: IntoIterator<Item = SigningInputView<'a>>,
    {
        let mut data = Vec::with_capacity(TX_SIGN_DOMAIN_TAG.len() + 256);
        // Domain separator — must be first.
        data.extend_from_slice(TX_SIGN_DOMAIN_TAG);
        data.push(version);
        data.push(tx_type as u8);
        data.extend_from_slice(&fee.as_atomic().to_le_bytes());

        // Collect inputs into a Vec so we can length-prefix (IntoIterator is
        // single-pass and the count would otherwise be unknown up front).
        let inputs: Vec<SigningInputView<'a>> = inputs.into_iter().collect();
        data.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
        for input in &inputs {
            data.extend_from_slice(input.key_image.as_bytes());
            data.extend_from_slice(input.pseudo_output_commitment);
            data.extend_from_slice(&(input.ring_members.len() as u32).to_le_bytes());
            for member in input.ring_members {
                data.extend_from_slice(member.public_key.as_bytes());
                data.extend_from_slice(&member.commitment);
            }
        }

        data.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
        for output in outputs {
            data.extend_from_slice(output.stealth_address.as_bytes());
            data.extend_from_slice(output.tx_public_key.as_bytes());
            data.extend_from_slice(&output.commitment);
            data.extend_from_slice(&(output.encrypted_amount.len() as u32).to_le_bytes());
            data.extend_from_slice(&output.encrypted_amount);
            data.push(output.view_tag);
            // Lock height: encode Some/None explicitly so Some(0) and None differ.
            match output.lock_height {
                Some(h) => {
                    data.push(1);
                    data.extend_from_slice(&h.to_le_bytes());
                }
                None => {
                    data.push(0);
                }
            }
            data.extend_from_slice(&(output.encrypted_memo.len() as u32).to_le_bytes());
            data.extend_from_slice(&output.encrypted_memo);
        }

        data.extend_from_slice(&(range_proof.len() as u32).to_le_bytes());
        data.extend_from_slice(range_proof);

        data.extend_from_slice(&(extra.len() as u32).to_le_bytes());
        data.extend_from_slice(extra);

        hash_concat(&[&data])
    }
}

/// View of the input fields that contribute to the signing hash preimage.
/// Used by [`Transaction::compute_signing_hash`] so the builder can compute
/// the signing hash before any `ClsagSignature` exists.
pub struct SigningInputView<'a> {
    pub key_image: &'a KeyImage,
    pub pseudo_output_commitment: &'a [u8; 32],
    pub ring_members: &'a [RingMemberRef],
}

impl<'a> SigningInputView<'a> {
    /// Build a view from a fully-constructed `TxInput` (verifier path).
    pub fn from_txinput(input: &'a TxInput) -> Self {
        Self {
            key_image: &input.key_image,
            pseudo_output_commitment: &input.pseudo_output_commitment,
            ring_members: &input.ring_members,
        }
    }

    /// Build a view from raw parts (signer path — signatures don't exist yet).
    pub fn from_parts(
        key_image: &'a KeyImage,
        pseudo_output_commitment: &'a [u8; 32],
        ring_members: &'a [RingMemberRef],
    ) -> Self {
        Self {
            key_image,
            pseudo_output_commitment,
            ring_members,
        }
    }
}

/// Domain-separation tag for the transaction signing hash preimage. Must be
/// prefixed to any bytes fed into CLSAG as the message. Never reuse this tag
/// for any other preimage in the protocol.
pub(crate) const TX_SIGN_DOMAIN_TAG: &[u8] = b"coincync/tx-sign/v1";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Amount;
    use rand::rngs::OsRng;

    fn make_minimal_tx() -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![TxOutput {
                stealth_address: PublicKey::from_bytes([1u8; 32]),
                tx_public_key: PublicKey::from_bytes([2u8; 32]),
                commitment: [3u8; 32],
                encrypted_amount: vec![0u8; 8],
                view_tag: 0,
                lock_height: None,
                encrypted_memo: vec![],
            }],
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![],
        }
    }

    #[test]
    fn test_transaction_hash_determinism() {
        let tx = make_minimal_tx();
        let h1 = tx.hash();
        let h2 = tx.hash();
        assert_eq!(h1, h2, "same transaction must produce the same hash");
    }

    #[test]
    fn test_coinbase_detection() {
        let tx = make_minimal_tx();
        assert!(tx.is_coinbase());
    }

    #[test]
    fn test_tx_type_variants() {
        assert_ne!(TxType::Coinbase, TxType::Transfer);
        assert_ne!(TxType::Transfer, TxType::Churn);
    }

    #[test]
    fn test_version_bytes_affect_signing_hash() {
        // The version byte is the first byte of the preimage, so different
        // versions must produce distinct signing hashes for otherwise-identical
        // transactions.
        let mut tx1 = make_minimal_tx();
        tx1.version = 1;
        let mut tx2 = make_minimal_tx();
        tx2.version = 2;
        assert_ne!(
            tx1.signing_hash(),
            tx2.signing_hash(),
            "version byte must be covered by signing_hash"
        );
    }

    /// Build a TxInput with valid curve points for the ring member and a mock
    /// CLSAG signature. Mirrors the construction in `builder::tests` — the
    /// signature content is irrelevant to hash/size/key_image accounting.
    fn make_dummy_input(seed: u8) -> TxInput {
        use crate::crypto::{ClsagSignature, KeyImage as CryptoKeyImage, SecretScalar};
        let secret = SecretScalar::random(&mut OsRng);
        let mock_ki = CryptoKeyImage::from_secret(&secret);
        let mock_pub = secret.to_public();
        TxInput {
            key_image: KeyImage::from_bytes([seed; 32]),
            ring_members: vec![RingMemberRef {
                public_key: PublicKey::from_bytes(mock_pub.to_bytes()),
                commitment: mock_pub.to_bytes(),
            }],
            signature: ClsagSignature {
                key_image: mock_ki,
                commitment_image: mock_pub,
                c1: [0u8; 32],
                responses: vec![[0u8; 32]],
            },
            pseudo_output_commitment: [seed; 32],
        }
    }

    // ---- Transaction::hash field-sensitivity (injectivity property) ----

    #[test]
    fn test_transaction_hash_is_field_sensitive() {
        let base = make_minimal_tx();
        let h = base.hash();

        let mut v = base.clone();
        v.version ^= 0xFF;
        assert_ne!(h, v.hash(), "version change must change the hash");

        let mut f = base.clone();
        f.fee = Amount::from_atomic(1);
        assert_ne!(h, f.hash(), "fee change must change the hash");

        let mut e = base.clone();
        e.extra = vec![0xAB];
        assert_ne!(h, e.hash(), "extra change must change the hash");

        let mut r = base.clone();
        r.range_proof = vec![0x01, 0x02];
        assert_ne!(h, r.hash(), "range_proof change must change the hash");

        let mut o = base.clone();
        o.outputs[0].commitment = [9u8; 32];
        assert_ne!(h, o.hash(), "output commitment change must change the hash");

        let mut t = base.clone();
        t.tx_type = TxType::Transfer;
        assert_ne!(h, t.hash(), "tx_type change must change the hash");
    }

    // ---- Transaction::size accounting ----

    #[test]
    fn test_size_returns_borsh_byte_length() {
        let tx = make_minimal_tx();
        let expected = borsh::to_vec(&tx).unwrap().len();
        assert_eq!(tx.size(), expected, "size() must equal borsh byte length");
    }

    #[test]
    fn test_size_matches_borsh_len_for_populated_tx() {
        let tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![make_dummy_input(1), make_dummy_input(2)],
            outputs: make_minimal_tx().outputs,
            fee: Amount::from_atomic(777),
            range_proof: vec![0u8; 512],
            extra: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(
            tx.size(),
            borsh::to_vec(&tx).unwrap().len(),
            "size() must equal borsh byte length for a populated tx"
        );
    }

    // ---- key_images accounting ----

    #[test]
    fn test_key_images_one_per_input() {
        let i0 = make_dummy_input(11);
        let i1 = make_dummy_input(22);
        let tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![i0.clone(), i1.clone()],
            outputs: make_minimal_tx().outputs,
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![],
        };
        let kis = tx.key_images();
        assert_eq!(kis.len(), 2, "one key image per input");
        assert_eq!(kis[0], i0.key_image);
        assert_eq!(kis[1], i1.key_image);
    }

    // ---- signing_hash: signer path (from_parts) == verifier path (from_txinput) ----

    #[test]
    fn test_signing_hash_signer_and_verifier_paths_are_byte_identical() {
        let input = make_dummy_input(42);
        let tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![input.clone()],
            outputs: make_minimal_tx().outputs,
            fee: Amount::from_atomic(500),
            range_proof: vec![7, 7, 7],
            extra: vec![1, 2, 3],
        };

        // Verifier path (from_txinput, over the fully-built TxInput).
        let verifier = tx.signing_hash();

        // Signer path (from_parts, as the builder does before signatures exist).
        let ki = input.key_image;
        let poc = input.pseudo_output_commitment;
        let views = vec![SigningInputView::from_parts(&ki, &poc, &input.ring_members)];
        let signer = Transaction::compute_signing_hash(
            tx.version,
            tx.tx_type,
            tx.fee,
            views,
            &tx.outputs,
            &tx.range_proof,
            &tx.extra,
        );

        assert_eq!(
            verifier, signer,
            "signer and verifier preimages must be byte-identical (no sign/verify drift)"
        );
    }

    // ---- signing_hash adversarial coverage ----

    #[test]
    fn test_lock_height_some_zero_differs_from_none_in_signing_hash() {
        let mut a = make_minimal_tx();
        a.outputs[0].lock_height = None;
        let mut b = make_minimal_tx();
        b.outputs[0].lock_height = Some(0);
        assert_ne!(
            a.signing_hash(),
            b.signing_hash(),
            "Some(0) lock_height must not collide with None in the signing hash"
        );
    }

    #[test]
    fn test_signing_hash_resists_field_reshuffle_between_amount_and_memo() {
        // Same concatenated bytes, different field boundaries: length-prefixing
        // must make these distinct preimages.
        let mut a = make_minimal_tx();
        a.outputs[0].encrypted_amount = vec![0xAA, 0xBB];
        a.outputs[0].encrypted_memo = vec![];

        let mut b = make_minimal_tx();
        b.outputs[0].encrypted_amount = vec![0xAA];
        b.outputs[0].encrypted_memo = vec![0xBB];

        assert_ne!(
            a.signing_hash(),
            b.signing_hash(),
            "moving a byte between encrypted_amount and encrypted_memo must change the signing hash"
        );
    }

    #[test]
    fn test_extra_bytes_are_covered_by_signing_hash() {
        let mut a = make_minimal_tx();
        a.extra = vec![];
        let mut b = make_minimal_tx();
        b.extra = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_ne!(
            a.signing_hash(),
            b.signing_hash(),
            "mutating extra must invalidate the signature preimage"
        );
    }

    // ---- Borsh decode: adversarial discriminant / length-prefix ----

    #[test]
    fn test_txtype_out_of_range_discriminant_decode_rejected() {
        // Valid TxType discriminants are 0 (Coinbase), 1 (Transfer), 2 (Churn),
        // 3 (Shielded). make_minimal_tx is Coinbase, so byte[0] is version and
        // byte[1] is the TxType discriminant. Setting it to 4 (out of range)
        // must fail to decode (no panic).
        let tx = make_minimal_tx();
        let mut bytes = borsh::to_vec(&tx).unwrap();
        bytes[1] = 4;
        let decoded = borsh::from_slice::<Transaction>(&bytes);
        assert!(
            decoded.is_err(),
            "out-of-range TxType discriminant must be rejected, not decoded"
        );
    }

    #[test]
    fn test_txtype_shielded_discriminant_roundtrips() {
        // Discriminant 3 (Shielded) is now a valid variant and must round-trip.
        let mut tx = make_minimal_tx();
        tx.tx_type = TxType::Shielded;
        let bytes = borsh::to_vec(&tx).unwrap();
        assert_eq!(bytes[1], 3, "Shielded is borsh discriminant 3");
        let decoded = borsh::from_slice::<Transaction>(&bytes).unwrap();
        assert_eq!(decoded.tx_type, TxType::Shielded);
        assert!(decoded.is_shielded() && !decoded.is_coinbase());
    }

    #[test]
    fn test_oversized_input_length_prefix_decode_rejected_without_giant_alloc() {
        // version=1, tx_type=Transfer(1), then inputs Vec length prefix = u32::MAX
        // with no element bytes following. Borsh must fail cleanly rather than
        // pre-allocating ~4 billion TxInputs.
        let mut bytes = vec![1u8, 1u8];
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        let decoded = borsh::from_slice::<Transaction>(&bytes);
        assert!(
            decoded.is_err(),
            "oversized inputs length prefix must be rejected without OOM/panic"
        );
    }

    #[test]
    fn test_txoutput_oversized_encrypted_amount_length_prefix_rejected() {
        // Hand-assemble a Transaction byte stream with a single output whose
        // encrypted_amount length prefix claims u32::MAX bytes but supplies none.
        // The decoder must not pre-allocate a multi-GB buffer.
        let mut bytes = Vec::new();
        bytes.push(1u8); // version
        bytes.push(0u8); // tx_type = Coinbase
        bytes.extend_from_slice(&0u32.to_le_bytes()); // inputs len = 0
        bytes.extend_from_slice(&1u32.to_le_bytes()); // outputs len = 1
        bytes.extend_from_slice(&[1u8; 32]); // stealth_address (fixed [u8;32], no prefix)
        bytes.extend_from_slice(&[2u8; 32]); // tx_public_key
        bytes.extend_from_slice(&[3u8; 32]); // commitment
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // encrypted_amount len (huge)
        // No payload follows.
        let decoded = borsh::from_slice::<Transaction>(&bytes);
        assert!(
            decoded.is_err(),
            "oversized encrypted_amount length prefix must be rejected without giant alloc"
        );
    }
}
