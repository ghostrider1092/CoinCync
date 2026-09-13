//! # Transaction Builder for CoinCync 1.0
//!
//! Complete transaction builder with:
//! - Stealth address generation for outputs
//! - Pedersen commitments with blinding factors
//! - Bulletproofs range proofs
//! - Ring signatures for inputs
//! - Amount encryption
//! - Fee calculation and change handling

use super::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};
use crate::constants::{MAX_TX_INPUTS, MAX_TX_OUTPUTS, MIN_FEE_PER_BYTE, MIN_OUTPUT_AMOUNT};
use crate::crypto::{
    clsag_sign,
    create_aggregated_range_proof_for_height,
    // Encrypted memos
    encrypt_memo,
    generate_stealth_address_checked,
    generate_stealth_address_checked_ext,
    BlindingFactor,
    // CLSAG ring signatures (EC-based, replacing hash-based)
    ClsagRingMember,
    ClsagSignature,
    EcCommitment,
    KeyImage as CryptoKeyImage,
    // Bulletproofs range proofs and commitments
    PedersenCommitment,
    PublicPoint,
    SecretScalar,
    // Stealth addresses
    StealthAddress,
};
use crate::error::{Error, Result};
use crate::primitives::{hash_domain, Amount, Hash, KeyImage, PublicKey};

use rand::{CryptoRng, Rng, RngCore};

/// Input to spend in a transaction
#[derive(Clone)]
pub struct SpendableInput {
    /// Transaction hash containing this output
    pub tx_hash: Hash,
    /// Output index within the transaction
    pub output_index: u8,
    /// Amount in atomic units
    pub amount: Amount,
    /// One-time secret key for this specific output.
    /// Computed as: H(view_secret * tx_public_key, output_index) + spend_secret.
    /// This must correspond to the public key stored as the stealth address of the output,
    /// i.e., `one_time_secret.public_key()` must equal the output's stealth address.
    /// Using the master spend_secret here would produce duplicate key images across inputs.
    pub one_time_secret: crate::primitives::SecretKey,
    /// Blinding factor for the commitment
    pub blinding: BlindingFactor,
    /// Height at which output was created
    pub height: u64,
}

/// Recipient information
#[derive(Clone)]
pub struct Recipient {
    /// Spend public key
    pub spend_public: PublicKey,
    /// View public key
    pub view_public: PublicKey,
    /// Amount to send
    pub amount: Amount,
    /// Optional lock height (output cannot be spent before this block height)
    pub lock_height: Option<u64>,
}

/// Decoy output for ring signature
#[derive(Clone)]
pub struct DecoyOutput {
    /// Public key of the decoy
    pub public_key: PublicKey,
    /// Commitment of the decoy
    pub commitment: [u8; 32],
    /// Block height when this output was created (used for decoy binning)
    pub height: u64,
}

/// Output being constructed
struct OutputBuilder {
    stealth_address: StealthAddress,
    amount: Amount,
    commitment: PedersenCommitment,
    blinding: BlindingFactor,
    encrypted_amount: Vec<u8>,
    view_tag: u8,
    lock_height: Option<u64>,
    /// Recipient's view public key (needed for memo encryption in build())
    recipient_view_public: Option<PublicKey>,
}

/// Input being constructed
struct InputBuilder {
    real_index: usize,
    ring: Vec<ClsagRingMember>,
    /// Ring member references for transaction serialization
    ring_refs: Vec<RingMemberRef>,
    one_time_secret: crate::primitives::SecretKey,
    amount: Amount,
    /// Blinding factor for this input's commitment
    /// Used to compute the pseudo-output commitment for balance verification
    blinding: BlindingFactor,
}

/// Transaction builder with full privacy features
pub struct TransactionBuilder {
    tx_type: TxType,
    inputs: Vec<InputBuilder>,
    outputs: Vec<OutputBuilder>,
    fee: Amount,
    output_blindings: Vec<BlindingFactor>,
    /// Per-output ECDH tx_secrets, needed by callers for post-build asset encryption.
    output_tx_secrets: Vec<crate::primitives::SecretKey>,
    /// Target block height — controls range proof version (BP+ at/above activation).
    target_height: u64,
    /// Optional plaintext memo to encrypt on the first recipient output.
    memo: Option<Vec<u8>>,
    /// Optional bytes to embed in `tx.extra`. Used by the dead-man's
    /// switch to encode `RecoveryMeta` (sender provides a recovery
    /// pubkey + inactivity-timeout-blocks; if the wallet stops signing
    /// for `timeout_blocks`, the recovery address can sweep these
    /// outputs). The CLI flow is `set-recovery` → store config →
    /// `send --recovery-address X --recovery-timeout Y` → embed.
    extra: Vec<u8>,
    /// Transaction version.
    tx_version: u8,
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new(tx_type: TxType) -> Self {
        TransactionBuilder {
            tx_type,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: Amount::ZERO,
            output_blindings: Vec::new(),
            output_tx_secrets: Vec::new(),
            target_height: 0,
            memo: None,
            extra: Vec::new(),
            tx_version: 1,
        }
    }

    /// Attach raw bytes to `tx.extra`. Used to embed `RecoveryMeta`
    /// (dead-man's switch) so the chain validator can persist the
    /// recovery address + timeout, and the recovery wallet can detect
    /// expiry. Format is whatever the caller provides — typically
    /// `RecoveryMeta::encode_all(&[meta])` for the dead-man's switch
    /// case. Empty → standard tx with no recovery metadata (default).
    pub fn with_extra(mut self, extra: Vec<u8>) -> Self {
        self.extra = extra;
        self
    }

    /// Set the target block height for range proof version selection.
    /// At/above BULLETPROOFS_PLUS_HEIGHT, BP+ proofs are generated.
    pub fn with_target_height(mut self, height: u64) -> Self {
        self.target_height = height;
        self.tx_version = crate::constants::block_version_at_height(height);
        self
    }

    /// Attach an encrypted memo to the first recipient output.
    /// The memo is encrypted during `build()` using the recipient's view public key.
    /// Max 256 bytes plaintext.
    pub fn with_memo(mut self, memo: &[u8]) -> Self {
        self.memo = Some(memo.to_vec());
        self
    }

    /// Create a transfer transaction builder
    pub fn transfer() -> Self {
        Self::new(TxType::Transfer)
    }

    /// Add an input with a randomly selected ring position
    ///
    /// SECURITY: This is the preferred method for adding inputs. The real input's
    /// position in the ring is selected randomly by the provided RNG, ensuring
    /// uniform distribution which is essential for ring signature privacy.
    ///
    /// # Arguments
    /// * `input` - The spendable input
    /// * `decoys` - Ring decoy members
    /// * `rng` - Cryptographically secure random number generator
    pub fn add_input_random_position<R: RngCore + CryptoRng>(
        &mut self,
        input: SpendableInput,
        decoys: Vec<DecoyOutput>,
        rng: &mut R,
    ) -> Result<&mut Self> {
        let ring_size = decoys.len() + 1;
        // SECURITY: Use rejection-sampled uniform random position to avoid
        // statistical analysis attacks (eliminates modular bias)
        let real_position = rng.gen_range(0..ring_size);
        self.add_input_at_position(input, decoys, real_position)
    }

    /// Add an input at a specific ring position (for advanced use cases)
    ///
    /// # Security Warning
    ///
    /// Prefer `add_input_random_position()` unless you have a specific reason
    /// to choose the position. Using predictable positions (e.g., always 0)
    /// destroys ring signature privacy and makes the real input identifiable.
    ///
    /// # Arguments
    /// * `input` - The spendable input
    /// * `decoys` - Ring decoy members
    /// * `real_position` - Position of real input in the ring (MUST be random)
    pub fn add_input_at_position(
        &mut self,
        input: SpendableInput,
        decoys: Vec<DecoyOutput>,
        real_position: usize,
    ) -> Result<&mut Self> {
        let ring_size = decoys.len() + 1;
        if ring_size < 2 {
            return Err(Error::InvalidRingSize {
                expected: 2,
                got: ring_size,
            });
        }
        if real_position >= ring_size {
            return Err(Error::InvalidRingSize {
                expected: ring_size,
                got: real_position + 1,
            });
        }

        // Build the ring with real output at the specified position.
        // Must use the per-output one_time_secret, not the master spend_secret.
        // one_time_secret.public_key() equals the stealth address stored in the ring,
        // so the CLSAG verifier can confirm the key image matches the ring member.
        let real_public = input.one_time_secret.public_key();
        let real_commitment = PedersenCommitment::commit(input.amount.as_atomic(), &input.blinding);

        // Build both CLSAG ring (for signing) and ring refs (for serialization)
        let mut clsag_ring = Vec::with_capacity(ring_size);
        let mut ring_refs = Vec::with_capacity(ring_size);
        let mut decoy_iter = decoys.into_iter();

        for i in 0..ring_size {
            if i == real_position {
                let commitment_bytes = real_commitment.to_bytes();
                let pub_point = PublicPoint::from_bytes(*real_public.as_bytes())
                    .ok_or(Error::CryptoError("invalid real public key point".into()))?;
                let ec_commit = EcCommitment::from_point(
                    PublicPoint::from_bytes(commitment_bytes)
                        .ok_or(Error::CryptoError("invalid real commitment point".into()))?,
                );
                clsag_ring.push(ClsagRingMember::new(pub_point, ec_commit));
                ring_refs.push(RingMemberRef {
                    public_key: real_public,
                    commitment: commitment_bytes,
                });
            } else {
                let decoy = decoy_iter.next().ok_or(Error::InvalidRingSize {
                    expected: ring_size - 1,
                    got: i,
                })?;
                let pub_point = PublicPoint::from_bytes(*decoy.public_key.as_bytes())
                    .ok_or(Error::CryptoError("invalid decoy public key point".into()))?;
                let ec_commit = EcCommitment::from_point(
                    PublicPoint::from_bytes(decoy.commitment)
                        .ok_or(Error::CryptoError("invalid decoy commitment point".into()))?,
                );
                clsag_ring.push(ClsagRingMember::new(pub_point, ec_commit));
                ring_refs.push(RingMemberRef {
                    public_key: decoy.public_key,
                    commitment: decoy.commitment,
                });
            }
        }

        self.inputs.push(InputBuilder {
            real_index: real_position,
            ring: clsag_ring,
            ring_refs,
            one_time_secret: input.one_time_secret,
            amount: input.amount,
            blinding: input.blinding,
        });

        Ok(self)
    }

    /// Backwards-compatible alias for `add_input_at_position`
    ///
    /// # Deprecated
    /// Use `add_input_random_position()` for better security, or
    /// `add_input_at_position()` if you need explicit control.
    #[inline]
    pub fn add_input(
        &mut self,
        input: SpendableInput,
        decoys: Vec<DecoyOutput>,
        real_position: usize,
    ) -> Result<&mut Self> {
        self.add_input_at_position(input, decoys, real_position)
    }

    /// Add an output to the transaction (main-address recipient, R = r*G).
    pub fn add_output<R: RngCore + CryptoRng>(
        &mut self,
        recipient: &Recipient,
        output_index: u8,
        rng: &mut R,
    ) -> Result<&mut Self> {
        self.add_output_ext(recipient, output_index, false, rng)
    }

    /// Add an output, choosing the stealth transaction-public-key form by
    /// recipient type. `is_subaddress = true` uses R = r*D_i so a subaddress
    /// recipient (published view key C_i = a*D_i) can detect and spend the
    /// output; `false` uses R = r*G for a main address. MUST be `true` for a
    /// subaddress recipient, or the output is undetectable/unspendable by them.
    pub fn add_output_ext<R: RngCore + CryptoRng>(
        &mut self,
        recipient: &Recipient,
        output_index: u8,
        is_subaddress: bool,
        rng: &mut R,
    ) -> Result<&mut Self> {
        if self.outputs.len() >= MAX_TX_OUTPUTS {
            return Err(Error::InvalidOutputCount {
                count: self.outputs.len() + 1,
                max: MAX_TX_OUTPUTS,
            });
        }

        if recipient.amount.as_atomic() < MIN_OUTPUT_AMOUNT {
            return Err(Error::OutputTooSmall {
                amount: recipient.amount.as_atomic(),
                min: MIN_OUTPUT_AMOUNT,
            });
        }

        // SECURITY (A6-STEALTH): Use checked version that returns Result instead of
        // panicking on invalid public keys. Prevents node crash from malformed
        // addresses submitted via RPC.
        let (stealth, tx_secret) = generate_stealth_address_checked_ext(
            &recipient.spend_public,
            &recipient.view_public,
            output_index,
            is_subaddress,
            rng,
        )?;

        // SECURITY (CRIT-R7-1): Derive blinding factor deterministically from ECDH
        // shared secret instead of using random. The recipient's scanner derives the
        // same blinding via H("COINCYNC_BLINDING", shared_secret). Using random()
        // creates a mismatch: the on-chain commitment uses one blinding, but the
        // recipient reconstructs a different one, making the output unspendable.
        let blinding = {
            let tx_scalar = SecretScalar::from_bytes(*tx_secret.as_bytes());
            let view_point = PublicPoint::from_bytes(*recipient.view_public.as_bytes()).ok_or(
                Error::CryptoError(
                    "invalid recipient view public key for blinding derivation".into(),
                ),
            )?;
            // P5-B1 SURGICAL FIX (2026-07-03): R-7 CLASS — zeroize
            // both the shared-point buffer and the RistrettoPoint.
            let mut shared_point = view_point.mul(&tx_scalar);
            let mut shared_bytes = shared_point.to_bytes();
            let mut ss_buf = Vec::with_capacity(32 + 1);
            ss_buf.extend_from_slice(&shared_bytes);
            ss_buf.push(output_index);
            let shared_secret = hash_domain(b"COINCYNC_SHARED_v2", &ss_buf);
            {
                use zeroize::Zeroize;
                ss_buf.zeroize();
                shared_bytes.zeroize();
                shared_point.zeroize();
            }
            let blinding_hash = hash_domain(b"COINCYNC_BLINDING", shared_secret.as_bytes());
            BlindingFactor::from_bytes(*blinding_hash.as_bytes())
        };
        let commitment = PedersenCommitment::commit(recipient.amount.as_atomic(), &blinding);

        // Encrypt amount for recipient
        let encrypted_amount = encrypt_amount(
            recipient.amount,
            &tx_secret,
            &recipient.view_public,
            output_index,
        );

        // Compute view tag (first byte of shared secret hash)
        let view_tag = compute_view_tag(&tx_secret, &recipient.view_public, output_index);

        self.outputs.push(OutputBuilder {
            stealth_address: stealth,
            amount: recipient.amount,
            commitment,
            blinding: blinding.clone(),
            encrypted_amount,
            view_tag,
            lock_height: recipient.lock_height,
            recipient_view_public: Some(recipient.view_public),
        });

        self.output_blindings.push(blinding);
        self.output_tx_secrets.push(tx_secret);

        Ok(self)
    }

    /// Add a change output
    pub fn add_change<R: RngCore + CryptoRng>(
        &mut self,
        spend_public: &PublicKey,
        view_public: &PublicKey,
        amount: Amount,
        output_index: u8,
        rng: &mut R,
    ) -> Result<&mut Self> {
        let recipient = Recipient {
            spend_public: *spend_public,
            view_public: *view_public,
            amount,
            lock_height: None,
        };
        self.add_output(&recipient, output_index, rng)
    }

    /// Add a dummy output for output-count privacy
    ///
    /// Creates a zero-amount output that is cryptographically indistinguishable
    /// from real outputs. This prevents observers from fingerprinting transactions
    /// by their output count (e.g., 2 outputs = simple transfer).
    ///
    /// Dummy outputs use random unspendable keys, proper stealth addresses,
    /// and valid Pedersen commitments to amount 0. They are included in
    /// range proofs and the balance equation like any other output.
    pub fn add_dummy_output<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<&mut Self> {
        if self.outputs.len() >= MAX_TX_OUTPUTS {
            return Ok(self); // Silently skip if at output limit
        }

        // Generate random keys — these are unspendable (nobody knows the secret)
        let dummy_secret = crate::primitives::SecretKey::generate(rng);
        let dummy_spend = dummy_secret.public_key();
        let dummy_view_secret = crate::primitives::SecretKey::generate(rng);
        let dummy_view = dummy_view_secret.public_key();
        let output_index = self.outputs.len() as u8;

        let (stealth, tx_secret) =
            generate_stealth_address_checked(&dummy_spend, &dummy_view, output_index, rng)?;

        let blinding = BlindingFactor::random(rng);
        let commitment = PedersenCommitment::commit(0, &blinding);

        let encrypted_amount = encrypt_amount(Amount::ZERO, &tx_secret, &dummy_view, output_index);
        let view_tag = compute_view_tag(&tx_secret, &dummy_view, output_index);

        self.outputs.push(OutputBuilder {
            stealth_address: stealth,
            amount: Amount::ZERO,
            commitment,
            blinding: blinding.clone(),
            encrypted_amount,
            view_tag,
            lock_height: None,
            recipient_view_public: None,
        });
        self.output_blindings.push(blinding);
        self.output_tx_secrets.push(tx_secret);

        Ok(self)
    }

    /// Set the transaction fee
    pub fn set_fee(&mut self, fee: Amount) -> &mut Self {
        self.fee = fee;
        self
    }

    /// Calculate the minimum required fee based on estimated size
    pub fn calculate_min_fee(&self) -> Amount {
        // Estimate transaction size
        // SECURITY: Calculate actual input sizes instead of using first input's ring size for all.
        // Different inputs may have different ring sizes, so we sum them individually.
        let total_input_size: usize = self
            .inputs
            .iter()
            .map(|i| 32 + 64 * i.ring.len()) // key_image + ring_sig per member
            .sum();

        let output_size = 32 + 32 + 32 + 32 + 16 + 1; // stealth_addr + tx_public_key + commitment + encrypted + view_tag
        let proof_size = 672 + 64 * self.outputs.len(); // bulletproof base + per-output

        let total_size = 8  // tx header
            + total_input_size
            + self.outputs.len() * output_size
            + proof_size
            + 8; // fee

        Amount::from_atomic((total_size as u64) * MIN_FEE_PER_BYTE)
    }

    /// Build the transaction and return the per-output ECDH tx_secrets.
    ///
    /// Callers that need to encrypt asset IDs post-build should use this
    /// method instead of `build()` so they can derive the correct ECDH
    /// shared secrets.
    pub fn build_with_secrets<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
    ) -> Result<(Transaction, Vec<crate::primitives::SecretKey>)> {
        let secrets = self.output_tx_secrets.clone();
        let tx = self.build(rng)?;
        Ok((tx, secrets))
    }

    /// Build and sign the transaction
    pub fn build<R: RngCore + CryptoRng>(self, rng: &mut R) -> Result<Transaction> {
        // Validate inputs/outputs
        if self.tx_type != TxType::Coinbase && self.inputs.is_empty() {
            return Err(Error::InvalidInputCount {
                count: 0,
                max: MAX_TX_INPUTS,
            });
        }
        if self.outputs.is_empty() {
            return Err(Error::InvalidOutputCount {
                count: 0,
                max: MAX_TX_OUTPUTS,
            });
        }

        // Verify balance: sum(inputs) = sum(outputs) + fee
        // SECURITY (M-1): Use checked_add to prevent silent u64 wrapping in release mode.
        // Previously used Iterator::sum() on raw u64 which bypasses Amount::Sum (saturating).
        let input_sum: u64 = self
            .inputs
            .iter()
            .try_fold(0u64, |acc, i| acc.checked_add(i.amount.as_atomic()))
            .ok_or(Error::AmountOverflow)?;
        let output_sum: u64 = self
            .outputs
            .iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.amount.as_atomic()))
            .ok_or(Error::AmountOverflow)?;

        let outputs_plus_fee = output_sum
            .checked_add(self.fee.as_atomic())
            .ok_or(Error::AmountOverflow)?;
        if input_sum != outputs_plus_fee {
            return Err(Error::TransactionUnbalanced {
                inputs: input_sum,
                outputs: outputs_plus_fee,
            });
        }

        // Encrypt memo for first output with a recipient view key (if memo set)
        let mut output_memos: Vec<Vec<u8>> = vec![Vec::new(); self.outputs.len()];
        if let Some(ref memo_bytes) = self.memo {
            // Find the first output with a known recipient view key (i.e., not a dummy)
            for (idx, o) in self.outputs.iter().enumerate() {
                if let Some(view_pub) = &o.recipient_view_public {
                    let tx_secret = &self.output_tx_secrets[idx];
                    output_memos[idx] =
                        encrypt_memo(memo_bytes, tx_secret.as_bytes(), view_pub.as_bytes())?;
                    break; // only attach to first recipient output
                }
            }
        }

        // Build outputs
        let tx_outputs: Vec<TxOutput> = self
            .outputs
            .iter()
            .enumerate()
            .map(|(idx, o)| TxOutput {
                stealth_address: o.stealth_address.public_key,
                tx_public_key: o.stealth_address.tx_public_key,
                commitment: o.commitment.to_bytes(),
                encrypted_amount: o.encrypted_amount.clone(),
                view_tag: o.view_tag,
                lock_height: o.lock_height,
                encrypted_memo: output_memos[idx].clone(),
            })
            .collect();

        // Create aggregated range proof for all outputs (BP+ at/above activation height)
        let amounts: Vec<Amount> = self.outputs.iter().map(|o| o.amount).collect();
        let blindings: Vec<BlindingFactor> =
            self.outputs.iter().map(|o| o.blinding.clone()).collect();
        let range_proof = create_aggregated_range_proof_for_height(
            &amounts,
            &blindings,
            rng,
            self.target_height,
        )?;

        // R-6 SURGICAL FIX (2026-07-03): use try_to_bytes so a borsh
        // serialization failure propagates as a real error rather
        // than panicking the whole tx-builder.
        let range_proof_bytes = range_proof.try_to_bytes().map_err(|e| {
            crate::error::Error::CryptoError(format!("R-6: RangeProof serialization failed: {}", e))
        })?;

        // Generate pseudo-output blinding factors for privacy
        // Each input gets a different pseudo-output blinding (r'_i), so that
        // C_real - C_pseudo = (r_real - r'_i) * G is non-trivial.
        // Balance constraint: sum(r'_i) = sum(r_out_j), so pseudo-outputs balance outputs.
        let n_inputs = self.inputs.len();
        let mut pseudo_blindings = Vec::with_capacity(n_inputs);
        let mut sum_pseudo = BlindingFactor::zero();

        // Sum all output blinding factors
        let mut sum_output = BlindingFactor::zero();
        for bf in &self.output_blindings {
            sum_output = sum_output.add(bf);
        }

        // Inputs 0..n-2: random pseudo-output blindings
        for _ in 0..n_inputs.saturating_sub(1) {
            let pseudo_bf = BlindingFactor::random(rng);
            sum_pseudo = sum_pseudo.add(&pseudo_bf);
            pseudo_blindings.push(pseudo_bf);
        }

        // Last input: constrained so sum(r'_i) = sum(r_out_j)
        if n_inputs > 0 {
            let last_pseudo = sum_output.sub(&sum_pseudo);
            pseudo_blindings.push(last_pseudo);
        }

        // Pre-compute key images and pseudo-output commitment bytes
        // needed for the signing message before we can sign
        let mut pre_key_images = Vec::with_capacity(n_inputs);
        let mut pre_pseudo_commitments = Vec::with_capacity(n_inputs);

        for (idx, input) in self.inputs.iter().enumerate() {
            let pseudo_bf = &pseudo_blindings[idx];
            let pseudo_commitment =
                PedersenCommitment::commit(input.amount.as_atomic(), pseudo_bf).to_bytes();
            pre_pseudo_commitments.push(pseudo_commitment);

            // Pre-compute CLSAG key image: I = x * Hp(x*G)
            // Must use the per-output one_time_secret (not the master spend_secret) to
            // produce unique key images. Using spend_secret for all inputs yields identical
            // key images → "Duplicate key image in block" validation failure.
            let secret_scalar = SecretScalar::from_bytes(*input.one_time_secret.as_bytes());
            let clsag_ki = CryptoKeyImage::from_secret(&secret_scalar);
            pre_key_images.push(KeyImage::from_bytes(clsag_ki.to_bytes()));
        }

        // SECURITY: builder MUST sign the exact preimage the verifier checks.
        // Funnel through `Transaction::compute_signing_hash` so signer and
        // verifier can never drift (pre-1.0 versions duplicated the preimage
        // here and drifted when the asset layer was stripped — classic
        // sign/verify-mismatch footgun, now eliminated).
        let signing_input_views: Vec<crate::transaction::types::SigningInputView> = self
            .inputs
            .iter()
            .enumerate()
            .map(|(idx, input)| {
                crate::transaction::types::SigningInputView::from_parts(
                    &pre_key_images[idx],
                    &pre_pseudo_commitments[idx],
                    &input.ring_refs,
                )
            })
            .collect();
        // The signing hash MUST cover `extra` for sign/verify consistency.
        // Earlier versions of the builder hardcoded extra = [] here and
        // also hardcoded `extra: Vec::new()` in the final Transaction —
        // those two zeros agreed by accident. Now that `with_extra()`
        // can populate `self.extra` (used by the dead-man's-switch flow
        // in wallet/send.rs::create_privacy_transaction_with_options),
        // the hash MUST cover the actual bytes — otherwise the verifier
        // computes a hash over the non-empty extra and rejects the
        // signature with "Ring signature verification failed".
        let signing_hash = Transaction::compute_signing_hash(
            self.tx_version,
            self.tx_type,
            self.fee,
            signing_input_views,
            &tx_outputs,
            &range_proof_bytes,
            &self.extra,
        );
        let message = signing_hash.as_bytes().to_vec();

        // Sign each input with CLSAG ring signature
        let mut tx_inputs = Vec::with_capacity(n_inputs);

        for (idx, input) in self.inputs.iter().enumerate() {
            let pseudo_bf = &pseudo_blindings[idx];
            let pseudo_output_commitment = pre_pseudo_commitments[idx];

            // Convert one-time secret to EC scalar for CLSAG.
            // This is the secret key corresponding to the stealth address at the real
            // ring position; must match the key image computed above.
            let secret_scalar = SecretScalar::from_bytes(*input.one_time_secret.as_bytes());

            // Blinding difference: r_real - r_pseudo (converted via bytes for cross-library compat)
            let diff_bf = input.blinding.sub(pseudo_bf);
            let blinding_diff = SecretScalar::from_bytes(diff_bf.to_bytes());

            // Reconstruct pseudo-output as EC commitment for CLSAG
            let pseudo_output =
                EcCommitment::from_point(PublicPoint::from_bytes(pseudo_output_commitment).ok_or(
                    Error::CryptoError("invalid pseudo-output commitment".into()),
                )?);

            let signature = clsag_sign(
                &message,
                &input.ring,
                input.real_index,
                &secret_scalar,
                &blinding_diff,
                &pseudo_output,
                rng,
            )?;

            tx_inputs.push(TxInput {
                key_image: pre_key_images[idx],
                ring_members: input.ring_refs.clone(),
                signature,
                pseudo_output_commitment,
            });
        }

        Ok(Transaction {
            version: self.tx_version,
            tx_type: self.tx_type,
            inputs: tx_inputs,
            outputs: tx_outputs,
            fee: self.fee,
            range_proof: range_proof_bytes,
            extra: self.extra,
        })
    }
}

/// Encrypt amount using ECDH shared secret derivation
///
/// SECURITY: Uses proper ECDH and the same derivation chain as scanner.rs decrypt_amount:
/// 1. shared_point = tx_secret * view_public (ECDH)
/// 2. shared_secret = H("COINCYNC_SHARED_v2", shared_point || output_index)
/// 3. amount_key = H("COINCYNC_AMOUNT_KEY", shared_secret)
/// 4. encrypted = amount XOR amount_key[0..8]
fn encrypt_amount(
    amount: Amount,
    tx_secret: &crate::primitives::SecretKey,
    view_public: &PublicKey,
    output_index: u8,
) -> Vec<u8> {
    let tx_scalar = SecretScalar::from_bytes(*tx_secret.as_bytes());
    let view_point = match PublicPoint::from_bytes(*view_public.as_bytes()) {
        Some(p) => p,
        None => return vec![0u8; 8],
    };
    let mut shared_point = view_point.mul(&tx_scalar);

    // Derive shared secret (same as scanner.rs compute_shared_secret).
    // P5-B1: R-7 CLASS zeroize.
    let mut shared_bytes = shared_point.to_bytes();
    let mut buf = Vec::with_capacity(32 + 1);
    buf.extend_from_slice(&shared_bytes);
    buf.push(output_index);
    let shared_secret = hash_domain(b"COINCYNC_SHARED_v2", &buf);
    {
        use zeroize::Zeroize;
        buf.zeroize();
        shared_bytes.zeroize();
        shared_point.zeroize();
    }

    // Derive amount key (same as scanner.rs decrypt_amount)
    let amount_key = hash_domain(b"COINCYNC_AMOUNT_KEY", shared_secret.as_bytes());

    // XOR amount with mask
    let amount_bytes = amount.as_atomic().to_le_bytes();
    let mut encrypted = Vec::with_capacity(8);
    for i in 0..8 {
        encrypted.push(amount_bytes[i] ^ amount_key.as_bytes()[i]);
    }
    encrypted
}

/// Compute view tag for fast output scanning (sender side)
///
/// SECURITY: Uses proper ECDH (tx_secret * view_public_POINT).
fn compute_view_tag(
    tx_secret: &crate::primitives::SecretKey,
    view_public: &PublicKey,
    output_index: u8,
) -> u8 {
    let tx_scalar = SecretScalar::from_bytes(*tx_secret.as_bytes());
    let view_point = match PublicPoint::from_bytes(*view_public.as_bytes()) {
        Some(p) => p,
        None => return 0,
    };
    let mut shared_point = view_point.mul(&tx_scalar);

    // P5-B1: R-7 CLASS zeroize.
    let mut shared_bytes = shared_point.to_bytes();
    let mut tag_input = Vec::with_capacity(32 + 1);
    tag_input.extend_from_slice(&shared_bytes);
    tag_input.push(output_index);
    let tag_hash = hash_domain(b"COINCYNC_VIEWTAG_v2", &tag_input);
    let tag = tag_hash.as_bytes()[0];
    {
        use zeroize::Zeroize;
        tag_input.zeroize();
        shared_bytes.zeroize();
        shared_point.zeroize();
    }
    tag
}

/// Decrypt amount using view secret key and ECDH
///
/// SECURITY: Uses proper ECDH and the same derivation chain as encrypt_amount.
pub fn decrypt_amount(
    encrypted: &[u8],
    tx_public: &PublicKey,
    view_secret: &crate::primitives::SecretKey,
    output_index: u8,
) -> Option<Amount> {
    if encrypted.len() != 8 {
        return None;
    }

    let view_scalar = SecretScalar::from_bytes(*view_secret.as_bytes());
    let tx_point = PublicPoint::from_bytes(*tx_public.as_bytes())?;
    let mut shared_point = tx_point.mul(&view_scalar);

    // Same derivation chain as encrypt_amount and scanner.rs.
    // P5-B1: R-7 CLASS zeroize.
    let mut shared_bytes = shared_point.to_bytes();
    let mut buf = Vec::with_capacity(32 + 1);
    buf.extend_from_slice(&shared_bytes);
    buf.push(output_index);
    let shared_secret = hash_domain(b"COINCYNC_SHARED_v2", &buf);
    {
        use zeroize::Zeroize;
        buf.zeroize();
        shared_bytes.zeroize();
        shared_point.zeroize();
    }
    let amount_key = hash_domain(b"COINCYNC_AMOUNT_KEY", shared_secret.as_bytes());

    let mut amount_bytes = [0u8; 8];
    for i in 0..8 {
        amount_bytes[i] = encrypted[i] ^ amount_key.as_bytes()[i];
    }

    Some(Amount::from_atomic(u64::from_le_bytes(amount_bytes)))
}

/// Simple builder for basic transactions (legacy interface)
#[deprecated(
    note = "H28: Does NOT generate range proofs. Use TransactionBuilder::build_with_proofs() for production."
)]
pub struct SimpleTransactionBuilder {
    tx_type: TxType,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    fee: Amount,
}

#[allow(deprecated)] // Internal impl block of the deprecated builder itself
impl SimpleTransactionBuilder {
    pub fn new(tx_type: TxType) -> Self {
        SimpleTransactionBuilder {
            tx_type,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: Amount::ZERO,
        }
    }

    pub fn add_input(
        &mut self,
        key_image: KeyImage,
        ring: Vec<RingMemberRef>,
        signature: ClsagSignature,
        pseudo_output_commitment: [u8; 32],
    ) -> &mut Self {
        self.inputs.push(TxInput {
            key_image,
            ring_members: ring,
            signature,
            pseudo_output_commitment,
        });
        self
    }

    pub fn add_output(
        &mut self,
        stealth: PublicKey,
        tx_pub: PublicKey,
        commitment: [u8; 32],
        enc_amount: Vec<u8>,
        view_tag: u8,
    ) -> &mut Self {
        self.outputs.push(TxOutput {
            stealth_address: stealth,
            tx_public_key: tx_pub,
            commitment,
            encrypted_amount: enc_amount,
            view_tag,
            lock_height: None,
            encrypted_memo: vec![],
        });
        self
    }

    pub fn set_fee(&mut self, fee: Amount) -> &mut Self {
        self.fee = fee;
        self
    }

    pub fn build(self) -> Result<Transaction> {
        if self.outputs.is_empty() {
            return Err(Error::InvalidOutputCount {
                count: 0,
                max: MAX_TX_OUTPUTS,
            });
        }

        Ok(Transaction {
            version: 1,
            tx_type: self.tx_type,
            inputs: self.inputs,
            outputs: self.outputs,
            fee: self.fee,
            // WARNING (H28): This builder does NOT generate range proofs.
            range_proof: Vec::new(),
            extra: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::SecretKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_amount_encryption_roundtrip() {
        let amount = Amount::from_atomic(12345678901234);
        let tx_secret = SecretKey::generate(&mut OsRng);
        let view_secret = SecretKey::generate(&mut OsRng);
        let view_public = view_secret.public_key();
        let tx_public = tx_secret.public_key();
        let output_index = 0;

        let encrypted = encrypt_amount(amount, &tx_secret, &view_public, output_index);
        assert_eq!(encrypted.len(), 8);

        // Verify sender encryption and receiver decryption produce the same amount (ECDH roundtrip)
        let decrypted = decrypt_amount(&encrypted, &tx_public, &view_secret, output_index);
        assert_eq!(decrypted, Some(amount), "ECDH amount roundtrip failed");
    }

    #[test]
    fn test_view_tag_generation() {
        let tx_secret = SecretKey::generate(&mut OsRng);
        let view_secret = SecretKey::generate(&mut OsRng);
        let view_public = view_secret.public_key();
        let tx_public = tx_secret.public_key();

        let sender_tag = compute_view_tag(&tx_secret, &view_public, 0);

        // The output index must affect the tag. The tag is a single byte, so
        // any single pair can collide ~1/256 by chance — asserting only
        // tag(0) != tag(1) is flaky (an intermittent CI failure). Instead
        // require variety across 0..16: if the index were ignored, all 16
        // would be identical; with a genuine dependency a chance all-16
        // collision is ~256^-15 (effectively never).
        let tags: Vec<u8> = (0..16u8)
            .map(|i| compute_view_tag(&tx_secret, &view_public, i))
            .collect();
        assert!(
            tags.iter().any(|&t| t != tags[0]),
            "output index must affect the view tag"
        );

        // Sender and receiver must compute same view tag (ECDH correctness)
        let receiver_tag = {
            use crate::crypto::{PublicPoint as PP, SecretScalar as SS};
            let vs = SS::from_bytes(*view_secret.as_bytes());
            let tp = PP::from_bytes(*tx_public.as_bytes()).unwrap();
            let shared = tp.mul(&vs);
            let tag_input = [shared.to_bytes().as_slice(), &[0u8]].concat();
            let tag_hash = crate::primitives::hash_domain(b"COINCYNC_VIEWTAG_v2", &tag_input);
            tag_hash.as_bytes()[0]
        };
        assert_eq!(
            sender_tag, receiver_tag,
            "ECDH view tag mismatch between sender and receiver"
        );
    }

    #[test]
    fn test_simple_builder() {
        use crate::crypto::{self, SecretScalar as EcSecret};

        // Generate valid curve points for mock CLSAG signature
        let mock_secret = EcSecret::random(&mut OsRng);
        let mock_ki = crypto::KeyImage::from_secret(&mock_secret);
        let mock_pub = mock_secret.to_public();

        let key_image = KeyImage::from_bytes(mock_ki.to_bytes());
        let stealth = PublicKey::from_bytes(mock_pub.to_bytes());
        let tx_pub = PublicKey::from_bytes(mock_pub.to_bytes());

        // Create ring member reference
        let ring_member = RingMemberRef {
            public_key: stealth,
            commitment: mock_pub.to_bytes(), // valid curve point bytes
        };

        // Create mock CLSAG signature with valid curve points
        let signature = ClsagSignature {
            key_image: mock_ki,
            commitment_image: mock_pub,
            c1: [0u8; 32],
            responses: vec![[0u8; 32]],
        };

        // SimpleTransactionBuilder is intentionally deprecated (no range proofs);
        // the test just exercises its construct-and-build wiring, not production
        // semantics, so silencing the deprecation warning here is correct.
        #[allow(deprecated)]
        let tx = {
            let mut builder = SimpleTransactionBuilder::new(TxType::Transfer);
            let pseudo_output = mock_pub.to_bytes();
            builder
                .add_input(key_image, vec![ring_member], signature, pseudo_output)
                .add_output(stealth, tx_pub, mock_pub.to_bytes(), vec![0u8; 8], 0x42)
                .set_fee(Amount::from_atomic(100_000_000));
            builder.build().unwrap()
        };
        assert_eq!(tx.tx_type, TxType::Transfer);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.fee.as_atomic(), 100_000_000);
    }

    #[test]
    fn test_calculate_min_fee() {
        let builder = TransactionBuilder::transfer();
        let min_fee = builder.calculate_min_fee();
        assert!(min_fee.as_atomic() > 0);
    }

    // =========================================================================
    // HELPERS — real curve points for inputs/outputs, mirroring the
    // full_pipeline_real_crypto integration helpers.
    // =========================================================================

    fn generate_keypair() -> (SecretKey, PublicKey) {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        (
            SecretKey::from_bytes(secret.to_bytes()),
            PublicKey::from_bytes(public.to_bytes()),
        )
    }

    fn make_spendable_input(amount: u64) -> SpendableInput {
        let secret = SecretScalar::random(&mut OsRng);
        SpendableInput {
            tx_hash: Hash::from_bytes([7u8; 32]),
            output_index: 0,
            amount: Amount::from_atomic(amount),
            one_time_secret: SecretKey::from_bytes(secret.to_bytes()),
            blinding: BlindingFactor::random(&mut OsRng),
            height: 1000,
        }
    }

    fn make_decoys(count: usize) -> Vec<DecoyOutput> {
        (0..count)
            .map(|i| {
                let s = SecretScalar::random(&mut OsRng);
                let bf = BlindingFactor::random(&mut OsRng);
                let commitment = PedersenCommitment::commit(1_000_000_000 + i as u64, &bf);
                DecoyOutput {
                    public_key: PublicKey::from_bytes(s.to_public().to_bytes()),
                    commitment: commitment.to_bytes(),
                    height: 500 + i as u64,
                }
            })
            .collect()
    }

    fn make_recipient(amount: u64) -> Recipient {
        let (_, spend) = generate_keypair();
        let (_, view) = generate_keypair();
        Recipient {
            spend_public: spend,
            view_public: view,
            amount: Amount::from_atomic(amount),
            lock_height: None,
        }
    }

    // =========================================================================
    // build() — input/output count guards, balance, overflow
    // =========================================================================

    #[test]
    fn build_transfer_with_no_inputs_rejected() {
        let b = TransactionBuilder::transfer();
        let err = b.build(&mut OsRng).err().unwrap();
        assert!(
            matches!(err, Error::InvalidInputCount { .. }),
            "non-coinbase with no inputs must be InvalidInputCount, got {err:?}"
        );
    }

    #[test]
    fn build_with_no_outputs_rejected() {
        // Coinbase skips the input-count check, so this reaches the output guard.
        let b = TransactionBuilder::new(TxType::Coinbase);
        let err = b.build(&mut OsRng).err().unwrap();
        assert!(
            matches!(err, Error::InvalidOutputCount { .. }),
            "no outputs must be InvalidOutputCount, got {err:?}"
        );
    }

    #[test]
    fn build_unbalanced_transaction_rejected() {
        let mut b = TransactionBuilder::transfer();
        b.add_input_at_position(make_spendable_input(10_000_000), make_decoys(2), 0)
            .unwrap();
        b.add_output(&make_recipient(5_000_000), 0, &mut OsRng).unwrap();
        b.set_fee(Amount::ZERO); // 10_000_000 != 5_000_000 + 0
        let err = b.build(&mut OsRng).err().unwrap();
        assert!(
            matches!(err, Error::TransactionUnbalanced { .. }),
            "input_sum != output_sum + fee must be TransactionUnbalanced, got {err:?}"
        );
    }

    #[test]
    fn build_input_sum_overflow_rejected() {
        // Two u64::MAX inputs overflow the checked input-sum (M-1 fix).
        let mut b = TransactionBuilder::transfer();
        b.add_input_at_position(make_spendable_input(u64::MAX), make_decoys(1), 0)
            .unwrap();
        b.add_input_at_position(make_spendable_input(u64::MAX), make_decoys(1), 0)
            .unwrap();
        b.add_dummy_output(&mut OsRng).unwrap();
        let err = b.build(&mut OsRng).err().unwrap();
        assert!(
            matches!(err, Error::AmountOverflow),
            "input_sum overflow must be AmountOverflow, got {err:?}"
        );
    }

    #[test]
    fn build_output_sum_overflow_rejected() {
        // Two u64::MAX outputs overflow the checked output-sum.
        let mut b = TransactionBuilder::new(TxType::Coinbase);
        b.add_output(&make_recipient(u64::MAX), 0, &mut OsRng).unwrap();
        b.add_output(&make_recipient(u64::MAX), 1, &mut OsRng).unwrap();
        let err = b.build(&mut OsRng).err().unwrap();
        assert!(
            matches!(err, Error::AmountOverflow),
            "output_sum overflow must be AmountOverflow, got {err:?}"
        );
    }

    #[test]
    fn build_output_plus_fee_overflow_rejected() {
        // output_sum (u64::MAX) + fee (1) overflows outputs_plus_fee.
        let mut b = TransactionBuilder::new(TxType::Coinbase);
        b.add_output(&make_recipient(u64::MAX), 0, &mut OsRng).unwrap();
        b.set_fee(Amount::from_atomic(1));
        let err = b.build(&mut OsRng).err().unwrap();
        assert!(
            matches!(err, Error::AmountOverflow),
            "output_sum + fee overflow must be AmountOverflow, got {err:?}"
        );
    }

    #[test]
    fn memo_attaches_to_first_recipient_output_and_skips_dummies() {
        let mut rng = OsRng;
        let recipient_amount = 2_000_000_000u64;
        let mut b = TransactionBuilder::transfer()
            .with_target_height(0)
            .with_memo(b"hello world");
        // Balance: input == dummy(0) + recipient + fee(0).
        b.add_input_at_position(make_spendable_input(recipient_amount), make_decoys(2), 0)
            .unwrap();
        b.add_dummy_output(&mut rng).unwrap(); // index 0 — dummy, no recipient view key
        b.add_output(&make_recipient(recipient_amount), 1, &mut rng)
            .unwrap(); // index 1 — real recipient
        b.set_fee(Amount::ZERO);
        let tx = b.build(&mut rng).expect("balanced tx must build");
        assert!(
            tx.outputs[0].encrypted_memo.is_empty(),
            "dummy output must carry no memo"
        );
        assert!(
            !tx.outputs[1].encrypted_memo.is_empty(),
            "memo must attach to the first recipient output only"
        );
    }

    // =========================================================================
    // add_input_at_position / add_input_random_position
    // =========================================================================

    #[test]
    fn add_input_with_ring_size_below_two_rejected() {
        let mut b = TransactionBuilder::transfer();
        let err = b
            .add_input_at_position(make_spendable_input(1_000_000), vec![], 0)
            .err().unwrap();
        assert!(
            matches!(err, Error::InvalidRingSize { .. }),
            "ring_size < 2 must be InvalidRingSize, got {err:?}"
        );
    }

    #[test]
    fn add_input_with_real_position_out_of_range_rejected() {
        let mut b = TransactionBuilder::transfer();
        // ring_size = 2, real_position 5 is out of range.
        let err = b
            .add_input_at_position(make_spendable_input(1_000_000), make_decoys(1), 5)
            .err().unwrap();
        assert!(
            matches!(err, Error::InvalidRingSize { .. }),
            "real_position >= ring_size must be InvalidRingSize, got {err:?}"
        );
    }

    #[test]
    fn add_input_places_real_output_at_requested_position() {
        let mut b = TransactionBuilder::transfer();
        let input = make_spendable_input(1_000_000);
        let expected_pub = input.one_time_secret.public_key();
        b.add_input_at_position(input, make_decoys(3), 2).unwrap();
        let built = &b.inputs[0];
        assert_eq!(built.real_index, 2, "real input at requested position");
        assert_eq!(built.ring_refs.len(), 4, "ring_refs fill the whole ring");
        assert_eq!(built.ring.len(), 4, "clsag_ring fills the whole ring");
        assert_eq!(
            built.ring_refs[2].public_key.as_bytes(),
            expected_pub.as_bytes(),
            "real output's public key sits at the requested ring position"
        );
    }

    #[test]
    fn add_input_invalid_decoy_public_key_errors_not_panics() {
        // A6 fix: malformed decoy points return CryptoError instead of panicking.
        let bad_decoy = DecoyOutput {
            public_key: PublicKey::from_bytes([0xFFu8; 32]), // not a valid ristretto point
            commitment: PedersenCommitment::commit(1, &BlindingFactor::random(&mut OsRng))
                .to_bytes(),
            height: 500,
        };
        let mut b = TransactionBuilder::transfer();
        // real at position 0 → the invalid decoy is parsed at position 1.
        let err = b
            .add_input_at_position(make_spendable_input(1_000_000), vec![bad_decoy], 0)
            .err().unwrap();
        assert!(
            matches!(err, Error::CryptoError(_)),
            "invalid decoy public key must be CryptoError, got {err:?}"
        );
    }

    #[test]
    fn add_input_random_position_stays_in_range_and_varies() {
        let ring_size = 4;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let mut b = TransactionBuilder::transfer();
            b.add_input_random_position(
                make_spendable_input(1_000_000),
                make_decoys(ring_size - 1),
                &mut OsRng,
            )
            .unwrap();
            let idx = b.inputs[0].real_index;
            assert!(idx < ring_size, "real_index {idx} must be in 0..{ring_size}");
            seen.insert(idx);
        }
        assert!(
            seen.len() > 1,
            "random position must produce more than one distinct index over many draws"
        );
    }

    // =========================================================================
    // add_output / add_change / add_dummy_output
    // =========================================================================

    #[test]
    fn add_output_beyond_max_outputs_rejected() {
        let mut b = TransactionBuilder::transfer();
        for _ in 0..MAX_TX_OUTPUTS {
            b.add_dummy_output(&mut OsRng).unwrap();
        }
        assert_eq!(b.outputs.len(), MAX_TX_OUTPUTS);
        let err = b
            .add_output(&make_recipient(2_000_000), 0, &mut OsRng)
            .err().unwrap();
        assert!(
            matches!(err, Error::InvalidOutputCount { .. }),
            "adding past MAX_TX_OUTPUTS must be InvalidOutputCount, got {err:?}"
        );
    }

    #[test]
    fn add_output_below_min_amount_rejected() {
        let mut b = TransactionBuilder::transfer();
        let err = b
            .add_output(&make_recipient(MIN_OUTPUT_AMOUNT - 1), 0, &mut OsRng)
            .err().unwrap();
        assert!(
            matches!(err, Error::OutputTooSmall { .. }),
            "amount < MIN_OUTPUT_AMOUNT must be OutputTooSmall, got {err:?}"
        );
    }

    #[test]
    fn add_output_invalid_view_key_errors_not_panics() {
        // A6-STEALTH: malformed recipient keys return an error, never panic.
        // The stealth generator validates the view point and returns
        // InvalidPublicKey (the checked-key path) rather than crashing the node.
        let (_, spend) = generate_keypair();
        let recipient = Recipient {
            spend_public: spend,
            view_public: PublicKey::from_bytes([0xFFu8; 32]), // invalid point
            amount: Amount::from_atomic(2_000_000),
            lock_height: None,
        };
        let mut b = TransactionBuilder::transfer();
        let err = b.add_output(&recipient, 0, &mut OsRng).err().unwrap();
        assert!(
            matches!(err, Error::InvalidPublicKey(_)),
            "invalid recipient view key must be a clean error, got {err:?}"
        );
    }

    #[test]
    fn add_dummy_output_silently_skips_at_output_limit() {
        let mut b = TransactionBuilder::transfer();
        for _ in 0..MAX_TX_OUTPUTS {
            b.add_dummy_output(&mut OsRng).unwrap();
        }
        assert_eq!(b.outputs.len(), MAX_TX_OUTPUTS);
        // At the limit, add_dummy_output is a silent Ok no-op — not an error.
        b.add_dummy_output(&mut OsRng).unwrap();
        assert_eq!(
            b.outputs.len(),
            MAX_TX_OUTPUTS,
            "dummy output must be silently skipped at the output limit"
        );
    }

    #[test]
    fn add_dummy_output_has_zero_amount() {
        let mut b = TransactionBuilder::transfer();
        b.add_dummy_output(&mut OsRng).unwrap();
        assert_eq!(
            b.outputs[0].amount,
            Amount::ZERO,
            "dummy output must commit to amount zero"
        );
    }

    // =========================================================================
    // with_target_height / with_extra
    // =========================================================================

    #[test]
    fn with_target_height_sets_tx_version() {
        use crate::constants::{block_version_at_height, V2_TX_ACTIVATION_HEIGHT};
        let b0 = TransactionBuilder::transfer().with_target_height(0);
        assert_eq!(b0.tx_version, block_version_at_height(0));
        let b2 = TransactionBuilder::transfer().with_target_height(V2_TX_ACTIVATION_HEIGHT);
        assert_eq!(
            b2.tx_version,
            block_version_at_height(V2_TX_ACTIVATION_HEIGHT)
        );
        assert_ne!(
            b0.tx_version, b2.tx_version,
            "tx_version must differ across the V2 activation height"
        );
    }

    #[test]
    fn with_extra_populates_extra_field() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let b = TransactionBuilder::transfer().with_extra(bytes.clone());
        assert_eq!(b.extra, bytes, "with_extra must populate tx.extra bytes");
    }

    // =========================================================================
    // encrypt_amount / decrypt_amount edge cases
    // =========================================================================

    #[test]
    fn decrypt_amount_wrong_length_returns_none() {
        let (view_secret, _) = generate_keypair();
        let (_, tx_public) = generate_keypair();
        assert_eq!(decrypt_amount(&[0u8; 7], &tx_public, &view_secret, 0), None);
        assert_eq!(decrypt_amount(&[0u8; 9], &tx_public, &view_secret, 0), None);
        assert_eq!(decrypt_amount(&[], &tx_public, &view_secret, 0), None);
    }

    #[test]
    fn encrypt_amount_invalid_view_point_returns_zero_fallback() {
        let (tx_secret, _) = generate_keypair();
        let bad_view = PublicKey::from_bytes([0xFFu8; 32]); // invalid ristretto point
        let out = encrypt_amount(Amount::from_atomic(123), &tx_secret, &bad_view, 0);
        assert_eq!(
            out,
            vec![0u8; 8],
            "invalid view point must yield the 8-byte zero fallback"
        );
    }

    // =========================================================================
    // SimpleTransactionBuilder (deprecated)
    // =========================================================================

    #[test]
    fn simple_builder_with_no_outputs_rejected() {
        #[allow(deprecated)]
        let err = {
            let builder = SimpleTransactionBuilder::new(TxType::Transfer);
            builder.build().err().unwrap()
        };
        assert!(
            matches!(err, Error::InvalidOutputCount { .. }),
            "SimpleTransactionBuilder with no outputs must be InvalidOutputCount, got {err:?}"
        );
    }
}
