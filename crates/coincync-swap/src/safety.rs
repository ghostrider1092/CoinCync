//! Bitcoin-first safety contract and the pre-CYNC-lock verification gate.
//!
//! The Bitcoin output has no key-path spend. Its two Tapscript leaves are
//! both 2-of-2 so neither party can bypass the adaptor signature that reveals
//! the counterparty's CYNC spend share:
//!
//! - success: Alice co-signs normally; Bob's signature is adapted to Alice's
//!   share, which Bob recovers after Alice claims BTC;
//! - refund: Bob co-signs normally; Alice's signature is adapted to Bob's
//!   share, which Alice recovers after Bob refunds BTC.
//!
//! [`verify_pre_cync_lock`] verifies the exact Bitcoin lock and both spend
//! templates, both adaptor pre-signatures, and strict cross-curve DLEQ proofs
//! before producing a non-serializable [`VerifiedPreCyncLock`] capability.

use std::str::FromStr;

use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_CSV, OP_DROP, OP_NUMEQUAL};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{schnorr::Signature, Message, PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    absolute::LockTime, transaction::Version, Address, Amount, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::adaptor::{
    cync_adaptor_point, recover_secret_from_btc_sig, verify_pre_sig, AdaptorSecret, BtcAdaptorSig,
};
use crate::btc::{FundingUtxo, DUST_THRESHOLD_SATS};
use crate::cync::{compute_swap_lock_recipient, SwapLockRecipient};
use crate::protocol::Swap;
use crate::strict_dleq::{verify_cross_curve_strict, CrossCurveDlProofStrict};
use crate::{Error, Result};

const EVIDENCE_VERSION: u8 = 1;
const NUMS_DOMAIN: &[u8] = b"CoinCync/Swap/Taproot-NUMS-v1";
const MAX_LOCK_TX_BYTES: usize = 4_000_000;
const MAX_SPEND_TX_BYTES: usize = 1_000_000;

/// The four independent signing keys and relative refund timeout committed by
/// the Bitcoin Taproot output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapTaprootContract {
    /// Alice's ordinary co-signing key on the success path.
    pub alice_claim_pubkey: [u8; 32],
    /// Bob's adaptor-signing key on the success path.
    pub bob_claim_pubkey: [u8; 32],
    /// Alice's adaptor-signing key on the refund path.
    pub alice_refund_pubkey: [u8; 32],
    /// Bob's ordinary co-signing key on the refund path.
    pub bob_refund_pubkey: [u8; 32],
    /// BIP-68/BIP-112 blocks-relative delay for the refund leaf.
    pub refund_csv_blocks: u16,
}

/// Inputs for the unsigned Bitcoin transaction that funds the safe swap
/// output. Funding input selection and signatures remain the BTC wallet's job.
#[derive(Clone, Debug)]
pub struct SafeLockTxRequest {
    pub utxos: Vec<FundingUtxo>,
    pub lock_amount_sats: u64,
    pub contract: SwapTaprootContract,
    pub change_address: String,
    pub fee_sats: u64,
    pub locktime: u32,
}

/// Exact transaction template for either Tapscript spend of the lock output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeSpendBase {
    pub lock_txid: String,
    pub lock_vout: u32,
    pub lock_value_sats: u64,
    pub contract: SwapTaprootContract,
    pub dest_address: String,
    pub fee_sats: u64,
}

/// Canonical strict-DLEQ material binding one CYNC share to one Bitcoin
/// adaptor point. Binary values use lowercase or uppercase hex on input;
/// verification decodes and validates their canonical form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareBindingEvidence {
    pub btc_adaptor_point_hex: String,
    pub cync_spend_share_hex: String,
    pub strict_dleq_proof_hex: String,
}

/// Wire representation of a Bitcoin adaptor pre-signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptorPreSignatureEvidence {
    pub r_point_hex: String,
    pub s_pre_hex: String,
}

/// Complete evidence required before Alice may create or broadcast the CYNC
/// lock. This type intentionally stores the proof, not a previously-computed
/// boolean, so every process restart can repeat all cryptographic checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreCyncLockSafetyEvidence {
    pub version: u8,
    pub swap_id: String,
    pub btc_network: String,
    pub lock_tx_hex: String,
    pub lock_vout: u32,
    pub contract: SwapTaprootContract,
    pub claim_destination: String,
    pub claim_fee_sats: u64,
    pub refund_destination: String,
    pub refund_fee_sats: u64,
    pub alice_share: ShareBindingEvidence,
    pub bob_share: ShareBindingEvidence,
    pub claim_adaptor: AdaptorPreSignatureEvidence,
    pub refund_adaptor: AdaptorPreSignatureEvidence,
    pub shared_view_public_hex: String,
    pub cync_amount_atomic: u64,
}

impl PreCyncLockSafetyEvidence {
    /// Current evidence wire version.
    pub const VERSION: u8 = EVIDENCE_VERSION;
}

/// Non-serializable capability returned only after the full pre-lock gate has
/// passed. Callers cannot construct this type directly or persist a stale
/// "verified=true" marker in place of the original evidence.
#[derive(Clone, Debug)]
pub struct VerifiedPreCyncLock {
    swap_id: String,
    fingerprint: [u8; 32],
    lock_txid: String,
    lock_vout: u32,
    recipient: SwapLockRecipient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RevealedParty {
    Alice,
    Bob,
}

/// Non-serializable proof that an exact Bitcoin claim or refund signature was
/// valid and revealed the share committed by the corresponding strict proof.
#[derive(Clone, Debug)]
pub struct VerifiedShareReveal {
    swap_id: String,
    party: RevealedParty,
    secret: [u8; 32],
}

impl VerifiedShareReveal {
    /// Recovered canonical Ristretto scalar for the revealed CYNC share.
    pub fn cync_secret_share(&self) -> [u8; 32] {
        self.secret
    }

    pub(crate) fn matches(&self, swap_id: &str, party: RevealedParty) -> bool {
        self.swap_id == swap_id && self.party == party
    }
}

impl VerifiedPreCyncLock {
    pub(crate) fn matches_swap(&self, swap_id: &str) -> bool {
        self.swap_id == swap_id
    }

    /// SHA-256 of the exact JSON evidence verified by this capability.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Transaction id of the Bitcoin lock bound by the evidence.
    pub fn lock_txid(&self) -> &str {
        &self.lock_txid
    }

    /// Output index of the Bitcoin lock bound by the evidence.
    pub fn lock_vout(&self) -> u32 {
        self.lock_vout
    }

    /// Wallet-ready joint CYNC recipient derived from the two proven shares.
    pub fn cync_recipient(&self) -> &SwapLockRecipient {
        &self.recipient
    }
}

fn parse_network(name: &str) -> Result<Network> {
    match name {
        "mainnet" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        "signet" => Ok(Network::Signet),
        _ => Err(Error::Verification(
            "Bitcoin network must be mainnet/testnet/regtest/signet",
        )),
    }
}

fn parse_xonly(bytes: &[u8; 32], label: &'static str) -> Result<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(bytes).map_err(|_| Error::Verification(label))
}

fn validate_contract(contract: &SwapTaprootContract) -> Result<()> {
    parse_xonly(
        &contract.alice_claim_pubkey,
        "alice_claim_pubkey is not a valid x-only key",
    )?;
    parse_xonly(
        &contract.bob_claim_pubkey,
        "bob_claim_pubkey is not a valid x-only key",
    )?;
    parse_xonly(
        &contract.alice_refund_pubkey,
        "alice_refund_pubkey is not a valid x-only key",
    )?;
    parse_xonly(
        &contract.bob_refund_pubkey,
        "bob_refund_pubkey is not a valid x-only key",
    )?;
    if contract.refund_csv_blocks == 0 {
        return Err(Error::Verification("refund_csv_blocks must be non-zero"));
    }
    Ok(())
}

fn contract_commitment_bytes(contract: &SwapTaprootContract) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 * 4 + 2);
    bytes.extend_from_slice(&contract.alice_claim_pubkey);
    bytes.extend_from_slice(&contract.bob_claim_pubkey);
    bytes.extend_from_slice(&contract.alice_refund_pubkey);
    bytes.extend_from_slice(&contract.bob_refund_pubkey);
    bytes.extend_from_slice(&contract.refund_csv_blocks.to_le_bytes());
    bytes
}

fn nums_internal_key(contract: &SwapTaprootContract) -> Result<XOnlyPublicKey> {
    let commitment = contract_commitment_bytes(contract);
    for counter in 0u32..=u32::MAX {
        let mut hash = Sha256::new();
        hash.update(NUMS_DOMAIN);
        hash.update(&commitment);
        hash.update(counter.to_le_bytes());
        let candidate: [u8; 32] = hash.finalize().into();
        if let Ok(key) = XOnlyPublicKey::from_slice(&candidate) {
            return Ok(key);
        }
    }
    Err(Error::Verification(
        "failed to derive Taproot NUMS internal key",
    ))
}

fn success_script(contract: &SwapTaprootContract) -> Result<ScriptBuf> {
    let alice = parse_xonly(
        &contract.alice_claim_pubkey,
        "alice_claim_pubkey is not a valid x-only key",
    )?;
    let bob = parse_xonly(
        &contract.bob_claim_pubkey,
        "bob_claim_pubkey is not a valid x-only key",
    )?;
    Ok(Builder::new()
        .push_x_only_key(&alice)
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&bob)
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUAL)
        .into_script())
}

fn refund_script(contract: &SwapTaprootContract) -> Result<ScriptBuf> {
    let alice = parse_xonly(
        &contract.alice_refund_pubkey,
        "alice_refund_pubkey is not a valid x-only key",
    )?;
    let bob = parse_xonly(
        &contract.bob_refund_pubkey,
        "bob_refund_pubkey is not a valid x-only key",
    )?;
    Ok(Builder::new()
        .push_int(i64::from(contract.refund_csv_blocks))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&alice)
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&bob)
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUAL)
        .into_script())
}

fn contract_spend_info(
    contract: &SwapTaprootContract,
) -> Result<(XOnlyPublicKey, TaprootSpendInfo, ScriptBuf, ScriptBuf)> {
    validate_contract(contract)?;
    let internal_key = nums_internal_key(contract)?;
    let success = success_script(contract)?;
    let refund = refund_script(contract)?;
    let secp = Secp256k1::verification_only();
    let spend_info = TaprootBuilder::new()
        .add_leaf(1, success.clone())
        .map_err(|_| Error::Verification("failed to add Taproot success leaf"))?
        .add_leaf(1, refund.clone())
        .map_err(|_| Error::Verification("failed to add Taproot refund leaf"))?
        .finalize(&secp, internal_key)
        .map_err(|_| Error::Verification("failed to finalize two-leaf Taproot contract"))?;
    Ok((internal_key, spend_info, success, refund))
}

/// Return the exact P2TR scriptPubKey used by the safe lock output.
pub fn safe_lock_script_pubkey(contract: &SwapTaprootContract) -> Result<ScriptBuf> {
    let (internal_key, spend_info, _, _) = contract_spend_info(contract)?;
    let secp = Secp256k1::verification_only();
    Ok(ScriptBuf::new_p2tr(
        &secp,
        internal_key,
        spend_info.merkle_root(),
    ))
}

/// Construct the unsigned Bitcoin-first lock transaction.
pub fn build_safe_lock_tx(network: &str, request: &SafeLockTxRequest) -> Result<Vec<u8>> {
    let network = parse_network(network)?;
    if request.utxos.is_empty() {
        return Err(Error::Verification(
            "SafeLockTxRequest.utxos must be non-empty",
        ));
    }
    if request.lock_amount_sats < DUST_THRESHOLD_SATS {
        return Err(Error::Verification(
            "lock_amount_sats is below the P2TR dust threshold",
        ));
    }
    let total_input = request
        .utxos
        .iter()
        .try_fold(0u64, |sum, utxo| sum.checked_add(utxo.value_sats))
        .ok_or(Error::Verification("input value sum overflowed u64"))?;
    let required = request
        .lock_amount_sats
        .checked_add(request.fee_sats)
        .ok_or(Error::Verification("lock amount plus fee overflowed u64"))?;
    if total_input < required {
        return Err(Error::Verification(
            "funding UTXOs do not cover lock amount plus fee",
        ));
    }
    let change_sats = total_input - required;
    let change_address = Address::from_str(&request.change_address)
        .map_err(|_| Error::Verification("change address parse failed"))?
        .require_network(network)
        .map_err(|_| Error::Verification("change address network mismatch"))?;

    let inputs = request
        .utxos
        .iter()
        .map(|utxo| TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(
                    utxo.txid.0,
                )),
                vout: utxo.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        })
        .collect();
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(request.lock_amount_sats),
        script_pubkey: safe_lock_script_pubkey(&request.contract)?,
    }];
    if change_sats > 0 {
        if change_sats < DUST_THRESHOLD_SATS {
            return Err(Error::Verification(
                "change after fee is below dust threshold",
            ));
        }
        outputs.push(TxOut {
            value: Amount::from_sat(change_sats),
            script_pubkey: change_address.script_pubkey(),
        });
    }
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(request.locktime),
        input: inputs,
        output: outputs,
    };
    Ok(bitcoin::consensus::serialize(&tx))
}

#[derive(Clone, Copy)]
enum SpendPath {
    Claim,
    Refund,
}

struct PreparedSpend {
    tx: Transaction,
    prevout: TxOut,
    script: ScriptBuf,
    spend_info: TaprootSpendInfo,
}

fn build_spend_internal(
    network: &str,
    base: &SafeSpendBase,
    path: SpendPath,
) -> Result<PreparedSpend> {
    let network = parse_network(network)?;
    if base.fee_sats >= base.lock_value_sats {
        return Err(Error::Verification("spend fee leaves no output"));
    }
    let output_value = base.lock_value_sats - base.fee_sats;
    if output_value < DUST_THRESHOLD_SATS {
        return Err(Error::Verification("spend output is below dust threshold"));
    }
    let destination = Address::from_str(&base.dest_address)
        .map_err(|_| Error::Verification("spend destination parse failed"))?
        .require_network(network)
        .map_err(|_| Error::Verification("spend destination network mismatch"))?;
    let lock_txid = bitcoin::Txid::from_str(&base.lock_txid)
        .map_err(|_| Error::Verification("lock_txid is not valid Bitcoin txid hex"))?;
    let (internal_key, spend_info, success, refund_script) = contract_spend_info(&base.contract)?;
    let prev_script = ScriptBuf::new_p2tr(
        &Secp256k1::verification_only(),
        internal_key,
        spend_info.merkle_root(),
    );
    let prevout = TxOut {
        value: Amount::from_sat(base.lock_value_sats),
        script_pubkey: prev_script,
    };
    let input = TxIn {
        previous_output: OutPoint {
            txid: lock_txid,
            vout: base.lock_vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: match path {
            SpendPath::Claim => Sequence::ENABLE_RBF_NO_LOCKTIME,
            SpendPath::Refund => Sequence::from_height(base.contract.refund_csv_blocks),
        },
        witness: Witness::new(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: destination.script_pubkey(),
        }],
    };
    Ok(PreparedSpend {
        tx,
        prevout,
        script: match path {
            SpendPath::Claim => success,
            SpendPath::Refund => refund_script,
        },
        spend_info,
    })
}

fn spend_sighash(prepared: &PreparedSpend) -> Result<[u8; 32]> {
    let leaf = TapLeafHash::from_script(&prepared.script, LeafVersion::TapScript);
    let mut cache = bitcoin::sighash::SighashCache::new(&prepared.tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(std::slice::from_ref(&prepared.prevout)),
            leaf,
            bitcoin::sighash::TapSighashType::Default,
        )
        .map_err(|_| Error::Verification("Taproot script-path sighash failed"))?;
    Ok(*sighash.as_ref())
}

/// Exact success-path sighash Bob's adaptor pre-signature must bind.
pub fn safe_claim_sighash(network: &str, base: &SafeSpendBase) -> Result<[u8; 32]> {
    spend_sighash(&build_spend_internal(network, base, SpendPath::Claim)?)
}

/// Exact refund-path sighash Alice's adaptor pre-signature must bind.
pub fn safe_refund_sighash(network: &str, base: &SafeSpendBase) -> Result<[u8; 32]> {
    spend_sighash(&build_spend_internal(network, base, SpendPath::Refund)?)
}

fn verify_signature(
    signature: &[u8; 64],
    sighash: &[u8; 32],
    pubkey: &[u8; 32],
    label: &'static str,
) -> Result<()> {
    let signature = Signature::from_slice(signature).map_err(|_| Error::Verification(label))?;
    let pubkey = parse_xonly(pubkey, label)?;
    let message = Message::from_digest(*sighash);
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &pubkey)
        .map_err(|_| Error::Verification(label))
}

fn build_signed_spend(
    network: &str,
    base: &SafeSpendBase,
    path: SpendPath,
    alice_signature: &[u8; 64],
    bob_signature: &[u8; 64],
) -> Result<Vec<u8>> {
    let prepared = build_spend_internal(network, base, path)?;
    let sighash = spend_sighash(&prepared)?;
    let PreparedSpend {
        mut tx,
        script,
        spend_info,
        ..
    } = prepared;
    let (alice_key, bob_key) = match path {
        SpendPath::Claim => (
            &base.contract.alice_claim_pubkey,
            &base.contract.bob_claim_pubkey,
        ),
        SpendPath::Refund => (
            &base.contract.alice_refund_pubkey,
            &base.contract.bob_refund_pubkey,
        ),
    };
    verify_signature(
        alice_signature,
        &sighash,
        alice_key,
        "Alice signature does not verify for the selected swap path",
    )?;
    verify_signature(
        bob_signature,
        &sighash,
        bob_key,
        "Bob signature does not verify for the selected swap path",
    )?;
    let control_block = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or(Error::Verification("Taproot control block lookup failed"))?;

    // Script evaluates Alice's key first. The top stack element must therefore
    // be Alice's signature, so Bob's signature is pushed first.
    let mut witness = Witness::new();
    witness.push(bob_signature);
    witness.push(alice_signature);
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());
    tx.input[0].witness = witness;
    Ok(bitcoin::consensus::serialize(&tx))
}

/// Assemble a success-path spend from Alice's ordinary signature and Bob's
/// adaptor-decrypted final signature.
pub fn build_safe_claim_tx(
    network: &str,
    base: &SafeSpendBase,
    alice_signature: &[u8; 64],
    bob_adapted_signature: &[u8; 64],
) -> Result<Vec<u8>> {
    build_signed_spend(
        network,
        base,
        SpendPath::Claim,
        alice_signature,
        bob_adapted_signature,
    )
}

/// Assemble a refund-path spend from Alice's adaptor-decrypted final signature
/// and Bob's ordinary signature.
pub fn build_safe_refund_tx(
    network: &str,
    base: &SafeSpendBase,
    alice_adapted_signature: &[u8; 64],
    bob_signature: &[u8; 64],
) -> Result<Vec<u8>> {
    build_signed_spend(
        network,
        base,
        SpendPath::Refund,
        alice_adapted_signature,
        bob_signature,
    )
}

fn signed_spend_signatures(tx_bytes: &[u8]) -> Result<([u8; 64], [u8; 64])> {
    if tx_bytes.is_empty() || tx_bytes.len() > MAX_SPEND_TX_BYTES {
        return Err(Error::Verification(
            "signed Bitcoin spend transaction length is invalid",
        ));
    }
    let tx: Transaction = bitcoin::consensus::deserialize(tx_bytes)
        .map_err(|_| Error::Verification("signed Bitcoin spend transaction decode failed"))?;
    if tx.input.len() != 1 || tx.input[0].witness.len() != 4 {
        return Err(Error::Verification(
            "safe Bitcoin spend must have one input and a four-element script-path witness",
        ));
    }
    let mut witness = tx.input[0].witness.iter();
    let bob_bytes = witness.next().ok_or(Error::Verification(
        "safe Bitcoin spend is missing Bob's signature",
    ))?;
    let alice_bytes = witness.next().ok_or(Error::Verification(
        "safe Bitcoin spend is missing Alice's signature",
    ))?;
    if alice_bytes.len() != 64 || bob_bytes.len() != 64 {
        return Err(Error::Verification(
            "safe Bitcoin spend signatures must use 64-byte SIGHASH_DEFAULT encoding",
        ));
    }
    let mut alice_signature = [0u8; 64];
    alice_signature.copy_from_slice(alice_bytes);
    let mut bob_signature = [0u8; 64];
    bob_signature.copy_from_slice(bob_bytes);
    Ok((alice_signature, bob_signature))
}

/// Verify that a signed Bitcoin claim is byte-for-byte the success spend
/// committed by the pre-CYNC evidence. The returned capability also proves
/// that Bob's final witness signature revealed Alice's committed CYNC share.
pub fn verify_safe_claim_transaction(
    evidence: &PreCyncLockSafetyEvidence,
    swap: &Swap,
    tx_bytes: &[u8],
) -> Result<VerifiedShareReveal> {
    let (alice_signature, bob_signature) = signed_spend_signatures(tx_bytes)?;
    let (base, _, _, _) = reveal_context(evidence, swap, SpendPath::Claim)?;
    let expected = build_safe_claim_tx(
        &evidence.btc_network,
        &base,
        &alice_signature,
        &bob_signature,
    )?;
    if expected != tx_bytes {
        return Err(Error::Verification(
            "signed Bitcoin claim does not match the safety evidence",
        ));
    }
    verify_claim_share_reveal(evidence, swap, &bob_signature)
}

/// Verify that a signed Bitcoin refund is byte-for-byte the CSV refund spend
/// committed by the pre-CYNC evidence. The returned capability also proves
/// that Alice's final witness signature revealed Bob's committed CYNC share.
pub fn verify_safe_refund_transaction(
    evidence: &PreCyncLockSafetyEvidence,
    swap: &Swap,
    tx_bytes: &[u8],
) -> Result<VerifiedShareReveal> {
    let (alice_signature, bob_signature) = signed_spend_signatures(tx_bytes)?;
    let (base, _, _, _) = reveal_context(evidence, swap, SpendPath::Refund)?;
    let expected = build_safe_refund_tx(
        &evidence.btc_network,
        &base,
        &alice_signature,
        &bob_signature,
    )?;
    if expected != tx_bytes {
        return Err(Error::Verification(
            "signed Bitcoin refund does not match the safety evidence",
        ));
    }
    verify_refund_share_reveal(evidence, swap, &alice_signature)
}

fn parse_hex_array<const N: usize>(value: &str, label: &'static str) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err(Error::Verification(label));
    }
    let mut bytes = [0u8; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| Error::Verification(label))?;
    Ok(bytes)
}

fn parse_adaptor(evidence: &AdaptorPreSignatureEvidence) -> Result<BtcAdaptorSig> {
    let r_bytes = parse_hex_array::<33>(
        &evidence.r_point_hex,
        "adaptor r_point must be 33-byte compressed point hex",
    )?;
    let r_point = PublicKey::from_slice(&r_bytes)
        .map_err(|_| Error::Verification("adaptor r_point is invalid"))?;
    let s_pre = parse_hex_array::<32>(
        &evidence.s_pre_hex,
        "adaptor s_pre must be 32-byte scalar hex",
    )?;
    Ok(BtcAdaptorSig { r_point, s_pre })
}

fn verify_share_binding(evidence: &ShareBindingEvidence) -> Result<([u8; 33], [u8; 32])> {
    let btc_point = parse_hex_array::<33>(
        &evidence.btc_adaptor_point_hex,
        "share BTC adaptor point must be 33-byte compressed point hex",
    )?;
    let cync_point = parse_hex_array::<32>(
        &evidence.cync_spend_share_hex,
        "share CYNC point must be 32-byte compressed point hex",
    )?;
    if evidence.strict_dleq_proof_hex.len() != CrossCurveDlProofStrict::CANONICAL_LEN * 2 {
        return Err(Error::Verification(
            "strict-DLEQ proof hex has wrong canonical length",
        ));
    }
    let proof_bytes = hex::decode(&evidence.strict_dleq_proof_hex)
        .map_err(|_| Error::Verification("strict-DLEQ proof is not valid hex"))?;
    let proof = CrossCurveDlProofStrict::from_canonical_bytes(&proof_bytes)?;
    verify_cross_curve_strict(&proof, &btc_point, &cync_point)?;
    Ok((btc_point, cync_point))
}

fn decode_lock_transaction(value: &str) -> Result<Transaction> {
    if value.len() % 2 != 0 || value.len() > MAX_LOCK_TX_BYTES * 2 {
        return Err(Error::Verification(
            "Bitcoin lock transaction hex length is invalid",
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|_| Error::Verification("Bitcoin lock transaction is not valid hex"))?;
    if bytes.is_empty() {
        return Err(Error::Verification("Bitcoin lock transaction is empty"));
    }
    bitcoin::consensus::deserialize(&bytes)
        .map_err(|_| Error::Verification("Bitcoin lock transaction decode failed"))
}

/// Verify all conditions that must hold before Alice locks CYNC.
pub fn verify_pre_cync_lock(
    evidence: &PreCyncLockSafetyEvidence,
    swap: &Swap,
) -> Result<VerifiedPreCyncLock> {
    if evidence.version != EVIDENCE_VERSION {
        return Err(Error::Verification(
            "unsupported pre-CYNC safety evidence version",
        ));
    }
    if evidence.swap_id != swap.id {
        return Err(Error::Verification(
            "safety evidence belongs to a different swap",
        ));
    }
    if evidence.btc_network != swap.parameters.btc_network {
        return Err(Error::Verification(
            "safety evidence Bitcoin network mismatch",
        ));
    }
    parse_network(&evidence.btc_network)?;
    if evidence.cync_amount_atomic != swap.parameters.cync_amount {
        return Err(Error::Verification("safety evidence CYNC amount mismatch"));
    }
    if swap.parameters.btc_timeout_blocks > u32::from(u16::MAX)
        || u32::from(evidence.contract.refund_csv_blocks) != swap.parameters.btc_timeout_blocks
    {
        return Err(Error::Verification(
            "Bitcoin refund CSV does not match swap parameters",
        ));
    }
    validate_contract(&evidence.contract)?;

    let lock_tx = decode_lock_transaction(&evidence.lock_tx_hex)?;
    let lock_output = lock_tx
        .output
        .get(evidence.lock_vout as usize)
        .ok_or(Error::Verification("Bitcoin lock vout does not exist"))?;
    if lock_output.value.to_sat() != swap.parameters.btc_amount_sats {
        return Err(Error::Verification("Bitcoin lock amount mismatch"));
    }
    if lock_output.script_pubkey != safe_lock_script_pubkey(&evidence.contract)? {
        return Err(Error::Verification(
            "Bitcoin lock output is not the required two-leaf share-reveal contract",
        ));
    }
    let lock_txid = lock_tx.compute_txid().to_string();
    let claim_base = SafeSpendBase {
        lock_txid: lock_txid.clone(),
        lock_vout: evidence.lock_vout,
        lock_value_sats: lock_output.value.to_sat(),
        contract: evidence.contract.clone(),
        dest_address: evidence.claim_destination.clone(),
        fee_sats: evidence.claim_fee_sats,
    };
    let refund_base = SafeSpendBase {
        lock_txid: lock_txid.clone(),
        lock_vout: evidence.lock_vout,
        lock_value_sats: lock_output.value.to_sat(),
        contract: evidence.contract.clone(),
        dest_address: evidence.refund_destination.clone(),
        fee_sats: evidence.refund_fee_sats,
    };
    let claim_hash = safe_claim_sighash(&evidence.btc_network, &claim_base)?;
    let refund_hash = safe_refund_sighash(&evidence.btc_network, &refund_base)?;

    let (alice_btc_point, alice_cync_share) = verify_share_binding(&evidence.alice_share)?;
    let (bob_btc_point, bob_cync_share) = verify_share_binding(&evidence.bob_share)?;
    let alice_adaptor_point = PublicKey::from_slice(&alice_btc_point)
        .map_err(|_| Error::Verification("Alice BTC adaptor point is invalid"))?;
    let bob_adaptor_point = PublicKey::from_slice(&bob_btc_point)
        .map_err(|_| Error::Verification("Bob BTC adaptor point is invalid"))?;
    let bob_claim_key = parse_xonly(
        &evidence.contract.bob_claim_pubkey,
        "bob_claim_pubkey is invalid",
    )?;
    verify_pre_sig(
        &parse_adaptor(&evidence.claim_adaptor)?,
        &bob_claim_key,
        &alice_adaptor_point,
        &claim_hash,
    )
    .map_err(|_| Error::Verification("claim adaptor pre-signature verification failed"))?;
    let alice_refund_key = parse_xonly(
        &evidence.contract.alice_refund_pubkey,
        "alice_refund_pubkey is invalid",
    )?;
    verify_pre_sig(
        &parse_adaptor(&evidence.refund_adaptor)?,
        &alice_refund_key,
        &bob_adaptor_point,
        &refund_hash,
    )
    .map_err(|_| Error::Verification("refund adaptor pre-signature verification failed"))?;

    let shared_view_public = parse_hex_array::<32>(
        &evidence.shared_view_public_hex,
        "shared CYNC view public key must be 32-byte point hex",
    )?;
    let recipient = compute_swap_lock_recipient(
        &alice_cync_share,
        &bob_cync_share,
        &shared_view_public,
        evidence.cync_amount_atomic,
    )?;
    let canonical_evidence = serde_json::to_vec(evidence)
        .map_err(|_| Error::Verification("safety evidence serialization failed"))?;
    let fingerprint = Sha256::digest(canonical_evidence).into();

    Ok(VerifiedPreCyncLock {
        swap_id: swap.id.clone(),
        fingerprint,
        lock_txid,
        lock_vout: evidence.lock_vout,
        recipient,
    })
}

fn reveal_context(
    evidence: &PreCyncLockSafetyEvidence,
    swap: &Swap,
    path: SpendPath,
) -> Result<(SafeSpendBase, [u8; 33], [u8; 32], BtcAdaptorSig)> {
    verify_pre_cync_lock(evidence, swap)?;
    let lock_tx = decode_lock_transaction(&evidence.lock_tx_hex)?;
    let lock_output = lock_tx
        .output
        .get(evidence.lock_vout as usize)
        .ok_or(Error::Verification("Bitcoin lock vout does not exist"))?;
    let (destination, fee, share, adaptor) = match path {
        SpendPath::Claim => (
            &evidence.claim_destination,
            evidence.claim_fee_sats,
            &evidence.alice_share,
            &evidence.claim_adaptor,
        ),
        SpendPath::Refund => (
            &evidence.refund_destination,
            evidence.refund_fee_sats,
            &evidence.bob_share,
            &evidence.refund_adaptor,
        ),
    };
    let (btc_point, cync_point) = verify_share_binding(share)?;
    Ok((
        SafeSpendBase {
            lock_txid: lock_tx.compute_txid().to_string(),
            lock_vout: evidence.lock_vout,
            lock_value_sats: lock_output.value.to_sat(),
            contract: evidence.contract.clone(),
            dest_address: destination.clone(),
            fee_sats: fee,
        },
        btc_point,
        cync_point,
        parse_adaptor(adaptor)?,
    ))
}

fn verify_recovered_share(
    recovered: &AdaptorSecret,
    expected_btc: &[u8; 33],
    expected_cync: &[u8; 32],
) -> Result<()> {
    let secp = Secp256k1::new();
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&recovered.secp256k1_bytes())
        .map_err(|_| Error::Verification("recovered share is not a secp256k1 scalar"))?;
    let recovered_btc = PublicKey::from_secret_key(&secp, &secret).serialize();
    let recovered_cync = cync_adaptor_point(recovered)?;
    if &recovered_btc != expected_btc || &recovered_cync != expected_cync {
        return Err(Error::Verification(
            "final Bitcoin signature revealed a different CYNC share",
        ));
    }
    Ok(())
}

/// Verify Alice's final Bitcoin claim signature and recover the exact share
/// Bob needs to sweep the joint CYNC output.
pub fn verify_claim_share_reveal(
    evidence: &PreCyncLockSafetyEvidence,
    swap: &Swap,
    final_signature: &[u8; 64],
) -> Result<VerifiedShareReveal> {
    let (base, expected_btc, expected_cync, adaptor) =
        reveal_context(evidence, swap, SpendPath::Claim)?;
    let sighash = safe_claim_sighash(&evidence.btc_network, &base)?;
    verify_signature(
        final_signature,
        &sighash,
        &evidence.contract.bob_claim_pubkey,
        "final Bitcoin claim signature is invalid",
    )?;
    let recovered = recover_secret_from_btc_sig(&adaptor, final_signature)?;
    verify_recovered_share(&recovered, &expected_btc, &expected_cync)?;
    Ok(VerifiedShareReveal {
        swap_id: swap.id.clone(),
        party: RevealedParty::Alice,
        secret: recovered.ristretto_bytes(),
    })
}

/// Verify Bob's final Bitcoin refund signature and recover the exact share
/// Alice needs to recover the joint CYNC output.
pub fn verify_refund_share_reveal(
    evidence: &PreCyncLockSafetyEvidence,
    swap: &Swap,
    final_signature: &[u8; 64],
) -> Result<VerifiedShareReveal> {
    let (base, expected_btc, expected_cync, adaptor) =
        reveal_context(evidence, swap, SpendPath::Refund)?;
    let sighash = safe_refund_sighash(&evidence.btc_network, &base)?;
    verify_signature(
        final_signature,
        &sighash,
        &evidence.contract.alice_refund_pubkey,
        "final Bitcoin refund signature is invalid",
    )?;
    let recovered = recover_secret_from_btc_sig(&adaptor, final_signature)?;
    verify_recovered_share(&recovered, &expected_btc, &expected_cync)?;
    Ok(VerifiedShareReveal {
        swap_id: swap.id.clone(),
        party: RevealedParty::Bob,
        secret: recovered.ristretto_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptor::{
        create_pre_sig_bip340, cync_adaptor_point, decrypt_btc_adaptor, AdaptorSecret,
    };
    use crate::cync::public_share_from_secret;
    use crate::protocol::{Role, State, SwapParameters, Transition};
    use crate::strict_dleq::prove_cross_curve_strict;
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use curve25519_dalek::scalar::Scalar;

    struct Fixture {
        evidence: PreCyncLockSafetyEvidence,
        swap: Swap,
        claim_base: SafeSpendBase,
        refund_base: SafeSpendBase,
        alice_claim_secret: SecretKey,
        bob_refund_secret: SecretKey,
        alice_share_secret: AdaptorSecret,
        bob_share_secret: AdaptorSecret,
        claim_adaptor: BtcAdaptorSig,
        refund_adaptor: BtcAdaptorSig,
    }

    fn secret(value: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        SecretKey::from_slice(&bytes).unwrap()
    }

    fn xonly(secp: &Secp256k1<bitcoin::secp256k1::All>, secret: &SecretKey) -> [u8; 32] {
        let keypair = Keypair::from_secret_key(secp, secret);
        keypair.x_only_public_key().0.serialize()
    }

    fn share_binding(value: u64, seed_byte: u8) -> (AdaptorSecret, ShareBindingEvidence) {
        let scalar = Scalar::from(value).to_bytes();
        let secret = AdaptorSecret::from_ristretto_bytes(scalar).unwrap();
        let secp = Secp256k1::new();
        let btc_secret = SecretKey::from_slice(&secret.secp256k1_bytes()).unwrap();
        let btc_point = PublicKey::from_secret_key(&secp, &btc_secret).serialize();
        let cync_point = cync_adaptor_point(&secret).unwrap();
        let proof =
            prove_cross_curve_strict(&secret, &btc_point, &cync_point, &[seed_byte; 32]).unwrap();
        (
            secret,
            ShareBindingEvidence {
                btc_adaptor_point_hex: hex::encode(btc_point),
                cync_spend_share_hex: hex::encode(cync_point),
                strict_dleq_proof_hex: hex::encode(proof.canonical_bytes()),
            },
        )
    }

    fn fixture() -> Fixture {
        let secp = Secp256k1::new();
        let alice_claim_secret = secret(11);
        let bob_claim_secret = secret(13);
        let alice_refund_secret = secret(17);
        let bob_refund_secret = secret(19);
        let contract = SwapTaprootContract {
            alice_claim_pubkey: xonly(&secp, &alice_claim_secret),
            bob_claim_pubkey: xonly(&secp, &bob_claim_secret),
            alice_refund_pubkey: xonly(&secp, &alice_refund_secret),
            bob_refund_pubkey: xonly(&secp, &bob_refund_secret),
            refund_csv_blocks: 100,
        };
        let change_address = Address::p2tr(
            &secp,
            XOnlyPublicKey::from_slice(&xonly(&secp, &bob_refund_secret)).unwrap(),
            None,
            Network::Regtest,
        )
        .to_string();
        let claim_destination = Address::p2tr(
            &secp,
            XOnlyPublicKey::from_slice(&xonly(&secp, &alice_claim_secret)).unwrap(),
            None,
            Network::Regtest,
        )
        .to_string();
        let refund_destination = Address::p2tr(
            &secp,
            XOnlyPublicKey::from_slice(&xonly(&secp, &bob_refund_secret)).unwrap(),
            None,
            Network::Regtest,
        )
        .to_string();
        let lock_tx = build_safe_lock_tx(
            "regtest",
            &SafeLockTxRequest {
                utxos: vec![FundingUtxo {
                    txid: crate::btc::Txid([7u8; 32]),
                    vout: 1,
                    value_sats: 1_100_000,
                }],
                lock_amount_sats: 1_000_000,
                contract: contract.clone(),
                change_address,
                fee_sats: 1_000,
                locktime: 0,
            },
        )
        .unwrap();
        let lock: Transaction = bitcoin::consensus::deserialize(&lock_tx).unwrap();
        let lock_txid = lock.compute_txid().to_string();
        let claim_base = SafeSpendBase {
            lock_txid: lock_txid.clone(),
            lock_vout: 0,
            lock_value_sats: 1_000_000,
            contract: contract.clone(),
            dest_address: claim_destination.clone(),
            fee_sats: 2_000,
        };
        let refund_base = SafeSpendBase {
            lock_txid,
            lock_vout: 0,
            lock_value_sats: 1_000_000,
            contract: contract.clone(),
            dest_address: refund_destination.clone(),
            fee_sats: 2_500,
        };
        let (alice_share_secret, alice_share) = share_binding(23, 0xA1);
        let (bob_share_secret, bob_share) = share_binding(29, 0xB2);
        let alice_adaptor_point =
            PublicKey::from_slice(&hex::decode(&alice_share.btc_adaptor_point_hex).unwrap())
                .unwrap();
        let bob_adaptor_point =
            PublicKey::from_slice(&hex::decode(&bob_share.btc_adaptor_point_hex).unwrap()).unwrap();
        let claim_hash = safe_claim_sighash("regtest", &claim_base).unwrap();
        let refund_hash = safe_refund_sighash("regtest", &refund_base).unwrap();
        let (claim_adaptor, _) = create_pre_sig_bip340(
            &bob_claim_secret,
            &claim_hash,
            &alice_adaptor_point,
            &[0x31; 32],
        )
        .unwrap();
        let (refund_adaptor, _) = create_pre_sig_bip340(
            &alice_refund_secret,
            &refund_hash,
            &bob_adaptor_point,
            &[0x42; 32],
        )
        .unwrap();
        let view_secret = Scalar::from(37u64).to_bytes();
        let shared_view_public = public_share_from_secret(&view_secret).unwrap();
        let evidence = PreCyncLockSafetyEvidence {
            version: PreCyncLockSafetyEvidence::VERSION,
            swap_id: "safe-swap".into(),
            btc_network: "regtest".into(),
            lock_tx_hex: hex::encode(&lock_tx),
            lock_vout: 0,
            contract,
            claim_destination,
            claim_fee_sats: 2_000,
            refund_destination,
            refund_fee_sats: 2_500,
            alice_share,
            bob_share,
            claim_adaptor: AdaptorPreSignatureEvidence {
                r_point_hex: hex::encode(claim_adaptor.r_point.serialize()),
                s_pre_hex: hex::encode(claim_adaptor.s_pre),
            },
            refund_adaptor: AdaptorPreSignatureEvidence {
                r_point_hex: hex::encode(refund_adaptor.r_point.serialize()),
                s_pre_hex: hex::encode(refund_adaptor.s_pre),
            },
            shared_view_public_hex: hex::encode(shared_view_public),
            cync_amount_atomic: 50_000_000,
        };
        let mut swap = Swap::negotiate(
            "safe-swap".into(),
            Role::Alice,
            SwapParameters {
                cync_amount: 50_000_000,
                btc_amount_sats: 1_000_000,
                cync_timeout_blocks: 720,
                btc_timeout_blocks: 100,
                alice_cync_address: "alice".into(),
                bob_btc_address: "bob".into(),
                cync_network: "regtest".into(),
                btc_network: "regtest".into(),
            },
        )
        .unwrap();
        swap.state = State::BobLocked;
        Fixture {
            evidence,
            swap,
            claim_base,
            refund_base,
            alice_claim_secret,
            bob_refund_secret,
            alice_share_secret,
            bob_share_secret,
            claim_adaptor,
            refund_adaptor,
        }
    }

    #[test]
    fn gate_verifies_both_paths_and_advances_only_with_capability() {
        let mut fixture = fixture();
        assert!(fixture.swap.apply(Transition::AliceLocksCync).is_err());
        let verified = verify_pre_cync_lock(&fixture.evidence, &fixture.swap).unwrap();
        assert_eq!(verified.lock_vout(), 0);
        assert_eq!(verified.cync_recipient().amount_atomic, 50_000_000);
        fixture.swap.apply_pre_cync_lock(&verified).unwrap();
        assert_eq!(fixture.swap.state, State::AliceLocked);

        let mut other_swap = Swap::negotiate(
            "different-swap".into(),
            Role::Alice,
            fixture.swap.parameters.clone(),
        )
        .unwrap();
        other_swap.state = State::BobLocked;
        assert!(other_swap.apply_pre_cync_lock(&verified).is_err());
        assert_eq!(other_swap.state, State::BobLocked);
    }

    #[test]
    fn final_claim_and_refund_use_two_signatures_and_script_paths() {
        let fixture = fixture();
        let secp = Secp256k1::new();

        let claim_hash = safe_claim_sighash("regtest", &fixture.claim_base).unwrap();
        let claim_message = Message::from_digest(claim_hash);
        let alice_claim_sig = secp.sign_schnorr_no_aux_rand(
            &claim_message,
            &Keypair::from_secret_key(&secp, &fixture.alice_claim_secret),
        );
        let alice_adaptor_point = PublicKey::from_slice(
            &hex::decode(&fixture.evidence.alice_share.btc_adaptor_point_hex).unwrap(),
        )
        .unwrap();
        let bob_adapted = decrypt_btc_adaptor(
            &fixture.claim_adaptor,
            &fixture.alice_share_secret,
            &alice_adaptor_point,
        )
        .unwrap();
        let claim = build_safe_claim_tx(
            "regtest",
            &fixture.claim_base,
            &alice_claim_sig.serialize(),
            &bob_adapted,
        )
        .unwrap();
        let verified_claim =
            verify_safe_claim_transaction(&fixture.evidence, &fixture.swap, &claim).unwrap();
        assert_eq!(
            verified_claim.cync_secret_share(),
            fixture.alice_share_secret.ristretto_bytes()
        );
        let parsed_claim: Transaction = bitcoin::consensus::deserialize(&claim).unwrap();
        assert_eq!(parsed_claim.input[0].witness.len(), 4);
        let claim_reveal =
            verify_claim_share_reveal(&fixture.evidence, &fixture.swap, &bob_adapted).unwrap();
        let mut tampered_claim = bob_adapted;
        tampered_claim[63] ^= 1;
        assert!(
            verify_claim_share_reveal(&fixture.evidence, &fixture.swap, &tampered_claim,).is_err()
        );
        assert_eq!(
            claim_reveal.cync_secret_share(),
            fixture.alice_share_secret.ristretto_bytes()
        );
        let mut bob_swap = Swap::negotiate(
            fixture.swap.id.clone(),
            Role::Bob,
            fixture.swap.parameters.clone(),
        )
        .unwrap();
        bob_swap.state = State::AliceLocked;
        assert!(bob_swap.apply(Transition::ObserveSecretRevealed).is_err());
        bob_swap.apply_verified_claim_reveal(&claim_reveal).unwrap();
        assert_eq!(bob_swap.state, State::SecretRevealed);

        let refund_hash = safe_refund_sighash("regtest", &fixture.refund_base).unwrap();
        let refund_message = Message::from_digest(refund_hash);
        let bob_refund_sig = secp.sign_schnorr_no_aux_rand(
            &refund_message,
            &Keypair::from_secret_key(&secp, &fixture.bob_refund_secret),
        );
        let bob_adaptor_point = PublicKey::from_slice(
            &hex::decode(&fixture.evidence.bob_share.btc_adaptor_point_hex).unwrap(),
        )
        .unwrap();
        let alice_adapted = decrypt_btc_adaptor(
            &fixture.refund_adaptor,
            &fixture.bob_share_secret,
            &bob_adaptor_point,
        )
        .unwrap();
        let refund = build_safe_refund_tx(
            "regtest",
            &fixture.refund_base,
            &alice_adapted,
            &bob_refund_sig.serialize(),
        )
        .unwrap();
        let verified_refund =
            verify_safe_refund_transaction(&fixture.evidence, &fixture.swap, &refund).unwrap();
        assert_eq!(
            verified_refund.cync_secret_share(),
            fixture.bob_share_secret.ristretto_bytes()
        );
        let parsed_refund: Transaction = bitcoin::consensus::deserialize(&refund).unwrap();
        assert_eq!(parsed_refund.input[0].witness.len(), 4);
        assert_eq!(
            parsed_refund.input[0].sequence,
            Sequence::from_height(fixture.evidence.contract.refund_csv_blocks)
        );
        let refund_reveal =
            verify_refund_share_reveal(&fixture.evidence, &fixture.swap, &alice_adapted).unwrap();
        let mut tampered_refund = alice_adapted;
        tampered_refund[63] ^= 1;
        assert!(
            verify_refund_share_reveal(&fixture.evidence, &fixture.swap, &tampered_refund,)
                .is_err()
        );
        assert_eq!(
            refund_reveal.cync_secret_share(),
            fixture.bob_share_secret.ristretto_bytes()
        );
        let mut alice_swap = fixture.swap.clone();
        alice_swap.state = State::AliceLocked;
        assert!(alice_swap.apply(Transition::ObserveBtcRefunded).is_err());
        alice_swap
            .apply_verified_refund_reveal(&refund_reveal)
            .unwrap();
        assert_eq!(alice_swap.state, State::BtcRefunded);

        let mut alice_before_cync_lock = fixture.swap.clone();
        assert_eq!(alice_before_cync_lock.state, State::BobLocked);
        alice_before_cync_lock
            .apply_verified_refund_reveal(&refund_reveal)
            .unwrap();
        assert_eq!(alice_before_cync_lock.state, State::Refunded);

        let mut changed_claim: Transaction = bitcoin::consensus::deserialize(&claim).unwrap();
        changed_claim.output[0].value =
            Amount::from_sat(changed_claim.output[0].value.to_sat() - 1);
        let changed_claim = bitcoin::consensus::serialize(&changed_claim);
        assert!(
            verify_safe_claim_transaction(&fixture.evidence, &fixture.swap, &changed_claim,)
                .is_err()
        );

        let mut changed_refund: Transaction = bitcoin::consensus::deserialize(&refund).unwrap();
        changed_refund.input[0].sequence = Sequence::ZERO;
        let changed_refund = bitcoin::consensus::serialize(&changed_refund);
        assert!(
            verify_safe_refund_transaction(&fixture.evidence, &fixture.swap, &changed_refund,)
                .is_err()
        );
    }

    #[test]
    fn gate_rejects_tampered_lock_spend_or_share_evidence() {
        let fixture = fixture();

        let mut wrong_lock = fixture.evidence.clone();
        wrong_lock.contract.alice_claim_pubkey = wrong_lock.contract.bob_claim_pubkey;
        assert!(verify_pre_cync_lock(&wrong_lock, &fixture.swap).is_err());

        let mut wrong_claim = fixture.evidence.clone();
        wrong_claim.claim_fee_sats += 1;
        assert!(verify_pre_cync_lock(&wrong_claim, &fixture.swap).is_err());

        let mut wrong_refund = fixture.evidence.clone();
        wrong_refund.refund_fee_sats += 1;
        assert!(verify_pre_cync_lock(&wrong_refund, &fixture.swap).is_err());

        let mut wrong_proof = fixture.evidence.clone();
        let replacement = if wrong_proof
            .alice_share
            .strict_dleq_proof_hex
            .starts_with('0')
        {
            "1"
        } else {
            "0"
        };
        wrong_proof
            .alice_share
            .strict_dleq_proof_hex
            .replace_range(0..1, replacement);
        assert!(verify_pre_cync_lock(&wrong_proof, &fixture.swap).is_err());
    }

    #[test]
    fn strict_proof_decoder_round_trips_canonical_bytes() {
        let fixture = fixture();
        let bytes = hex::decode(&fixture.evidence.alice_share.strict_dleq_proof_hex).unwrap();
        let decoded = CrossCurveDlProofStrict::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.canonical_bytes(), bytes);
        assert!(CrossCurveDlProofStrict::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
    }
}
