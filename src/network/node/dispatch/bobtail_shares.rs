//! Inbound dispatch for Bobtail proof-share gossip (feature `bobtail`,
//! **Observe-only**).
//!
//! Decodes a [`ProofShareBatch`], admits each share into a process-local,
//! parent-bound [`SharePool`] (self-managing tip changes by reading the chain
//! each call), and floods the shares that clear admission to the other connected
//! peers. It never gates block validity — the pool exists so the Observe
//! telemetry (`SharePool::observe` / `view_divergence`) runs on real gossiped
//! shares. It is dormant until [`bobtail::bobtail_observe_active_at`] (fail-closed
//! at `u64::MAX` until a rollout height is set), so a feature build with no
//! Observe height does nothing here.
//!
//! **INTERIM share hash.** Each share's RandomX hash is computed with the
//! existing public [`compute_pow_hash`] as `RandomX(prev_hash ‖ nonce ‖ pubkey)`
//! at the next block's epoch — a well-defined invocation that touches no
//! hash-locked file. The domain-separated share preimage (`bobtail-spec.md` §2 +
//! the share-domain-tag hardening item) is a pre-Enforce consensus decision and
//! replaces this at the Enforce fork.

use crate::consensus::bobtail::{self, Admit, ProofShareBatch, ShareProof, SharePool};
use crate::consensus::{compute_pow_hash, PowAlgorithm};
use crate::network::peer::PeerId;
use crate::network::protocol::Message;
use crate::primitives::Hash;
use dashmap::DashMap;
use tokio::sync::mpsc;

/// Process-local Observe share pool (one node per process). `None` until the
/// first admitted batch, then bound to the current tip.
static POOL: std::sync::Mutex<Option<SharePool>> = std::sync::Mutex::new(None);

/// Handle an inbound `ProofShares` message: admit + relay. Best-effort and
/// side-effect-only (never fails the dispatch loop); malformed input is dropped.
pub(super) async fn handle_proof_shares(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    chain: &crate::chain::SharedBlockchain,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
) {
    let height = chain.height();
    // Fail-closed: inert until the Observe height is reached.
    if !bobtail::bobtail_observe_active_at(height) {
        return;
    }

    let batch: ProofShareBatch = match borsh::from_slice(payload) {
        Ok(b) => b,
        Err(_) => return, // malformed — drop
    };
    if !batch.is_well_formed() {
        return; // empty or oversize — drop
    }

    let tip = chain.tip_hash();
    let target = chain.next_target();
    let tau = bobtail::tau_share_target(&target, bobtail::BOBTAIL_K, bobtail::BOBTAIL_C_SHARE);
    let epoch_height = height.saturating_add(1); // the share's block height (RandomX epoch)

    // Resolve each share's hash via the existing RandomX path (interim §2).
    let hasher = |s: &ShareProof, prev: &Hash| -> Hash {
        let pk = Hash::from_bytes(*s.miner_pubkey.as_bytes());
        compute_pow_hash(PowAlgorithm::RandomX, prev, s.nonce, &pk, epoch_height)
            .unwrap_or_else(|_| Hash::from_bytes([0xFF; 32])) // un-hashable → worst (never admitted)
    };

    // Admit under the lock, collecting the shares to relay. The guard is dropped
    // before any `.await` so no lock is held across the network send.
    let to_relay: Vec<ShareProof> = {
        let mut guard = POOL.lock().unwrap_or_else(|e| e.into_inner());
        let pool = guard.get_or_insert_with(|| {
            SharePool::new(tip, bobtail::BOBTAIL_K, bobtail::BOBTAIL_C_SHARE)
        });
        pool.on_tip_change(tip); // shares are parent-bound; reset if the tip moved
        let verdicts = pool.admit_batch(&batch, &tau, hasher);
        batch
            .shares
            .iter()
            .zip(verdicts)
            .filter_map(|(s, v)| matches!(v, Admit::Accepted { relay: true }).then(|| s.clone()))
            .collect()
    };

    if to_relay.is_empty() {
        return;
    }

    // Flood the admitted shares to the other connected peers. Each node's
    // admission dedups (Duplicate verdict), so loops terminate.
    let relay_batch = ProofShareBatch {
        prev_hash: tip,
        shares: to_relay,
    };
    let Ok(msg) = Message::proof_shares(magic, &relay_batch) else {
        return;
    };
    let Ok(data) = msg.to_bytes() else {
        return;
    };
    let targets: Vec<mpsc::Sender<Vec<u8>>> = senders
        .iter()
        .filter(|e| *e.key() != peer_id)
        .map(|e| e.value().clone())
        .collect();
    for sender in targets {
        let _ = sender.send(data.clone()).await;
    }
}
