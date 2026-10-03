//! Snapshot-bound spend construction.
//!
//! Builds a signed, submission-ready transaction from one validated session:
//! select inputs, perform the single covered lookup, allocate rings and seal a
//! [`BuiltSpend`] — all pinned to the session's snapshot so nothing recombines
//! across snapshots and submission cannot rediscover different inputs.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `build_privacy_transaction`** — INVARIANT: consumes the session and
//!   performs exactly one covered lookup bound to that session's snapshot, so a
//!   retry must start from a fresh node snapshot and inputs cannot be
//!   recombined across snapshots. THREAT: cross-snapshot ring mixing or silent
//!   input rediscovery that deanonymizes the spender.
//!   TESTS: `covered_request_binds_snapshot_and_policy`,
//!   `covered_response_rejects_snapshot_order_and_height_mismatches`.
//! - **§2 input selection & balance (`prepare_privacy_transaction`)** —
//!   INVARIANT: the selected inputs equal payments + change + fee before any
//!   ring work, and insufficient funds error without reserving.
//!   THREAT: value creation or an unbalanced transaction.
//!   TESTS: `prepare_uniform_standard_satisfies_inputs_equal_payments_plus_change_plus_fee`,
//!   `prepare_change_below_min_still_balances_inputs_equal_payments_plus_change_plus_fee`,
//!   `prepare_insufficient_funds_errors_without_reserving`.
//! - **§3 covered lookup binding (`build_covered_request` / `validate_covered_response`)**
//!   — INVARIANT: the single lookup's request and response are pinned to the
//!   session snapshot id, policy version and height ordering, and reject a real
//!   locator outside the snapshot. THREAT: a swapped or misordered decoy set.
//!   TESTS: `covered_request_binds_snapshot_and_policy`,
//!   `covered_request_rejects_a_real_locator_outside_the_snapshot`,
//!   `covered_response_rejects_snapshot_order_and_height_mismatches`.
//! - **§4 ring allocation (`allocate_unique_rings`)** — INVARIANT: the real
//!   output sits at a secret index in every ring, matched to its real identity,
//!   with no decoy public key repeated across rings. THREAT: real-output
//!   linkage or decoy reuse that breaks unlinkability.
//!   TESTS: `allocation_places_real_member_at_the_secret_index_in_every_ring`,
//!   `allocation_uses_no_repeated_decoy_public_key_across_rings`,
//!   `allocation_rejects_real_identity_mismatch`.
//! - **§5 sealing into `BuiltSpend` (`BuiltSpend::try_new`)** — INVARIANT: the
//!   built spend seals selected outputs, key images, the canonical tx hash and
//!   encoded payload with a target height matching the snapshot, so submission
//!   cannot drift to different inputs. THREAT: build/submit input drift or a
//!   mismatched payload. TESTS: `built_spend_tx_hash_is_canonical_and_stable_across_reserialization`,
//!   `input_bindings_preserve_selected_order`.

use super::super::decoy_selection::{
    allocate_unique_rings, build_covered_request, validate_covered_response,
};
use super::super::send::{build_prepared_privacy_transaction, prepare_privacy_transaction};
use super::super::{Balance, KeyEpoch};
use super::{BuiltSpend, SpendCoordinator, SpendIntent, SpendSession};
use crate::error::Result;
use rand::{CryptoRng, RngCore};

impl SpendCoordinator {
    /// Select inputs, perform the one covered lookup and build a signed,
    /// submission-ready transaction without broadcasting it.
    ///
    /// The returned [`BuiltSpend`] captures the selected wallet outputs,
    /// generated key images, canonical transaction hash and serialized RPC
    /// payload. Submission therefore cannot silently rediscover different
    /// wallet inputs or fail local serialization after reservations are made.
    /// The session is consumed so any retry starts from a fresh node snapshot.
    pub async fn build_privacy_transaction<R>(
        &self,
        session: SpendSession,
        balance: &Balance,
        keys: &KeyEpoch,
        intent: SpendIntent,
        rng: &mut R,
    ) -> Result<BuiltSpend>
    where
        R: RngCore + CryptoRng,
    {
        let prepared = prepare_privacy_transaction(
            balance,
            intent.into_request(session.context()),
            keys,
            rng,
        )?;
        let selected_outputs = prepared.selected_output_keys();
        let real_outputs = prepared.real_outputs();
        let real_locators = real_outputs
            .iter()
            .map(|output| output.locator())
            .collect::<Vec<_>>();
        let request = build_covered_request(
            &session.snapshot,
            &real_locators,
            prepared.ring_size(),
            session.context().min_output_age(),
            rng,
        )?;
        let response = self.rpc.resolve_outputs(&request).await?;
        let response = validate_covered_response(request, response)?;
        let rings = allocate_unique_rings(response, &real_outputs, rng)?;
        let transaction = build_prepared_privacy_transaction(prepared, rings, rng)?;

        BuiltSpend::try_new(
            transaction,
            session.snapshot_id(),
            session.target_height(),
            selected_outputs,
        )
    }
}
