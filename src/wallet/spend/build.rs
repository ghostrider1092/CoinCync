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
