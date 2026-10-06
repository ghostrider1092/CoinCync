//! Wallet transaction integration for CYNC atomic-swap outputs.

use super::send::Payment;
use super::spend::{BuiltSpend, SpendCoordinator, SpendIntent, SpendSession};
use super::{Balance, KeyEpoch};
use crate::error::{Error, Result};
use crate::primitives::{Amount, PublicKey, SecretKey};
use coincync_swap::cync::{
    combine_spend_secret_shares, public_share_from_secret, SwapLockRecipient,
};
use coincync_swap::safety::{VerifiedPreCyncLock, VerifiedShareReveal};
use rand::{CryptoRng, RngCore};

/// Convert the negotiated joint address into the wallet's normal payment type.
fn lock_payment(recipient: &SwapLockRecipient) -> Result<Payment> {
    let spend_public = PublicKey::from_bytes_checked(recipient.spend_public_bytes)?;
    let view_public = PublicKey::from_bytes_checked(recipient.view_public_bytes)?;
    Ok(Payment::new(
        spend_public,
        view_public,
        Amount::from_atomic(recipient.amount_atomic),
    ))
}

/// Reconstruct the temporary wallet epoch that owns the joint CYNC output.
///
/// `local_spend_share` remains local for the life of the swap.
/// `revealed_spend_share` comes from the completed Bitcoin claim or refund
/// adaptor. `shared_view_secret` is negotiated before either chain is locked
/// so both parties can scan the joint output.
fn joint_key_epoch(
    epoch: u64,
    local_spend_share: &[u8; 32],
    revealed_spend_share: &[u8; 32],
    shared_view_secret: &[u8; 32],
) -> Result<KeyEpoch> {
    let spend_secret_bytes =
        combine_spend_secret_shares(local_spend_share, revealed_spend_share)
            .map_err(|error| Error::InvalidState(format!("invalid joint spend shares: {error}")))?;
    let spend_secret = SecretKey::from_bytes(spend_secret_bytes);
    let spend_public = PublicKey::from_bytes_checked(*spend_secret.public_key().as_bytes())?;

    let view_public_bytes = public_share_from_secret(shared_view_secret)
        .map_err(|error| Error::InvalidState(format!("invalid shared view secret: {error}")))?;
    let view_secret = SecretKey::from_bytes(*shared_view_secret);
    let view_public = PublicKey::from_bytes_checked(view_public_bytes)?;

    Ok(KeyEpoch {
        epoch,
        spend_secret,
        spend_public,
        view_secret,
        view_public,
    })
}

/// Reconstruct the joint CYNC wallet epoch from a Bitcoin signature whose
/// adaptor share was verified against the original safety evidence.
pub fn joint_key_epoch_from_reveal(
    epoch: u64,
    local_spend_share: &[u8; 32],
    reveal: &VerifiedShareReveal,
    shared_view_secret: &[u8; 32],
) -> Result<KeyEpoch> {
    joint_key_epoch(
        epoch,
        local_spend_share,
        &reveal.cync_secret_share(),
        shared_view_secret,
    )
}

/// Build Alice's ordinary CYNC transfer to the negotiated joint address.
///
/// The required capability is produced only after the exact Bitcoin lock,
/// claim/refund adaptor signatures, and both strict share proofs verify. The
/// wallet therefore cannot accidentally build a CYNC lock from an unchecked
/// recipient. Input selection, covered decoy lookup, CLSAG signing, and
/// serialization remain identical to an ordinary wallet transfer.
pub async fn build_lock_transaction<R>(
    coordinator: &SpendCoordinator,
    session: SpendSession,
    funding_balance: &Balance,
    funding_keys: &KeyEpoch,
    verified: &VerifiedPreCyncLock,
    rng: &mut R,
) -> Result<BuiltSpend>
where
    R: RngCore + CryptoRng,
{
    let intent = SpendIntent::new(vec![lock_payment(verified.cync_recipient())?]);
    coordinator
        .build_privacy_transaction(session, funding_balance, funding_keys, intent, rng)
        .await
}

/// Build the ordinary CYNC sweep used by either successful claim or refund.
///
/// The supplied balance must contain outputs scanned under `joint_keys`.
/// Which party owns those keys is determined solely by which Bitcoin adaptor
/// revealed the missing spend share.
pub async fn build_sweep_transaction<R>(
    coordinator: &SpendCoordinator,
    session: SpendSession,
    joint_balance: &Balance,
    joint_keys: &KeyEpoch,
    destination: Payment,
    rng: &mut R,
) -> Result<BuiltSpend>
where
    R: RngCore + CryptoRng,
{
    coordinator
        .build_privacy_transaction(
            session,
            joint_balance,
            joint_keys,
            SpendIntent::new(vec![destination]),
            rng,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use coincync_swap::cync::{
        combine_spend_public_shares, compute_swap_lock_recipient, public_share_from_secret,
    };
    use curve25519_dalek::scalar::Scalar;

    fn scalar(value: u64) -> [u8; 32] {
        Scalar::from(value).to_bytes()
    }

    #[test]
    fn lock_payment_uses_joint_spend_and_shared_view_keys() {
        let alice = scalar(11);
        let bob = scalar(29);
        let view = scalar(47);
        let recipient = compute_swap_lock_recipient(
            &public_share_from_secret(&alice).unwrap(),
            &public_share_from_secret(&bob).unwrap(),
            &public_share_from_secret(&view).unwrap(),
            50_000,
        )
        .unwrap();

        let payment = lock_payment(&recipient).unwrap();
        assert_eq!(
            payment.spend_public.as_bytes(),
            &recipient.spend_public_bytes
        );
        assert_eq!(payment.view_public.as_bytes(), &recipient.view_public_bytes);
        assert_eq!(payment.amount.as_atomic(), 50_000);
        assert!(!payment.is_subaddress);
    }

    #[test]
    fn joint_epoch_matches_the_negotiated_public_keys() {
        let alice = scalar(13);
        let bob = scalar(31);
        let view = scalar(53);
        let epoch = joint_key_epoch(7, &alice, &bob, &view).unwrap();

        let expected_spend = combine_spend_public_shares(
            &public_share_from_secret(&alice).unwrap(),
            &public_share_from_secret(&bob).unwrap(),
        )
        .unwrap();
        assert_eq!(epoch.epoch, 7);
        assert_eq!(epoch.spend_public.as_bytes(), &expected_spend);
        assert_eq!(
            epoch.view_public.as_bytes(),
            &public_share_from_secret(&view).unwrap()
        );
    }

    #[test]
    fn joint_epoch_rejects_zero_shared_view_secret() {
        let error = match joint_key_epoch(0, &scalar(1), &scalar(2), &[0u8; 32]) {
            Ok(_) => panic!("zero shared view secret must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("secret share"));
    }
}
