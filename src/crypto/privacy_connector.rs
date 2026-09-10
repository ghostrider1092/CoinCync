//! # Privacy-Scheme Connector — the single guarded boundary
//!
//! CoinCync's consensus chain is RingCT/CLSAG. Lelantus Spark and MimbleWimble
//! cut-through are *alternative* privacy schemes that are NOT part of that chain
//! (feature-gated, no transaction type). This module is the ONE place that
//! connects those schemes to chain state, so the whole integration has a single
//! auditable surface with every safety gate centralized here.
//!
//! ## Safety model (fail-closed, inert by default)
//!
//! Nothing here does anything unless it passes [`ConnectorGate::check`], which
//! refuses by default:
//!   1. **Kill switch** — a runtime flag disables every operation instantly.
//!   2. **Mainnet audit gate** — on mainnet the connector refuses unless
//!      [`CONNECTOR_AUDITED`] is `true`. It ships `false`: the hand-rolled ZK in
//!      Spark (dual-base tag binding) and MW (excess signature) has NOT had
//!      external cryptographic review, so it must never gate real mainnet value.
//!   3. **Activation height** — `None` means permanently inert; a `Some(h)`
//!      only activates at/after height `h` (so a mainnet turn-on is a scheduled,
//!      reviewed hard fork, never an accident).
//!   4. **Feature availability** — a scheme whose crate feature isn't compiled
//!      is unavailable.
//!   5. **Rate limit** — a per-block operation cap bounds blast radius.
//!
//! The cross-scheme **value converter** ([`convert_value`]) is additionally
//! hard-disabled behind [`CONNECTOR_AUDITED`]; it enforces value conservation so
//! the anti-inflation property is already in place for the day it is activated,
//! but it returns an error while unaudited so it cannot mint or burn value.
//!
//! Every entry point returns `Result` and fails closed — any error, missing
//! gate, or verification failure rejects.

use crate::config::NetworkType;
use crate::error::{Error, Result};

/// Attestation that the hand-rolled zero-knowledge constructions this connector
/// routes (Spark dual-base serial-tag binding; MW excess signature) have passed
/// an EXTERNAL cryptographic audit. Ships `false`. Do NOT flip to `true` without
/// a completed third-party review — it is the master safety interlock for any
/// mainnet activation and for the value converter.
pub const CONNECTOR_AUDITED: bool = false;

/// The privacy schemes this connector can bridge. Each is a "spoke" routed
/// through the single [`ConnectorGate`] hub, so the whole privacy surface has
/// one activation/safety boundary rather than scattered per-scheme hooks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// Lelantus Spark spend proofs (serial-tag nullifier). Feature-gated.
    LelantusSpark,
    /// MimbleWimble cut-through kernels (excess-signature verified).
    MwCutThrough,
    /// Shielded note-commitment pool (nullifier double-spend set).
    Shielded,
    /// Dead-man's-switch recovery-address sweep authorization.
    DeadMansSwitch,
}

impl Scheme {
    fn name(self) -> &'static str {
        match self {
            Scheme::LelantusSpark => "lelantus-spark",
            Scheme::MwCutThrough => "mw-cut-through",
            Scheme::Shielded => "shielded-pool",
            Scheme::DeadMansSwitch => "dead-mans-switch",
        }
    }

    /// Whether the crate feature backing this scheme is compiled in.
    fn compiled(self) -> bool {
        match self {
            Scheme::LelantusSpark => cfg!(feature = "sketch-lelantus-spark"),
            // These are compiled in the default build (but inert until the gate
            // activates them).
            Scheme::MwCutThrough | Scheme::Shielded | Scheme::DeadMansSwitch => true,
        }
    }
}

/// Centralized activation + safety gate. Construct one per validation context
/// and consult it before ANY connector operation.
pub struct ConnectorGate {
    network: NetworkType,
    current_height: u64,
    /// `None` = permanently inert. `Some(h)` = active at/after height `h`.
    activation_height: Option<u64>,
    killed: bool,
    max_ops_per_block: u32,
    ops_this_block: u32,
}

impl ConnectorGate {
    /// Default per-block operation cap. Conservative — a diversity/rate floor
    /// per the Act-phase safety guidance.
    pub const DEFAULT_MAX_OPS_PER_BLOCK: u32 = 16;

    pub fn new(network: NetworkType, current_height: u64, activation_height: Option<u64>) -> Self {
        Self {
            network,
            current_height,
            activation_height,
            killed: false,
            max_ops_per_block: Self::DEFAULT_MAX_OPS_PER_BLOCK,
            ops_this_block: 0,
        }
    }

    /// Engage the kill switch — every subsequent operation is refused.
    pub fn kill(&mut self) {
        self.killed = true;
    }

    pub fn is_killed(&self) -> bool {
        self.killed
    }

    /// Reset the per-block op counter (call at the start of each block).
    pub fn reset_block(&mut self) {
        self.ops_this_block = 0;
    }

    pub fn with_max_ops_per_block(mut self, cap: u32) -> Self {
        self.max_ops_per_block = cap;
        self
    }

    /// The core interlock. Returns `Ok(())` only if EVERY safety condition
    /// holds; otherwise a descriptive fail-closed error.
    pub fn check(&self, scheme: Scheme) -> Result<()> {
        if self.killed {
            return Err(Error::InvalidState(
                "privacy connector: kill switch engaged — all operations refused".into(),
            ));
        }
        if !scheme.compiled() {
            return Err(Error::InvalidState(format!(
                "privacy connector: scheme '{}' is not compiled into this build",
                scheme.name()
            )));
        }
        // Mainnet requires the external-audit attestation, full stop.
        if matches!(self.network, NetworkType::Mainnet) && !CONNECTOR_AUDITED {
            return Err(Error::InvalidState(format!(
                "privacy connector: '{}' is INERT on mainnet — the hand-rolled ZK \
                 awaits external audit (CONNECTOR_AUDITED=false)",
                scheme.name()
            )));
        }
        match self.activation_height {
            None => {
                return Err(Error::InvalidState(format!(
                    "privacy connector: '{}' has no activation height configured — inert",
                    scheme.name()
                )))
            }
            Some(h) if self.current_height < h => {
                return Err(Error::InvalidState(format!(
                    "privacy connector: '{}' not active until height {} (current {})",
                    scheme.name(),
                    h,
                    self.current_height
                )))
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Gate check + rate-limit accounting. Call once per connector operation.
    fn admit(&mut self, scheme: Scheme) -> Result<()> {
        self.check(scheme)?;
        if self.ops_this_block >= self.max_ops_per_block {
            return Err(Error::InvalidState(format!(
                "privacy connector: per-block op cap {} reached for this block",
                self.max_ops_per_block
            )));
        }
        self.ops_this_block += 1;
        Ok(())
    }
}

/// Cross-scheme value conversion (RingCT <-> a privacy scheme).
///
/// **STUB — NOT A REAL CONVERTER.** This is an intentionally unimplemented
/// interface placeholder, hard-disabled behind [`CONNECTOR_AUDITED`]. It exists
/// only so the activation boundary and the fail-closed contract are in place.
///
/// A genuine cross-scheme conversion does NOT reduce to comparing cleartext
/// amounts: the two sides commit to value on *different* generator bases
/// (RingCT vs. Spark's `v*G + s*H + r*K`), so conservation must be proven in
/// zero knowledge — a proof that the burned input commitment and the minted
/// scheme commitment encode the *same value* without revealing it (a
/// cross-scheme equal-committed-value proof). That protocol is not designed
/// yet. The cleartext check below is a last-ditch guard only, and is
/// unreachable while unaudited. Do NOT treat this function as providing
/// conservation until the real proof lands and is audited.
pub fn convert_value(
    gate: &ConnectorGate,
    scheme: Scheme,
    ringct_value: u64,
    scheme_value: u64,
) -> Result<()> {
    gate.check(scheme)?;
    // Fail closed: no real conversion protocol exists, and it is unaudited.
    if !CONNECTOR_AUDITED {
        return Err(Error::NotImplemented(
            "privacy connector: cross-scheme value conversion is a STUB — no \
             zero-knowledge equal-value protocol is implemented, and it is \
             disabled pending external audit (CONNECTOR_AUDITED=false)"
                .into(),
        ));
    }
    // Last-ditch cleartext guard (real conservation requires a ZK proof — see
    // the doc comment). Unreachable while unaudited.
    if ringct_value != scheme_value {
        return Err(Error::InvalidState(format!(
            "privacy connector: value-conservation violated (ringct={ringct_value}, \
             scheme={scheme_value})"
        )));
    }
    Ok(())
}

// ── MimbleWimble cut-through routing (compiled in default build) ─────────────

/// Connect a MimbleWimble kernel set to chain state: gate → verify (signatures
/// + aggregate balance) → persist. Fail-closed at every step.
pub fn connect_mw_kernels(
    gate: &mut ConnectorGate,
    store: &crate::storage::KernelStore,
    kernels: &[crate::crypto::mw_cutthrough::MwKernel],
) -> Result<()> {
    gate.admit(Scheme::MwCutThrough)?;
    // Soundness: per-kernel excess signatures + aggregate balance.
    crate::crypto::mw_cutthrough::CutThroughEngine::verify_kernel_set(kernels)?;
    for k in kernels {
        store.append(k.clone());
    }
    Ok(())
}

// ── Shielded note-commitment pool routing (compiled in default build) ───────

/// Connect a new shielded note commitment to the pool. Gate → append. Returns
/// the assigned tree position. Fail-closed.
pub fn connect_shielded_note(
    gate: &mut ConnectorGate,
    store: &crate::storage::ShieldedStore,
    entry: crate::storage::NoteCommitmentEntry,
) -> Result<u64> {
    gate.admit(Scheme::Shielded)?;
    Ok(store.append_commitment(entry))
}

/// Connect a shielded spend: gate → nullifier double-spend check → record. The
/// nullifier is the public tag that burns a note; a repeat is a double-spend
/// and is rejected before it is recorded. Fail-closed.
pub fn connect_shielded_spend(
    gate: &mut ConnectorGate,
    store: &crate::storage::ShieldedStore,
    nullifier: [u8; 32],
) -> Result<()> {
    gate.admit(Scheme::Shielded)?;
    if store.is_nullifier_spent(&nullifier) {
        return Err(Error::InvalidState(
            "privacy connector: shielded nullifier already spent (double-spend)".into(),
        ));
    }
    store.mark_nullifier_spent(nullifier, gate.current_height);
    Ok(())
}

// ── Lelantus Spark routing (feature-gated) ──────────────────────────────────

/// Connect a Spark spend to chain state: gate → serial-tag double-spend check
/// against the store → verify the spend proof → record the serial tag. The tag
/// `T = s*G` is the public nullifier; a repeat tag is a double-spend and is
/// rejected before verification. Fail-closed.
#[cfg(feature = "sketch-lelantus-spark")]
pub fn connect_spark_spend(
    gate: &mut ConnectorGate,
    store: &crate::storage::SparkStore,
    proof: &crate::crypto::lelantus_spark::SparkSpendProof,
    pubkeys: &[curve25519_dalek::ristretto::RistrettoPoint],
) -> Result<()> {
    gate.admit(Scheme::LelantusSpark)?;
    let tag = proof.serial_tag;
    // Double-spend: the serial tag must be unseen.
    if store.is_serial_spent(&tag) {
        return Err(Error::SparkVerifyFailed);
    }
    // Soundness: the dual-base-bound spend proof must verify.
    crate::crypto::lelantus_spark::verify_spark_spend(proof, pubkeys)?;
    // Commit: burn the coin by recording its serial tag.
    store.mark_serial_spent(tag, gate.current_height);
    Ok(())
}

// ── Dead-man's-switch recovery-sweep authorization ──────────────────────────

/// Authorize a dead-man's-switch recovery sweep: gate → the claimed recovery
/// address must match the one embedded in the output's `RecoveryMeta` → the
/// inactivity timeout must have elapsed. Returns `Ok(())` only if the sweep is
/// authorized. This is the guarded activation of the otherwise-dormant recovery
/// path (`RecoveryMeta::is_recovery_eligible`), so a mainnet turn-on is a
/// reviewed, height-gated event rather than silent. Fail-closed.
pub fn connect_recovery_sweep(
    gate: &mut ConnectorGate,
    meta: &crate::transaction::recovery::RecoveryMeta,
    creation_height: u64,
    current_height: u64,
    claimed_recovery_address: [u8; 32],
) -> Result<()> {
    gate.admit(Scheme::DeadMansSwitch)?;
    if claimed_recovery_address != meta.recovery_address {
        return Err(Error::InvalidState(
            "privacy connector: recovery sweep address does not match the output's \
             dead-man's-switch recovery address"
                .into(),
        ));
    }
    if !meta.is_recovery_eligible(creation_height, current_height) {
        return Err(Error::InvalidState(format!(
            "privacy connector: recovery not yet eligible — needs {} blocks of \
             inactivity (created {}, current {})",
            meta.timeout_blocks, creation_height, current_height
        )));
    }
    Ok(())
}

// ── Read-only privacy-feature registry ──────────────────────────────────────

/// Reported state of a privacy feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureStatus {
    /// Shipped and running in the default build.
    Active,
    /// Present but gated off / inert until the connector activates it.
    GatedInert,
    /// Deliberately disabled (e.g. pending a security rewrite).
    Disabled,
}

/// One row of the privacy-feature registry.
#[derive(Clone, Copy, Debug)]
pub struct PrivacyFeature {
    pub name: &'static str,
    pub status: FeatureStatus,
    pub note: &'static str,
}

/// Enumerate EVERY privacy feature and its current status. Read-only: this
/// reports state, it does not switch anything — the live wallet/network
/// features are always on and cannot be disabled from here (that would be a
/// privacy regression). Gated consensus schemes report their live status via
/// `gate`. This is the single hub that "knows about" the whole privacy surface.
pub fn privacy_feature_registry(gate: &ConnectorGate) -> Vec<PrivacyFeature> {
    let scheme_status = |s: Scheme| {
        if gate.check(s).is_ok() {
            FeatureStatus::Active
        } else {
            FeatureStatus::GatedInert
        }
    };
    vec![
        // Live wallet/network features — always on in the default build.
        PrivacyFeature { name: "decoy-defense", status: FeatureStatus::Active, note: "ring decoy selection in the live send path" },
        PrivacyFeature { name: "encrypted-memos", status: FeatureStatus::Active, note: "ECDH-encrypted memo on the first output" },
        PrivacyFeature { name: "scoped-view-keys", status: FeatureStatus::Active, note: "per-epoch scoped disclosure keys" },
        PrivacyFeature { name: "auto-churn", status: FeatureStatus::Active, note: "opt-in self-send churn engine" },
        PrivacyFeature { name: "traffic-shaping", status: FeatureStatus::Active, note: "jitter + size-norm + cover packets (default-on)" },
        // Deliberately disabled.
        PrivacyFeature { name: "deniable-wallets", status: FeatureStatus::Disabled, note: "disabled pending structural rewrite + audit (C37/C38/C39)" },
        // Gated consensus schemes — routed through this connector.
        PrivacyFeature { name: "lelantus-spark", status: scheme_status(Scheme::LelantusSpark), note: "serial-tag spend proofs; hand-rolled ZK awaits audit" },
        PrivacyFeature { name: "mw-cut-through", status: scheme_status(Scheme::MwCutThrough), note: "kernel excess-signature verified pruning" },
        PrivacyFeature { name: "shielded-pool", status: scheme_status(Scheme::Shielded), note: "note-commitment + nullifier pool" },
        PrivacyFeature { name: "dead-mans-switch", status: scheme_status(Scheme::DeadMansSwitch), note: "recovery-address sweep authorization" },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regtest_active() -> ConnectorGate {
        // Regtest, height 100, activated at 50 → live.
        ConnectorGate::new(NetworkType::Regtest, 100, Some(50))
    }

    #[test]
    fn inert_on_mainnet_without_audit() {
        let g = ConnectorGate::new(NetworkType::Mainnet, 1000, Some(1));
        assert!(g.check(Scheme::MwCutThrough).is_err(), "mainnet must be inert while unaudited");
        // The interlock is CONNECTOR_AUDITED — it ships false.
        assert!(!CONNECTOR_AUDITED);
    }

    #[test]
    fn inert_without_activation_height() {
        let g = ConnectorGate::new(NetworkType::Regtest, 1000, None);
        assert!(g.check(Scheme::MwCutThrough).is_err(), "no activation height => inert");
    }

    #[test]
    fn inert_below_activation_height() {
        let g = ConnectorGate::new(NetworkType::Regtest, 10, Some(50));
        assert!(g.check(Scheme::MwCutThrough).is_err(), "below activation height => inert");
    }

    #[test]
    fn kill_switch_refuses_everything() {
        let mut g = regtest_active();
        assert!(g.check(Scheme::MwCutThrough).is_ok());
        g.kill();
        assert!(g.check(Scheme::MwCutThrough).is_err(), "kill switch must refuse");
    }

    #[test]
    fn rate_limit_caps_ops_per_block() {
        let mut g = regtest_active().with_max_ops_per_block(2);
        assert!(g.admit(Scheme::MwCutThrough).is_ok());
        assert!(g.admit(Scheme::MwCutThrough).is_ok());
        assert!(g.admit(Scheme::MwCutThrough).is_err(), "3rd op exceeds cap");
        g.reset_block();
        assert!(g.admit(Scheme::MwCutThrough).is_ok(), "cap resets per block");
    }

    #[test]
    fn value_converter_is_disabled_until_audited() {
        let g = regtest_active();
        // Even value-conserving conversions are refused while unaudited.
        let err = convert_value(&g, Scheme::MwCutThrough, 100, 100);
        assert!(err.is_err(), "converter must be disabled while CONNECTOR_AUDITED=false");
    }

    #[test]
    fn connect_mw_kernels_accepts_valid_rejects_inflation() {
        use crate::crypto::mw_cutthrough::{build_signed_kernel, MwKernel};
        use curve25519_dalek::scalar::Scalar;

        let mut g = regtest_active();
        let store = crate::storage::KernelStore::new();

        // Valid, balanced, signed kernel (x=0 => excess = fee*H).
        let r = Scalar::from(7u64);
        let good = build_signed_kernel(&[r], &[r], 1000, 10);
        assert!(connect_mw_kernels(&mut g, &store, &[good]).is_ok());

        // Inflation: canceling +v*H / -v*H, unsigned → rejected.
        let h = crate::crypto::generator_h();
        let hidden = Scalar::from(5u64);
        let bad = vec![
            MwKernel {
                excess: (h * (Scalar::from(10u64) + hidden)).compress().to_bytes(),
                signature: vec![],
                fee: 10,
                height: 1,
            },
            MwKernel {
                excess: (h * (Scalar::from(20u64) - hidden)).compress().to_bytes(),
                signature: vec![],
                fee: 20,
                height: 2,
            },
        ];
        assert!(
            connect_mw_kernels(&mut g, &store, &bad).is_err(),
            "connector must reject hidden-value inflation"
        );
    }

    #[test]
    fn connect_shielded_note_and_nullifier_double_spend() {
        let mut g = regtest_active();
        let store = crate::storage::ShieldedStore::new();

        // Mint a note commitment through the connector.
        let entry = crate::storage::NoteCommitmentEntry {
            commitment: [1u8; 32],
            height: 5,
            tx_index: 0,
            position: 0,
        };
        assert!(connect_shielded_note(&mut g, &store, entry).is_ok());

        // First spend of a nullifier is accepted; the second is a double-spend.
        let nf = [9u8; 32];
        assert!(connect_shielded_spend(&mut g, &store, nf).is_ok());
        assert!(
            connect_shielded_spend(&mut g, &store, nf).is_err(),
            "connector must reject the shielded double-spend via the nullifier set"
        );
    }

    #[test]
    fn connect_recovery_sweep_gates_on_address_and_timeout() {
        use crate::transaction::recovery::RecoveryMeta;
        let mut g = regtest_active();
        let addr = [7u8; 32];
        let meta = RecoveryMeta { output_index: 0, recovery_address: addr, timeout_blocks: 720 };

        // Wrong recovery address → rejected.
        assert!(connect_recovery_sweep(&mut g, &meta, 100, 1000, [1u8; 32]).is_err());
        // Right address but inactivity window not elapsed (50 < 720) → rejected.
        assert!(connect_recovery_sweep(&mut g, &meta, 1000, 1050, addr).is_err());
        // Right address + elapsed >= timeout → authorized.
        assert!(connect_recovery_sweep(&mut g, &meta, 100, 100 + 720, addr).is_ok());
    }

    #[test]
    fn registry_reports_every_feature() {
        // Mainnet (unaudited): gated schemes inert, live features active, deniable disabled.
        let g = ConnectorGate::new(NetworkType::Mainnet, 1000, Some(1));
        let reg = privacy_feature_registry(&g);
        assert_eq!(reg.len(), 10, "registry must cover all privacy features");
        let by = |n: &str| reg.iter().find(|f| f.name == n).unwrap().status;
        assert_eq!(by("decoy-defense"), FeatureStatus::Active);
        assert_eq!(by("encrypted-memos"), FeatureStatus::Active);
        assert_eq!(by("traffic-shaping"), FeatureStatus::Active);
        assert_eq!(by("deniable-wallets"), FeatureStatus::Disabled);
        assert_eq!(by("lelantus-spark"), FeatureStatus::GatedInert);
        assert_eq!(by("mw-cut-through"), FeatureStatus::GatedInert);
        assert_eq!(by("shielded-pool"), FeatureStatus::GatedInert);
        assert_eq!(by("dead-mans-switch"), FeatureStatus::GatedInert);
    }

    #[test]
    fn registry_shows_gated_schemes_active_when_admitted() {
        // Regtest + activated: default-build schemes report Active; live features
        // stay Active. (Spark stays GatedInert unless its feature is compiled.)
        let g = regtest_active();
        let reg = privacy_feature_registry(&g);
        let by = |n: &str| reg.iter().find(|f| f.name == n).unwrap().status;
        assert_eq!(by("mw-cut-through"), FeatureStatus::Active);
        assert_eq!(by("shielded-pool"), FeatureStatus::Active);
        assert_eq!(by("dead-mans-switch"), FeatureStatus::Active);
        assert_eq!(by("decoy-defense"), FeatureStatus::Active);
    }

    #[cfg(feature = "sketch-lelantus-spark")]
    #[test]
    fn connect_spark_spend_detects_double_spend() {
        use crate::crypto::lelantus_spark::{prove_spark_spend, spark_commit, spark_pubkey};
        use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
        use rand::{rngs::OsRng, RngCore};

        fn rnd() -> Scalar {
            let mut b = [0u8; 64];
            OsRng.fill_bytes(&mut b);
            Scalar::from_bytes_mod_order_wide(&b)
        }

        let value = 1000u64;
        let randomness = rnd();
        let n = 4usize;
        let real_index = 1usize;
        let real_serial = rnd();
        let anon: Vec<RistrettoPoint> = (0..n)
            .map(|i| spark_commit(value, &(if i == real_index { real_serial } else { rnd() }), &randomness))
            .collect();
        let pubkeys: Vec<RistrettoPoint> =
            anon.iter().map(|c| spark_pubkey(c, value, &randomness)).collect();
        let note = crate::crypto::lelantus_spark::SparkNote {
            commitment: anon[real_index].compress().to_bytes(),
            value,
            serial: real_serial.to_bytes(),
            randomness: randomness.to_bytes(),
            diversifier: [0u8; 11],
            height: 1,
            coin_id: real_index as u64,
        };
        let indices: Vec<u64> = (0..n as u64).collect();
        let msg = [9u8; 32];
        let proof =
            prove_spark_spend(&note, &anon, &indices, real_index, &msg, &mut OsRng).unwrap();

        let mut g = regtest_active();
        let store = crate::storage::SparkStore::new();
        // First spend: accepted + recorded.
        assert!(connect_spark_spend(&mut g, &store, &proof, &pubkeys).is_ok());
        // Second spend of the same coin (same serial tag): double-spend → rejected.
        assert!(
            connect_spark_spend(&mut g, &store, &proof, &pubkeys).is_err(),
            "connector must reject the double-spend via the serial-tag nullifier"
        );
    }
}
