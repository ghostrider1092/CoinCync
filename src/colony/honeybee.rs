//! honeybee — quorum-gated trust: the colony's spine.
//!
//! A honeybee swarm does not commit to a nest site on one scout's dance; it
//! waits until enough *independent* scouts, checking the site themselves, agree.
//! This caste is that discipline for the colony's act phase: **no defensive
//! response fires on a single signal.** A threat is only believed once
//! independent observers, across *different kinds* of evidence, corroborate it —
//! and even then the output is a *confidence scalar*, not a yes/no, so every
//! downstream response can be graduated instead of lurching.
//!
//! ## Why this is the spine, not caste number twelve
//!
//! Every act-phase caste consumes a network-state signal (`spider`'s eclipse /
//! flood / partition signatures, `sensor`'s fleet health) and would act on it.
//! Any such signal is *attacker-influenceable*: an eclipse attacker controls the
//! inbound connections `spider` reads; a partition can be faked by dropping
//! sentinel reachability. If each caste acted on a raw signal, the colony's
//! defenses would themselves be the attack surface — forge the trigger, steer
//! the response (an anti-eclipse bridge selection becomes an eclipse vector; a
//! tarpit becomes a way to get honest peers held). honeybee is the gate that
//! makes wiring the rest safe: **nothing acts on evidence that honeybee has not
//! raised to sufficient confidence.**
//!
//! ## The three properties that make it un-forgeable
//!
//! 1. **Independence weighting, not a headcount.** Observations are grouped by
//!    `source_group` (a netgroup / vantage key). Many observations from one
//!    group count as **one** independent voter, so an attacker who spams the
//!    same claim from a thousand sockets in one /16 moves the count by one.
//! 2. **Cross-dimension corroboration.** High confidence requires agreement
//!    across at least two *distinct evidence kinds* (local topology AND fleet
//!    health, say). One metric — however many mouths repeat it — is capped below
//!    the act threshold, because one metric is the easiest thing to game.
//! 3. **An explicit fault budget.** The caller states `max_faulty`: the number
//!    of independent source-groups an adversary might control. Confidence only
//!    rises once corroboration *exceeds* what that many colluders could
//!    fabricate. Below that, confidence is `0` — fabricable evidence is worth
//!    nothing.
//!
//! Plus **freshness**: stale observations evaporate (hard TTL), so yesterday's
//! consensus cannot trigger today's response.
//!
//! ## Purity
//!
//! A pure, deterministic decision core (integer math, ordered iteration, no
//! clock, no RNG, no I/O). `now` is passed in. Same inputs → same confidence,
//! always — so it is exhaustively unit- and adversarially-testable, and the
//! sidecar (which reads the clock and gathers observations) stays a thin shell.
//!
//! ## Prime Privacy Invariant
//!
//! honeybee sees only what every caste sees: public network-state evidence. An
//! `Observation` carries a threat kind, an evidence kind, a source-group key, and
//! a timestamp — no transaction, no stem-phase data, nothing that could name an
//! individual payment. It cannot cross the boundary because its input type has
//! no field that could.

/// A network-level threat the colony can be asked to believe in.
///
/// Deliberately coarse and network-scoped — these describe the *shape of an
/// attack on connectivity/topology*, never anything about a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Threat {
    /// Inbound/topology concentration consistent with an eclipse attempt.
    Eclipse,
    /// Connection/message-rate pattern consistent with flooding.
    Flood,
    /// Reachability/tip evidence consistent with a network partition.
    Partition,
}

/// A *kind* of evidence — a dimension of observation. Independence across kinds
/// is what separates "one metric, many mouths" from genuine corroboration.
///
/// Two observations of the same [`Threat`] from different [`EvidenceKind`]s
/// corroborate; two from the same kind do not add a dimension (they can still
/// add independent *sources*, which counts for less).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceKind {
    /// Local inbound-connection / netgroup-concentration topology (`spider`).
    LocalTopology,
    /// Aggregated fleet health — tip divergence, stalled hosts (`sensor`).
    FleetHealth,
    /// Peer liveness / reachability probes.
    PeerLiveness,
    /// Block-relay success/failure observations.
    RelayFailure,
}

/// One corroborating observation of a threat.
///
/// `source_group` is the independence key: distinct vantage points (e.g. peers
/// in different netgroups, or distinct fleet hosts) get distinct values;
/// anything an attacker can mint cheaply from one location should share one
/// value, so it cannot masquerade as many independent voters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub threat: Threat,
    pub kind: EvidenceKind,
    /// Independence key. Same group = same voter, no matter how many times seen.
    pub source_group: u64,
    /// Unix seconds the observation was made. Compared against `now` for TTL.
    pub observed_at: u64,
}

/// Tunable quorum policy. Defaults via [`QuorumParams::standard`].
#[derive(Clone, Copy, Debug)]
pub struct QuorumParams {
    /// Independent source-groups an adversary might control. Confidence stays
    /// `0` until independent corroboration strictly exceeds this — evidence a
    /// colluding set could fabricate on its own is worth nothing.
    pub max_faulty: u32,
    /// Observations older than this many seconds are dropped (freshness).
    pub ttl_secs: u64,
    /// Independent source-groups (beyond `max_faulty`) at which a *single*
    /// evidence dimension reaches its capped confidence.
    pub single_dim_saturation: u32,
    /// Confidence cap when only ONE evidence dimension corroborates, however
    /// many independent sources. One metric is gameable, so it can never on its
    /// own authorise the strongest responses.
    pub single_dim_cap: u8,
}

impl QuorumParams {
    /// A conservative default: tolerate 1 malicious source-group, 5-minute
    /// freshness, a single dimension caps at 49 (below a 50-to-act threshold),
    /// full confidence only with cross-dimension agreement.
    pub fn standard() -> Self {
        QuorumParams {
            max_faulty: 1,
            ttl_secs: 300,
            single_dim_saturation: 4,
            single_dim_cap: 49,
        }
    }
}

/// Confidence that a threat is real, `0..=100`. The colony's action currency:
/// a response scales its intensity to this, and a guard gates on it (see
/// [`super::guards`]). `0` means "not corroborated beyond what an attacker could
/// fake" — never act.
pub type Confidence = u8;

/// Assess the confidence for a single [`Threat`] from a set of observations.
///
/// Deterministic. Steps:
/// 1. Drop observations for other threats, and stale ones (`now - observed_at >
///    ttl`). A `now` earlier than an observation (clock skew) does not make it
///    stale — future-dated evidence is kept, never negative-aged.
/// 2. Reduce to **independent voters**: dedupe by `source_group`, and separately
///    track the distinct `EvidenceKind`s present.
/// 3. If independent source-groups `<= max_faulty`, return `0` — the whole set
///    could be fabricated by the tolerated adversary.
/// 4. With `>= 2` evidence dimensions, confidence scales toward `100` on the
///    corroborating independent sources. With one dimension, it scales toward
///    `single_dim_cap` only.
pub fn confidence_for(threat: Threat, obs: &[Observation], now: u64, p: &QuorumParams) -> Confidence {
    // Collect fresh, on-threat observations; track distinct source groups and
    // distinct evidence kinds. Small fixed sets → linear scan, no allocation of
    // hash maps needed for the group/kind dedup at colony scale, but we keep it
    // simple and correct with sorted-unique vecs.
    let mut groups: Vec<u64> = Vec::new();
    let mut kinds: Vec<EvidenceKind> = Vec::new();
    for o in obs {
        if o.threat != threat {
            continue;
        }
        // Freshness: stale if strictly older than the TTL. Future-dated (now <
        // observed_at) is treated as age 0, never stale — a source slightly
        // ahead of us must not be silently discarded.
        let age = now.saturating_sub(o.observed_at);
        if age > p.ttl_secs {
            continue;
        }
        if !groups.contains(&o.source_group) {
            groups.push(o.source_group);
        }
        if !kinds.contains(&o.kind) {
            kinds.push(o.kind);
        }
    }

    let independent = groups.len() as u32;
    // Corroboration must EXCEED the fault budget: a set an attacker could
    // fabricate wholesale carries no weight.
    if independent <= p.max_faulty {
        return 0;
    }
    let effective = independent - p.max_faulty; // corroboration beyond fabricable

    let dimensions = kinds.len() as u32;
    if dimensions >= 2 {
        // Cross-dimension: scale toward 100. Two independent dimensions is
        // already strong; more independent sources push it to full.
        scale(effective, p.single_dim_saturation.max(1), 100)
    } else {
        // Single dimension: capped, because one metric is the most gameable.
        scale(effective, p.single_dim_saturation.max(1), p.single_dim_cap)
    }
}

/// Linear saturation: `effective`/`saturation` of `ceiling`, clamped to
/// `ceiling`. Integer math; at/above `saturation` returns `ceiling`.
fn scale(effective: u32, saturation: u32, ceiling: u8) -> u8 {
    if effective >= saturation {
        return ceiling;
    }
    // effective in 1..saturation
    ((effective as u32 * ceiling as u32) / saturation) as u8
}

/// Assess every threat present in `obs`, returning `(threat, confidence)` for
/// those with non-zero confidence, in deterministic `Threat` order.
pub fn assess_all(obs: &[Observation], now: u64, p: &QuorumParams) -> Vec<(Threat, Confidence)> {
    let mut out = Vec::new();
    for threat in [Threat::Eclipse, Threat::Flood, Threat::Partition] {
        let c = confidence_for(threat, obs, now, p);
        if c > 0 {
            out.push((threat, c));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ob(threat: Threat, kind: EvidenceKind, group: u64, at: u64) -> Observation {
        Observation { threat, kind, source_group: group, observed_at: at }
    }

    const NOW: u64 = 10_000;

    // ─── The attack this caste exists to stop ────────────────────────────────

    /// A single forged observation must not move confidence off zero. This is
    /// the "forge the trigger" attack that every act-phase caste is exposed to
    /// without a quorum in front of it.
    #[test]
    fn one_forged_signal_yields_zero_confidence() {
        let p = QuorumParams::standard();
        let obs = [ob(Threat::Eclipse, EvidenceKind::LocalTopology, 1, NOW)];
        assert_eq!(confidence_for(Threat::Eclipse, &obs, NOW, &p), 0);
    }

    /// The same claim spammed from a thousand sockets in ONE netgroup is one
    /// voter, not a thousand. Independence is by source-group, so a flood of
    /// duplicate observations from a single vantage cannot manufacture quorum.
    #[test]
    fn spam_from_one_source_group_counts_once() {
        let p = QuorumParams::standard();
        let obs: Vec<Observation> = (0..1000)
            .map(|i| ob(Threat::Flood, EvidenceKind::LocalTopology, 7, NOW - (i % 5)))
            .collect();
        // one independent group (7) <= max_faulty(1) → fabricable → 0.
        assert_eq!(confidence_for(Threat::Flood, &obs, NOW, &p), 0);
    }

    /// Corroboration must EXCEED the fault budget. With max_faulty=2, two
    /// independent groups is still fabricable (0); three crosses the line.
    #[test]
    fn confidence_requires_exceeding_the_fault_budget() {
        let mut p = QuorumParams::standard();
        p.max_faulty = 2;
        let two = [
            ob(Threat::Partition, EvidenceKind::FleetHealth, 1, NOW),
            ob(Threat::Partition, EvidenceKind::PeerLiveness, 2, NOW),
        ];
        assert_eq!(confidence_for(Threat::Partition, &two, NOW, &p), 0, "2 groups == budget");

        let three = [
            ob(Threat::Partition, EvidenceKind::FleetHealth, 1, NOW),
            ob(Threat::Partition, EvidenceKind::PeerLiveness, 2, NOW),
            ob(Threat::Partition, EvidenceKind::RelayFailure, 3, NOW),
        ];
        assert!(confidence_for(Threat::Partition, &three, NOW, &p) > 0, "3 groups > budget");
    }

    // ─── Single dimension is capped; cross-dimension unlocks full ────────────

    /// Many independent sources on ONE evidence dimension are capped below the
    /// act threshold — one metric, however widely seen, is the most gameable.
    #[test]
    fn single_dimension_is_capped() {
        let p = QuorumParams::standard();
        let obs: Vec<Observation> = (1..=50)
            .map(|g| ob(Threat::Eclipse, EvidenceKind::LocalTopology, g, NOW))
            .collect();
        let c = confidence_for(Threat::Eclipse, &obs, NOW, &p);
        assert_eq!(c, p.single_dim_cap, "one dimension saturates at the cap, not 100");
        assert!(c < 50, "and stays below a 50-to-act threshold");
    }

    /// Two independent dimensions with enough independent sources reaches full
    /// confidence — genuine corroboration.
    #[test]
    fn cross_dimension_reaches_full_confidence() {
        let p = QuorumParams::standard();
        let obs = [
            ob(Threat::Partition, EvidenceKind::FleetHealth, 1, NOW),
            ob(Threat::Partition, EvidenceKind::PeerLiveness, 2, NOW),
            ob(Threat::Partition, EvidenceKind::FleetHealth, 3, NOW),
            ob(Threat::Partition, EvidenceKind::RelayFailure, 4, NOW),
            ob(Threat::Partition, EvidenceKind::PeerLiveness, 5, NOW),
        ];
        // 5 groups, minus 1 faulty = 4 effective == saturation → 100.
        assert_eq!(confidence_for(Threat::Partition, &obs, NOW, &p), 100);
    }

    /// Confidence is monotonic in independent corroboration and graduated, so a
    /// downstream response can scale to it rather than lurching.
    #[test]
    fn confidence_is_graduated_and_monotonic() {
        let p = QuorumParams::standard();
        let mk = |n: u64| -> Vec<Observation> {
            (1..=n)
                .map(|g| {
                    let kind = if g % 2 == 0 { EvidenceKind::FleetHealth } else { EvidenceKind::PeerLiveness };
                    ob(Threat::Flood, kind, g, NOW)
                })
                .collect()
        };
        let mut last = 0u8;
        for n in 2..=6 {
            let c = confidence_for(Threat::Flood, &mk(n), NOW, &p);
            assert!(c >= last, "confidence must not decrease as corroboration grows");
            last = c;
        }
        assert_eq!(last, 100);
    }

    // ─── Freshness ───────────────────────────────────────────────────────────

    /// Stale observations evaporate — yesterday's consensus cannot trigger
    /// today's response.
    #[test]
    fn stale_evidence_does_not_count() {
        let p = QuorumParams::standard();
        let obs = [
            ob(Threat::Eclipse, EvidenceKind::LocalTopology, 1, NOW - p.ttl_secs - 1),
            ob(Threat::Eclipse, EvidenceKind::FleetHealth, 2, NOW - p.ttl_secs - 1),
            ob(Threat::Eclipse, EvidenceKind::PeerLiveness, 3, NOW - p.ttl_secs - 1),
        ];
        assert_eq!(confidence_for(Threat::Eclipse, &obs, NOW, &p), 0, "all stale → nothing");
    }

    /// Future-dated evidence (a source whose clock is slightly ahead) is kept,
    /// not silently discarded as "negative age".
    #[test]
    fn future_dated_evidence_is_not_discarded() {
        let p = QuorumParams::standard();
        let obs = [
            ob(Threat::Partition, EvidenceKind::FleetHealth, 1, NOW + 30),
            ob(Threat::Partition, EvidenceKind::PeerLiveness, 2, NOW + 30),
        ];
        assert!(confidence_for(Threat::Partition, &obs, NOW, &p) > 0);
    }

    // ─── Cross-threat isolation + determinism ────────────────────────────────

    /// Evidence for one threat must not raise confidence for another.
    #[test]
    fn threats_do_not_cross_contaminate() {
        let p = QuorumParams::standard();
        let obs = [
            ob(Threat::Flood, EvidenceKind::LocalTopology, 1, NOW),
            ob(Threat::Flood, EvidenceKind::FleetHealth, 2, NOW),
            ob(Threat::Flood, EvidenceKind::PeerLiveness, 3, NOW),
        ];
        assert!(confidence_for(Threat::Flood, &obs, NOW, &p) > 0);
        assert_eq!(confidence_for(Threat::Eclipse, &obs, NOW, &p), 0);
        assert_eq!(confidence_for(Threat::Partition, &obs, NOW, &p), 0);
    }

    #[test]
    fn assess_all_is_deterministic_and_ordered() {
        let p = QuorumParams::standard();
        let obs = [
            ob(Threat::Partition, EvidenceKind::FleetHealth, 1, NOW),
            ob(Threat::Partition, EvidenceKind::PeerLiveness, 2, NOW),
            ob(Threat::Partition, EvidenceKind::RelayFailure, 3, NOW),
            ob(Threat::Eclipse, EvidenceKind::LocalTopology, 4, NOW),
            ob(Threat::Eclipse, EvidenceKind::PeerLiveness, 5, NOW),
        ];
        let a = assess_all(&obs, NOW, &p);
        let b = assess_all(&obs, NOW, &p);
        assert_eq!(a, b, "same inputs → same output");
        // Eclipse precedes Partition in enum order.
        assert_eq!(a[0].0, Threat::Eclipse);
        assert_eq!(a[1].0, Threat::Partition);
    }
}
