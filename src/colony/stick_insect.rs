//! stick-insect — protocol camouflage (wire-fingerprint normalization).
//!
//! A stick insect survives by looking exactly like every other twig. This
//! caste does the same for a node's **wire fingerprint**: the user-agent
//! string, message sizes, and version banner a node presents are snapped to
//! a single **canonical** form, so every CoinCync node looks byte-identical
//! on the wire. Uniformity is anonymity (rule C.6): a node that advertises a
//! distinctive build string, an odd padding, or a unique size distribution
//! is trivially re-identifiable across sessions and networks; a node that
//! looks like all the others is not.
//!
//! ## Scope: the canonical *profile*, not the transport
//!
//! This module defines the **normalization functions** — "what does the
//! camouflaged fingerprint look like". It sends nothing. The live wire-size
//! normalization already runs in
//! [`super::super::network::traffic_shaping`]; stick-insect's
//! [`padded_len`] is the same idea expressed as a pure, testable ladder so
//! the *policy* (which buckets, canonical UA) has one audited definition.
//! Wiring these as the source of truth for the handshake banner is a later
//! phase.
//!
//! ## Why a fixed canonical UA and not "hide the version"
//!
//! We deliberately advertise **one** constant user-agent for the whole
//! network rather than a randomized or empty one. A random UA is itself a
//! fingerprint (the randomness distribution leaks); an empty UA is a
//! fingerprint (few nodes do it). One shared constant is the only choice
//! that makes nodes *mutually indistinguishable*.
//!
//! Integer / deterministic — same discipline as [`super::pheromone`].

/// The single user-agent every node advertises. Intentionally version-less
/// and build-less: any per-node variation here is a re-identification
/// handle, so there is exactly one value for the whole network.
pub const CANONICAL_USER_AGENT: &str = "/coincync/";

/// Canonical message-size ladder (bytes). Real payloads are padded **up**
/// to the next rung so observed sizes cluster onto a handful of values
/// instead of leaking exact lengths. Ascending, powers-of-two for cheap
/// reasoning and wide coverage from tiny control frames to full blocks.
pub const SIZE_BUCKETS: [usize; 9] = [256, 512, 1_024, 2_048, 4_096, 8_192, 16_384, 32_768, 65_536];

/// Normalize any advertised user-agent to the canonical one. Mimicry: the
/// input is discarded — whatever a peer *claims*, we always present (and
/// expect to present) the single shared string.
pub fn normalize_user_agent(_raw: &str) -> &'static str {
    CANONICAL_USER_AGENT
}

/// Pad a raw payload length up to the next canonical bucket, so the
/// on-wire size reveals only which bucket it fell in, not the exact byte
/// count.
///
/// Boundaries (stated per the integer discipline):
/// - a length already equal to a bucket stays put (idempotent).
/// - `0` → the smallest bucket (even an empty frame is padded, so "empty"
///   is not itself a signal).
/// - lengths above the largest rung round **up** to the next multiple of
///   the largest bucket, so huge payloads still quantize (never leak an
///   exact size) and the result never shrinks the payload.
pub fn padded_len(raw_len: usize) -> usize {
    for &b in &SIZE_BUCKETS {
        if raw_len <= b {
            return b;
        }
    }
    // Above the ladder: round up to a whole multiple of the top rung.
    let top = SIZE_BUCKETS[SIZE_BUCKETS.len() - 1];
    // ceil(raw_len / top) * top, overflow-safe: raw_len + top - 1 could
    // overflow only for lengths within `top` of usize::MAX, which no real
    // payload reaches; saturating_add makes even that fail safe (returns
    // the max multiple representable) rather than wrapping to a small pad.
    let rungs = raw_len.saturating_add(top - 1) / top;
    // Never shrink: for a length within `top` of usize::MAX the ceil
    // multiple isn't representable and the division floors *below* raw_len;
    // clamp so the pad is always >= the payload (fail-safe, unreachable in
    // practice at these sizes).
    rungs.saturating_mul(top).max(raw_len)
}

/// True when a user-agent is already the canonical form. A peer presenting
/// anything else is (harmlessly) non-conformant — useful only as a soft
/// telemetry signal, never a ban reason on its own.
pub fn is_canonical_user_agent(ua: &str) -> bool {
    ua == CANONICAL_USER_AGENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_is_always_canonicalized() {
        assert_eq!(
            normalize_user_agent("/coincync:1.0.11/linux/"),
            CANONICAL_USER_AGENT
        );
        assert_eq!(normalize_user_agent(""), CANONICAL_USER_AGENT);
        assert_eq!(normalize_user_agent("/some-fork:2/"), CANONICAL_USER_AGENT);
        assert!(is_canonical_user_agent(CANONICAL_USER_AGENT));
        assert!(!is_canonical_user_agent("/coincync:1.0/"));
    }

    #[test]
    fn different_nodes_produce_identical_fingerprint() {
        // The whole point (C.6): two nodes with different raw banners must
        // be indistinguishable after normalization.
        let node_a = normalize_user_agent("/coincync-debug:1.0.11-dirty/");
        let node_b = normalize_user_agent("/coincync:1.0.9/win/");
        assert_eq!(node_a, node_b);
    }

    #[test]
    fn padding_snaps_up_to_bucket_and_never_shrinks() {
        assert_eq!(padded_len(1), 256);
        assert_eq!(padded_len(255), 256);
        assert_eq!(padded_len(256), 256); // exact bucket stays
        assert_eq!(padded_len(257), 512);
        assert_eq!(padded_len(5_000), 8_192);
        for raw in [0usize, 1, 300, 1_000, 40_000, 70_000] {
            assert!(
                padded_len(raw) >= raw,
                "padding must never shrink the payload"
            );
        }
    }

    #[test]
    fn empty_payload_is_still_padded() {
        // "empty" must not be its own observable signal.
        assert_eq!(padded_len(0), SIZE_BUCKETS[0]);
    }

    #[test]
    fn padding_is_idempotent() {
        for &b in &SIZE_BUCKETS {
            assert_eq!(padded_len(padded_len(b)), padded_len(b));
            assert_eq!(padded_len(b), b);
        }
    }

    #[test]
    fn oversize_rounds_up_to_multiple_of_top_bucket() {
        let top = SIZE_BUCKETS[SIZE_BUCKETS.len() - 1];
        assert_eq!(padded_len(top), top);
        assert_eq!(padded_len(top + 1), top * 2);
        assert_eq!(padded_len(top * 2), top * 2);
        assert_eq!(padded_len(top * 2 + 1), top * 3);
        // Still quantized (a multiple of top), never an exact leak.
        assert_eq!(padded_len(100_000) % top, 0);
    }

    #[test]
    fn oversize_padding_does_not_overflow() {
        // Pathological length near usize::MAX must fail safe, not wrap.
        let d = padded_len(usize::MAX - 10);
        assert!(d >= usize::MAX - 10, "must not wrap to a small pad");
    }
}
