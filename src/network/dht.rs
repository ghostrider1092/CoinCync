// M-13: Per-key-image queries leak privacy. TODO: Replace with BIP158-style block filters.
//! # DHT Stripe Assignment for Key Image Sharding
//!
//! Distributes key image storage across Network (Tier 2) nodes using
//! deterministic stripe assignment (Monero pruning pattern adapted for DHT).
//!
//! ## How It Works
//!
//! Each network node picks a "stripe" based on its node identity.
//! Key images are assigned to stripes by hashing: `stripe = blake3(ki) % N`.
//! A node only stores and serves key images in its assigned stripe.
//!
//! With N=8 stripes, each node stores ~12.5% of all key images.
//! The full network has redundancy because multiple nodes share each stripe.
//!
//! ## Routing
//!
//! When a personal node queries "is this key image spent?", it:
//! 1. Computes `stripe = blake3(ki) % N`
//! 2. Routes the query to a peer in that stripe
//! 3. Receives the spend status response
//!
//! ## References
//! - Monero stripe-based pruning: `common/pruning.{h,cpp}`
//! - CKB discovery protocol: `network/src/protocols/discovery/`

use crate::primitives::{KeyImage, hash_domain};
use crate::config::NetworkTierConfig;
use crate::network::peer::PeerId;

/// Default number of DHT stripes.
pub const DEFAULT_STRIPE_COUNT: u32 = 8;

/// Compute the DHT stripe for a key image.
///
/// Deterministic: same key image always maps to same stripe.
/// Uses blake3 hash to ensure uniform distribution.
pub fn key_image_stripe(ki: &KeyImage, stripe_count: u32) -> u32 {
    let hash = hash_domain(b"DHT_KI_STRIPE", ki.as_bytes());
    // SAFETY: hash output is always 32 bytes; [0..4] is a valid 4-byte slice
    let hash_val = u32::from_le_bytes(hash.as_bytes()[0..4].try_into().expect("hash is 32 bytes"));
    hash_val % stripe_count
}

/// Compute the DHT stripe assigned to a node based on its identity.
pub fn node_stripe(node_id: &PeerId, stripe_count: u32) -> u32 {
    let hash = hash_domain(b"DHT_NODE_STRIPE", node_id);
    let hash_val = u32::from_le_bytes(hash.as_bytes()[0..4].try_into().expect("hash is 32 bytes"));
    hash_val % stripe_count
}

/// Check if a node is responsible for a given key image.
pub fn is_responsible(node_id: &PeerId, ki: &KeyImage, stripe_count: u32) -> bool {
    node_stripe(node_id, stripe_count) == key_image_stripe(ki, stripe_count)
}

/// DHT state for a network (Tier 2) node.
///
/// Tracks which stripe this node owns and which peers serve other stripes.
pub struct DhtState {
    /// This node's stripe assignment.
    pub our_stripe: u32,
    /// Total number of stripes in the network.
    pub stripe_count: u32,
    /// Known peers indexed by their stripe assignment.
    /// Used for routing key image queries to the correct stripe.
    pub peers_by_stripe: Vec<Vec<PeerId>>,
}

impl DhtState {
    /// Create a new DHT state for a node.
    pub fn new(our_id: &PeerId, config: &NetworkTierConfig) -> Self {
        let stripe_count = config.dht_stripe_count;
        let our_stripe = config.dht_stripe
            .unwrap_or_else(|| node_stripe(our_id, stripe_count));

        let mut peers_by_stripe = Vec::with_capacity(stripe_count as usize);
        for _ in 0..stripe_count {
            peers_by_stripe.push(Vec::new());
        }

        tracing::info!(
            "DHT initialized: stripe {}/{} (node stores ~{:.1}% of key images)",
            our_stripe, stripe_count,
            100.0 / stripe_count as f64
        );

        DhtState {
            our_stripe,
            stripe_count,
            peers_by_stripe,
        }
    }

    /// Register a peer and assign it to a stripe.
    pub fn add_peer(&mut self, peer_id: PeerId) {
        let stripe = node_stripe(&peer_id, self.stripe_count) as usize;
        if stripe < self.peers_by_stripe.len() {
            if !self.peers_by_stripe[stripe].contains(&peer_id) {
                self.peers_by_stripe[stripe].push(peer_id);
            }
        }
    }

    /// Remove a disconnected peer.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        for stripe_peers in &mut self.peers_by_stripe {
            stripe_peers.retain(|p| p != peer_id);
        }
    }

    /// Check if a key image belongs to our stripe.
    pub fn is_ours(&self, ki: &KeyImage) -> bool {
        key_image_stripe(ki, self.stripe_count) == self.our_stripe
    }

    /// Find peers responsible for a key image's stripe.
    pub fn peers_for_key_image(&self, ki: &KeyImage) -> &[PeerId] {
        let stripe = key_image_stripe(ki, self.stripe_count) as usize;
        if stripe < self.peers_by_stripe.len() {
            &self.peers_by_stripe[stripe]
        } else {
            &[]
        }
    }

    /// Get statistics about stripe coverage.
    pub fn coverage_stats(&self) -> DhtCoverageStats {
        let covered = self.peers_by_stripe.iter()
            .filter(|peers| !peers.is_empty())
            .count() as u32;
        let total_peers: usize = self.peers_by_stripe.iter()
            .map(|peers| peers.len())
            .sum();

        DhtCoverageStats {
            our_stripe: self.our_stripe,
            stripe_count: self.stripe_count,
            stripes_covered: covered,
            total_peers,
            coverage_pct: (covered as f64 / self.stripe_count as f64 * 100.0) as u32,
        }
    }
}

/// DHT network coverage statistics.
#[derive(Clone, Debug)]
pub struct DhtCoverageStats {
    pub our_stripe: u32,
    pub stripe_count: u32,
    pub stripes_covered: u32,
    pub total_peers: usize,
    pub coverage_pct: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stripe_deterministic() {
        let ki = KeyImage::from_bytes([42u8; 32]);
        let s1 = key_image_stripe(&ki, 8);
        let s2 = key_image_stripe(&ki, 8);
        assert_eq!(s1, s2, "Same key image must always map to same stripe");
        assert!(s1 < 8, "Stripe must be within range");
    }

    #[test]
    fn test_stripe_distribution() {
        // Generate 1000 key images and check distribution across 8 stripes
        let mut counts = [0u32; 8];
        for i in 0..1000u32 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            let ki = KeyImage::from_bytes(bytes);
            let stripe = key_image_stripe(&ki, 8);
            counts[stripe as usize] += 1;
        }

        // Each stripe should get roughly 125 (1000/8). Allow 50% variance.
        for (i, &count) in counts.iter().enumerate() {
            assert!(
                count > 60 && count < 200,
                "Stripe {} has {} entries (expected ~125)", i, count
            );
        }
    }

    #[test]
    fn test_node_stripe() {
        let node_a = [1u8; 32];
        let node_b = [2u8; 32];
        let sa = node_stripe(&node_a, 8);
        let sb = node_stripe(&node_b, 8);
        assert!(sa < 8);
        assert!(sb < 8);
        // Different nodes should (usually) get different stripes
        // Not guaranteed but very likely with random-looking hashes
    }

    #[test]
    fn test_dht_state() {
        let our_id = [1u8; 32];
        let config = crate::config::NetworkTierConfig {
            dht_stripe_count: 4,
            dht_stripe: Some(2), // Force stripe 2
            serve_block_filters: true,
            serve_output_digests: true,
            relay_fee_share_bps: 50,
        };

        let mut dht = DhtState::new(&our_id, &config);
        assert_eq!(dht.our_stripe, 2);
        assert_eq!(dht.stripe_count, 4);

        // Add peers
        let peer_a = [10u8; 32];
        dht.add_peer(peer_a);
        assert!(dht.coverage_stats().total_peers >= 1);

        // Remove peer
        dht.remove_peer(&peer_a);
        assert_eq!(dht.coverage_stats().total_peers, 0);
    }
}
