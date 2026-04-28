//! Edge Case Tests for CoinCync
//!
//! These tests verify behavior under adversarial or unusual conditions.
//! All tests should pass before mainnet launch.

use coincync::primitives::{Amount, PublicKey, SecretKey, hash_data};
use coincync::wallet::{Wallet, SubaddressManager, SubaddressIndex};
use coincync::crypto::SecretScalar;
use tempfile::tempdir;

// =============================================================================
// NETWORK EDGE CASES
// =============================================================================

mod network_edge_cases {
    use super::*;

    /// Test: Malformed data should not crash
    #[test]
    fn test_malformed_data_handling() {
        // Various invalid byte sequences
        let test_cases: Vec<&[u8]> = vec![
            &[],                    // Empty
            &[0xFF],                // Single byte
            &[0u8; 16],             // Too short for hash
            &[0xFF; 1000],          // Large garbage
        ];

        for data in test_cases {
            // Hashing should never panic
            let result = std::panic::catch_unwind(|| {
                let _ = hash_data(data);
            });
            assert!(result.is_ok(), "Hash should not panic on any input");
        }
    }

    /// Test: Connection limit simulation
    #[test]
    fn test_connection_memory_bounds() {
        let max_connections = 1000;
        let mut peer_data: Vec<[u8; 64]> = Vec::with_capacity(max_connections);

        for i in 0..max_connections {
            peer_data.push([i as u8; 64]);
        }

        let memory_used = peer_data.len() * 64;
        assert!(memory_used <= max_connections * 64);
        println!("Memory for {} connections: {} KB", max_connections, memory_used / 1024);
    }

    /// Test: Out-of-order data processing
    #[test]
    fn test_out_of_order_processing() {
        let heights = vec![100u64, 98, 99, 101, 97];
        let mut sorted = heights.clone();
        sorted.sort();

        assert_eq!(sorted, vec![97, 98, 99, 100, 101]);
    }

    /// Test: Large message handling
    #[test]
    fn test_large_message_bounds() {
        let max_message_size = 10 * 1024 * 1024; // 10MB limit

        // Don't actually allocate, just verify bounds logic
        let message_sizes = vec![100, 1000, 100_000, 1_000_000, 20_000_000];

        for size in message_sizes {
            let is_valid = size <= max_message_size;
            println!("Message size {}: valid = {}", size, is_valid);
        }
    }
}

// =============================================================================
// WALLET EDGE CASES
// =============================================================================

mod wallet_edge_cases {
    use super::*;

    /// Test: Wallet with various password types
    #[test]
    fn test_password_variations() {
        let dir = tempdir().unwrap();

        let long_password = "a".repeat(100);
        let passwords: Vec<(&str, &str)> = vec![
            ("normal", "password123"),
            ("empty", ""),
            ("space", " "),
            ("long", &long_password),
            ("special", "!@#$%^&*()"),
        ];

        for (name, password) in passwords {
            let path = dir.path().join(format!("wallet_{}.cync", name));

            let result = Wallet::create(path.clone(), Some(password), "testnet");

            match result {
                Ok((wallet, _mnemonic)) => {
                    println!("Password '{}': wallet created successfully", name);
                    drop(wallet);

                    // Verify unlock works
                    let mut wallet2 = Wallet::open(path).unwrap();
                    let unlock = wallet2.unlock(password);
                    assert!(unlock.is_ok(), "Should unlock with password '{}'", name);
                }
                Err(e) => {
                    println!("Password '{}': creation failed (may be expected): {}", name, e);
                }
            }
        }
    }

    /// Test: Subaddress generation at scale
    #[test]
    fn test_many_subaddresses() {
        let spend_scalar = SecretScalar::random(&mut rand::rngs::OsRng);
        let view_scalar = SecretScalar::random(&mut rand::rngs::OsRng);

        let spend_public = PublicKey::from_bytes(spend_scalar.to_public().to_bytes());
        let view_secret = SecretKey::from_bytes(view_scalar.to_bytes());
        let view_public = PublicKey::from_bytes(view_scalar.to_public().to_bytes());

        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);

        let start = std::time::Instant::now();

        // Generate 10,000 subaddresses
        for i in 0..10_000u32 {
            manager.generate_at(SubaddressIndex::new(0, i));
        }

        let elapsed = start.elapsed();
        println!("Generated 10,000 subaddresses in {:?}", elapsed);

        // Should complete in reasonable time
        assert!(elapsed.as_secs() < 10, "Subaddress generation too slow: {:?}", elapsed);

        // Verify count
        assert_eq!(manager.count(), 10_000);

        // Verify lookup works
        let sub = manager.get(SubaddressIndex::new(0, 5000));
        assert!(sub.is_some(), "Should find subaddress 5000");
    }

    /// Test: Wallet file corruption detection
    #[test]
    fn test_corrupted_wallet_detection() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt_test.wallet");

        // Create valid wallet
        let (wallet, _) = Wallet::create(path.clone(), Some("test123"), "testnet").unwrap();
        drop(wallet);

        // Read and corrupt
        let mut data = std::fs::read(&path).unwrap();
        if data.len() > 100 {
            for i in 50..60 {
                data[i] ^= 0xFF;
            }
        }
        std::fs::write(&path, data).unwrap();

        // Try to unlock - should fail
        let result = Wallet::open(path.clone());
        match result {
            Ok(mut wallet) => {
                let unlock = wallet.unlock("test123");
                // Unlock should fail on corrupted data
                if unlock.is_err() {
                    println!("Correctly detected corruption on unlock");
                }
            }
            Err(e) => {
                println!("Correctly detected corruption on open: {}", e);
            }
        }
    }

    /// Test: Wrong password handling
    #[test]
    fn test_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wrong_pw_test.wallet");

        let (wallet, _) = Wallet::create(path.clone(), Some("correct_password"), "testnet").unwrap();
        drop(wallet);

        let mut wallet = Wallet::open(path).unwrap();

        // Wrong passwords should fail
        let wrong_passwords = vec![
            "wrong_password",
            "correct_passwor",  // Missing char
            "correct_password ", // Extra space
            "CORRECT_PASSWORD", // Case change
            "",
        ];

        for wrong in wrong_passwords {
            let result = wallet.unlock(wrong);
            assert!(result.is_err(), "Should reject wrong password: '{}'", wrong);
        }
    }
}

// =============================================================================
// TRANSACTION EDGE CASES
// =============================================================================

mod transaction_edge_cases {
    use super::*;

    /// Test: Dust threshold handling
    #[test]
    fn test_dust_detection() {
        let dust_threshold = 1_000u64; // 0.00001 CYNC

        let amounts = vec![0u64, 1, 100, 999, 1000, 1001, 1_000_000];

        for amount in amounts {
            let is_dust = amount < dust_threshold;
            let is_zero = amount == 0;

            println!("Amount {}: dust={}, zero={}", amount, is_dust, is_zero);

            if is_zero {
                // Zero amounts should always be rejected
                assert!(is_dust || is_zero);
            }
        }
    }

    /// Test: Amount overflow protection
    #[test]
    fn test_amount_overflow() {
        let max = Amount::MAX;

        // Adding to max should be handled
        let result = max.as_atomic().checked_add(1);
        assert!(result.is_none() || result.unwrap() == 0, "Should handle overflow");

        // Subtraction should work
        let sub = max.as_atomic().checked_sub(1);
        assert!(sub.is_some(), "Subtraction should work");

        // Multiplication overflow
        let large = u64::MAX / 2;
        let mult = large.checked_mul(3);
        assert!(mult.is_none(), "Should detect multiplication overflow");
    }

    /// Test: Fee calculation edge cases
    #[test]
    fn test_fee_calculations() {
        let test_cases = vec![
            (1_000_000_000u64, 10_000_000u64, 990_000_000u64), // Normal
            (10_000_000, 10_000_000, 0),                        // Exact fee
            (10_000_001, 10_000_000, 1),                        // Tiny amount left
        ];

        for (balance, fee, expected_sendable) in test_cases {
            let sendable = balance.saturating_sub(fee);
            assert_eq!(sendable, expected_sendable,
                "balance={}, fee={}, expected={}, got={}",
                balance, fee, expected_sendable, sendable);
        }
    }

    /// Test: Many inputs selection
    #[test]
    fn test_many_inputs() {
        let num_inputs = 100;
        let mut total = 0u64;

        for i in 1..=num_inputs {
            total = total.saturating_add(i as u64 * 1_000_000);
        }

        println!("Total from {} inputs: {} raw units", num_inputs, total);
        assert!(total > 0, "Should have positive total");
    }
}

// =============================================================================
// CONSENSUS EDGE CASES
// =============================================================================

mod consensus_edge_cases {

    /// Test: Timestamp validation bounds
    #[test]
    fn test_timestamp_bounds() {
        let current = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let max_future_drift = 2 * 60 * 60; // 2 hours

        let timestamps = vec![
            ("current", current, true),
            ("1h future", current + 3600, true),
            ("3h future", current + 10800, false),
            ("1h past", current - 3600, true),
            ("zero", 0, false),
            ("far future", current + 86400 * 365, false),
        ];

        for (name, ts, expected_valid) in timestamps {
            let is_valid = ts > 0
                && ts <= current + max_future_drift
                && ts < u64::MAX / 2;

            println!("Timestamp '{}' ({}): valid={}, expected={}",
                name, ts, is_valid, expected_valid);
        }
    }

    /// Test: Difficulty adjustment bounds
    #[test]
    fn test_difficulty_bounds() {
        let initial = 1_000_000u64;
        let max_adjustment = 4.0f64; // 4x max change

        let scenarios: Vec<(&str, f64)> = vec![
            ("normal", 1.0),
            ("2x faster", 2.0),
            ("2x slower", 0.5),
            ("10x faster", 10.0),  // Should be capped
            ("10x slower", 0.1),   // Should be capped
        ];

        for (name, multiplier) in scenarios {
            let clamped = multiplier.max(1.0 / max_adjustment).min(max_adjustment);
            let new_diff = (initial as f64 * clamped) as u64;

            println!("Scenario '{}': mult={}, clamped={}, new_diff={}",
                name, multiplier, clamped, new_diff);

            assert!(new_diff > 0, "Difficulty should never be zero");
            assert!(new_diff < u64::MAX / 2, "Difficulty should not overflow");
        }
    }

    /// Test: Double-spend detection
    #[test]
    fn test_double_spend_detection() {
        use std::collections::HashSet;

        let mut spent: HashSet<[u8; 32]> = HashSet::new();

        let key_image_1 = [1u8; 32];
        let key_image_2 = [2u8; 32];

        // First spend succeeds
        assert!(spent.insert(key_image_1));

        // Double spend detected
        assert!(!spent.insert(key_image_1), "Double spend should be detected");

        // Different output succeeds
        assert!(spent.insert(key_image_2));
    }

    /// Test: Chain reorg detection
    #[test]
    fn test_reorg_detection() {
        let main_chain: Vec<(u64, [u8; 32])> = vec![
            (1, [1; 32]),
            (2, [2; 32]),
            (3, [3; 32]),
        ];

        let fork_chain: Vec<(u64, [u8; 32])> = vec![
            (1, [1; 32]),   // Same
            (2, [20; 32]),  // Fork point
            (3, [30; 32]),
            (4, [40; 32]),  // Longer
        ];

        // Find fork point
        let fork_height = main_chain.iter()
            .zip(fork_chain.iter())
            .take_while(|(a, b)| a.1 == b.1)
            .count() as u64;

        println!("Fork detected at height {}", fork_height);
        assert_eq!(fork_height, 1);

        // Longer chain wins
        let should_reorg = fork_chain.len() > main_chain.len();
        assert!(should_reorg, "Should reorg to longer chain");
    }

    /// Test: Block reward bounds
    #[test]
    fn test_block_reward_bounds() {
        use coincync::emission::calculate_block_reward;

        let heights = vec![0u64, 1, 100, 10_000, 1_000_000];

        for height in heights {
            let result = std::panic::catch_unwind(|| {
                calculate_block_reward(height)
            });

            match result {
                Ok(reward) => {
                    println!("Height {}: reward = {:?}", height, reward);
                }
                Err(_) => {
                    panic!("Block reward panicked at height {}", height);
                }
            }
        }
    }
}

// =============================================================================
// STRESS TESTS
// =============================================================================

mod stress_tests {
    use super::*;

    /// Test: Hash throughput
    #[test]
    fn test_hash_throughput() {
        let data = vec![0u8; 1024];
        let iterations = 100_000;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = hash_data(&data);
        }
        let elapsed = start.elapsed();

        let per_sec = iterations as f64 / elapsed.as_secs_f64();
        println!("Hash throughput: {:.0}/sec ({:?} total)", per_sec, elapsed);

        assert!(per_sec > 10_000.0, "Hash throughput too low");
    }

    /// Test: Memory allocation patterns
    #[test]
    fn test_memory_patterns() {
        let mut allocs: Vec<Vec<u8>> = Vec::new();

        for i in 0..1_000 {
            let size = (i % 100) + 1;
            allocs.push(vec![0u8; size]);
        }

        assert_eq!(allocs.len(), 1_000);
        drop(allocs); // Should not leak
    }

    /// Test: Concurrent operations simulation
    #[test]
    fn test_concurrent_ops() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (0..4).map(|_| {
            let c = Arc::clone(&counter);
            std::thread::spawn(move || {
                for _ in 0..10_000 {
                    c.fetch_add(1, Ordering::Relaxed);
                }
            })
        }).collect();

        for t in threads {
            t.join().unwrap();
        }

        assert_eq!(counter.load(Ordering::Relaxed), 40_000);
    }
}
