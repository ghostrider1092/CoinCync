//! # Testnet Configuration
//!
//! Configuration, genesis block, and checkpoints for CoinCync testnet.

use crate::primitives::{Hash, PublicKey, Amount};
use crate::consensus::{Block, BlockHeader};
use crate::config::NetworkType;
use crate::transaction::{Transaction, TxType, TxOutput};
use std::net::SocketAddr;

// ── Network constants ────────────────────────────────────────────────────────

pub const TESTNET_MAGIC: [u8; 4] = [0x74, 0x43, 0x59, 0x4E]; // "tCYN"
pub const TESTNET_P2P_PORT: u16 = 28080;
pub const TESTNET_RPC_PORT: u16 = 28081;
pub const TESTNET_ADDRESS_PREFIX: &str = "tCYNC";

/// Public DNS names that must resolve to hosts listening on `TESTNET_P2P_PORT`.
/// (The `*.testnet.*` hostnames are not deployed in DNS; clearnet bootstrap uses these.)
pub const TESTNET_DNS_SEEDS: &[&str] = &[
    "seed1.coincync.network",
    "seed2.coincync.network",
    "seed3.coincync.network",
];

/// Hard-coded testnet seed peers — Monero-style minimal bootstrap set.
///
/// These are PURE SEED hosts: their only job is to accept inbound P2P,
/// hand out a peer list, and serve the chain to bootstrapping nodes.
/// They do NOT run app workloads (landing page, explorer, API) — those
/// live on separate hosts (NYC3, LON, TOR) which are deliberately
/// excluded from this list so a public-app DDoS doesn't take out the
/// bootstrap layer too.
///
/// Six entries across three continents (US, Europe, Australia) mirrors
/// Monero's `MIN_WANTED_SEED_NODES = 12` posture but at half the count
/// (we run a smaller fleet during testnet). Add community-run seeds as
/// volunteers come online; never remove an entry without a paired add.
pub const TESTNET_SEED_NODES: &[&str] = &[
    "192.34.59.42:28080",     // NYC1 — mempool + relay (US-East)
    "46.101.138.120:28080",   // FRA  — mempool + relay (Europe)
    "165.245.161.62:28080",   // RIC  — relay (US-East)
    "165.245.140.113:28080",  // ATL  — relay (US-South)
    "164.92.153.24:28080",    // AMS  — relay (Europe) + DNS seed3
    "170.64.142.146:28080",   // SYD  — relay (Asia-Pacific)
];

pub const TESTNET_MIN_RING_SIZE: usize = 11;
pub const TESTNET_BLOCK_TIME: u64 = crate::constants::TARGET_BLOCK_TIME;
// Matched to the measured ~40 H/s RandomX JIT throughput on DO
// Premium AMD 1 vCPU droplets (light mode, no huge pages). Target
// block time = 120 s → difficulty = 40 × 120 = 4800. from_difficulty
// rounds to 12 leading zero bits (effective ~4096).
pub const TESTNET_INITIAL_DIFFICULTY: u64 = 4_800;

// Recomputed after the header/tx signing-hash domain separator landing.
// See `BlockHeader::HEADER_HASH_DOMAIN_TAG` in src/consensus/header.rs and
// `TX_SIGN_DOMAIN_TAG` in src/transaction/types.rs. If either tag changes,
// this constant must be recomputed — `test_genesis_hash_consistency` below
// fails fast so CI catches it before it ships.
// Public testnet genesis — April 21, 2026 reset
pub const TESTNET_GENESIS_HASH: [u8; 32] = [
    0x41, 0xf9, 0x70, 0xdf, 0x61, 0x52, 0x42, 0x5a,
    0x29, 0x38, 0x72, 0x54, 0x23, 0x23, 0x5c, 0x2c,
    0x40, 0xec, 0x52, 0x55, 0x6e, 0xcc, 0x0f, 0xd1,
    0x42, 0x2d, 0x58, 0x86, 0x52, 0xcc, 0x56, 0xb4,
];

// ── Checkpoints ──────────────────────────────────────────────────────────────

/// Hardcoded testnet checkpoints (height → block hash) — pinned by
/// the project to short-circuit long-range attacks and to make IBD
/// reject divergent forks early instead of mining hashes against
/// an alternative chain from genesis. Any chain that disagrees with a checkpoint
/// at or below the checkpoint height is rejected immediately.
pub const TESTNET_CHECKPOINT_LIST: &[(u64, &str)] = &[
    // Re-populated 2026-05-15 from the live testnet fleet via
    // https://api.coincync.network/rpc/testnet · get_block_by_height.
    // 80 entries, height 50 through 4,000 in steps of 50. Pulled with
    // current tip at 4,106 (margin of 106 blocks above the highest
    // entry — comfortably outside the testnet `max_reorg_depth = 1000`
    // buffer that we *don't* rely on here; the margin only matters
    // because reorgs at this depth would invalidate older blocks too,
    // not just the latest entry). Next refresh: when tip exceeds
    // 5,500 or when the next `v1.x.x-testnet` cuts.
    (50, "6c5f66557fd18b99bac207ce618ee370c143cd5a1c83f54b2dec6130c2ec2b7a"),
    (100, "1133992ddde514c17e36989740573ba3eff15445458b384d7b1a95f38d96a0d7"),
    (150, "d8bf63cc3daea46022bac4db9a57418e32aafdbfa5805a44d0455333d455745f"),
    (200, "5ebe76f5ce34b70ba8eb3edbc258075773d4ed165489c1bf0b47f393965d44ef"),
    (250, "473e3761276f4ab4edd3364edf02e6b97bec4e99e04b0051e5fb687a74ec8159"),
    (300, "7895e9a607b33cf178f5097f77a28840bf6663cbf569f5d9065153b785066f98"),
    (350, "94f99312e434703f748c07ecf95f390ee5214666201eeadd705b6223ea666b5a"),
    (400, "e9cd381f2f347ecda0ef73d439a7b521d96f1fbbf9c6dfa34403bee87f9f5cd0"),
    (450, "c78ee7aa408729e2c5274dac4b8f2abe82aa1f6362167981796e218a302df1c1"),
    (500, "a870d8c4b25d9fb80531f19326377c6ad15a9d44c7c30e448948fe4f7ef77938"),
    (550, "4747b3d6c0844d54904ee9eb182193f87fdc159f7f624eae8774e23646ffbd74"),
    (600, "6b9f9753702d3df257da2cf1568f7c25b2ebbdcf605c44edbb97b744a2147b27"),
    (650, "c19af5b3c0f7be89986dbc6971b278da6f2f5d04638c5c791d79a3233b624b71"),
    (700, "e26ef63df333e8b8c2d1f5f738234059c926df5a7b97e0d45669cd82b9939058"),
    (750, "efeac28c1e7ea729b619bb79d104cfb7168bdf7d6303b5f74feffdf4cf735723"),
    (800, "197b0616ed935eb5b5bf42b5afeaf1873faf1f1c049724763da73d625a4ae813"),
    (850, "cb7a9080bffcdb476e17c676077e62cab7f95fdebb3d7b980f31fc25d68f61c6"),
    (900, "bb90ed9a27191f37b6cb55837a739d984ce4ace2d0d97bb8c0542b617a9392d8"),
    (950, "b53b5468a6021f5935b31704ce2226c243368fe500e74f62c89576494db926aa"),
    (1000, "c1eb30537a360a9e154eee6bda809a5264c6a3aa8a9c0d9f521a52820200d0c0"),
    (1050, "6d252c7c124f83c4ceb6c0e8dd5468df8c5ab52d5603f42b31cedeabff842a12"),
    (1100, "ad9dea06097bbcd624bc90eb8a888c942bafa929e1fc4c18d46d55dc09868458"),
    (1150, "452300ff177af15c10812ffdd71427cd72d7000cad1b95c63759826b226e0da0"),
    (1200, "171ff7922eb4d565543a2b404e586886b2d3b70cebf2d9eb8b96ba8dffed3449"),
    (1250, "f32274a69a249fba5eab734d0e7a499229ef0aa07f5e6bb886734e9622797ab9"),
    (1300, "596401e8058ab3271eec917563de7b2604f795275d7eec4aee64fa3ae9e7bfef"),
    (1350, "38fcdadf9b9bdbcdb599b06ab60e34891657737d7b783f9ec69ad2b10947f6ee"),
    (1400, "01075832b3f532b5f4a81964eec8dffc7dd4e2ee2dd672979eddad413de46c98"),
    (1450, "f00951a7276cb783e6d46a09356d2804b84398d55d9935322c9333a3527fe24a"),
    (1500, "b343359f63cabb87cbd0614fc4e0ce65b9aedd6ba55cde33cb63e9d6ef05fbc5"),
    (1550, "88f371660495e3a835e720b1e66e3a05e68777ce42fe4aa53f7ce6a26678f8c1"),
    (1600, "4d0d1fdda1783c472b73cf5ff80c8e0958c4185dddc7974f606ab13ca76b95ea"),
    (1650, "ad840caee9f637295fd670214023ce64c178fcaf3649049c1e7fee26dff3cddf"),
    (1700, "680b7c690625b7f28b484eb219807f099bb912941543af0ecd82addadd27bb38"),
    (1750, "5a4037de33e4bd53f1dce0758ae1b8016c398121cfc8f93248c2a73f9085f0ac"),
    (1800, "128fbb0e72e1c065e6a4e686f0cb83e8bd4c7786851dbf4a54db3c927b7200ed"),
    (1850, "d3fdc68f8d8cc1dd9ec948fbe5271c0a652835a9a09141d13e7136f01e917fe7"),
    (1900, "a007d012d915286d97d15047ac02f4a4355967a178d3766459a7c50b7cbca3cb"),
    (1950, "182cb04eb12adf27f3580fa99812bdec18b61ef5be3bcfa3ced333182688b59b"),
    (2000, "40ad8a652ff937ba9ee10b38533807de596864792960a1406cf9b76b39249a64"),
    (2050, "ff312e02c6c1e7b8afbcafa443d35b5271227882f9a2e142630f08e97cecc1d2"),
    (2100, "2f80e675c4f0aa38237bb3ddd5e1f965826dda702990ece464385bcbe292c782"),
    (2150, "149f6ad9a306cde1dbdf3fdaaf6ed8b9f528761dbe9aadcd224334fb9e53be65"),
    (2200, "5f698e9f54a58217653dcf976ad5a2ffe189e12570fa595315220b2997cbffeb"),
    (2250, "09c5f6996a3c001bea254d3943ec9b4ac01f094ac34dc0cdea108fe652b2f0b5"),
    (2300, "faf72a11a62ad6bc3a48d13f94162b5592bdeee851182d661ecdcfdf4d1959f4"),
    (2350, "fa90de85851f073e9e0c31fb5de8cc05214867e9209e1107859138142a82269d"),
    (2400, "8ce692c48c2e4ce7d37b00a3bf938bbcd6a051c21a5f13a2bd34b0e1c78127b6"),
    (2450, "459109f6be8131f68af52339d2e8b1598333432ffca38280752b7d74677acae1"),
    (2500, "059d1f58276744fee86a5489be11a343358c751d55b02a3be33ee4a150ad4fcc"),
    (2550, "565b99977b70b9d2c2fd2aea96cea0f163181ca5a8bfb3c07b3b754fcf7a6d2d"),
    (2600, "279f8de29ac9260318228fc55c535bb7a748150538124c8e708d1681d3b0acb4"),
    (2650, "98a95afcd7b94b2016cbe374e30120c2586e9f1305db319c76af637c05a774bc"),
    (2700, "ddf7bd5064dd09def19cea7211657ae60fc3309b83f5a190c5e9a96206d580b3"),
    (2750, "c77fcb4b8fbc848df71d79808c9e849bd8e1d6c27908e71124e4177fa8baf019"),
    (2800, "bc915eae9753f49ef169efe2e820c29a4d7d15fbfdb7a538690e5f7dc2a52ce0"),
    (2850, "28dc8724ecf3b7cd4fc2821f5f8b4f1ae9b6b52c184c28db8d1a301cd20cd5c9"),
    (2900, "c44ffa503515216cfd35a60ce778904dd2053b4dfb4e7cd120fb4a1db1a98c34"),
    (2950, "7dcb9189d9fa34075c22d8d6e16370ad448b2380f93ab82cc2e2108eb958df19"),
    (3000, "a293b5513af6a99e401c34559b3f42703cea77ac84d1eb0c8802d55a61f4949f"),
    (3050, "fbe1c92d0b0f2783c09b51421bced83700ee67fbd08288d42e29191110e1df63"),
    (3100, "4275e7fa2f8615069fdc4e909d8d525d16a9a88df3c328fa81646e13b22eaa4d"),
    (3150, "2c50c7fbee3967a92ab2e492e38180145d862f4b0bd4f382a71ab001f5aa5f26"),
    (3200, "17d4017f4d6aa80d20a7fa28cb3fbb6b8ab797163347e0c742acec04ed229232"),
    (3250, "49486f8fecf4d235374e35de45a259b3dcf5246391ef0bcb1bb73a5c5b751e1e"),
    (3300, "b15789b1217f22256325dbe9c2dada3290ffe8bf006e777afc96b60768b077f8"),
    (3350, "ada4e34b68cea0a6daa141f86a48e48956e51bff9b015d9397ccc12670fc6665"),
    (3400, "4d4b2f403672ef7e76aaa10ef618deccecdd7f857d6fccfc16686992f3dd6de3"),
    (3450, "e1c02a50936c0c9b0bcc317735d40897469a187a1b01636da36a5cdac2620ad4"),
    (3500, "3b93b5a0f7d20d1a2c707471a12386c6bd3bd75f13bac8c23d5171962b2a8b5c"),
    (3550, "f3d241b26c3dbbb4d82cb3137b3a8931c3f20fc56b02957ba38ebfb1d9c2b32d"),
    (3600, "f2374c5a583885784a6a232ff01f03a284037c0cd2bf9259eafa9230f6cb7b13"),
    (3650, "fb3f51782d55aa041d121b6af2ec70be196182d219033d7ad4ad35ff5a55461a"),
    (3700, "bfe51f4c42ef5694e7b173ba2cac137fc56e4012059b0ec0ee0993074baa0b25"),
    (3750, "644ade2fd2e0e03b203bc0a25f71c9aa678b381164c93956d8ce1bab166ea445"),
    (3800, "b87947ec31edae48072b51e64fe69151e97ba3609f5a5eb0520ce35ef98a1e46"),
    (3850, "ac8802a0b2f24e8672da56de8e6b4631a8a6c19f15408a2c31e888ebddc39456"),
    (3900, "4fa79d4ba120214fa80fcb9c535c0c311c047ef7e20aaac2539a2da4e7f802f0"),
    (3950, "f7ad935362829a6d3315d22852fdea84c5d4fb786784cc162877d50ae0caf84e"),
    (4000, "bbababd796c79b6c9f325df1313b004aca01b042b53f8b1f7f13fe6acd123edc"),
];

pub fn highest_checkpoint_height() -> u64 {
    TESTNET_CHECKPOINT_LIST.iter().map(|(h, _)| *h).max().unwrap_or(0)
}

pub fn verify_hardcoded_checkpoint(height: u64, hash: &Hash) -> Option<bool> {
    if height == 0 {
        return Some(&Hash::from_bytes(TESTNET_GENESIS_HASH) == hash);
    }
    for (cp_h, cp_hex) in TESTNET_CHECKPOINT_LIST {
        if *cp_h == height {
            let mut bytes = [0u8; 32];
            if hex::decode_to_slice(cp_hex, &mut bytes).is_ok() {
                return Some(&Hash::from_bytes(bytes) == hash);
            }
            return Some(false);
        }
    }
    None
}

// ── Emission ─────────────────────────────────────────────────────────────────

pub mod emission {
    pub const INITIAL_REWARD: u64 = 50_000_000_000;
    pub const TAIL_EMISSION: u64 = 600_000_000;
    pub const TAIL_EMISSION_HEIGHT: u64 = 2_000_000;
    pub const ANNUAL_DECAY: u64 = 8500;
}

// ── Config ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct TestnetConfig {
    pub network_magic: [u8; 4],
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub address_prefix: String,
    pub min_ring_size: usize,
    pub block_time: u64,
    pub initial_difficulty: u64,
    pub dns_seeds: Vec<String>,
    pub seed_nodes: Vec<SocketAddr>,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        let params = NetworkType::Testnet.params();
        TestnetConfig {
            network_magic: params.magic,
            p2p_port: params.p2p_port,
            rpc_port: params.rpc_port,
            address_prefix: params.address_prefix.to_string(),
            min_ring_size: TESTNET_MIN_RING_SIZE,
            block_time: TESTNET_BLOCK_TIME,
            initial_difficulty: TESTNET_INITIAL_DIFFICULTY,
            dns_seeds: TESTNET_DNS_SEEDS.iter().map(|s| s.to_string()).collect(),
            seed_nodes: TESTNET_SEED_NODES.iter().filter_map(|s| s.parse().ok()).collect(),
        }
    }
}

// ── Genesis ──────────────────────────────────────────────────────────────────

pub fn testnet_genesis() -> Block {
    // Bumped +1 from the original 1772784000 — the old value produced
    // genesis hash 41863f9e which derives RandomX key 4759d1a3, and that
    // specific key triggers a pathological hang in randomx_rs's Argon2d
    // cache fill on DigitalOcean's KVM hypervisor (both AMD and Intel).
    // Bumping the timestamp by 1 second changes the genesis hash and
    // therefore the RandomX key, avoiding the bad key.
    // L-7: +1 workaround for randomx_rs Argon2d KVM hang. File upstream bug.
    // RESET 2026-04-21: New genesis for public testnet launch.
    // Previous timestamp 1772784001 produced chains that got contaminated
    // during infrastructure updates. Fresh start with current timestamp.
    let timestamp = 1776818628;
    let genesis_message = b"CoinCync Public Testnet - April 2026 - Trust the Math";
    let coinbase_tx = create_genesis_coinbase(genesis_message);

    let params = NetworkType::Testnet.params();
    let header = BlockHeader {
        network_magic: params.magic,
        version: 1, height: 0, timestamp,
        prev_hash: Hash::zero(),
        tx_root: crate::primitives::merkle_root(&[coinbase_tx.hash()]),
        anchor: Hash::zero(), algorithm: 0, nonce: 0,
        target: Hash::from_difficulty(TESTNET_INITIAL_DIFFICULTY),
        miner_pubkey: PublicKey::from_bytes([0u8; 32]),
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    };

    Block { header, transactions: vec![coinbase_tx] }
}

fn create_genesis_coinbase(message: &[u8]) -> Transaction {
    let pk = PublicKey::from_bytes([0u8; 32]);
    let output = TxOutput {
        stealth_address: pk,
        tx_public_key: pk,
        encrypted_amount: vec![0u8; 8],
        commitment: [0u8; 32],
        view_tag: 0,
        lock_height: None,
        encrypted_memo: vec![],
    };
    Transaction {
        version: 1,
        tx_type: TxType::Coinbase,
        inputs: vec![],
        outputs: vec![output],
        fee: Amount::from_atomic(0),
        range_proof: vec![],
        extra: message.to_vec(),
    }
}

pub fn verify_genesis(block: &Block) -> bool {
    block.header.height == 0 && block.header.prev_hash.is_zero()
        && !block.transactions.is_empty()
        && block.transactions[0].tx_type == TxType::Coinbase
        && block.transactions[0].inputs.is_empty()
}

pub fn expected_genesis_hash() -> Hash {
    let hardcoded = Hash::from_bytes(TESTNET_GENESIS_HASH);
    #[cfg(any(debug_assertions, test))]
    {
        let computed = testnet_genesis().hash();
        assert_eq!(hardcoded, computed,
            "CRITICAL: Genesis hash mismatch! Update TESTNET_GENESIS_HASH. Computed: {}",
            computed.to_hex()
        );
    }
    hardcoded
}

#[derive(Clone, Debug)]
pub struct Checkpoint { pub height: u64, pub hash: Hash }

pub fn testnet_checkpoints() -> Vec<Checkpoint> {
    let mut cps = vec![Checkpoint { height: 0, hash: expected_genesis_hash() }];
    for (h, hex_str) in TESTNET_CHECKPOINT_LIST {
        let mut bytes = [0u8; 32];
        if hex::decode_to_slice(hex_str, &mut bytes).is_ok() {
            cps.push(Checkpoint { height: *h, hash: Hash::from_bytes(bytes) });
        }
    }
    cps
}

pub fn verify_checkpoint(height: u64, hash: &Hash) -> Option<bool> {
    verify_hardcoded_checkpoint(height, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_creation() {
        let g = testnet_genesis();
        assert_eq!(g.header.height, 0);
        assert!(verify_genesis(&g));
    }

    #[test]
    fn test_genesis_hash_consistency() {
        assert_eq!(expected_genesis_hash(), testnet_genesis().hash());
    }

    #[test]
    fn test_genesis_hash_stability() {
        assert_eq!(testnet_genesis().hash(), expected_genesis_hash());
    }

    #[test]
    fn test_config_default() {
        let c = TestnetConfig::default();
        assert_eq!(c.p2p_port, 28080);
        assert_eq!(c.rpc_port, 28081);
    }

    #[test]
    fn test_checkpoints_populated() {
        // Heights not in the list return None (no opinion).
        assert_eq!(verify_hardcoded_checkpoint(999_999, &Hash::zero()), None);
        // Highest checkpoint must be at or above the last known good height
        // captured during list population. Bump this when adding new entries.
        assert!(highest_checkpoint_height() >= 488,
            "checkpoint list regressed: highest is {}", highest_checkpoint_height());
        // List must be strictly monotonic in height — accidental duplicates
        // or out-of-order entries break the long-range-attack defence.
        let heights: Vec<u64> = TESTNET_CHECKPOINT_LIST.iter().map(|(h, _)| *h).collect();
        for w in heights.windows(2) {
            assert!(w[0] < w[1], "checkpoint heights not strictly increasing: {} >= {}", w[0], w[1]);
        }
        // Each hash string must parse to 32 bytes.
        for (h, hex_str) in TESTNET_CHECKPOINT_LIST {
            assert_eq!(hex_str.len(), 64, "checkpoint at h={} has wrong hex length", h);
            for c in hex_str.chars() {
                assert!(c.is_ascii_hexdigit(), "checkpoint h={} has non-hex char {:?}", h, c);
            }
        }
    }

    #[test]
    fn test_genesis_checkpoint() {
        let gh = expected_genesis_hash();
        assert_eq!(verify_hardcoded_checkpoint(0, &gh), Some(true));
        assert_eq!(verify_hardcoded_checkpoint(0, &Hash::from_bytes([1u8; 32])), Some(false));
    }
}
