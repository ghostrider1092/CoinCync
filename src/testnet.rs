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
/// either live on separate hosts OR (for `api.coincync.network`) live
/// as nginx-only proxies that forward to one of these seeds. So an
/// app-layer DDoS does not take out the bootstrap layer.
///
/// Five entries spanning US + EU. Asia/Oceania coverage is intentionally
/// deferred until v1.0 mainnet when budget for additional fleet boxes
/// is committed. Add community-run seeds as volunteers come online;
/// never remove an entry without a paired add.
///
/// 2026-06-03 REFRESH: the previous list referenced legacy DigitalOcean
/// hosts that were decommissioned during the 2026-05 Vultr migration.
/// Operators bootstrapping with that list could not reach a live seed
/// without supplying `--addnode` explicitly — observed multiple times
/// during 2026-06-01 → 06-03 community testing. The correct deployed
/// fleet is enumerated in `docs/src/getting-started/run-a-node.md`
/// and `scripts/deploy-node-binary.sh` (which both reference these IPs).
/// `95.179.165.225` (the former api node) is intentionally excluded —
/// see `docs/operations/api-role-architecture.md` for that node's
/// migration to nginx-only.
pub const TESTNET_SEED_NODES: &[&str] = &[
    "66.135.23.193:28080",    // Vultr — seed (US)
    "140.82.57.168:28080",    // Vultr — seed (US, Atlanta)
    "207.148.111.76:28080",   // Vultr — seed (US)
    "207.148.6.50:28080",     // Vultr — seed (US)
    "192.248.151.16:28080",   // Vultr London — seed + baseline miner (EU)
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
    // ── Original population 2026-05-15 (80 entries h=50 → h=4000) ──
    // Pulled from the live testnet fleet via get_block_by_height.
    //
    // ── 2026-06-03 REFRESH: extended +200 entries (h=4050 → h=14000) ──
    // Cross-verified between two independent fleet seeds
    // (66.135.23.193 and 207.148.111.76) — both returned identical
    // hashes for spot-checked heights at h=4500, h=12000, h=14000.
    // The boundary entry (4000) also matched the existing pre-refresh
    // hash, so this is a clean continuation, not a re-anchoring.
    //
    // Cut off at h=14000 deliberately: the chain experienced
    // operator-induced forks in the 14k+ range during the v1.0.10
    // rollout window (2026-06-01 → 06-03) and a checkpoint above
    // that boundary could lock in the wrong branch. Re-extend in a
    // dedicated session once the chain has soaked stably above
    // h=20k for >72h on the current rc3 fleet binary.
    //
    // Total: 280 entries (h=50 through h=14000 in steps of 50).
    // Margin: chain tip is at ~17k, leaving 3000+ blocks above the
    // newest checkpoint — well outside the testnet `max_reorg_depth`
    // buffer.
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
    (4050, "fdfead6bf607e71609aa9366c760c09ff2818ee9eca9b215ae5591f127ec8199"),
    (4100, "246353d4847e3c34ecbc4bd11c3a848ba5f76bf5fa595d75196017d8a86da916"),
    (4150, "be3569ec1870f6a697580a639ae37e848cd7ba8225bc7c17acfc95c409bfdbdf"),
    (4200, "e73cc3bf3c54684e602b573b3b8c72b77c31b1597165500e0b1c8dbc2c2b6567"),
    (4250, "29a31b97f069a41c668e233e7a484008f34b1dcdd0998e38505711c75037804d"),
    (4300, "f22f7d55a814afb2015742337c9c38f94f245ef43c21d63652eb46c97a7341eb"),
    (4350, "b2bbc1cb97e0684b2590717f5844172e543e31fa54b9881defb1c6b5e8115302"),
    (4400, "65b03eaf09f4a096c1c434d487f46308352fdbe2ba2f59e03bc9f4c270c77298"),
    (4450, "61f903a8490cacff2892946c04409a9d73ea7c00f8e335b525cd1ce526ab7f5e"),
    (4500, "245b6f9b471ee3a2e093afefb854082a01b4ef2c374e6e183fac22da823a03b1"),
    (4550, "23a10919cdb9484cf6d87dc96a095f5b821d2003841a8e33a8664fe5a383feea"),
    (4600, "313055033dfd5f9dd1e1b0e6e5e9f9b8db46b53e060e8e9618665ed10700babf"),
    (4650, "9dbac8952a722841bcec0a6c5d84b6a8a1d7d6542859746d1642af670bbcb9d2"),
    (4700, "b81c7869bba030fe376203602a83fa4276750f39a8f93ed62194ca26994ff8b6"),
    (4750, "46d83519f3468881f5f4a5c35114a12af576c87ae1fc6ca1d9273ca6018a2c1c"),
    (4800, "76b28e2135532aae816b7157395dff5db0a8610b877b7517b33679ce91f82962"),
    (4850, "bc96d3cd7a3bfa266493008cc51aab3e8603acc9e9ec8461c7797775b00c1b64"),
    (4900, "d24ad871136666414205015e1565edfb0b52d12835ded5bdc01730a70909ca2b"),
    (4950, "11685ea9d3857a077fb086a1541554bcc77588bcb7367883eeec65a33613b43b"),
    (5000, "9e928fd87569d6b904cca688162e91349402f9e024051aae95d5b66cf5ccf9d1"),
    (5050, "7814e85ab8594bdd3331f2ab8cd99eb7cdbda2ea1ad375413fe91d41944d4dd8"),
    (5100, "a20cdd6a17dd7a0c7231eeedd8cca056b7e62521a11baea054d71151e1711b01"),
    (5150, "b429080c9bf5e88f75f7587b931a691e100779f95a3eca2536014020298dbdb0"),
    (5200, "4675e4d36f008d222963fb86a058774cb236e56035b4b9d782abaf67f75b845d"),
    (5250, "8e79276d55bd4ef45d0bcbccdf6933f2365b82899ff2c0f786efc52f0e25f819"),
    (5300, "d6ddef12823d4f548ee45115904b40896375b02a6c98531ffa7d9b31f185f409"),
    (5350, "45fa28e0a48c5214e35c8cb8fd5d03b0125818956fccb9731b1a563a05e334a6"),
    (5400, "4c98eb28af22825c13123d676f1dd412bbc2290a02e009665ce32a944fddf937"),
    (5450, "b0afc4e0ae5c410eceb3e04b842d121b2b9f0477ad3401e679b74c5fa5715779"),
    (5500, "4732f648e0953e612084a0d83d631c9833fdf3d399512e34d5487b3a440a3781"),
    (5550, "c8b871ce0900d1b2ba620e7efd2f9f693f710e42a04165d4179e73f03f2aa951"),
    (5600, "bf2eabc8b6f89616a8cb7bdf747c18a5623bfe4e691094ebfd7a84ae874a02be"),
    (5650, "b80c19cc57600f8005c3fbac0616fed5d53446e4d5e113f5cd3cfd4d01c50e45"),
    (5700, "6a26724baf896bc65f5e1ba8b935a816f9b4f24d59b388ae39eb349e94828bb2"),
    (5750, "44092177683cfd0e1af772b9a6d2c4fad65055a4ece9a0d988b08fcac81fa8d8"),
    (5800, "6bb41cd95763d9fdb012bac856f2b32b417d6536f587c63c65755b9773fc0db6"),
    (5850, "b093bc1ac02f0a5f0f66f81eab68b9bac2d5728103e957000dfe3667201ffc89"),
    (5900, "e5fb09a3ad0d19928776e592f80ae12c64e732017d0510c60d2f579d58ad6e16"),
    (5950, "a7dd53d556f87ed36c800b4a10416e0a27ee3d645067c0a37e9fc81a843cc651"),
    (6000, "5887b393cceac719898ff623a9fd8be253f81a6777afa94c080f6202e231b82b"),
    (6050, "8fd116d8de2ca500327cbe70db329eadcedd61694a0ee141c583be209262bd1d"),
    (6100, "225bccef0c384ccad7029aa08a5ef9054bbc5041d1cec1c5fb74214d21947c1b"),
    (6150, "3e4591e48141c8262d162417c32b2772d62603680d99aa802070b5ce7a5e43f5"),
    (6200, "65bda791c81bb0e4a82e8ad8cb249f083626408ff197fe15d707b0e72632b484"),
    (6250, "bf1bdc256bbc0ddf6a8c95516d472462356e549ec542988d2a3d09da1d7e5bbc"),
    (6300, "f59202d75b19241d04184a6de766b091f14b1b680f7e6d7872bd6d5234249846"),
    (6350, "f604204454c8f2df282010dae7da0bfede7661a0c1ca8169addd3b1bb447ae8d"),
    (6400, "64be94229f48e59da8f9fb1361c6e2b711519a92464aee52c2a0d89754742931"),
    (6450, "4d51b418428ab72dfa451b9d98ec7cea5d8f4d418955b57ea733808e2cffc673"),
    (6500, "7a4e5847d98f924c63f81bbc9c17d5fe17c0992b8016d12eaf12adcc156c515a"),
    (6550, "7cd6c12ab3addd991c8d4bfadb3c7b2df91661950acd7d35b3c1f59b7418cf58"),
    (6600, "1e16ab1212f24d002d1ec0953094bed29a0d6e2fbd6edb30b60351ebbed56e50"),
    (6650, "ebe3f7646b828da5bbb8cefb12ce93f0e9077566c6acc323b8f82ce2a2ef30cb"),
    (6700, "d3bcba524bb690920932830e6d11774e4023a038f61e0a437f5934f91076475d"),
    (6750, "d842ad7175722e1cc0443b09f7a5da04f00800f66b5b4ad677a95a20380202c1"),
    (6800, "a49a663de6af280f6615bc302442bc535b213abf53567bd0e4b1560630cbb90f"),
    (6850, "8ca04543ead6394ab171fbdf6939f315f338a66f4889b803f5ea378880da4435"),
    (6900, "a3b40f68f707da1f0fc8d955c74690fd2331aa68996d96f03fe3c39110f6bfd6"),
    (6950, "ec5aec597d881da666cab7ea7a23358b347f463c1513411e84d576e5c94e1ef5"),
    (7000, "edd16aac8a147cca379d46cff0341b6c189f202c8c11d4e1f14ff176e9fe189f"),
    (7050, "42d2f403f12159353c5ec3b4c36a3e0038be561284970c7eb0087981f2429331"),
    (7100, "c1781428aa433bc0f0430d5ef31da1842107c9275bbc240860ad29b5c9cfa394"),
    (7150, "67fd03328ac8e39ee64a8b46afbff8923cfec02c06f4b6228171f97870825219"),
    (7200, "6d259ad6c8475a548d309c096f775a0da48d2e65a4a879d08b84c884f26763ac"),
    (7250, "a01ec640caa9ffc26b625e9918c19d6692c0569f7713411b6113851b4f711f2c"),
    (7300, "5bf0319494aa75f2a2fe31506a056371c307e491c73025ace027dd9090a74970"),
    (7350, "8557c46562a056bc4daecd6dc10bb1d80041ecccf9d27d8461f3dbe42ec8b4bf"),
    (7400, "c0dfa80fa8313690c768558ee1ab6b408e77d3c1a66722c60a56283c9299b8f9"),
    (7450, "2fb3b0daf55e703bee2df4c27088d0065a6a4439ac2709dfe42b4b9749b99252"),
    (7500, "6f15a4ae0b5a9c87c510207be20979c6ea50e45a8aa442c07887e2758563e5c4"),
    (7550, "523d57a95db9d207b8cbfd7515d108cbf004e1519764644f1e0ffb3f6acf625f"),
    (7600, "9bb69c3ac5cac9ca69e68adccc1fc1998001cbecfe8820541983e21f45aaa456"),
    (7650, "728a81b2b5531e570bd117e34133667e160b6e2d095f212c1587736f5fcc987a"),
    (7700, "4bfe2485694cf5ba6798585e2b9baf54e44f0c3c1f0468cc0bc66eb1cc9dd08a"),
    (7750, "257023807abc647ca723dd651d81b02e7939b50cc5bd2ff5b7eafab8869e8682"),
    (7800, "d9caad3f06108fa7a8ac2b94d857f404fa881ddfd2613f4e644ddc87e86e552d"),
    (7850, "a7e8f1ca6ae79417f05e4ff56c9ddfe37aa18e34c18d1128b7d06502cf2563af"),
    (7900, "67dd8ace79b8e850a644d830352ee65ae51623e1813b49a70d9b7113ea68f2f3"),
    (7950, "ddfd0831db91aa8ca856854e41836594075f06fbb4808e892e3df852f1089812"),
    (8000, "8ce4f0e52c689dde7363ee92ea02a3ed64cf0ebade0b8d4a59f1da32bd152513"),
    (8050, "5fc5aeb7290aacb564ab3e450f3669446ee3dcd40f89eb786abebf7011b895cd"),
    (8100, "a48e79089d95b7f918aa2df1e502c80f7725bfc74afa1adf5284a27a3023f60d"),
    (8150, "e9497f1fc432682e0fbb6addf1135427961c82074bca682ce7cc513f0f4b9d8b"),
    (8200, "1c2c5d6f6be1955a56b75c743c8db19ee68d1db2b6178694255457e7c1d9d9ee"),
    (8250, "a36daf9db0b9ce984f4e4c0d97ca6dc7fe6b961da350b25c85009aae8066e151"),
    (8300, "afb26661a9f9a3f031f147b00f8e85c402db1bf64495ceb8da37f3216e6424a8"),
    (8350, "12a135bf7cad21f23f5a47ca2319c232c80bf541596521a0bc098f112698721b"),
    (8400, "f46ff94e5a9175d183ef98371305add63762acec4d2b59090062d7953903ad1c"),
    (8450, "53b65fee066f2a6ceedf81580abab3eba82f7ac2a2ca3a46a7a9fbb2ade3d9bc"),
    (8500, "9f75db98e830eb68ac67d921d0a9f1d85d4ed50ee98b6bd7249da13cc611119a"),
    (8550, "b21f075587673d23a36c3b4d6ec5c18b918cd98fb2fa22a858b0def3d39c5d19"),
    (8600, "404558ee6d323a2a838a2fa4890ef6aa0f5347da33e01893fb4f99373261a079"),
    (8650, "156241e547385ce75b6226d974ddf7e75bba6b54553a7246fd0100dd910b6b71"),
    (8700, "917f883780873260ac45bdb9fb427adc9d53be8502f30d1bc4e8cfe3d8463f78"),
    (8750, "2101657ec208251f68cc9ee1d9cf06319edcb9675186173a2649b12f9814ec73"),
    (8800, "23a24896fc1e11237bff7d9d63f3ff16ca7a9b812180a6ffb893cb45fcce9f50"),
    (8850, "4eb83b34a02ddf4813874abe8d5605696ac7324cb3d7309c4e7428e90680f178"),
    (8900, "9a79316373135b785dfe0dafecddde4f33145c274d755a89815789c2205e21d6"),
    (8950, "b6b077a3e8a76441dec0823fcea31c41c1b9a25a12a4d048faf87ab40a24f4a7"),
    (9000, "ca945e5e7b90d94017a03cb9c513507f008616ceb156eeca81e8783f46d8a7ee"),
    (9050, "be93c46ed20934c6ec68c6defdb594056a3462b67a8c7e7dd2579f8c24f046ee"),
    (9100, "6cebbb4983c2b1af159a1fe8906812a9671c7f3b82e6128a68981e50d0b2d623"),
    (9150, "3dc747ef2c892a0b9cd751e0552c45c46899192223cf3d5fa57b12281432f1cb"),
    (9200, "17919f2630ea2b38b4a80edd21a83ac7bf504a734e5005dbeed4fc5b8cbceb54"),
    (9250, "e1de39883c4b196851ea0498b4b6b9011e547a61fe2b8033b6aa757f58e8965a"),
    (9300, "964db0870305d4ef9b9a572c7114aa2c6156210d3c97a35c824a7f6708aeede8"),
    (9350, "c3d199b71424bff87c4bcdb81311ab23d8a6b89e6062d7ec6b71992ee8242e54"),
    (9400, "b0b8342e25f6220e4d740600cc15f98db19ec79d4a9f6ff66ba2cacef896600f"),
    (9450, "ccb21de6861419e2bf3f94deb813576d47c734db42e7c5543c0185857955d568"),
    (9500, "43aff5de7b28312ff65871867691770a4ebbb8d19b203976b2d8e57a9a352916"),
    (9550, "f06ca5f52e2f619d08587202e4aa75a5cbbf5518458e2ad760e0837d78ae5897"),
    (9600, "7fdb5250a44aa4d7d53224e35762fc99bc7c214e7a7427b3a8fb0644a542cce5"),
    (9650, "389163c84a3ebc6a3c2068bb2c7bf6a2678ace10ec78513fd746b03e319aef5f"),
    (9700, "2f5631565a86ee5b93350f363ca486da0e08f7dfe4f6e3392be4b64d03124070"),
    (9750, "925be937685f06abe5022acd0714a011c28d310da0461aec4eac8351c24cd129"),
    (9800, "392b3fa5cceca5c81f451635311089ef43a758e24b308c7da5230b3128f5c65a"),
    (9850, "d8a6f4a40c586540d6f928db83ccede83849335504aa0b8128d2551184d2953a"),
    (9900, "80266d11c377c10151dedaf1aa92b17ecaeba72849b034929422298642052e10"),
    (9950, "5f84b86aaeec5f67f9018f98bf7503334b89b2e2fad55b10c14ffdd0e0557047"),
    (10000, "8faec642574628d31278f39ae969081b51b7c6364aa0b29ff33ffd5caff8d830"),
    (10050, "8ebb2d28aa2da1bb7e4eded712ab28742188401e19e635d01381db298104cff2"),
    (10100, "677e49135924157e0c5c02ac375a9212d0ab75df784e44306eed97b5f16f7bd9"),
    (10150, "fc64aa688847ae470908bd5be6288ced442ccaa6b30ce2feedc3490483b6c010"),
    (10200, "77f94361677e39ea6193f7caa0947a212f652357a04e8f6f9bdbc3e1501ee549"),
    (10250, "c96ef201b4aaa9007c58ebc93a1db46a2e29135569b7b4f2d1867a95eadcab6e"),
    (10300, "f428ba933aab1e1f31917aec57ee6634213e02f58700b8439b33b4392e345a3d"),
    (10350, "3303ec971eafca5f0faf69308de6dccdf654b681a4b1bdd9fb34cf49372e5918"),
    (10400, "5535026582c10f935281feaabc15d70c4c16e9314e5ba0703901adfbcb379072"),
    (10450, "8781730061861559bb55e25eed54de1c10b66333a85ce6df92ed4b82f4b3f31b"),
    (10500, "7e32a59ffcf2737755dc828754d77a27247d52a01bb154b728e79e9981a045ca"),
    (10550, "27fce886cb241939351698f774c8bd7c77ce7caac5755d7fd3eaf0d64b7759c2"),
    (10600, "da4b79b1828a041921037e1810f8216fe569812dce0fba9d89c724b0e301d44a"),
    (10650, "69c6f87b905373b435dd8bcedfafb20cfa38d14337e17d96960728feec3b0426"),
    (10700, "09b8333a57be0fa4867ee3a24402797c2da0814ea63e33a31e53b142026b0775"),
    (10750, "c140168ad27e87f27a80bdc466b2cfaeefa474ff40bf3ce1cbcadca52699e595"),
    (10800, "4a54a7e540b117bb17adda623b9cd43035d8aae7d6d8f39f445e05be35486357"),
    (10850, "f5dc92e77d389cfb2dee7c6755ee2c374833fb8545209974bcb7b8acefd0dafb"),
    (10900, "94eac9817739c1b782affc0ea420028725d18d188921ff0b06e63429ddac0b7e"),
    (10950, "d7429a1b2e044771d91ddbf08dc6b6b22ce47e2ce59eaea288ca2017c2fdb7e2"),
    (11000, "4f65d28388d3c4c864490e37d227fd05dc3528c2a5797cda69b8401f40235458"),
    (11050, "bb9109a53a936f58245d7e77876498a223b4f07b57f03cd44f97a94457de30b4"),
    (11100, "42499c6485de56a08ea01bb2fca9787111c0ed22316645b0c8868b4976ad7646"),
    (11150, "4c5158e51d8bd7da251753467f6d6b4b5c71713c1c520477ddcaab7bfc12c883"),
    (11200, "23737b92d20f3a53a42d9c8fdea92d49e5fffc2d1798b78c6a89469ebfacb85d"),
    (11250, "e6900739969350eae118b7441419e52f403d54a39de8cb32538f43a5e268260a"),
    (11300, "55b4e0fb77578bdc830090786369ad91f3be57bc2a1a3fd223782db580ac0bde"),
    (11350, "fc4e334a687e4f325c33b2fa3e90dcc15d9297a792b98614a9956a5ac3a298e4"),
    (11400, "cf4a3d76bec97c821aedf8565bd5559b85eeff4edc6ec3123c6b1c561fd665b4"),
    (11450, "f2935db1cafc7e0dbb9dbf5bd543f954d1380e9f23dea7fff139fa82fbcce414"),
    (11500, "6064c47abea1960a93c88732c17579963c0a3f7fa8a72a296bafb4b15eb2334b"),
    (11550, "325c1fd8e75e861c0f9ce844c85a8bc77cbfd1a82c085d9d3457f365f9566fb9"),
    (11600, "69416a15b78a73f8f49500cb0b0eb171e15f5520bcbcc4029456be6e5b53a31e"),
    (11650, "fb71e2919fb9103d5d0df96e647355b6a8ff4277a35723c400b61e2436d58562"),
    (11700, "a9fae7e63e0d27d6b55bbf5adfb1d1ac82d4c367757065a00819a301d54068fa"),
    (11750, "16c15788c2aed9989bad8e338abd663f5e52658c643805a7439fa90de4b5a815"),
    (11800, "af33601f1bc932034581842d298fc8922dfb0e7a9b1f0d46614755c6f9635413"),
    (11850, "37793b350df2935ef21432cada011c8489ce97db0ccc14ffdef354eae8820e34"),
    (11900, "a0acf1356d36595886c6083fa7cf6439e4526b2514d950e65a9a369a4c4b45ec"),
    (11950, "20544c98b9cf6978ad7af9184e2c75b0a544bf5bc00cc6d3b221e56e3c502549"),
    (12000, "0fc0576dd935b9e1c0877a503b3a702444d1a10d70ab8eb127c7bc2182186e69"),
    (12050, "d8a8a8a5b45a1237c58110a098a722432ec3763daef833718d5d921ae49fe33b"),
    (12100, "3a95eb45309ec041eb63a8b1f86f6db747b4db4757afa7562ec6e23723046a6a"),
    (12150, "2a81b3f97c675decc187b8cfcb2dc01e90bac8a8ec7e74361abfd64c32210a06"),
    (12200, "c9fadd07ada117fc20d9b2c1e173eda99404900498fad1c2784990c1d2834e1d"),
    (12250, "8eb2bb2e532dd8cb7edec1bb5b322820b4306eb0735d2f3014462e56b92d318c"),
    (12300, "7941437b7c204f00f9452ca5deb7b8f038da1c329e26f5e1ef60f594bbcd42de"),
    (12350, "2c11a4e21d26e77957ada2715dc48cff640a78231ac40bf9753965b7ae57132a"),
    (12400, "b2afc4b3a2f34ce4639499ad849be50339a14cbeaa830a462931b9580d2afb43"),
    (12450, "71a7ac2c5979544b07f2050aaf0fd5ee0bb7c758349537250b8766b55689074e"),
    (12500, "e55c8976c4e6b26f2b47c606fb6ca5c4283629ae5701049b61f852990e323659"),
    (12550, "b28c952505d403e455248c5bafae907151fbf479e73bd1aa64083bc339d2e5a2"),
    (12600, "523cc4f7033ca366cb5611cd9b815b1e6c41c95a86970767e9b8c5d889e2266e"),
    (12650, "f0b94a4ffbc873e1229f7d4ea66e747c7860eea7fd4cc7a112b11218b99aa681"),
    (12700, "176f4083e45a6c88555125093c8db37fdf482f5459f709ae3e7e1191acd6ad90"),
    (12750, "3d1a0cd517443130f9d861b9b61cf8e775901d050685390fb942e513609ffabe"),
    (12800, "d43f826d2235b57dd75c9fcec44fbcb80a4093bccfff9667d7086c9b5d8f1d24"),
    (12850, "172eb743db0905eb4b20b65c7d220a3fd880f103455cf685fb1b3ed9292a5a50"),
    (12900, "078d1955ec309df39fa8bb3e8250acfc05e2da83235ce0f7a014cc29ea92b468"),
    (12950, "ec49c31be8c1420e6c26904c4465f0c7db78d1b2c3a9a7ed74cf887df162bf96"),
    (13000, "06d1acfa602361f865bfa00b74dd8ca9b2384e7542632c7304c84e40fc295b0b"),
    (13050, "5ac9c5d91db6471550f07c641510bc4a548d1fd1f97d42a6bb026b91020c7c11"),
    (13100, "6bef720c1e0256298eb42b5bcc8d4800623716f7e734d7b6e2243bdb37bc955b"),
    (13150, "bea1d96f07d7711f4875afdaf13a1b218bc5b2e1a26c57238de0e5ca1eb4962f"),
    (13200, "46737f48f3375cd4f794a4d8cf6d03fab679557795721b149b480737139ffe73"),
    (13250, "3c86eb76b6dfab14a2ff0b905dac824f5564dcaf564f6ad468e7078b35e6694f"),
    (13300, "d3ea886e7ddb54dcfcf2931f303a75600a7a042b8e0b5f685816a3b34857a31d"),
    (13350, "4ab40351012860594a65b7008185430033c775e9bfaeb872bdb4cc08f013dd73"),
    (13400, "63e34e3ebd7d82e199cacd4dc0b366f20efb5aab637dca877d4acd0c779610d8"),
    (13450, "b57c826f42c3702da6588cdae91b1eaeddd5a525eff7f62ae1f7e6986aeaa162"),
    (13500, "9f47cf40130d28de51fe7c740cb1c635a08652af2e525b6cf9e80fd766d05f9d"),
    (13550, "a39893bcf7472fab9f4532c20f02f6f92ed02712509a7510405adcbc4d54bfcc"),
    (13600, "edee4b2789a7d8dc52092a6450043505bde342a445b0bd36868d9e4541a361ab"),
    (13650, "c3887efea03efbcd108c902147c267080d001df17636f2aeee87576954b7e723"),
    (13700, "64a2330adb006f2a301586acb8cd0de105615f1be9dd86708f733de51d248755"),
    (13750, "c00bf043655045cba3aabe2eb0ed1a10fb20f16df3ea4c2d02fb61d392c434af"),
    (13800, "75fa9f2db8d9e6546d2097249aecd91688eda6d88f201b1257bbb13c8b9705a5"),
    (13850, "921cf818fd505a98629438714620c92c17b7e8b79f7b877a5f568f0658fadae9"),
    (13900, "ae85983d20f7600dce6f7cfafc9cde5be25ee8ca5876b6d8cb6a14137c03bdf0"),
    (13950, "f890049f145e606ecba91968ebc466492ff14e242a31755e60fcc6100d043953"),
    (14000, "24dabdb2c50127a34289278b1c00f31e5d980bafed250221ecf231c99ccd64ca"),
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
        // Bumped from 488 → 14000 after the 2026-06-03 refresh added 200
        // new entries (h=4050 → h=14000 in steps of 50). The bar is set to
        // the highest expected entry so an accidental truncation of the
        // list (e.g. someone re-using the bottom half of the file for
        // edit-then-paste) fails CI before reaching review.
        assert!(highest_checkpoint_height() >= 14000,
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
