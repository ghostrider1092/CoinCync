// C shim over vendored Firo libspark — the flat, extern "C" boundary the Rust
// LibsparkBackend calls. secp256k1 / OpenSSL / C++ types stay entirely behind
// this boundary. Stage 3a exposes a self-test that exercises the vendored
// crypto + proof machinery end-to-end; verify/create/identify marshalling
// (over byte buffers) lands in Stage 3b.
#include "params.h"
#include "keys.h"
#include "coin.h"
#include "chaum.h"
#include "chaum_proof.h"
#include "spend_transaction.h"
#include "hash.h"
#include "streams.h"
#include "version.h"
#include "uint256.h"
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <map>
#include <cmath>
#include <cstdio>

using secp_primitives::GroupElement;
using secp_primitives::Scalar;

// ── #258 helpers: node-authoritative cover set ──────────────────────────────
// When the node resolves the anchored cover set from its own store and passes
// it to verify, these recompute the cover-set representation DETERMINISTICALLY
// from the ordered coins (so a spender cannot prove membership in a set they
// made up: the Grootle proof is checked against the node's coins and `rep`,
// bound into the proof's challenge, only matches if the sets are identical) and
// parse the flat FFI wire form `[u32 count][ (u32 len)(coin) ]...`.

// Deterministic cover-set representation: a domain-separated hash over the
// ORDERED cover-set coins, as a canonical 32-byte scalar. Both the wallet
// (build) and the node (verify) compute the same value from the same set.
static std::vector<unsigned char> cc_cover_set_rep(const std::vector<spark::Coin>& coins) {
    spark::Hash h(std::string("coincync_spark_cover_set_rep_v1"));
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << (uint64_t)coins.size();
    for (const auto& c : coins) s << c;
    h.include(s);
    Scalar sc = h.finalize_scalar();
    std::vector<unsigned char> rep(32);
    sc.serialize(rep.data());
    return rep;
}

// Parse the flat FFI cover-set wire form into libspark coins.
static std::vector<spark::Coin> cc_parse_cover_set(const unsigned char* set_ptr, int set_len,
                                                   const spark::Params* params) {
    std::vector<spark::Coin> cover_set;
    std::size_t off = 0;
    auto need = [&](std::size_t n) {
        if (off + n > (std::size_t)set_len) throw std::runtime_error("cover set truncated");
    };
    auto rd_u32 = [&]() -> uint32_t {
        need(4);
        uint32_t v = (uint32_t)set_ptr[off] | ((uint32_t)set_ptr[off + 1] << 8) |
                     ((uint32_t)set_ptr[off + 2] << 16) | ((uint32_t)set_ptr[off + 3] << 24);
        off += 4;
        return v;
    };
    uint32_t count = rd_u32();
    cover_set.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t clen = rd_u32();
        need(clen);
        spark::Coin c(params);
        CDataStream in((const char*)set_ptr + off, (const char*)set_ptr + off + clen,
                       SER_NETWORK, PROTOCOL_VERSION);
        in >> c;
        c.setParams(params);
        cover_set.push_back(c);
        off += clen;
    }
    return cover_set;
}

extern "C" {

// Exercise the full stack: build a real coin + recover its VRF tag T, and run a
// Chaum tag-proof prove->verify round-trip. Returns 1 iff everything succeeds.
// Proves the vendored libspark (crypto + proof/verify machinery) is live.
int spark_ffi_selftest(void) {
    const spark::Params* params = spark::Params::get_test();

    // Coin + tag recovery path.
    spark::SpendKey spend(params);
    spark::FullViewKey full(spend);
    spark::IncomingViewKey incoming(full);
    spark::Address addr(incoming, 0);

    Scalar k;
    k.randomize();
    std::vector<unsigned char> serial_context = {1, 2, 3};
    spark::Coin coin(params, spark::COIN_TYPE_SPEND, k, addr, 123u, std::string("memo"), serial_context);

    spark::IdentifiedCoinData id = coin.identify(incoming);
    spark::RecoveredCoinData rec = coin.recover(full, id);
    unsigned char tag_buf[GroupElement::serialize_size];
    rec.T.serialize(tag_buf);
    bool tag_ok = false;
    for (std::size_t i = 0; i < sizeof(tag_buf); i++) {
        if (tag_buf[i] != 0) { tag_ok = true; break; }
    }
    if (!tag_ok) return 0;

    // Chaum tag-proof prove -> verify round-trip.
    GroupElement F = params->get_F();
    GroupElement G = params->get_G();
    GroupElement H = params->get_H();
    GroupElement U = params->get_U();
    spark::Chaum chaum(F, G, H, U);

    Scalar x; x.randomize();
    Scalar y; y.randomize();
    Scalar z; z.randomize();
    GroupElement S = F * x + G * y + H * z;
    GroupElement T = (U + (G * y).inverse()) * x.inverse();
    std::vector<Scalar> xs{x}, ys{y}, zs{z};
    std::vector<GroupElement> Ss{S}, Ts{T};
    Scalar mu; mu.randomize();

    spark::ChaumProofV1 proof;
    chaum.prove_v1(mu, xs, ys, zs, Ss, Ts, proof);
    if (!chaum.verify_v1(mu, Ss, Ts, proof)) return 0;

    return 1;
}

// Build a valid V2 spend, SERIALIZE the transaction to bytes, DESERIALIZE it,
// and verify the deserialized transaction. Returns 1 iff verify passes on the
// round-tripped transaction — proving SpendBytes marshalling carries a real,
// verifiable spend across the byte boundary (the core of verify_spend). The
// cover set is held locally (in CoinCync it comes from the ShieldedStore).
static int spend_roundtrip_impl();

// FFI boundary: never let a C++ exception cross into Rust (it would abort).
int spark_ffi_spend_verify_roundtrip(void) {
    try {
        return spend_roundtrip_impl();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "spark_ffi_spend_verify_roundtrip threw: %s\n", e.what());
        return 0;
    } catch (...) {
        std::fprintf(stderr, "spark_ffi_spend_verify_roundtrip threw (unknown)\n");
        return 0;
    }
}

static int spend_roundtrip_impl() {
    const spark::Params* params = spark::Params::get_test();
    const std::string memo = "roundtrip";

    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);
    spark::Address address(incoming_view_key, 42);

    // Cover set of N = n^m mint coins.
    std::size_t N = (std::size_t)pow(params->get_n_grootle(), params->get_m_grootle());
    std::vector<spark::Coin> in_coins;
    in_coins.reserve(N);
    for (std::size_t i = 0; i < N; i++) {
        Scalar k; k.randomize();
        std::vector<unsigned char> ctx(32);
        Scalar t; t.randomize(); t.serialize(ctx.data());
        in_coins.emplace_back(spark::Coin(params, spark::COIN_TYPE_MINT, k, address, 123u + (uint64_t)i, memo, ctx));
    }

    // One input (index 1).
    const std::size_t spend_index = 1;
    const uint64_t cover_set_id = 31415;
    std::vector<spark::InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, spark::CoverSetData> cover_set_data;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;

    spark::IdentifiedCoinData id = in_coins[spend_index].identify(incoming_view_key);
    spark::RecoveredCoinData rec = in_coins[spend_index].recover(full_view_key, id);
    std::vector<unsigned char> rep = cc_cover_set_rep(in_coins); // #258: deterministic
    spark::CoverSetData setData;
    setData.cover_set_size = in_coins.size();
    setData.cover_set_representation = rep;
    cover_set_data[cover_set_id] = setData;
    cover_sets[cover_set_id] = in_coins;

    spend_coin_data.emplace_back();
    spend_coin_data.back().cover_set_id = cover_set_id;
    spend_coin_data.back().index = spend_index;
    spend_coin_data.back().k = id.k;
    spend_coin_data.back().s = rec.s;
    spend_coin_data.back().T = rec.T;
    spend_coin_data.back().v = id.v;

    // One output; balance the fee: fee = in_value - out_value.
    const uint64_t out_value = 100u;
    const uint64_t fee = id.v - out_value; // id.v = 124 -> fee 24
    std::vector<spark::OutputCoinData> out_coin_data;
    out_coin_data.emplace_back();
    out_coin_data.back().address = address;
    out_coin_data.back().v = out_value;
    out_coin_data.back().memo = memo;

    std::map<uint64_t, uint256> block_hashes;
    block_hashes.emplace(cover_set_id, uint256());

    spark::SpendTransaction tx(
        params, full_view_key, spend_key, spend_coin_data, cover_set_data,
        cover_sets, fee, 0, out_coin_data,
        spark::SpendTransactionVersion::V2, uint256(), block_hashes);
    tx.setCoverSets(cover_set_data);

    // Sanity: the freshly-built tx verifies.
    if (!spark::SpendTransaction::verify(tx, cover_sets)) {
        std::fprintf(stderr, "spend_roundtrip: FRESH tx verify returned false\n");
        return 0;
    }

    // Serialize -> bytes -> deserialize (the SpendBytes boundary).
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;

    // The version is external context (not in the bytes), so the reader must be
    // constructed with the matching version + output count, else it misparses.
    spark::SpendTransaction tx2(params, spark::SpendTransactionVersion::V2, out_coin_data.size());
    CDataStream in(ss.begin(), ss.end(), SER_NETWORK, PROTOCOL_VERSION);
    in >> tx2;
    tx2.setCoverSets(cover_set_data);
    // out_coins are not on the wire — in Firo they live in the block; the verifier
    // sets them. Here we carry them from the built tx (in CoinCync they come from
    // the block's shielded outputs / ShieldedStore).
    tx2.setOutCoins(tx.getOutCoins());

    // The round-tripped transaction must still verify.
    bool ok = spark::SpendTransaction::verify(tx2, cover_sets);
    if (!ok) std::fprintf(stderr, "spend_roundtrip: ROUND-TRIPPED tx verify returned false\n");
    return ok ? 1 : 0;
}

// ── Stage 3c: the verify BUNDLE — CoinCync's self-contained shielded-spend
// serialization. Because libspark needs verifier-side state that is NOT in the
// SpendTransaction bytes (cover set, its representation, output coins, block
// hash), the bundle packs all of it. Wire order (CDataStream), identical on both
// sides:  cover_set_id | representation | block_hash | cover_set | out_coins |
// output_count | SpendTransaction(V2).
static void pack_or_verify_build(const spark::Params* params,
                                 uint64_t output_value,
                                 uint64_t& cover_set_id,
                                 std::vector<unsigned char>& rep,
                                 uint256& block_hash,
                                 std::vector<spark::Coin>& cover_set,
                                 std::vector<spark::Coin>& out_coins,
                                 CDataStream& tx_stream);

// Build a valid spend and serialize the whole verify bundle into `out` (<= cap).
// Returns the byte length written, or -1 if it does not fit / on error.
int spark_ffi_make_verify_bundle(unsigned char* out, int cap) {
    try {
        const spark::Params* params = spark::Params::get_test();
        uint64_t cover_set_id;
        std::vector<unsigned char> rep;
        uint256 block_hash;
        std::vector<spark::Coin> cover_set, out_coins;
        CDataStream tx_stream(SER_NETWORK, PROTOCOL_VERSION);
        pack_or_verify_build(params, 100u, cover_set_id, rep, block_hash, cover_set, out_coins, tx_stream);

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << cover_set_id;
        ss << rep;
        ss << block_hash;
        ss << cover_set;
        ss << out_coins;
        ss << (uint64_t)out_coins.size();
        ss.insert(ss.end(), tx_stream.begin(), tx_stream.end());

        if ((int)ss.size() > cap) return -1;
        std::copy(ss.begin(), ss.end(), out);
        return (int)ss.size();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "make_verify_bundle threw: %s\n", e.what());
        return -1;
    } catch (...) {
        return -1;
    }
}

// Build a wallet-issued spend of an owned note with output `output_value`, and
// serialize the verify bundle into `out`. Returns the length, or -1 on error
// (e.g. output_value not in (0, input_value)). The produced bundle is exactly
// what `spark_ffi_verify_bundle` verifies — closing the build -> verify loop.
int spark_ffi_build_spend(uint64_t output_value, unsigned char* out, int cap) {
    try {
        const spark::Params* params = spark::Params::get_test();
        uint64_t cover_set_id;
        std::vector<unsigned char> rep;
        uint256 block_hash;
        std::vector<spark::Coin> cover_set, out_coins;
        CDataStream tx_stream(SER_NETWORK, PROTOCOL_VERSION);
        pack_or_verify_build(params, output_value, cover_set_id, rep, block_hash, cover_set, out_coins, tx_stream);

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << cover_set_id;
        ss << rep;
        ss << block_hash;
        ss << cover_set;
        ss << out_coins;
        ss << (uint64_t)out_coins.size();
        ss.insert(ss.end(), tx_stream.begin(), tx_stream.end());

        if ((int)ss.size() > cap) return -1;
        std::copy(ss.begin(), ss.end(), out);
        return (int)ss.size();
    } catch (...) {
        // Invalid request (e.g. over-spend) fails closed.
        return -1;
    }
}

// Verify a bundle. On a valid spend, writes the linking tags (nullifiers) to
// out_tags as [u32 count][34-byte tag]... and returns 1. Returns 0 on an invalid
// spend or any error (fail-closed).
int spark_ffi_verify_bundle(const unsigned char* ptr, int len,
                            const unsigned char* set_ptr, int set_len,
                            uint64_t vout,
                            unsigned char* out_tags, int tags_cap, int* out_tags_len) {
    try {
        const spark::Params* params = spark::Params::get_test();
        CDataStream ss((const char*)ptr, (const char*)ptr + len, SER_NETWORK, PROTOCOL_VERSION);

        uint64_t cover_set_id;
        std::vector<unsigned char> rep;
        uint256 block_hash;
        std::vector<spark::Coin> cover_set, out_coins;
        uint64_t output_count;
        ss >> cover_set_id;
        ss >> rep;
        ss >> block_hash;
        ss >> cover_set;
        ss >> out_coins;
        ss >> output_count;

        // #258: when the node supplies its own anchored cover set (set_len > 0),
        // it is AUTHORITATIVE — the cover set and representation from the
        // spender's bundle are discarded and replaced with the node-resolved set
        // and a representation recomputed from it. A spender can then no longer
        // prove membership in a set they made up: the Grootle proof is verified
        // against the node's real pool coins, and `rep` only matches if the set
        // the proof was built against is identical. An empty set_len keeps the
        // legacy self-contained behaviour (the non-authoritative STATELESS admit;
        // the authoritative store-aware verify runs separately).
        if (set_len > 0) {
            cover_set = cc_parse_cover_set(set_ptr, set_len, params);
            rep = cc_cover_set_rep(cover_set);
        }
        for (auto& c : cover_set) c.setParams(params);
        for (auto& c : out_coins) c.setParams(params);

        spark::SpendTransaction tx(params, spark::SpendTransactionVersion::V2, (std::size_t)output_count);
        ss >> tx;

        std::unordered_map<uint64_t, spark::CoverSetData> cover_set_data;
        spark::CoverSetData sd;
        sd.cover_set_size = cover_set.size();
        sd.cover_set_representation = rep;
        cover_set_data[cover_set_id] = sd;
        std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;
        cover_sets[cover_set_id] = cover_set;

        tx.setCoverSets(cover_set_data);
        tx.setOutCoins(out_coins);

        if (!spark::SpendTransaction::verify(tx, cover_sets)) return 0;

        // #258: in STRICT mode (the node supplied its authoritative cover set),
        // bind the spend's public output `vout` to the transaction's declared
        // value_balance. The balance proof commits to `vout`, so this rejects a
        // tx that claims to unshield value_balance its spend never releases
        // (vout == 0) — the inflation break in the issue. The spend's internal
        // libspark fee `f` is POOL-INTERNAL (it is the input/output coin-value
        // difference, conserved by the spend's own balance proof and realised as
        // pool shrinkage — NOT the transparent `tx.fee`, which is 0 for a pure
        // shielded tx), so it is intentionally not bound here. In the permissive
        // STATELESS admit (set_len == 0) even the vout binding is deferred to the
        // authoritative store-aware verify, exactly like the membership check.
        if (set_len > 0 && tx.getVout() != vout) return 0;

        // Emit the linking tags (nullifiers).
        const std::vector<GroupElement>& tags = tx.getUsedLTags();
        const int enc = (int)GroupElement::serialize_size;
        int need = 4 + (int)tags.size() * enc;
        if (need > tags_cap) return 0;
        uint32_t n = (uint32_t)tags.size();
        out_tags[0] = (unsigned char)(n & 0xff);
        out_tags[1] = (unsigned char)((n >> 8) & 0xff);
        out_tags[2] = (unsigned char)((n >> 16) & 0xff);
        out_tags[3] = (unsigned char)((n >> 24) & 0xff);
        for (std::size_t i = 0; i < tags.size(); i++) {
            tags[i].serialize(out_tags + 4 + (int)i * enc);
        }
        *out_tags_len = need;
        return 1;
    } catch (...) {
        // A rejected/malformed spend is NORMAL operation on this adversarial path
        // (a thrown libspark decode/verify error == "invalid"), so fail-closed
        // silently — no diagnostic spam.
        return 0;
    }
}

// ── Stage 3f: the wallet BUILD side — create shielded outputs. ──────────────

// Generate a fresh Spark wallet address (bech32m string) into `out`. Returns the
// length, or -1 on error / insufficient capacity. (Key persistence is the
// wallet's concern; this produces a valid recipient address to create coins to.)
int spark_ffi_gen_address(unsigned char* out, int cap) {
    try {
        const spark::Params* params = spark::Params::get_test();
        spark::SpendKey spend(params);
        spark::FullViewKey full(spend);
        spark::IncomingViewKey incoming(full);
        spark::Address addr(incoming, 0);
        // The network byte becomes part of the bech32 HRP, so it must be a
        // printable char: 't' = ADDRESS_NETWORK_TESTNET (libspark util.h).
        std::string s = addr.encode((unsigned char)'t');
        if ((int)s.size() > cap) return -1;
        std::copy(s.begin(), s.end(), out);
        return (int)s.size();
    } catch (...) {
        return -1;
    }
}

// Create a shielded output coin addressed to `addr` (a bech32m address string),
// for `value`, with `memo`. Serializes the coin into `out`. Returns the length,
// or -1 on error / insufficient capacity. This is the send-side primitive: the
// sender needs only the recipient's public address.
int spark_ffi_create_output(const unsigned char* addr_ptr, int addr_len,
                            uint64_t value,
                            const unsigned char* memo_ptr, int memo_len,
                            unsigned char* out, int cap) {
    try {
        const spark::Params* params = spark::Params::get_test();
        std::string addr_str((const char*)addr_ptr, (std::size_t)addr_len);
        spark::Address address(params);
        address.decode(addr_str);

        std::string memo((const char*)memo_ptr, (std::size_t)memo_len);
        secp_primitives::Scalar k; k.randomize();
        // Empty (deterministic) serial context: it is not carried in the coin
        // wire form, so a scanner deserializing the coin uses the empty default —
        // both sides must agree. (In-chain, the context is a deterministic block/
        // tx value set via setSerialContext on both create and scan.)
        std::vector<unsigned char> serial_context;

        spark::Coin coin(params, spark::COIN_TYPE_SPEND, k, address, value, memo, serial_context);

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << coin;
        if ((int)ss.size() > cap) return -1;
        std::copy(ss.begin(), ss.end(), out);
        return (int)ss.size();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "create_output threw: %s\n", e.what());
        return -1;
    } catch (...) {
        return -1;
    }
}

// Derive a deterministic, canonical spend-key scalar from an arbitrary seed.
static secp_primitives::Scalar seed_to_r(const unsigned char* seed, int seed_len) {
    spark::Hash h(std::string("coincync_wallet_seed_v1"));
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    std::vector<unsigned char> sv(seed, seed + seed_len);
    s << sv;
    h.include(s);
    return h.finalize_scalar();
}

// The bech32m address of the wallet derived from `seed`. Returns length or -1.
int spark_ffi_address_from_seed(const unsigned char* seed, int seed_len, unsigned char* out, int cap) {
    try {
        const spark::Params* params = spark::Params::get_test();
        spark::SpendKey spend(params, seed_to_r(seed, seed_len));
        spark::FullViewKey full(spend);
        spark::IncomingViewKey incoming(full);
        spark::Address addr(incoming, 0);
        std::string a = addr.encode((unsigned char)'t');
        if ((int)a.size() > cap) return -1;
        std::copy(a.begin(), a.end(), out);
        return (int)a.size();
    } catch (...) {
        return -1;
    }
}

// Scan a coin with the wallet derived from `seed` (receive side). If owned,
// writes the recovered value + memo and returns 1; if not ours / malformed,
// returns 0. (Uses the seed to derive the incoming view key; a true view-only
// key path is a follow-up — libspark's IncomingViewKey has no reconstruction
// ctor, so watch-only scanning needs a small upstream addition.)
int spark_ffi_identify(const unsigned char* seed, int seed_len,
                       const unsigned char* coin_ptr, int coin_len,
                       const unsigned char* ctx_ptr, int ctx_len,
                       uint64_t* out_value,
                       unsigned char* out_memo, int memo_cap, int* out_memo_len) {
    try {
        const spark::Params* params = spark::Params::get_test();
        spark::SpendKey spend(params, seed_to_r(seed, seed_len));
        spark::FullViewKey full(spend);
        spark::IncomingViewKey incoming(full);

        spark::Coin coin(params);
        CDataStream in((const char*)coin_ptr, (const char*)coin_ptr + coin_len, SER_NETWORK, PROTOCOL_VERSION);
        in >> coin;
        coin.setParams(params);
        // The serial context is not carried in the coin wire form; a scanner must
        // supply the same context the coin was minted with (empty for the default).
        // Both sides must agree, or identify fails to recognize the coin.
        std::vector<unsigned char> serial_context(ctx_ptr, ctx_ptr + ctx_len);
        coin.setSerialContext(serial_context);

        spark::IdentifiedCoinData id = coin.identify(incoming); // throws if not ours
        *out_value = id.v;
        int mlen = (int)id.memo.size();
        if (mlen > memo_cap) mlen = memo_cap;
        std::copy(id.memo.begin(), id.memo.begin() + mlen, out_memo);
        *out_memo_len = mlen;
        return 1;
    } catch (...) {
        return 0; // not ours / malformed
    }
}

// Export the WATCH-ONLY incoming view key material (s1, P2) for the wallet
// derived from `seed`: s1 is a 32-byte scalar, P2 a 34-byte group element. A
// holder of (s1, P2) can scan/identify owned coins (spark_ffi_identify_view_only)
// but CANNOT spend — there is no spend key in this material. Returns 1 on
// success, 0 on error (incl. undersized buffers).
int spark_ffi_export_incoming_view_key(const unsigned char* seed, int seed_len,
                                       unsigned char* out_s1, int s1_cap, int* out_s1_len,
                                       unsigned char* out_p2, int p2_cap, int* out_p2_len) {
    try {
        if (s1_cap < 32 || p2_cap < 34) return 0;
        const spark::Params* params = spark::Params::get_test();
        spark::SpendKey spend(params, seed_to_r(seed, seed_len));
        spark::FullViewKey full(spend);
        spark::IncomingViewKey incoming(full);
        incoming.get_s1().serialize(out_s1);
        *out_s1_len = 32;
        incoming.get_P2().serialize(out_p2);
        *out_p2_len = 34;
        return 1;
    } catch (...) {
        return 0;
    }
}

// WATCH-ONLY identify: reconstruct an IncomingViewKey from exported (s1, P2) via
// the CoinCync reconstruction ctor, set the coin's serial context, and identify.
// Returns 1 + value/memo if the coin is owned by that view key, 0 if not ours or
// malformed. Uses NO seed or spend key — it cannot spend.
int spark_ffi_identify_view_only(const unsigned char* s1_ptr, int s1_len,
                                 const unsigned char* p2_ptr, int p2_len,
                                 const unsigned char* coin_ptr, int coin_len,
                                 const unsigned char* ctx_ptr, int ctx_len,
                                 uint64_t* out_value,
                                 unsigned char* out_memo, int memo_cap, int* out_memo_len) {
    try {
        if (s1_len != 32 || p2_len != 34) return 0;
        const spark::Params* params = spark::Params::get_test();
        secp_primitives::Scalar s1;
        s1.deserialize(s1_ptr);
        secp_primitives::GroupElement P2;
        P2.deserialize(p2_ptr);
        spark::IncomingViewKey incoming(params, s1, P2);

        spark::Coin coin(params);
        CDataStream in((const char*)coin_ptr, (const char*)coin_ptr + coin_len, SER_NETWORK, PROTOCOL_VERSION);
        in >> coin;
        coin.setParams(params);
        std::vector<unsigned char> serial_context(ctx_ptr, ctx_ptr + ctx_len);
        coin.setSerialContext(serial_context);

        spark::IdentifiedCoinData id = coin.identify(incoming); // throws if not ours
        *out_value = id.v;
        int mlen = (int)id.memo.size();
        if (mlen > memo_cap) mlen = memo_cap;
        std::copy(id.memo.begin(), id.memo.begin() + mlen, out_memo);
        *out_memo_len = mlen;
        return 1;
    } catch (...) {
        return 0; // not ours / malformed
    }
}

// Self-contained create->recover round-trip: generate a wallet, create a coin to
// its own address for `value`, then identify (incoming view) + recover (full
// view) and check the recovered value. Writes the recovered value to
// `*out_recovered`. Returns 1 iff recovered == value. Proves the send-side coin
// creation is recoverable by the recipient.
int spark_ffi_create_recover_roundtrip(uint64_t value, uint64_t* out_recovered) {
    try {
        const spark::Params* params = spark::Params::get_test();
        spark::SpendKey spend(params);
        spark::FullViewKey full(spend);
        spark::IncomingViewKey incoming(full);
        spark::Address address(incoming, 0);

        secp_primitives::Scalar k; k.randomize();
        std::vector<unsigned char> ctx(32);
        { secp_primitives::Scalar t; t.randomize(); t.serialize(ctx.data()); }
        spark::Coin coin(params, spark::COIN_TYPE_SPEND, k, address, value, std::string("memo"), ctx);

        // Serialize + deserialize the coin (exercise the wire form), then recover.
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << coin;
        spark::Coin coin2(params);
        CDataStream in(ss.begin(), ss.end(), SER_NETWORK, PROTOCOL_VERSION);
        in >> coin2;
        coin2.setParams(params);
        coin2.setSerialContext(ctx);

        spark::IdentifiedCoinData id = coin2.identify(incoming);
        *out_recovered = id.v;
        return (id.v == value) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

// Shared builder: constructs a valid single-input V2 spend and hands back the
// verify-context pieces + the serialized transaction bytes.
static void pack_or_verify_build(const spark::Params* params,
                                 uint64_t output_value,
                                 uint64_t& cover_set_id,
                                 std::vector<unsigned char>& rep,
                                 uint256& block_hash,
                                 std::vector<spark::Coin>& cover_set,
                                 std::vector<spark::Coin>& out_coins,
                                 CDataStream& tx_stream) {
    const std::string memo = "bundle";
    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);
    spark::Address address(incoming_view_key, 7);

    std::size_t N = (std::size_t)pow(params->get_n_grootle(), params->get_m_grootle());
    for (std::size_t i = 0; i < N; i++) {
        Scalar k; k.randomize();
        std::vector<unsigned char> ctx(32);
        Scalar t; t.randomize(); t.serialize(ctx.data());
        cover_set.emplace_back(spark::Coin(params, spark::COIN_TYPE_MINT, k, address, 123u + (uint64_t)i, memo, ctx));
    }

    const std::size_t spend_index = 1;
    cover_set_id = 31415;
    // #258: deterministic representation over the ordered cover set so the node
    // recomputes the identical value when it verifies against its own set.
    rep = cc_cover_set_rep(cover_set);
    block_hash = uint256();

    spark::IdentifiedCoinData id = cover_set[spend_index].identify(incoming_view_key);
    spark::RecoveredCoinData rec = cover_set[spend_index].recover(full_view_key, id);

    std::vector<spark::InputCoinData> spend_coin_data;
    spend_coin_data.emplace_back();
    spend_coin_data.back().cover_set_id = cover_set_id;
    spend_coin_data.back().index = spend_index;
    spend_coin_data.back().k = id.k;
    spend_coin_data.back().s = rec.s;
    spend_coin_data.back().T = rec.T;
    spend_coin_data.back().v = id.v;

    std::unordered_map<uint64_t, spark::CoverSetData> cover_set_data;
    spark::CoverSetData sd; sd.cover_set_size = cover_set.size(); sd.cover_set_representation = rep;
    cover_set_data[cover_set_id] = sd;
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;
    cover_sets[cover_set_id] = cover_set;

    if (output_value == 0 || output_value >= id.v) {
        throw std::invalid_argument("build_spend: output_value must be in (0, input_value)");
    }
    const uint64_t out_value = output_value;
    const uint64_t fee = id.v - out_value;
    std::vector<spark::OutputCoinData> out_coin_data;
    out_coin_data.emplace_back();
    out_coin_data.back().address = address;
    out_coin_data.back().v = out_value;
    out_coin_data.back().memo = memo;

    std::map<uint64_t, uint256> block_hashes;
    block_hashes.emplace(cover_set_id, block_hash);

    spark::SpendTransaction tx(
        params, full_view_key, spend_key, spend_coin_data, cover_set_data,
        cover_sets, fee, 0, out_coin_data,
        spark::SpendTransactionVersion::V2, block_hash, block_hashes);
    tx.setCoverSets(cover_set_data);

    out_coins = tx.getOutCoins();
    tx_stream << tx;
}

// ── Stage 3g: spend over a CALLER-SUPPLIED cover set + owned note. ───────────
// The build_spend above uses an internal fixture wallet/cover set. These two
// functions let CoinCync drive a spend over a real cover set it holds (in the
// ShieldedStore): `mint_to_seed` produces a recoverable cover coin owned by the
// seed wallet, and `build_spend_over_set` recovers the owned coin at
// `spend_index` and builds+packs the verify bundle over the given cover set.
//
// Serial-context note (see coin.h): a serialized Coin carries S, K, C on the
// wire, so the VERIFIER needs no per-coin context. Only the PROVER needs the
// owned coin's context to recover (s, T); the caller supplies it here.

// The Grootle cover-set cardinality N = n_grootle ^ m_grootle for the active
// params. A caller sizes its cover set to this.
int spark_ffi_cover_set_size(void) {
    try {
        const spark::Params* params = spark::Params::get_test();
        return (int)pow(params->get_n_grootle(), params->get_m_grootle());
    } catch (...) {
        return -1;
    }
}

// Mint a COIN_TYPE_MINT coin to the seed wallet's own address, bound to the
// caller-supplied serial `context`, and serialize it into `out`. Returns the
// length, or -1 on error. The coin is recoverable/spendable by the same seed
// via build_spend_over_set with the identical context.
int spark_ffi_mint_to_seed(const unsigned char* seed, int seed_len, uint64_t value,
                           const unsigned char* ctx_ptr, int ctx_len,
                           unsigned char* out, int cap) {
    try {
        const spark::Params* params = spark::Params::get_test();
        spark::SpendKey spend(params, seed_to_r(seed, seed_len));
        spark::FullViewKey full(spend);
        spark::IncomingViewKey incoming(full);
        spark::Address addr(incoming, 0);

        Scalar k; k.randomize();
        std::vector<unsigned char> ctx(ctx_ptr, ctx_ptr + ctx_len);
        spark::Coin coin(params, spark::COIN_TYPE_MINT, k, addr, value, std::string("cover"), ctx);

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << coin;
        if ((int)ss.size() > cap) return -1;
        std::copy(ss.begin(), ss.end(), out);
        return (int)ss.size();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "mint_to_seed threw: %s\n", e.what());
        return -1;
    } catch (...) {
        return -1;
    }
}

// Build a spend over a CALLER-SUPPLIED cover set. `set_ptr` is
// [u32 count][ (u32 len)(coin bytes) ]... (little-endian lengths). The seed
// wallet must OWN `cover_set[spend_index]` (minted to its address with the
// serial `context` passed here). Recovers that coin, builds a single-input V2
// spend paying `output_value` back to the wallet (fee = input − output), and
// packs the same verify bundle `spark_ffi_verify_bundle` consumes. Returns the
// bundle length, or -1 on error (bad index, output_value ∉ (0, input), …).
//
// The output coin is paid to `recip_addr` (a bech32m Spark address) when
// `recip_addr_len > 0` — a shielded→shielded TRANSFER to another wallet — else
// back to the spender's own address (a change/consolidation self-spend). The
// output coin re-enters the pool (see spark_ffi_spend_outputs); the recipient
// recovers it by scanning with the same serial context the pool stores.
int spark_ffi_build_spend_over_set(const unsigned char* seed, int seed_len,
                                   const unsigned char* set_ptr, int set_len,
                                   uint64_t spend_index,
                                   const unsigned char* ctx_ptr, int ctx_len,
                                   uint64_t output_value,
                                   const unsigned char* recip_addr_ptr, int recip_addr_len,
                                   unsigned char* out, int cap) {
    try {
        const spark::Params* params = spark::Params::get_test();
        spark::SpendKey spend_key(params, seed_to_r(seed, seed_len));
        spark::FullViewKey full_view_key(spend_key);
        spark::IncomingViewKey incoming_view_key(full_view_key);

        // Parse the cover set: [u32 count][ (u32 len)(bytes) ]...
        std::size_t off = 0;
        auto need = [&](std::size_t n) {
            if (off + n > (std::size_t)set_len) throw std::runtime_error("cover set truncated");
        };
        auto rd_u32 = [&]() -> uint32_t {
            need(4);
            uint32_t v = (uint32_t)set_ptr[off] | ((uint32_t)set_ptr[off + 1] << 8) |
                         ((uint32_t)set_ptr[off + 2] << 16) | ((uint32_t)set_ptr[off + 3] << 24);
            off += 4;
            return v;
        };
        uint32_t count = rd_u32();
        std::vector<spark::Coin> cover_set;
        cover_set.reserve(count);
        for (uint32_t i = 0; i < count; i++) {
            uint32_t clen = rd_u32();
            need(clen);
            spark::Coin c(params);
            CDataStream in((const char*)set_ptr + off, (const char*)set_ptr + off + clen,
                           SER_NETWORK, PROTOCOL_VERSION);
            in >> c;
            c.setParams(params);
            cover_set.push_back(c);
            off += clen;
        }
        if (spend_index >= (uint64_t)cover_set.size()) {
            throw std::runtime_error("spend_index out of range");
        }

        // Only the spent coin needs its serial context (to recover s, T).
        std::vector<unsigned char> ctx(ctx_ptr, ctx_ptr + ctx_len);
        cover_set[(std::size_t)spend_index].setSerialContext(ctx);
        spark::IdentifiedCoinData id = cover_set[(std::size_t)spend_index].identify(incoming_view_key);
        spark::RecoveredCoinData rec = cover_set[(std::size_t)spend_index].recover(full_view_key, id);

        if (output_value == 0 || output_value >= id.v) {
            throw std::invalid_argument("output_value must be in (0, input_value)");
        }

        const uint64_t cover_set_id = 31415;
        std::vector<unsigned char> rep = cc_cover_set_rep(cover_set); // #258: deterministic
        uint256 block_hash = uint256();

        std::vector<spark::InputCoinData> spend_coin_data;
        spend_coin_data.emplace_back();
        spend_coin_data.back().cover_set_id = cover_set_id;
        spend_coin_data.back().index = (std::size_t)spend_index;
        spend_coin_data.back().k = id.k;
        spend_coin_data.back().s = rec.s;
        spend_coin_data.back().T = rec.T;
        spend_coin_data.back().v = id.v;

        std::unordered_map<uint64_t, spark::CoverSetData> cover_set_data;
        spark::CoverSetData sd;
        sd.cover_set_size = cover_set.size();
        sd.cover_set_representation = rep;
        cover_set_data[cover_set_id] = sd;
        std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;
        cover_sets[cover_set_id] = cover_set;

        const uint64_t fee = id.v - output_value;
        // Pay the output to the recipient's address (transfer) or back to the
        // spender (self-spend) when no recipient is supplied.
        spark::Address address(incoming_view_key, 0);
        if (recip_addr_len > 0) {
            std::string addr_str((const char*)recip_addr_ptr, (std::size_t)recip_addr_len);
            address.decode(addr_str);
        }
        std::vector<spark::OutputCoinData> out_coin_data;
        out_coin_data.emplace_back();
        out_coin_data.back().address = address;
        out_coin_data.back().v = output_value;
        out_coin_data.back().memo = "solvency";

        std::map<uint64_t, uint256> block_hashes;
        block_hashes.emplace(cover_set_id, block_hash);

        spark::SpendTransaction tx(
            params, full_view_key, spend_key, spend_coin_data, cover_set_data,
            cover_sets, fee, 0, out_coin_data,
            spark::SpendTransactionVersion::V2, block_hash, block_hashes);
        tx.setCoverSets(cover_set_data);
        std::vector<spark::Coin> out_coins = tx.getOutCoins();

        CDataStream tx_stream(SER_NETWORK, PROTOCOL_VERSION);
        tx_stream << tx;

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << cover_set_id;
        ss << rep;
        ss << block_hash;
        ss << cover_set;
        ss << out_coins;
        ss << (uint64_t)out_coins.size();
        ss.insert(ss.end(), tx_stream.begin(), tx_stream.end());

        if ((int)ss.size() > cap) return -1;
        std::copy(ss.begin(), ss.end(), out);
        return (int)ss.size();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "build_spend_over_set threw: %s\n", e.what());
        return -1;
    } catch (...) {
        return -1;
    }
}

// Extract a spend bundle's OUTPUT coins (the spend's change/payments) and their
// shared serial context, so the pool can be fed with them (symmetric with the
// mint feed). libspark derives an output coin's serial context as the
// serialization of the spend's linking tags T (spend_transaction.cpp), so it is
// deterministic + recoverable. Writes coins as [u32 count][ (u32 len)(bytes) ]
// to `out_coins` and the context bytes to `out_ctx`. Returns 1 on success.
int spark_ffi_spend_outputs(const unsigned char* ptr, int len,
                            unsigned char* out_coins, int coins_cap, int* out_coins_len,
                            unsigned char* out_ctx, int ctx_cap, int* out_ctx_len) {
    try {
        const spark::Params* params = spark::Params::get_test();
        CDataStream ss((const char*)ptr, (const char*)ptr + len, SER_NETWORK, PROTOCOL_VERSION);
        uint64_t cover_set_id;
        std::vector<unsigned char> rep;
        uint256 block_hash;
        std::vector<spark::Coin> cover_set, out_coins_v;
        uint64_t output_count;
        ss >> cover_set_id;
        ss >> rep;
        ss >> block_hash;
        ss >> cover_set;
        ss >> out_coins_v;
        ss >> output_count;
        spark::SpendTransaction tx(params, spark::SpendTransactionVersion::V2, (std::size_t)output_count);
        ss >> tx;

        // Output coin serial context = serialize(spend tags T), per libspark
        // (spend_transaction.cpp). `getUsedLTags()` exposes the same tags T.
        CDataStream sc(SER_NETWORK, PROTOCOL_VERSION);
        sc << tx.getUsedLTags();
        if ((int)sc.size() > ctx_cap) return 0;
        std::copy(sc.begin(), sc.end(), out_ctx);
        *out_ctx_len = (int)sc.size();

        // Serialize the output coins: [u32 count][ (u32 len)(bytes) ]...
        std::vector<unsigned char> cbuf;
        auto put_u32 = [&](uint32_t v) {
            cbuf.push_back(v & 0xff);
            cbuf.push_back((v >> 8) & 0xff);
            cbuf.push_back((v >> 16) & 0xff);
            cbuf.push_back((v >> 24) & 0xff);
        };
        put_u32((uint32_t)out_coins_v.size());
        for (auto& c : out_coins_v) {
            CDataStream cs(SER_NETWORK, PROTOCOL_VERSION);
            cs << c;
            put_u32((uint32_t)cs.size());
            cbuf.insert(cbuf.end(), cs.begin(), cs.end());
        }
        if ((int)cbuf.size() > coins_cap) return 0;
        std::copy(cbuf.begin(), cbuf.end(), out_coins);
        *out_coins_len = (int)cbuf.size();
        return 1;
    } catch (...) {
        return 0;
    }
}

// Stateless extraction of a spend bundle's linking tags T (`getUsedLTags`), for
// mempool double-spend dedup on UNTRUSTED P2P input. Unlike spark_ffi_verify_bundle
// it does NOT verify the proof and needs no cover set; unlike spark_ffi_spend_outputs
// it does not extract output coins. It bounds the attacker-controlled
// `output_count` BEFORE constructing the SpendTransaction — the one unbounded
// allocation on this path (the preceding vector reads are chunk-capped by the
// serialization framework) — so a crafted bundle cannot force a large allocation.
// Writes tags as [u32 count][serialize_size-byte tag]... (same wire form as
// spark_ffi_verify_bundle) and returns 1; returns 0 on malformed/oversized input
// (fail-closed). The returned tags are a deterministic function of the spent
// coin(s) regardless of proof validity, so two spends of the same coin yield the
// same tag — exactly what the mempool needs to reject a conflicting second spend.
#define SPARK_FFI_MAX_SPEND_OUTPUTS 64
int spark_ffi_spend_ltags(const unsigned char* ptr, int len,
                          unsigned char* out_tags, int tags_cap, int* out_tags_len) {
    try {
        const spark::Params* params = spark::Params::get_test();
        CDataStream ss((const char*)ptr, (const char*)ptr + len, SER_NETWORK, PROTOCOL_VERSION);
        uint64_t cover_set_id;
        std::vector<unsigned char> rep;
        uint256 block_hash;
        std::vector<spark::Coin> cover_set, out_coins;
        uint64_t output_count;
        ss >> cover_set_id;
        ss >> rep;
        ss >> block_hash;
        ss >> cover_set;
        ss >> out_coins;
        ss >> output_count;
        // DoS bound: output_count is read raw (not via the chunk-capped vector
        // reader) and sizes the SpendTransaction's internal vectors. A legitimate
        // spend has a handful of outputs; reject anything absurd before building.
        if (output_count > SPARK_FFI_MAX_SPEND_OUTPUTS) return 0;
        spark::SpendTransaction tx(params, spark::SpendTransactionVersion::V2, (std::size_t)output_count);
        ss >> tx;

        const std::vector<GroupElement>& tags = tx.getUsedLTags();
        const int enc = (int)GroupElement::serialize_size;
        int need = 4 + (int)tags.size() * enc;
        if (need > tags_cap) return 0;
        uint32_t n = (uint32_t)tags.size();
        out_tags[0] = (unsigned char)(n & 0xff);
        out_tags[1] = (unsigned char)((n >> 8) & 0xff);
        out_tags[2] = (unsigned char)((n >> 16) & 0xff);
        out_tags[3] = (unsigned char)((n >> 24) & 0xff);
        for (std::size_t i = 0; i < tags.size(); i++) {
            tags[i].serialize(out_tags + 4 + (int)i * enc);
        }
        *out_tags_len = need;
        return 1;
    } catch (...) {
        return 0;
    }
}

// ── Mint bundle: authenticated shield-in (transparent -> shielded). ─────────
// A libspark MintTransaction proves each coin's value commitment C opens to its
// PUBLIC value v (a Schnorr proof over C − G·v = H·hash_val(k)), so a verifier
// can trust the minted values without the recipient's view key. Wire format
// (raw, little-endian): [u32 count][ (u32 len)(coin stream) ]..., where the
// first coin stream also carries the value proof (libspark's own layout).

#include "mint_transaction.h"

// Build a mint bundle to the seed wallet's address for `values`, bound to the
// serial `context`. Serializes the MintTransaction. Returns length or -1.
int spark_ffi_build_mint_bundle(const unsigned char* seed, int seed_len,
                                const uint64_t* values, int n_values,
                                const unsigned char* ctx_ptr, int ctx_len,
                                unsigned char* out, int cap) {
    try {
        const spark::Params* params = spark::Params::get_test();
        spark::SpendKey spend(params, seed_to_r(seed, seed_len));
        spark::FullViewKey full(spend);
        spark::IncomingViewKey incoming(full);
        spark::Address addr(incoming, 0);
        std::vector<unsigned char> ctx(ctx_ptr, ctx_ptr + ctx_len);

        std::vector<spark::MintedCoinData> outs;
        for (int i = 0; i < n_values; i++) {
            spark::MintedCoinData d;
            d.address = addr;
            d.v = values[i];
            d.memo = "mint";
            outs.push_back(d);
        }
        spark::MintTransaction mint(params, outs, ctx, true);
        std::vector<CDataStream> streams = mint.getMintedCoinsSerialized();

        std::vector<unsigned char> buf;
        auto put_u32 = [&](uint32_t v) {
            buf.push_back(v & 0xff);
            buf.push_back((v >> 8) & 0xff);
            buf.push_back((v >> 16) & 0xff);
            buf.push_back((v >> 24) & 0xff);
        };
        put_u32((uint32_t)streams.size());
        for (auto& s : streams) {
            put_u32((uint32_t)s.size());
            buf.insert(buf.end(), s.begin(), s.end());
        }
        if ((int)buf.size() > cap) return -1;
        std::copy(buf.begin(), buf.end(), out);
        return (int)buf.size();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "build_mint_bundle threw: %s\n", e.what());
        return -1;
    } catch (...) {
        return -1;
    }
}

// Verify a mint bundle and, on success, write the total authenticated minted
// value (Σ v) to `out_total` AND the individual coins to `out_coins` as
// [u32 count][ (u32 len)(coin bytes) ]... (the same shape the cover-set /
// build_spend_over_set path consumes) so the caller can feed them to the pool.
// Returns 1 iff the value proof verifies, the sum does not overflow, and the
// coins fit; 0 otherwise (fail-closed).
int spark_ffi_verify_mint_bundle(const unsigned char* ptr, int len, uint64_t* out_total,
                                 unsigned char* out_coins, int coins_cap, int* out_coins_len) {
    try {
        const spark::Params* params = spark::Params::get_test();
        std::size_t off = 0;
        auto need = [&](std::size_t n) {
            if (off + n > (std::size_t)len) throw std::runtime_error("mint bundle truncated");
        };
        auto rd_u32 = [&]() -> uint32_t {
            need(4);
            uint32_t v = (uint32_t)ptr[off] | ((uint32_t)ptr[off + 1] << 8) |
                         ((uint32_t)ptr[off + 2] << 16) | ((uint32_t)ptr[off + 3] << 24);
            off += 4;
            return v;
        };
        uint32_t count = rd_u32();
        if (count == 0) return 0;
        std::vector<CDataStream> streams;
        streams.reserve(count);
        for (uint32_t i = 0; i < count; i++) {
            uint32_t sl = rd_u32();
            need(sl);
            streams.emplace_back((const char*)ptr + off, (const char*)ptr + off + sl,
                                 SER_NETWORK, PROTOCOL_VERSION);
            off += sl;
        }
        spark::MintTransaction mint(params);
        mint.setMintTransaction(streams);
        if (!mint.verify()) return 0;

        std::vector<spark::Coin> coins;
        mint.getCoins(coins);
        uint64_t total = 0;
        for (auto& c : coins) {
            c.setParams(params);
            if (total > std::numeric_limits<uint64_t>::max() - c.v) return 0; // overflow
            total += c.v;
        }

        // Serialize the coins for the caller: [u32 count][ (u32 len)(bytes) ]...
        std::vector<unsigned char> cbuf;
        auto put_u32 = [&](uint32_t v) {
            cbuf.push_back(v & 0xff);
            cbuf.push_back((v >> 8) & 0xff);
            cbuf.push_back((v >> 16) & 0xff);
            cbuf.push_back((v >> 24) & 0xff);
        };
        put_u32((uint32_t)coins.size());
        for (auto& c : coins) {
            CDataStream cs(SER_NETWORK, PROTOCOL_VERSION);
            cs << c;
            put_u32((uint32_t)cs.size());
            cbuf.insert(cbuf.end(), cs.begin(), cs.end());
        }
        if ((int)cbuf.size() > coins_cap) return 0;
        std::copy(cbuf.begin(), cbuf.end(), out_coins);
        *out_coins_len = (int)cbuf.size();
        *out_total = total;
        return 1;
    } catch (...) {
        return 0;
    }
}

// Derive a DETERMINISTIC 32-byte serial context from an opaque outpoint
// identifier (e.g. tx_hash ‖ output_index). Mint and spend MUST pass the
// identical outpoint so the recovered (s, T) match the on-wire serial
// commitment S. Domain-separated so it can never collide with other hashes.
// Writes 32 bytes; returns 32, or -1 on error.
int spark_ffi_serial_context(const unsigned char* op_ptr, int op_len,
                             unsigned char* out, int cap) {
    try {
        if (cap < 32) return -1;
        spark::Hash h(std::string("coincync_spark_serial_ctx_v1"));
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        std::vector<unsigned char> ov(op_ptr, op_ptr + op_len);
        s << ov;
        h.include(s);
        Scalar sc = h.finalize_scalar();
        sc.serialize(out); // canonical 32-byte scalar encoding
        return 32;
    } catch (...) {
        return -1;
    }
}

} // extern "C"
