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
    std::vector<unsigned char> rep(32);
    { Scalar t; t.randomize(); t.serialize(rep.data()); }
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

} // extern "C"
