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
#include <cstdint>
#include <vector>
#include <string>

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

} // extern "C"
