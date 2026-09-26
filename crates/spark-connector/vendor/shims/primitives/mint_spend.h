#pragma once
// SPIKE SHIM (replaces Firo NODE primitives/mint_spend.h). libspark's Spark
// Coin/tag path doesn't call these; coin.h's legacy PublicCoin::getValueHash
// only needs the symbol DECLARED (not defined) to compile.
#include "uint256.h"
#include "include/GroupElement.h"
namespace primitives {
    uint256 GetPubCoinValueHash(const secp_primitives::GroupElement& bcoin);
}
