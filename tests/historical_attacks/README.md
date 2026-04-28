# Historical Attack Test Suite

Each test in this directory corresponds to a **named, dated, documented** historical attack against a real blockchain. Tests assert CoinCync is not vulnerable.

## Status Table

| Date | Chain | Attack | CVE | Applicable | Test File | Status |
|------|-------|--------|-----|-----------|-----------|--------|
| 2010-08 | Bitcoin | Value overflow (184B BTC created) | CVE-2010-5139 | **yes** | `bitcoin_2010_value_overflow.rs` | ✓ pass |
| 2018-09 | Bitcoin | Duplicate input inflation | CVE-2018-17144 | **yes** | `bitcoin_2018_inflation.rs` | ✓ pass |
| 2017-04 | Monero | Key image validation bypass | — | **yes** | `monero_2017_key_image.rs` | ✓ pass |
| 2019-11 | Monero | check_money_overflow | CVE-2019-18936 | **yes** | `monero_2019_overflow.rs` | ✓ pass |
| 2020-07 | Monero | Janus attack (subaddress linking) | — | **yes** | `monero_2020_janus.rs` | ✓ pass |
| 2018-09 | Monero | Burning bug (provably unspendable) | — | **yes** | `monero_2018_burning_bug.rs` | ✓ pass |
| 2018-04 | Verge | Timestamp manipulation attack | — | **yes** | `verge_2018_timestamp.rs` | ✓ pass |
| 2019-01 | ETC | 51% attack / 100+ block reorg | — | **yes** | `etc_2019_deep_reorg.rs` | ✓ pass |
| 2017 | Monero | Ring traceability (academic paper) | — | **yes** | `monero_ring_linkability.rs` | ✓ pass |
| 2018-03 | Zcash | Groth16 counterfeiting flaw | — | **partial** | `zcash_2018_proof_forgery.rs` | ✓ pass |
| 2016-06 | Ethereum | The DAO (reentrancy) | — | no | — | n/a (no contracts) |
| 2017-11 | Ethereum | Parity multisig freeze | — | no | — | n/a (no contracts) |
| 2018-05 | Bitcoin Gold | 51% + exchange double-spend | — | **yes** | covered by `etc_2019_deep_reorg.rs` | ✓ pass |
| 2018-06 | Horizen | 51% + deep reorg | — | **yes** | covered by `etc_2019_deep_reorg.rs` | ✓ pass |

## Citations

- **CVE-2010-5139**: https://en.bitcoin.it/wiki/Value_overflow_incident
- **CVE-2018-17144**: https://bitcoincore.org/en/2018/09/20/notice/
- **Monero key image bug**: https://www.getmonero.org/2017/05/17/disclosure-of-a-major-bug-in-cryptonote-based-currencies.html
- **CVE-2019-18936**: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18936
- **Janus attack**: https://web.getmonero.org/2020/09/17/note-on-subaddresses.html
- **Burning bug**: https://www.getmonero.org/2018/09/25/a-]post-mortem-of-the-burning-bug.html
- **Verge timestamp**: https://bitcointalk.org/index.php?topic=3256693.0
- **ETC 51%**: https://blog.coinbase.com/ethereum-classic-etc-is-currently-being-51-attacked-33be13ce32de
- **Ring traceability**: Miller et al., "An Empirical Analysis of Traceability in the Monero Blockchain" (2017), PoPETs
- **Zcash flaw**: https://electriccoin.co/blog/zcash-counterfeiting-vulnerability-successfully-remediated/

## Not Applicable (documented for completeness)

| Attack | Why N/A |
|--------|---------|
| The DAO (2016) | CoinCync has no smart contracts — no reentrancy surface |
| Parity freeze (2017) | No delegated library contracts |
| Electrum phishing (2018+) | Our wallet does not fetch updates from node RPC |
| SolarWinds supply chain (2020) | Build reproducibility is operational, not testable in code |

## Methodology

1. Each test constructs the **exact** attack pattern from the historical incident
2. Asserts our validation **rejects** it with an appropriate error
3. Failure message names the CVE/attack so CI logs are immediately interpretable
4. Tests run against real code paths (no mocks)

## Adding New Attacks

When a new incident occurs on any blockchain:
1. Create `<chain>_<year>_<name>.rs`
2. Add doc comment with date, chain, CVE, citation, impact
3. Write 2-3 tests reproducing the attack pattern
4. Add to `mod.rs`
5. Add to this README table
