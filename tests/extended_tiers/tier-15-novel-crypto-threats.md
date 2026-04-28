# Tier 15 — Novel Cryptographic Threats Watch List

_Quarterly review. Last reviewed: 2026-04-20. Next: 2026-07-20._

---

## Currently tracked

| ID | Threat | Status | Action |
|----|--------|--------|--------|
| T15.1 | Ring signature statistical traceability | Active research | Monitor; match Monero's ring selection |
| T15.2 | Stealth address linkability (Janus) | Patched in Monero | Verify our implementation matches fix |
| T15.3 | Bulletproofs+ soundness | No known issues | Track upstream library updates |
| T15.4 | Pedersen commitment binding loss | Requires DL break | Track PQ timeline (Tier 12) |
| T15.5 | Hash function compromise (SHA-256) | No known issues | Use 256-bit outputs everywhere |
| T15.6 | RandomX ASIC development | No public ASICs | Track Monero's decisions |
| T15.7 | Nonce leakage in CLSAG | Deterministic nonces used | Run timing tests (Tier 9) |
| T15.8 | Transaction graph analysis at scale | Active research area | Commission privacy analysis pre-mainnet |

## Sources to check quarterly

- IACR ePrint (eprint.iacr.org) — "ring signature", "stealth address", "Bulletproofs"
- Monero Research Lab
- Zcash Foundation research
- RustSec advisory database
- NIST PQC announcements
- Chainalysis public reports

## Threat response process

1. **Classify:** Imminent / Near-term / Long-term / Speculative
2. **Assess:** Does it affect our primitives? Our implementation?
3. **Decide:** Immediate patch / Planned migration / Research tracking / Monitor only
4. **Document:** Add to this file, update advisories
5. **Test:** Add regression test if testable
