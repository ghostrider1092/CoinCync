# Standardized fee tiers (privacy)

**Status:** implemented, OFF by default (audit-gated); wallet-side, non-consensus.

`round_up_to_fee_tier` rounds an atomic fee UP to the next value on a 1–2–5×10^k
ladder, so distinct wallets converge on a small set of fee amounts and the
per-wallet fee-amount fingerprint disappears (Monero-style). `standardized_fee`
applies it to a tx shape. Overflow-safe, pure, unit-tested.

NOT on the default send path — the shipped wallet pays the exact fee. This is
built + tested for an audited opt-in (flipping it trades a small overpay for fee
uniformity), consistent with the testnet-only / mainnet-parked posture. Consensus
never constrains the fee amount beyond the minimum, so this cannot fork the chain.
