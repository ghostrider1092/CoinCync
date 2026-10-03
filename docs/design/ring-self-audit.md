# Ring self-audit lint (privacy)

**Status:** implemented (advisory, wallet-side, non-consensus).

`audit_ring_ages(member_heights, spend_height)` flags a just-built ring whose
decoy ages cluster in a single order of magnitude — a weak ring that makes the
real spend easier to distinguish. Returns `RingAudit { ok, distinct_age_decades,
age_spread, reason }`. Rings smaller than 3 are treated as OK (bootstrap).

Advisory only: consensus validates ring membership/size/maturity, never
selection quality, so a wallet can use this to warn or rebuild without any
chain-level effect. Heuristic; unit-tested (clustered → flagged, spread → OK).
