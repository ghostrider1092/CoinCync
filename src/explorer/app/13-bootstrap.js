// ── INIT ──────────────────────────────────────────────────────
// 4-second polling cadence — fast enough to feel real-time on a 120s
// block target, slow enough not to hammer the public RPC. The home page's
// stat cards, anonymity-set counter, and live-feed all read from this poll.
poll();setInterval(poll,4000);

//
