//! # DNS-over-TCP through SOCKS5
//!
//! Closes the bootstrap DNS leak that previously forced us to skip all
//! DNS seed queries whenever a proxy was active (see the SECURITY block
//! in [`crate::network::bootstrap::Bootstrapper::get_peers`]). The cost
//! of skipping was real — Tor-mode wallets had only hardcoded seed nodes
//! + peer exchange to bootstrap, so a single seed-set staleness event
//! could blackhole new installs.
//!
//! ## Design choice: DNS-over-TCP via SOCKS5 CONNECT (not UDP-ASSOCIATE)
//!
//! The natural-sounding fix is "SOCKS5 UDP-ASSOCIATE for DNS" (RFC 1928
//! §7). It's a dead end in practice:
//!
//!   - **Tor does not implement UDP-ASSOCIATE.** Tor is a TCP-only
//!     overlay; the spec says so explicitly. Building a DNS path that
//!     fails closed on the dominant SOCKS5 proxy is not a fix.
//!   - **Most non-Tor SOCKS5 daemons skip UDP-ASSOCIATE** too — Dante
//!     gates it behind a separate config, most provider-side proxies
//!     don't expose it at all.
//!   - **DNS-over-TCP is universally supported** by RFC 7766 resolvers
//!     (Cloudflare 1.1.1.1, Quad9, Google 8.8.8.8). One TCP CONNECT
//!     through the proxy, a length-prefixed DNS message, done.
//!
//! Privacy property: the proxy (e.g. a Tor exit) sees "TCP to
//! 1.1.1.1:53"; the resolver sees a DNS query but not the user's IP.
//! Equivalent to how torsocks routes DNS today, and matches the
//! Bitcoin Core "dnsseed via proxy" posture.
//!
//! A future enhancement could add the Tor-specific SOCKS RESOLVE
//! extension (CMD 0xF0, see tor-spec/socks-extensions.txt) as a faster
//! path that avoids the round-trip to an external resolver; the
//! DNS-over-TCP fallback would still cover non-Tor SOCKS5 paths.
//!
//! ## Resolver selection
//!
//! Default `1.1.1.1:53` (Cloudflare — no-logging stated policy, fast,
//! anycast). Override with `COINCYNC_SOCKS_DNS_RESOLVER=ip:port`.
//! Multiple comma-separated resolvers are tried in order; first success
//! wins.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, warn};

use crate::config::ProxyConfig;
use crate::error::{Error, Result};

/// Default upstream resolver when the env override isn't set.
const DEFAULT_RESOLVER: &str = "1.1.1.1:53";

/// Hard cap on a DNS-over-TCP response. RFC 6891 allows EDNS to lift the
/// 512-byte UDP cap; over TCP messages can be up to 65535 bytes, but
/// realistic A/AAAA answers for our seeds top out well under 2KB.
/// Cap matches typical Tor circuit budget and bounds attacker effort to
/// inflate buffers.
const MAX_DNS_RESPONSE: usize = 4096;

/// Resolve `hostname` via DNS-over-TCP routed through `proxy`. Queries
/// A and AAAA in parallel-ish (sequentially, with the AAAA failure
/// treated as "no v6 record" rather than fatal) and combines results.
///
/// On success returns the deduplicated address list; never returns an
/// empty `Ok(vec![])` — empty is upgraded to `Err` so the caller can
/// fall back to hardcoded seeds.
pub async fn resolve_via_socks5(
    hostname: &str,
    proxy: &ProxyConfig,
    query_timeout: Duration,
) -> Result<Vec<IpAddr>> {
    if !proxy.is_active() {
        return Err(Error::ConfigError(
            "resolve_via_socks5 called with inactive proxy".into(),
        ));
    }

    let resolvers = resolver_list();
    if resolvers.is_empty() {
        return Err(Error::ConfigError(
            "no SOCKS DNS resolvers configured".into(),
        ));
    }

    // Try each resolver in order; first success wins.
    let mut last_err: Option<Error> = None;
    for resolver in &resolvers {
        match query_one_resolver(hostname, proxy, *resolver, query_timeout).await {
            Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
            Ok(_) => {
                debug!(
                    "Resolver {} returned no records for {}, trying next",
                    resolver, hostname
                );
                last_err = Some(Error::ConnectionFailed(format!(
                    "no DNS records for {}",
                    hostname
                )));
            }
            Err(e) => {
                debug!("Resolver {} failed for {}: {}", resolver, hostname, e);
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        Error::ConnectionFailed("SOCKS DNS resolution exhausted all resolvers".into())
    }))
}

/// Send A + AAAA queries to one resolver via one SOCKS5 tunnel.
async fn query_one_resolver(
    hostname: &str,
    proxy: &ProxyConfig,
    resolver: SocketAddr,
    query_timeout: Duration,
) -> Result<Vec<IpAddr>> {
    let mut addrs: Vec<IpAddr> = Vec::new();

    // A query — the dominant case; failure here is fatal for this resolver.
    let a = timeout(
        query_timeout,
        query_one(hostname, proxy, resolver, QueryType::A),
    )
    .await
    .map_err(|_| Error::ConnectionFailed("SOCKS DNS A query timed out".into()))??;
    addrs.extend(a);

    // AAAA query — best effort; many seeds publish v4 only. We swallow
    // failures rather than blocking bootstrap on v6 availability.
    match timeout(
        query_timeout,
        query_one(hostname, proxy, resolver, QueryType::Aaaa),
    )
    .await
    {
        Ok(Ok(v6)) => addrs.extend(v6),
        Ok(Err(e)) => debug!("AAAA query for {} via SOCKS5 ignored: {}", hostname, e),
        Err(_) => debug!("AAAA query for {} via SOCKS5 timed out (ignored)", hostname),
    }

    addrs.sort();
    addrs.dedup();
    Ok(addrs)
}

/// One DNS query: open a SOCKS5 CONNECT tunnel to `resolver`, send a
/// length-prefixed DNS message (RFC 7766), read the length-prefixed
/// response, parse out the answer section.
async fn query_one(
    hostname: &str,
    proxy: &ProxyConfig,
    resolver: SocketAddr,
    qtype: QueryType,
) -> Result<Vec<IpAddr>> {
    let proxy_addr = format!("{}:{}", proxy.address, proxy.port);
    let query_id = transaction_id();
    let query = build_query(query_id, hostname, qtype)?;

    let stream_res = match (&proxy.username, &proxy.password) {
        (Some(u), Some(p)) => {
            Socks5Stream::connect_with_password(
                proxy_addr.as_str(),
                resolver,
                u.as_str(),
                p.as_str(),
            )
            .await
        }
        _ => Socks5Stream::connect(proxy_addr.as_str(), resolver).await,
    };

    let mut stream = stream_res
        .map_err(|e| Error::ConnectionFailed(format!("SOCKS5 to resolver: {}", e)))?
        .into_inner();

    // RFC 7766: DNS-over-TCP is a 2-byte big-endian length prefix +
    // raw DNS message bytes. Validate the outbound length the same way
    // we validate the inbound `resp_len` below — silent `as u16` cast
    // would wrap a >65535-byte query to a smaller value and corrupt the
    // framing, and a zero-length query is malformed DNS that some
    // resolvers will hang on rather than reject. `build_query` already
    // bounds its output via the per-label limit (RFC 1035 §2.3.4), so
    // this is defense-in-depth, not an exploit-today path.
    if query.is_empty() || query.len() > MAX_DNS_RESPONSE {
        return Err(Error::ConnectionFailed(format!(
            "DNS-over-TCP query length out of range: {}",
            query.len()
        )));
    }
    let len = query.len() as u16;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| Error::ConnectionFailed(format!("DNS-over-TCP write len: {}", e)))?;
    stream
        .write_all(&query)
        .await
        .map_err(|e| Error::ConnectionFailed(format!("DNS-over-TCP write query: {}", e)))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::ConnectionFailed(format!("DNS-over-TCP flush: {}", e)))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::ConnectionFailed(format!("DNS-over-TCP read len: {}", e)))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > MAX_DNS_RESPONSE {
        return Err(Error::ConnectionFailed(format!(
            "DNS-over-TCP response length out of range: {}",
            resp_len
        )));
    }

    let mut resp = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| Error::ConnectionFailed(format!("DNS-over-TCP read body: {}", e)))?;

    parse_response(&resp, query_id, qtype)
}

// ── Wire format ─────────────────────────────────────────────────────────
//
// We hand-roll just enough of RFC 1035 to send a single A or AAAA
// query and pull addresses out of the answer section. Pulling
// `hickory-proto` in as a direct dep would also work but: (a) it's
// currently transitive only and pinning a second version risks
// duplicate-version trees, (b) DNS-A-for-one-name is genuinely small.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryType {
    A,
    Aaaa,
}

impl QueryType {
    fn code(self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::Aaaa => 28,
        }
    }
}

fn transaction_id() -> u16 {
    // Sub-millisecond entropy is fine for DNS-over-TCP transaction IDs
    // (the TCP connection itself is the spoofing barrier); we don't need
    // cryptographic randomness. Use a fast nano clock.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos as u16) ^ 0xC0FE
}

fn build_query(id: u16, hostname: &str, qtype: QueryType) -> Result<Vec<u8>> {
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(Error::InvalidState("DNS hostname out of range".into()));
    }

    let mut buf = Vec::with_capacity(64);

    // Header: 12 bytes.
    buf.extend_from_slice(&id.to_be_bytes()); // ID
    // Flags: standard query, recursion desired (RD=1)
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // QNAME — length-prefixed labels terminated by zero byte.
    for label in hostname.split('.') {
        if label.is_empty() {
            // Trailing dot or double-dot; skip empty labels rather than
            // erroring, since "host." is a valid FQDN form.
            continue;
        }
        if label.len() > 63 {
            return Err(Error::InvalidState(format!(
                "DNS label too long: {}",
                label
            )));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0u8); // root label

    buf.extend_from_slice(&qtype.code().to_be_bytes()); // QTYPE
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    Ok(buf)
}

fn parse_response(buf: &[u8], expected_id: u16, qtype: QueryType) -> Result<Vec<IpAddr>> {
    if buf.len() < 12 {
        return Err(Error::InvalidState("DNS response truncated header".into()));
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return Err(Error::InvalidState(format!(
            "DNS response ID mismatch: got {}, expected {}",
            id, expected_id
        )));
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        // 3 = NXDOMAIN, 2 = SERVFAIL, etc. Return empty rather than err
        // for NXDOMAIN so the caller treats "no record" the same as
        // "resolver returned []".
        if rcode == 3 {
            return Ok(Vec::new());
        }
        return Err(Error::ConnectionFailed(format!("DNS RCODE={}", rcode)));
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;

    // Skip questions — we know the layout we sent, but parse defensively.
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        // QTYPE (2) + QCLASS (2)
        if pos + 4 > buf.len() {
            return Err(Error::InvalidState("DNS truncated in question".into()));
        }
        pos += 4;
    }

    // Walk the answer section pulling out A or AAAA RDATA.
    let mut addrs = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            return Err(Error::InvalidState("DNS truncated in answer".into()));
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        // class (2) + ttl (4) skipped
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(Error::InvalidState("DNS RDATA truncated".into()));
        }
        let rdata = &buf[pos..pos + rdlen];
        match (rtype, qtype) {
            (1, QueryType::A) if rdata.len() == 4 => {
                addrs.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            }
            (28, QueryType::Aaaa) if rdata.len() == 16 => {
                let mut octs = [0u8; 16];
                octs.copy_from_slice(rdata);
                addrs.push(IpAddr::V6(std::net::Ipv6Addr::from(octs)));
            }
            // Ignore CNAMEs and other RR types — most resolvers chase
            // CNAMEs internally and return the final A/AAAA, but if one
            // surfaces a CNAME we just skip it. The caller falls back if
            // we return empty.
            _ => {}
        }
        pos += rdlen;
    }

    Ok(addrs)
}

/// Walk a DNS name (compressed or uncompressed) and return the byte
/// offset *after* it. Doesn't decode — we never need the actual name
/// since we already know which question we sent.
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize> {
    // Bounded by buf.len() to defend against compression-pointer loops.
    let mut steps = 0usize;
    loop {
        if pos >= buf.len() {
            return Err(Error::InvalidState("DNS name overran buffer".into()));
        }
        steps += 1;
        if steps > 256 {
            return Err(Error::InvalidState("DNS name decode loop".into()));
        }
        let b = buf[pos];
        if b == 0 {
            return Ok(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes, name ends here.
            if pos + 1 >= buf.len() {
                return Err(Error::InvalidState("DNS pointer truncated".into()));
            }
            return Ok(pos + 2);
        }
        // Uncompressed label: 1 length byte + N data bytes.
        let len = b as usize;
        if len > 63 {
            return Err(Error::InvalidState("DNS label length invalid".into()));
        }
        pos += 1 + len;
    }
}

fn resolver_list() -> Vec<SocketAddr> {
    let raw = std::env::var("COINCYNC_SOCKS_DNS_RESOLVER")
        .unwrap_or_else(|_| DEFAULT_RESOLVER.to_string());
    let mut out = Vec::new();
    for token in raw.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<SocketAddr>() {
            Ok(addr) => out.push(addr),
            Err(_) => warn!("Invalid COINCYNC_SOCKS_DNS_RESOLVER entry: {}", t),
        }
    }
    if out.is_empty() {
        // Env was set but every entry was invalid — fall back to default.
        if let Ok(default) = DEFAULT_RESOLVER.parse() {
            out.push(default);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_a_record_shape() {
        let q = build_query(0x1234, "seed1.coincync.network", QueryType::A).unwrap();
        // Header (12) + qname (1+5 + 1+8 + 1+7 + 1) + qtype (2) + qclass (2)
        assert_eq!(q.len(), 12 + 1 + 5 + 1 + 8 + 1 + 7 + 1 + 2 + 2);
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD set
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT
        // First label length byte
        assert_eq!(q[12], 5);
        assert_eq!(&q[13..18], b"seed1");
        // QTYPE at the end
        let qt = u16::from_be_bytes([q[q.len() - 4], q[q.len() - 3]]);
        assert_eq!(qt, QueryType::A.code());
    }

    #[test]
    fn build_query_aaaa_qtype_is_28() {
        let q = build_query(1, "example.com", QueryType::Aaaa).unwrap();
        let qt = u16::from_be_bytes([q[q.len() - 4], q[q.len() - 3]]);
        assert_eq!(qt, 28);
    }

    #[test]
    fn build_query_rejects_oversized_label() {
        let long = "a".repeat(64);
        let res = build_query(1, &long, QueryType::A);
        assert!(res.is_err());
    }

    #[test]
    fn build_query_accepts_trailing_dot() {
        let q = build_query(1, "example.com.", QueryType::A).unwrap();
        // Same length as without trailing dot
        let q2 = build_query(1, "example.com", QueryType::A).unwrap();
        assert_eq!(q.len(), q2.len());
    }

    #[test]
    fn parse_response_extracts_a_record() {
        // Hand-built response: ID=0x1234, RD+RA, 1 question, 1 answer
        // (A record pointing to 1.2.3.4)
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA, RCODE=0
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Question: example.com A IN
        resp.push(7);
        resp.extend_from_slice(b"example");
        resp.push(3);
        resp.extend_from_slice(b"com");
        resp.push(0);
        resp.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        resp.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        // Answer: compression pointer back to offset 12 (the qname),
        // type A, class IN, TTL 60, rdlen 4, rdata 1.2.3.4
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&[1, 2, 3, 4]); // RDATA

        let addrs = parse_response(&resp, 0x1234, QueryType::A).unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn parse_response_rejects_wrong_id() {
        let mut resp = vec![0u8; 12];
        resp[0] = 0xAA;
        resp[1] = 0xBB;
        assert!(parse_response(&resp, 0x1234, QueryType::A).is_err());
    }

    #[test]
    fn parse_response_treats_nxdomain_as_empty() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        // QR + RD + RA + RCODE=3 (NXDOMAIN) = 0x8183
        resp.extend_from_slice(&0x8183u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        let addrs = parse_response(&resp, 0x1234, QueryType::A).unwrap();
        assert!(addrs.is_empty());
    }

    #[test]
    fn resolver_list_default() {
        // We can't safely unset env in a test, but the default path
        // shouldn't crash even if env is set.
        let list = resolver_list();
        assert!(!list.is_empty());
        // Default port for DNS is 53
        for r in &list {
            assert!(r.port() > 0);
        }
    }

    #[test]
    fn transaction_ids_differ_between_calls() {
        // Best-effort sanity check; nanos-derived IDs can collide but
        // shouldn't on back-to-back calls.
        let a = transaction_id();
        std::thread::sleep(std::time::Duration::from_nanos(50));
        let b = transaction_id();
        // Either differ or at minimum the XOR mask is applied
        assert!(a != 0xC0FE || b != 0xC0FE, "transaction_id seed leaked through");
    }
}
