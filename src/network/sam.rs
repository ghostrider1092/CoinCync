//! SAM v3 client for I2P — dial `.b32.i2p` peers through a local SAM bridge
//! (i2pd or Java I2P, default `127.0.0.1:7656`).
//!
//! This fills the network-transport gap Monero's **Kovri** left unfinished:
//! anonymous peer connections over I2P, alongside the Tor onion transport. A
//! node that runs a SAM-enabled I2P router can dial other nodes by their I2P
//! destination without ever exposing an IP.
//!
//! ## SAM v3 outbound dialing is two sockets
//!
//! 1. A **control** socket creates a STREAM session and MUST stay open for the
//!    session's lifetime — [`SamSession`] owns it; dropping the session tears
//!    the I2P session down.
//! 2. A **data** socket, opened per outbound stream, issues `STREAM CONNECT`
//!    against the session id and then carries the raw peer bytes.
//!
//! Handshake per socket: `HELLO VERSION` → `HELLO REPLY RESULT=OK`. The control
//! socket then does `SESSION CREATE`, and each data socket does `STREAM
//! CONNECT`. Every reply is a single newline-terminated line, read with a bound
//! and a timeout so a rogue bridge cannot stall or flood us before the reply.
//!
//! A background **supervisor** owns the control socket and rebuilds the session
//! in place (same persistent destination, new id) if it dies, so a bridge
//! restart or tunnel loss doesn't permanently sever I2P dialing. Inbound
//! (`STREAM ACCEPT`) uses the same session; the accept pool and `dial_v2` share
//! one `SamSession` and follow it across rebuilds without re-plumbing.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Default SAM bridge address (i2pd / Java I2P listen on this by default).
pub const DEFAULT_SAM_ADDR: &str = "127.0.0.1:7656";

/// We advertise support for SAM 3.0–3.3; the bridge picks the highest it knows.
const SAM_HELLO: &[u8] = b"HELLO VERSION MIN=3.0 MAX=3.3\n";

/// Max bytes we read while waiting for a single SAM reply line.
const SAM_REPLY_CAP: usize = 4096;

/// Reconnect backoff bounds for the session supervisor: after the control
/// socket dies it retries `SESSION CREATE` starting at `MIN`, doubling to `MAX`,
/// forever (the node keeps trying until the SAM bridge is back).
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_millis(500);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Reconstruct the `.b32.i2p` host from a 32-byte I2P destination hash. addrv2
/// net_id 5 carries the 32-byte SHA-256 of the destination; the `.b32` address
/// is its base32 (lowercase, unpadded) with the `.b32.i2p` suffix.
pub fn i2p_b32_from_hash(hash: &[u8; 32]) -> String {
    let mut host = base32_lower_nopad(hash);
    host.push_str(".b32.i2p");
    host
}

/// Decode a `.b32.i2p` host back to its 32-byte I2P destination hash (the
/// inverse of [`i2p_b32_from_hash`]), for seeding an addrv2 entry from an
/// `--addnode <host>.b32.i2p`. Returns `None` if the host is not a valid
/// 52-char I2P b32 address.
pub fn i2p_hash_from_b32(host: &str) -> Option<[u8; 32]> {
    let h = host.strip_suffix(".b32.i2p").unwrap_or(host);
    if h.len() != 52 || !h.is_ascii() {
        return None;
    }
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    let mut out: Vec<u8> = Vec::with_capacity(32);
    for c in h.bytes() {
        let v = ALPHABET.iter().position(|&a| a == c.to_ascii_lowercase())? as u16;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u16 << bits) - 1;
        }
    }
    if out.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out);
    Some(hash)
}

/// RFC 4648 base32, lowercase, no `=` padding — the I2P `.b32` alphabet.
fn base32_lower_nopad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(data.len() * 2); // ~1.6x; loose hint
    let mut acc: u16 = 0; // holds at most 12 live bits
    let mut bits: u8 = 0;
    for &b in data {
        acc = (acc << 8) | b as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1u16 << bits) - 1; // drop already-emitted high bits
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// A SAM v3 STREAM session for dialing and accepting `.b32.i2p` peers. Holds the
/// control socket open behind a background **supervisor** that rebuilds the
/// session in place if the control socket dies (bridge restart, tunnel loss):
/// the shared `Arc<SamSession>` the outbound connector and inbound accept pool
/// hold never changes, so they transparently pick up the rebuilt session — with
/// its new id — the moment it is back. While the session is down,
/// `stream_connect`/`stream_accept` fail fast instead of hanging.
pub struct SamSession {
    /// The bridge we dial for every data socket; fixed for the session's life.
    sam_addr: String,
    /// Shared, swappable session state; the supervisor swaps the live id in here.
    state: Arc<SessionState>,
    /// Supervisor task: owns the current control socket, watches it for EOF, and
    /// on death reconnects (persistent key → same `.b32.i2p`) with capped
    /// backoff, forever. Aborted when the `SamSession` is dropped.
    _supervisor: tokio::task::JoinHandle<()>,
}

/// The parts of a SAM session the supervisor swaps on a rebuild. Shared via
/// `Arc` so every holder of the `SamSession` reads the current id and liveness
/// without re-plumbing when the session is rebuilt.
struct SessionState {
    /// Current SAM session id. Re-randomized on every (re)connect so a stale
    /// control socket lingering on the bridge can't collide with the new one.
    session_id: Mutex<String>,
    /// False while the session is down (control socket closed, rebuild pending);
    /// `stream_connect`/`stream_accept` fail fast instead of hanging.
    alive: AtomicBool,
    /// Bumped on each successful (re)connect — 1 after the initial open, 2 after
    /// the first rebuild, … Lets callers and tests observe a rebuild.
    generation: AtomicU64,
}

impl SamSession {
    /// Open a SAM session for I2P dialing/accepting: `HELLO`, then `SESSION
    /// CREATE` with our persistent destination (stable `.b32.i2p` across
    /// restarts). Fails if the bridge is unreachable at startup. Once open, a
    /// supervisor keeps it alive and rebuilds it in place after any later drop.
    pub async fn connect(
        sam_addr: &str,
        data_dir: &std::path::Path,
        connect_timeout: Duration,
        session_timeout: Duration,
    ) -> Result<SamSession> {
        let sam_addr = sam_addr.to_string();
        let data_dir = data_dir.to_path_buf();
        // Initial session — connect() surfaces a startup bridge failure to the
        // caller; the supervisor only takes over rebuilds after this succeeds.
        let (control, session_id) =
            create_session(&sam_addr, &data_dir, connect_timeout, session_timeout).await?;
        let state = Arc::new(SessionState {
            session_id: Mutex::new(session_id),
            alive: AtomicBool::new(true),
            generation: AtomicU64::new(1),
        });
        let supervisor = tokio::spawn(supervise(
            control,
            state.clone(),
            sam_addr.clone(),
            data_dir,
            connect_timeout,
            session_timeout,
        ));
        Ok(SamSession {
            sam_addr,
            state,
            _supervisor: supervisor,
        })
    }

    /// Whether the session is currently usable (control socket open). False
    /// during the window between a control-socket death and the rebuild.
    pub fn is_alive(&self) -> bool {
        self.state.alive.load(Ordering::Relaxed)
    }

    /// The session id the bridge currently knows us by (changes across rebuilds).
    pub fn session_id(&self) -> String {
        self.state
            .session_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// How many times the session has (re)connected: 1 after the initial open,
    /// incremented on every in-place rebuild. Observability / tests.
    pub fn generation(&self) -> u64 {
        self.state.generation.load(Ordering::Relaxed)
    }

    /// Open an outbound I2P stream to `dest` (a `.b32.i2p` host or a full base64
    /// destination) through this session. On success the returned socket is the
    /// raw, bidirectional byte stream to the peer — hand it straight to the
    /// Noise handshake, exactly like a TCP or Tor stream.
    pub async fn stream_connect(&self, dest: &str, timeout: Duration) -> Result<TcpStream> {
        if !self.is_alive() {
            return Err(Error::ConnectionFailed(
                "I2P SAM session is down (control socket closed, rebuild pending)".into(),
            ));
        }
        let session_id = self.session_id();
        let mut data = dial(&self.sam_addr, timeout).await?;
        sam_hello(&mut data, timeout).await?;
        let cmd = format!("STREAM CONNECT ID={session_id} DESTINATION={dest} SILENT=false\n");
        let reply = sam_cmd(&mut data, cmd.as_bytes(), timeout).await?;
        if !reply.contains("RESULT=OK") {
            return Err(Error::ConnectionFailed(format!(
                "SAM STREAM CONNECT to {dest} failed: {reply}"
            )));
        }
        Ok(data)
    }

    /// Wait for ONE inbound I2P peer via `STREAM ACCEPT`, making us DIALABLE over
    /// I2P. `setup_timeout` bounds the HELLO + ACCEPT registration; the wait for
    /// a peer afterward is UNbounded (an accept socket may idle indefinitely). On
    /// an inbound connection SAM sends the remote destination line, after which
    /// the socket is the raw peer stream — hand it to the Noise handshake like
    /// any inbound TCP accept. Returns `(stream, remote_destination)`. Callers
    /// run a POOL of these so simultaneous inbound handshakes don't queue.
    pub async fn stream_accept(&self, setup_timeout: Duration) -> Result<(TcpStream, String)> {
        if !self.is_alive() {
            return Err(Error::ConnectionFailed(
                "I2P SAM session is down (control socket closed, rebuild pending)".into(),
            ));
        }
        let session_id = self.session_id();
        let mut data = dial(&self.sam_addr, setup_timeout).await?;
        sam_hello(&mut data, setup_timeout).await?;
        let cmd = format!("STREAM ACCEPT ID={session_id} SILENT=false\n");
        let reply = sam_cmd(&mut data, cmd.as_bytes(), setup_timeout).await?;
        if !reply.contains("RESULT=OK") {
            return Err(Error::ConnectionFailed(format!(
                "SAM STREAM ACCEPT failed: {reply}"
            )));
        }
        // Block (NO timeout) until a peer connects; SAM then sends one line with
        // the remote destination, and the socket becomes the data stream.
        let remote = read_line(&mut data).await?;
        Ok((data, remote))
    }
}

/// Establish one SAM STREAM session: dial the bridge, `HELLO`, `SESSION CREATE`
/// with our persistent destination (first boot mints an Ed25519 key — never the
/// weak DSA-SHA1 default — and saves it; later boots reuse it for a STABLE
/// `.b32.i2p`). Returns the held-open control socket and the new session id.
/// Shared by the initial [`SamSession::connect`] and every supervisor rebuild.
async fn create_session(
    sam_addr: &str,
    data_dir: &Path,
    connect_timeout: Duration,
    session_timeout: Duration,
) -> Result<(TcpStream, String)> {
    // Randomized session id — a fixed id collides if a prior control socket is
    // still closing on the bridge (exactly the rebuild case).
    let session_id = format!("cync-{:08x}", rand::random::<u32>());
    let mut control = dial(sam_addr, connect_timeout).await?;
    sam_hello(&mut control, connect_timeout).await?;

    // Persistent destination: reuse the on-disk private key for a stable
    // .b32.i2p across restarts AND rebuilds (TRANSIENT would mint a new address
    // each time and poison peers' addrv2 tables with dead hashes).
    let key_path = data_dir.join("i2p_dest.key");
    let saved = std::fs::read_to_string(&key_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let cmd = match &saved {
        Some(priv_key) => {
            format!("SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION={priv_key}\n")
        }
        None => format!(
            "SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION=TRANSIENT SIGNATURE_TYPE=7\n"
        ),
    };
    // SESSION CREATE blocks until the router builds initial tunnels — 30s to
    // several minutes on a cold start — so read its reply with the generous
    // session timeout, not the short per-command one.
    let reply = sam_cmd(&mut control, cmd.as_bytes(), session_timeout).await?;
    if !reply.contains("RESULT=OK") {
        return Err(Error::ConnectionFailed(format!(
            "SAM SESSION CREATE failed: {reply}"
        )));
    }
    // A fresh (TRANSIENT) session returns our new DESTINATION (the full private
    // key) — persist it so next boot/rebuild keeps the same .b32.i2p.
    if saved.is_none() {
        if let Some(priv_key) = sam_value(&reply, "DESTINATION=") {
            match std::fs::write(&key_path, &priv_key) {
                Ok(()) => tracing::info!(
                    "Saved I2P destination key to {} — stable .b32.i2p across restarts",
                    key_path.display()
                ),
                Err(e) => tracing::warn!("Could not persist I2P destination key: {e}"),
            }
        }
    }
    Ok((control, session_id))
}

/// Own the control socket until it closes. SAM may push async notices on it
/// (e.g. `PING`) which we drain and ignore; EOF or error means the session died.
async fn watch_control(control: &mut TcpStream) {
    let mut buf = [0u8; 256];
    loop {
        match control.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {} // async SAM notices — ignore
        }
    }
}

/// Session supervisor: holds the control socket, and when it dies flags the
/// session down, logs, then rebuilds it in place (same persistent destination,
/// new id) with capped backoff — forever, so a bridge that comes back restores
/// I2P dialing without a node restart. Runs until the `SamSession` is dropped.
async fn supervise(
    mut control: TcpStream,
    state: Arc<SessionState>,
    sam_addr: String,
    data_dir: PathBuf,
    connect_timeout: Duration,
    session_timeout: Duration,
) {
    loop {
        watch_control(&mut control).await;
        // The control socket closed: the whole session and every peer stream
        // died with it. Fail new dials fast until we rebuild.
        state.alive.store(false, Ordering::Relaxed);
        let dead_sid = state
            .session_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        tracing::error!(
            "[{code}] I2P SAM control socket (session {dead_sid}) closed — the I2P session is \
             DEAD; rebuilding (.b32.i2p dialing fails until the SAM bridge is back).",
            code = crate::diagnostics::CYNC_NET_002,
        );

        let mut backoff = RECONNECT_BACKOFF_MIN;
        loop {
            tokio::time::sleep(backoff).await;
            match create_session(&sam_addr, &data_dir, connect_timeout, session_timeout).await {
                Ok((new_control, new_sid)) => {
                    *state
                        .session_id
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = new_sid.clone();
                    state.alive.store(true, Ordering::Relaxed);
                    let generation = state.generation.fetch_add(1, Ordering::Relaxed) + 1;
                    tracing::warn!(
                        "I2P SAM session REBUILT (session {new_sid}, generation {generation}) — \
                         .b32.i2p dialing restored."
                    );
                    control = new_control;
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        "[{code}] I2P SAM reconnect failed ({e}); retrying in {backoff:?}.",
                        code = crate::diagnostics::CYNC_NET_002,
                    );
                    backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
                }
            }
        }
    }
}

/// Extract the value of a `KEY=VALUE` token from a SAM reply line (the reply is
/// space-separated tokens). Used to read the DESTINATION a SESSION CREATE
/// returns for a transient destination.
fn sam_value(reply: &str, key: &str) -> Option<String> {
    reply
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(key))
        .map(|v| v.to_string())
}

async fn dial(addr: &str, timeout: Duration) -> Result<TcpStream> {
    tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::ConnectionFailed(format!("SAM connect to {addr} timed out")))?
        .map_err(|e| Error::ConnectionFailed(format!("SAM connect to {addr}: {e}")))
}

async fn sam_hello(s: &mut TcpStream, timeout: Duration) -> Result<()> {
    let reply = sam_cmd(s, SAM_HELLO, timeout).await?;
    if !reply.contains("RESULT=OK") {
        return Err(Error::ConnectionFailed(format!("SAM HELLO failed: {reply}")));
    }
    Ok(())
}

/// Write one SAM command line and read exactly one newline-terminated reply
/// line, bounded and time-boxed.
async fn sam_cmd(s: &mut TcpStream, cmd: &[u8], timeout: Duration) -> Result<String> {
    tokio::time::timeout(timeout, s.write_all(cmd))
        .await
        .map_err(|_| Error::ConnectionFailed("SAM write timed out".into()))?
        .map_err(|e| Error::ConnectionFailed(format!("SAM write: {e}")))?;

    let line = tokio::time::timeout(timeout, read_line(s))
        .await
        .map_err(|_| Error::ConnectionFailed("SAM reply timed out".into()))??;
    Ok(line)
}

async fn read_line(s: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = s
            .read(&mut byte)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("SAM read: {e}")))?;
        if n == 0 {
            return Err(Error::ConnectionFailed("SAM closed before reply".into()));
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > SAM_REPLY_CAP {
            return Err(Error::ConnectionFailed("SAM reply exceeded cap".into()));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn b32_of_zero_hash_is_52_chars_all_a() {
        // 32 zero bytes -> 256 bits -> 52 base32 chars (51 full + 1 partial).
        let host = i2p_b32_from_hash(&[0u8; 32]);
        assert!(host.ends_with(".b32.i2p"));
        let b32 = host.strip_suffix(".b32.i2p").unwrap();
        assert_eq!(b32.len(), 52, "a 32-byte hash encodes to 52 base32 chars");
        assert!(b32.chars().all(|c| c == 'a'), "zero hash is all 'a'");
    }

    #[test]
    fn b32_is_stable_and_distinct_per_hash() {
        let a = i2p_b32_from_hash(&[0x11u8; 32]);
        let b = i2p_b32_from_hash(&[0x22u8; 32]);
        assert_ne!(a, b);
        assert_eq!(a, i2p_b32_from_hash(&[0x11u8; 32])); // deterministic
        assert_eq!(a.strip_suffix(".b32.i2p").unwrap().len(), 52);
    }

    #[test]
    fn b32_encode_decode_round_trips() {
        for seed in [0x00u8, 0x11, 0x5a, 0xff] {
            let hash = [seed; 32];
            let host = i2p_b32_from_hash(&hash);
            assert_eq!(i2p_hash_from_b32(&host), Some(hash), "round-trip with suffix");
            let bare = host.strip_suffix(".b32.i2p").unwrap();
            assert_eq!(i2p_hash_from_b32(bare), Some(hash), "round-trip bare");
        }
        // Wrong length / bad alphabet → None.
        assert_eq!(i2p_hash_from_b32("tooshort.b32.i2p"), None);
        assert_eq!(i2p_hash_from_b32(&"1".repeat(52)), None); // '1' not in base32
    }

    async fn read_sam_line(s: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = s.read(&mut byte).await.unwrap();
            if n == 0 || byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Minimal in-process SAM v3 bridge: answers HELLO, SESSION CREATE and
    /// STREAM CONNECT per the protocol, then echoes the data stream — standing
    /// in for a real i2pd/Java-I2P router so the client is tested without one.
    async fn spawn_mock_sam() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    // Every socket begins with HELLO.
                    let hello = read_sam_line(&mut sock).await;
                    if !hello.starts_with("HELLO VERSION") {
                        return;
                    }
                    let _ = sock
                        .write_all(b"HELLO REPLY RESULT=OK VERSION=3.3\n")
                        .await;
                    // Next line selects the role of this socket.
                    let cmd = read_sam_line(&mut sock).await;
                    if cmd.starts_with("SESSION CREATE") {
                        let _ = sock
                            .write_all(b"SESSION STATUS RESULT=OK DESTINATION=ZmFrZWRlc3Q=\n")
                            .await;
                        // Hold the control socket open until the client drops it.
                        let mut sink = [0u8; 64];
                        loop {
                            match sock.read(&mut sink).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    } else if cmd.starts_with("STREAM CONNECT") {
                        let _ = sock.write_all(b"STREAM STATUS RESULT=OK\n").await;
                        // Raw data stream: echo everything (the "peer").
                        let mut buf = [0u8; 1024];
                        loop {
                            match sock.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if sock.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    } else if cmd.starts_with("STREAM ACCEPT") {
                        let _ = sock.write_all(b"STREAM STATUS RESULT=OK\n").await;
                        // Simulate an inbound peer arriving: send its destination
                        // line, then act as that peer by echoing.
                        let _ = sock.write_all(b"REMOTEpeerDESTbase64==\n").await;
                        let mut buf = [0u8; 1024];
                        loop {
                            match sock.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if sock.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn sam_session_connects_dials_a_stream_and_round_trips() {
        let sam = spawn_mock_sam().await;
        let t = Duration::from_secs(5);

        // Control socket: HELLO + SESSION CREATE.
        let dir = tempfile::tempdir().unwrap();
        let session = SamSession::connect(&sam.to_string(), dir.path(), t, t)
            .await
            .expect("SAM session should be created against the mock bridge");
        assert!(session.session_id().starts_with("cync-"));
        assert!(session.is_alive(), "session is alive while the control socket is open");
        // First boot persisted the destination key for a stable .b32.i2p.
        assert!(
            dir.path().join("i2p_dest.key").exists(),
            "the I2P destination key is saved on first boot"
        );

        // Data socket: HELLO + STREAM CONNECT, then raw bytes to the "peer".
        let dest = i2p_b32_from_hash(&[0x42u8; 32]);
        let mut stream = session
            .stream_connect(&dest, t)
            .await
            .expect("STREAM CONNECT to a .b32.i2p dest should succeed");
        stream.write_all(b"i2p-dial").await.unwrap();
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"i2p-dial", "the I2P stream round-trips bytes");
    }

    #[tokio::test]
    async fn sam_session_accepts_an_inbound_stream_and_round_trips() {
        let sam = spawn_mock_sam().await;
        let t = Duration::from_secs(5);
        let dir = tempfile::tempdir().unwrap();
        let session = SamSession::connect(&sam.to_string(), dir.path(), t, t)
            .await
            .unwrap();

        // STREAM ACCEPT yields an inbound peer (the mock presents one immediately).
        let (mut stream, remote) = session
            .stream_accept(t)
            .await
            .expect("STREAM ACCEPT should yield an inbound peer");
        assert!(!remote.is_empty(), "the remote destination line is returned");
        stream.write_all(b"i2p-in").await.unwrap();
        let mut buf = [0u8; 6];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"i2p-in", "the inbound I2P stream round-trips bytes");
    }

    #[tokio::test]
    async fn stream_connect_surfaces_a_bridge_refusal() {
        // A bridge that OKs HELLO/SESSION but refuses the stream.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let _ = read_sam_line(&mut sock).await; // HELLO
                    let _ = sock.write_all(b"HELLO REPLY RESULT=OK VERSION=3.3\n").await;
                    let cmd = read_sam_line(&mut sock).await;
                    if cmd.starts_with("SESSION CREATE") {
                        let _ = sock.write_all(b"SESSION STATUS RESULT=OK DESTINATION=x\n").await;
                        let mut sink = [0u8; 64];
                        while let Ok(n) = sock.read(&mut sink).await {
                            if n == 0 {
                                break;
                            }
                        }
                    } else if cmd.starts_with("STREAM CONNECT") {
                        let _ = sock
                            .write_all(b"STREAM STATUS RESULT=CANT_REACH_PEER\n")
                            .await;
                    }
                });
            }
        });
        let t = Duration::from_secs(5);
        let dir = tempfile::tempdir().unwrap();
        let session = SamSession::connect(&addr.to_string(), dir.path(), t, t)
            .await
            .unwrap();
        let err = session
            .stream_connect("aaaa.b32.i2p", t)
            .await
            .expect_err("a non-OK STREAM STATUS must surface as an error");
        assert!(format!("{err}").contains("STREAM CONNECT"));
    }

    /// A SAM bridge that KILLS the control socket right after the first SESSION
    /// CREATE (a bridge/tunnel drop), then serves a normal, held-open session on
    /// the next SESSION CREATE — so the supervisor's in-place rebuild shows up.
    async fn spawn_flaky_sam() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sessions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    let hello = read_sam_line(&mut sock).await;
                    if !hello.starts_with("HELLO VERSION") {
                        return;
                    }
                    let _ = sock.write_all(b"HELLO REPLY RESULT=OK VERSION=3.3\n").await;
                    let cmd = read_sam_line(&mut sock).await;
                    if cmd.starts_with("SESSION CREATE") {
                        let _ = sock
                            .write_all(b"SESSION STATUS RESULT=OK DESTINATION=ZmFrZWRlc3Q=\n")
                            .await;
                        if sessions.fetch_add(1, Ordering::Relaxed) == 0 {
                            // First session: drop the control socket at once to
                            // force a rebuild.
                            return;
                        }
                        // Later sessions: hold open like a healthy bridge.
                        let mut sink = [0u8; 64];
                        loop {
                            match sock.read(&mut sink).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    } else if cmd.starts_with("STREAM CONNECT") {
                        let _ = sock.write_all(b"STREAM STATUS RESULT=OK\n").await;
                        let mut buf = [0u8; 1024];
                        loop {
                            match sock.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if sock.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn sam_session_rebuilds_in_place_after_the_control_socket_dies() {
        let sam = spawn_flaky_sam().await;
        let t = Duration::from_secs(5);
        let dir = tempfile::tempdir().unwrap();
        let session = SamSession::connect(&sam.to_string(), dir.path(), t, t)
            .await
            .unwrap();
        assert_eq!(session.generation(), 1, "a fresh session is generation 1");

        // The bridge killed the first control socket; the supervisor must notice,
        // mark the session down, then rebuild it in place (generation 2, alive).
        let mut rebuilt = false;
        for _ in 0..100 {
            if session.generation() >= 2 && session.is_alive() {
                rebuilt = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            rebuilt,
            "the supervisor rebuilds the session in place after its control socket dies"
        );

        // The rebuilt session is usable: STREAM CONNECT goes through its new id.
        let dest = i2p_b32_from_hash(&[0x42u8; 32]);
        let mut stream = session
            .stream_connect(&dest, t)
            .await
            .expect("dialing works again through the rebuilt session");
        stream.write_all(b"rebuilt!").await.unwrap();
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"rebuilt!", "the rebuilt I2P stream round-trips bytes");
    }
}
