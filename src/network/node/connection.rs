use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use crate::primitives::Hash;

use super::super::connection_tracker::{ConnectionTracker, OutboundSubnetSlot};
use super::super::framing::{MessageFramer, HEADER_SIZE};
use super::super::noise::{
    self, NodeIdentity, NoiseRecvState, NoiseSendState, NoiseTransport, MAX_NOISE_PAYLOAD,
    NOISE_LENGTH_PREFIX_SIZE, NOISE_TAG_SIZE,
};
use super::super::peer::{PeerId, PeerInfo};
use super::super::protocol::{Message, MessageType};
use super::super::traffic_shaping::TrafficShaper;
use super::constants::PEER_QUEUE_SIZE;
use super::types::NodeEvent;
use super::PeerMessage;

struct AbortOnDrop(JoinHandle<()>);

const NOISE_WIRE_OVERHEAD: usize = NOISE_LENGTH_PREFIX_SIZE + NOISE_TAG_SIZE;

fn normalize_noise_record(traffic_shaper: &TrafficShaper, plaintext: &[u8]) -> Vec<u8> {
    traffic_shaper.normalize_size_with_overhead(plaintext, NOISE_WIRE_OVERHEAD)
}

fn denormalize_noise_record(traffic_shaper: &TrafficShaper, record: Vec<u8>) -> Result<Vec<u8>> {
    if !traffic_shaper.normalization_enabled() {
        return Ok(record);
    }
    if !TrafficShaper::is_normalized_payload_size(record.len(), NOISE_WIRE_OVERHEAD) {
        return Err(Error::InvalidMessage(
            "non-canonical normalized Noise record size".into(),
        ));
    }
    TrafficShaper::denormalize(&record)
        .ok_or_else(|| Error::InvalidMessage("invalid normalized Noise record".into()))
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Bridge tasks: shuttles data between the encrypted TCP stream and the
/// plaintext duplex streams that the MessageFramer reads/writes.
///
/// CRITICAL: Uses TWO separate tasks (read and write) instead of a single
/// `select!` loop. This is because `read_encrypted` is NOT cancellation-safe:
/// it makes two sequential read_exact calls with a nonce increment between
/// them. If a select! arm cancels the future mid-read, the nonce gets
/// permanently desynced and all subsequent decryptions fail.
async fn noise_bridge(
    transport: NoiseTransport,
    tcp_reader: tokio::net::tcp::OwnedReadHalf,
    tcp_writer: tokio::net::tcp::OwnedWriteHalf,
    from_app: tokio::io::DuplexStream, // plaintext from MessageFramer
    to_app: tokio::io::DuplexStream,   // plaintext to MessageFramer
    traffic_shaper: Arc<TrafficShaper>,
) {
    // Split the transport into send and recv halves so each direction can
    // run in its own task without interfering with the other's nonce state.
    let (send_state, recv_state) = transport.split_into_send_recv();
    let mut directions = JoinSet::new();
    directions.spawn(noise_bridge_reader(
        recv_state,
        tcp_reader,
        to_app,
        Arc::clone(&traffic_shaper),
    ));
    directions.spawn(noise_bridge_writer(
        send_state,
        tcp_writer,
        from_app,
        traffic_shaper,
    ));

    // Neither direction can make useful progress once its counterpart exits.
    let _ = directions.join_next().await;
    directions.abort_all();
    while directions.join_next().await.is_some() {}
}

async fn noise_bridge_reader(
    state: NoiseRecvState,
    mut tcp_reader: tokio::net::tcp::OwnedReadHalf,
    mut to_app: tokio::io::DuplexStream,
    traffic_shaper: Arc<TrafficShaper>,
) {
    use tokio::io::AsyncWriteExt;
    loop {
        let record = {
            match state.read_encrypted(&mut tcp_reader).await {
                Ok(pt) => pt,
                Err(e) => {
                    // Clean remote closes are operational noise; decryption
                    // and framing failures still need operator attention.
                    let msg = e.to_string();
                    if msg.contains("unexpected end of file") || msg.contains("UnexpectedEof") {
                        info!("Peer disconnected (noise stream closed): {}", e);
                    } else {
                        warn!("Noise bridge reader error: {}", e);
                    }
                    return;
                }
            }
        };
        let plaintext = match denormalize_noise_record(&traffic_shaper, record) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                warn!("Noise bridge reader: {}", error);
                return;
            }
        };
        if to_app.write_all(&plaintext).await.is_err() {
            return;
        }
        if to_app.flush().await.is_err() {
            return;
        }
    }
}

async fn noise_bridge_writer<W, R>(
    state: NoiseSendState,
    mut tcp_writer: W,
    mut from_app: R,
    traffic_shaper: Arc<TrafficShaper>,
) where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let Some(max_input) =
        TrafficShaper::max_normalizable_input(MAX_NOISE_PAYLOAD, NOISE_WIRE_OVERHEAD)
    else {
        warn!("Noise bridge writer: no valid normalization bucket");
        return;
    };
    loop {
        let mut header = [0u8; HEADER_SIZE];
        if let Err(error) = from_app.read_exact(&mut header).await {
            if error.kind() != std::io::ErrorKind::UnexpectedEof {
                warn!("Noise bridge writer: {}", error);
            }
            return;
        }
        let payload_len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
        let max_payload = if traffic_shaper.normalization_enabled() {
            TrafficShaper::normalized_payload_limit(
                crate::network::protocol::MAX_MESSAGE_SIZE,
                HEADER_SIZE,
            )
        } else {
            crate::network::protocol::MAX_MESSAGE_SIZE
        };
        if payload_len > max_payload {
            warn!("Noise bridge writer: frame payload too large");
            return;
        }

        let mut remaining = payload_len;
        let mut first_record = true;
        while first_record || remaining > 0 {
            let mut plaintext = Vec::with_capacity(max_input);
            if first_record {
                plaintext.extend_from_slice(&header);
                first_record = false;
            }
            let to_read = remaining.min(max_input.saturating_sub(plaintext.len()));
            if to_read > 0 {
                let start = plaintext.len();
                plaintext.resize(start + to_read, 0);
                if let Err(error) = from_app.read_exact(&mut plaintext[start..]).await {
                    warn!("Noise bridge writer: {}", error);
                    return;
                }
                remaining -= to_read;
            }

            let record = normalize_noise_record(&traffic_shaper, &plaintext);
            if let Err(error) = state.write_encrypted(&mut tcp_writer, &record).await {
                warn!("Noise bridge writer: {}", error);
                return;
            }
        }
    }
}

fn cleanup_connection(
    peer_id: PeerId,
    connection_token: &Arc<()>,
    own_sender: &mpsc::WeakSender<Vec<u8>>,
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    event_tx: &broadcast::Sender<NodeEvent>,
) -> bool {
    senders.remove_if(&peer_id, |_, sender| {
        own_sender
            .upgrade()
            .is_some_and(|own| sender.same_channel(&own))
    });
    let removed = peers
        .remove_if(&peer_id, |_, peer| {
            Arc::ptr_eq(&peer.connection_token, connection_token)
        })
        .is_some();

    if removed {
        let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
    } else {
        debug!(
            "Skipping cleanup for peer {:?}: replacement connection exists",
            peer_id
        );
    }

    removed
}

/// Handle a new connection (inbound or outbound) with proper message framing
pub(super) async fn handle_connection(
    stream: TcpStream,
    peer_id: PeerId,
    outbound: bool,
    magic: [u8; 4],
    our_nonce: u64,
    our_height: u64,
    our_tip: Hash,
    peers: Arc<DashMap<PeerId, PeerInfo>>,
    senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>>,
    event_tx: broadcast::Sender<NodeEvent>,
    msg_tx: mpsc::Sender<PeerMessage>,
    conn_tracker: Arc<ConnectionTracker>,
    identity: Arc<NodeIdentity>,
    encryption_config: crate::config::P2PEncryptionConfig,
    traffic_shaper: Arc<TrafficShaper>,
    // Per-/16 outbound slot for eclipse defense. Some for outbound
    // dials (acquired by the connector before spawn), None for
    // inbound accepts. We move it into the PeerInfo entry below
    // so the slot's lifetime tracks the entry's lifetime — when
    // the peers DashMap drops or overwrites this entry, the slot
    // drops with it, releasing the /16 counter cleanly even in
    // the skip-cleanup branch (where peers.remove is intentionally
    // not called to preserve a concurrent reconnection).
    eclipse_slot: Option<Arc<OutboundSubnetSlot>>,
) -> Result<()> {
    let addr = stream
        .peer_addr()
        .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

    // Disable Nagle's algorithm for latency-sensitive handshake and message
    // framing. Without this, the 2-byte length prefix of a Noise handshake
    // message can stall for 200ms waiting for more data, causing timeouts.
    if let Err(e) = stream.set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY on {}: {}", addr, e);
    }

    let mut info = PeerInfo::new(peer_id, addr, outbound);
    info.eclipse_slot = eclipse_slot;

    // ─── Noise_XX Encryption ────────────────────────────────────────────
    //
    // Modeled after Lightning BOLT #8: encryption starts immediately with no
    // proposal/negotiation byte. The Noise_XX handshake runs directly.
    //
    // Each handshake message carries a 1-byte version field (currently 0x00).
    // An unknown version causes an immediate, descriptive error before any
    // crypto is attempted — fast detection of misconfigured or incompatible nodes.
    //
    // If encryption is disabled on this node, plaintext is used. Two nodes
    // with mismatched encryption configs simply cannot connect (the Noise
    // handshake will fail with a clear version/MAC error — no stream corruption).

    let mut stream = stream;

    let noise_result: Option<(NoiseTransport, PeerId)> =
        if encryption_config.preferred || encryption_config.required {
            let timeout_result = tokio::time::timeout(
                Duration::from_secs(noise::NOISE_HANDSHAKE_TIMEOUT_SECS),
                noise::perform_noise_handshake(&mut stream, identity.clone(), outbound),
            )
            .await;

            match timeout_result {
                Ok(Ok((transport, remote_id))) => Some((transport, remote_id)),
                Ok(Err(e)) => {
                    // Noise handshake failed — TCP stream has partial handshake bytes
                    // on it and CANNOT be reused for plaintext. Close and let the
                    // retry loop reconnect. The stale node_key detection in
                    // load_or_generate_fresh() prevents the most common failure mode.
                    warn!("Noise handshake failed with {}: {}", addr, e);
                    return Err(e);
                }
                Err(_) => {
                    warn!(
                        "Noise handshake timed out with {} after {}s",
                        addr,
                        noise::NOISE_HANDSHAKE_TIMEOUT_SECS
                    );
                    return Err(Error::NoiseHandshakeFailed("timeout".into()));
                }
            }
        } else {
            None
        };

    // Resolve canonical peer_id: use the remote's Noise static key when
    // available (it's authenticated), otherwise fall back to the TCP-level id.
    let peer_id = if let Some((_, ref remote_id)) = noise_result {
        info.encrypted = true;
        info.remote_static_key = Some(*remote_id);

        // SECURITY: If trusted_peers is non-empty, verify this peer is trusted.
        if !encryption_config.trusted_peers.is_empty() {
            let remote_hex = hex::encode(remote_id);
            if !encryption_config.trusted_peers.contains(&remote_hex) {
                warn!(
                    "Peer {} has untrusted static key {}, disconnecting",
                    addr, remote_hex
                );
                return Err(Error::NoiseHandshakeFailed("untrusted peer".into()));
            }
        }

        info!(
            "Noise handshake succeeded with {} (remote key: {})",
            addr,
            hex::encode(&remote_id[..8])
        );

        *remote_id
    } else {
        if !encryption_config.trusted_peers.is_empty() {
            warn!(
                "Plaintext connection from {} rejected (trusted_peers configured)",
                addr
            );
            return Err(Error::NoiseHandshakeFailed(
                "encryption required for trusted peers".into(),
            ));
        }
        if encryption_config.required {
            warn!("Encryption required but not established with {}", addr);
            return Err(Error::NoiseHandshakeFailed("encryption required".into()));
        }
        peer_id
    };

    // Sync info.id with the finalized peer_id (which may have been replaced by
    // the Noise-derived remote static key). pick_scored_peer() returns p.id,
    // so it must match the key used in `senders` and `peers` maps.
    info.id = peer_id;
    let connection_token = Arc::clone(&info.connection_token);

    // Create message sender after peer_id is finalized so every map uses the
    // Noise-authenticated identity when encryption is active.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(PEER_QUEUE_SIZE);
    let sender_identity = tx.downgrade();

    // ─── Set up message framing (plaintext or encrypted) ───────────────
    // For encrypted connections, bridge NoiseTransport ↔ MessageFramer via
    // in-memory duplex streams. The bridge task handles encrypt/decrypt on
    // the real TCP stream while the MessageFramer operates on plaintext.
    //
    // For plaintext, the MessageFramer operates directly on the TCP stream.
    // We use Box<dyn ...> to unify the types for the connection loop.

    type DynRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
    type DynWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

    let (app_reader, app_writer, noise_bridge_handle): (
        DynRead,
        DynWrite,
        Option<tokio::task::JoinHandle<()>>,
    ) = if let Some((transport, _remote_id)) = noise_result {
        let (tcp_reader, tcp_writer) = stream.into_split();
        let (app_read, bridge_write) = tokio::io::duplex(64 * 1024);
        let (bridge_read, app_write) = tokio::io::duplex(64 * 1024);

        // Spawn bridge task: decrypt from TCP → app, encrypt from app → TCP
        let handle = tokio::spawn(noise_bridge(
            transport,
            tcp_reader,
            tcp_writer,
            bridge_read,
            bridge_write,
            Arc::clone(&traffic_shaper),
        ));

        (Box::new(app_read), Box::new(app_write), Some(handle))
    } else {
        let (tcp_reader, tcp_writer) = stream.into_split();
        (Box::new(tcp_reader), Box::new(tcp_writer), None)
    };
    let _noise_bridge_guard = noise_bridge_handle.map(AbortOnDrop);

    let mut framer =
        MessageFramer::new_budgeted(app_reader, app_writer, magic, conn_tracker, traffic_shaper);

    // Per-peer rate limiter to prevent abuse

    // SECURITY (NET-001): Send version message with our nonce for self-connection detection
    let version_msg = Message::version_with_nonce(magic, our_height, our_tip, our_nonce)?;
    let version_bytes = version_msg.to_bytes()?;
    // The framer handles header creation, but version_msg already includes header
    // Write the complete message directly for initial handshake
    framer
        .write_message(MessageType::Version as u8, &version_bytes[HEADER_SIZE..])
        .await?;
    info.bytes_sent = info.bytes_sent.saturating_add(version_bytes.len() as u64);

    // Failed initial handshakes must never be visible as live peers.
    peers.insert(peer_id, info);
    senders.insert(peer_id, tx);

    // Notify of connection
    let _ = event_tx.send(NodeEvent::PeerConnected(peer_id));

    // Connection loop with proper message framing
    loop {
        tokio::select! {
            // SECURITY (H-2): Use the inactivity-timed read to prevent Slowloris DoS.
            // A peer sending partial data would otherwise pin the connection slot.
            result = framer.read_budgeted_message_timeout() => {
                match result {
                    Ok(message) => {
                        // DoS protection is handled by:
                        // 1. MAX_MESSAGE_SIZE check in framing.rs (16MB cap)
                        // 2. Per-peer misbehavior scoring in process_message()
                        // 3. Connection limits (MAX_CONNECTIONS_PER_IP)
                        // Never drop solicited data because doing so breaks IBD.

                        if msg_tx.send(PeerMessage {
                            peer_id,
                            msg_type: message.msg_type,
                            payload: message.payload,
                            _reservation: message.reservation,
                        }).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Read error from peer {:?}: {}", &peer_id[..4], e);
                        break;
                    }
                }
            }

            // Write to network (messages from other parts of the system)
            data = rx.recv() => {
                let Some(data) = data else {
                    break;
                };
                // Data should be a complete message with header
                // Extract type and payload, then use framer to send
                // NOTE: >= HEADER_SIZE allows empty-payload messages (Verack, GetAddr)
                if data.len() >= HEADER_SIZE {
                    let msg_type = data[4];
                    // WIRETRACE (CIP-020 baseline): when COINCYNC_WIRE_TRACE=1,
                    // emit one line per outbound packet so off-node analysis can
                    // reconstruct the on-wire adversary view and compute the
                    // timing-correlation r on REAL traffic. `msg_type` 99 =
                    // MessageType::Padding (cover/dummy); anything else = real.
                    // This is the muxed choke point — every outbound packet to
                    // this peer (stem, fluff, inv, ping, block, padding) passes
                    // here. Off by default; the per-packet cost when disabled is
                    // one relaxed OnceLock load. Purely observational — it never
                    // alters what is sent, so it cannot affect consensus or
                    // propagation.
                    {
                        static WIRE_TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
                        let on = *WIRE_TRACE.get_or_init(|| {
                            std::env::var("COINCYNC_WIRE_TRACE").as_deref() == Ok("1")
                        });
                        if on {
                            let ts_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_millis())
                                .unwrap_or(0);
                            let p = &peer_id[..4];
                            info!(
                                target: "wiretrace",
                                "WIRETRACE {} {:02x}{:02x}{:02x}{:02x} {} {}",
                                ts_ms, p[0], p[1], p[2], p[3], msg_type, data.len()
                            );
                        }
                    }
                    let payload = &data[HEADER_SIZE..];
                    if let Err(e) = framer.write_message(msg_type, payload).await {
                        debug!("Write error to peer {:?}: {}", &peer_id[..4], e);
                        break;
                    }
                    // Track outbound bytes for telemetry (get_peers RPC, sync diagnostics).
                    // Without this, bytes_sent stays at 0 forever — masking real propagation
                    // health. Counter is per-peer, behind a DashMap entry guard, so no race.
                    if let Some(mut peer) = peers.get_mut(&peer_id) {
                        peer.bytes_sent = peer.bytes_sent.saturating_add(data.len() as u64);
                    }
                }
            }
        }
    }

    drop(rx);
    cleanup_connection(
        peer_id,
        &connection_token,
        &sender_identity,
        &peers,
        &senders,
        &event_tx,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn peer(peer_id: PeerId) -> PeerInfo {
        let addr: SocketAddr = "127.0.0.1:28080".parse().unwrap();
        PeerInfo::new(peer_id, addr, false)
    }

    #[test]
    fn cleanup_removes_the_connection_that_owns_the_entries() {
        let peer_id = [1; 32];
        let peers = DashMap::new();
        let senders = DashMap::new();
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let (sender, _receiver) = mpsc::channel(1);
        let sender_identity = sender.downgrade();
        let info = peer(peer_id);
        let token = Arc::clone(&info.connection_token);

        peers.insert(peer_id, info);
        senders.insert(peer_id, sender.clone());

        assert!(cleanup_connection(
            peer_id,
            &token,
            &sender_identity,
            &peers,
            &senders,
            &event_tx,
        ));
        assert!(!peers.contains_key(&peer_id));
        assert!(!senders.contains_key(&peer_id));
        assert!(matches!(
            event_rx.try_recv(),
            Ok(NodeEvent::PeerDisconnected(id)) if id == peer_id
        ));
    }

    #[test]
    fn stale_cleanup_preserves_a_replacement_connection() {
        let peer_id = [2; 32];
        let peers = DashMap::new();
        let senders = DashMap::new();
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let (old_sender, _old_receiver) = mpsc::channel(1);
        let old_sender_identity = old_sender.downgrade();
        let (new_sender, _new_receiver) = mpsc::channel(1);
        let old_info = peer(peer_id);
        let old_token = Arc::clone(&old_info.connection_token);
        let new_info = peer(peer_id);
        let new_token = Arc::clone(&new_info.connection_token);

        peers.insert(peer_id, new_info);
        senders.insert(peer_id, new_sender.clone());

        assert!(!cleanup_connection(
            peer_id,
            &old_token,
            &old_sender_identity,
            &peers,
            &senders,
            &event_tx,
        ));
        assert!(Arc::ptr_eq(
            &peers.get(&peer_id).unwrap().connection_token,
            &new_token,
        ));
        assert!(senders.get(&peer_id).unwrap().same_channel(&new_sender));
        assert!(matches!(
            event_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn cleanup_identity_does_not_keep_the_send_channel_open() {
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(1);
        let identity = sender.downgrade();

        drop(sender);

        assert!(identity.upgrade().is_none());
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn noise_record_rejects_noncanonical_wire_size() {
        let shaper = TrafficShaper::default_enabled();
        let record = shaper.normalize_size(b"wrong overhead");
        assert!(denormalize_noise_record(&shaper, record).is_err());
    }

    #[tokio::test]
    async fn normalized_noise_record_round_trip_uses_bucket_size() {
        let client_identity = Arc::new(NodeIdentity::generate());
        let server_identity = Arc::new(NodeIdentity::generate());
        let (mut client_handshake, mut server_handshake) = tokio::io::duplex(8192);
        let (client_result, server_result) = tokio::join!(
            noise::perform_noise_handshake(&mut client_handshake, client_identity, true),
            noise::perform_noise_handshake(&mut server_handshake, server_identity, false),
        );
        let (client_transport, _) = client_result.unwrap();
        let (server_transport, _) = server_result.unwrap();
        let (client_send, _) = client_transport.split_into_send_recv();
        let (_, server_recv) = server_transport.split_into_send_recv();
        let shaper = Arc::new(TrafficShaper::default_enabled());
        let logical_payload = vec![0x6d; 777];
        let framed_payload = shaper.normalize_size_with_overhead(&logical_payload, HEADER_SIZE);
        let plaintext = Message::new([1, 2, 3, 4], MessageType::Blocks, framed_payload)
            .to_bytes()
            .unwrap();

        let (encrypted_writer, mut encrypted_reader) = tokio::io::duplex(4096);
        let (mut app_writer, app_reader) = tokio::io::duplex(4096);
        let writer_task = tokio::spawn(noise_bridge_writer(
            client_send,
            encrypted_writer,
            app_reader,
            Arc::clone(&shaper),
        ));
        app_writer.write_all(&plaintext).await.unwrap();
        let mut length_prefix = [0u8; 2];
        encrypted_reader
            .read_exact(&mut length_prefix)
            .await
            .unwrap();
        let ciphertext_len = u16::from_be_bytes(length_prefix) as usize;
        let mut ciphertext = vec![0u8; ciphertext_len];
        encrypted_reader.read_exact(&mut ciphertext).await.unwrap();
        let wire_len = length_prefix.len() + ciphertext.len();
        assert!(
            crate::colony::stick_insect::SIZE_BUCKETS.contains(&wire_len)
                || wire_len
                    % crate::colony::stick_insect::SIZE_BUCKETS
                        [crate::colony::stick_insect::SIZE_BUCKETS.len() - 1]
                    == 0
        );

        let (mut feed_writer, mut feed_reader) = tokio::io::duplex(4096);
        feed_writer.write_all(&length_prefix).await.unwrap();
        feed_writer.write_all(&ciphertext).await.unwrap();
        let decrypted = server_recv.read_encrypted(&mut feed_reader).await.unwrap();
        let recovered = denormalize_noise_record(&shaper, decrypted).unwrap();
        assert_eq!(recovered, plaintext);
        writer_task.abort();
    }
}
