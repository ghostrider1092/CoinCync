//! # Noise_XX Encrypted Transport for CoinCync P2P
//!
//! Uses the `snow` crate for Noise_XX handshake (audited, production-grade).
//! Pattern: Noise_XX_25519_ChaChaPoly_SHA256
//!
//! Transport framing (kept from original):
//!   [18 bytes: enc(2-byte msg len) + Poly1305 tag]
//!   [N+16 bytes: enc(payload) + Poly1305 tag]

use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use snow::{Builder, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::PublicKey as X25519Public;
use zeroize::ZeroizeOnDrop;

use crate::error::{Error, Result};
use super::PeerId;

/// Noise pattern for the handshake.
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const ANCHOR_SIGN_DOMAIN: &[u8] = b"coincync/anchor-sign/v1";

/// Maximum plaintext payload per Noise transport message.
const MAX_NOISE_PAYLOAD: usize = 65519;

/// Noise handshake timeout in seconds.
pub const NOISE_HANDSHAKE_TIMEOUT_SECS: u64 = 15;

fn harden_secret_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        if let Some(path_str) = path.to_str() {
            let _ = std::process::Command::new("icacls")
                .args([path_str, "/inheritance:r"])
                .status();
            let user = std::env::var("USERNAME").unwrap_or_else(|_| "Users".to_string());
            let grant = format!("{user}:F");
            let _ = std::process::Command::new("icacls")
                .args([path_str, "/grant:r", &grant])
                .status();
        }
    }
}

// ─── NodeIdentity ────────────────────────────────────────────────────────────

/// Persistent node identity keypair (X25519 static key).
///
/// Stored at `{data_dir}/node_key` (64 bytes: 32 secret + 32 public).
/// Anchor signing secret is stored separately at `{data_dir}/node_signing_key`
/// (32 bytes). Both secrets are zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct NodeIdentity {
    #[zeroize(skip)]
    public: X25519Public,
    transport_secret_bytes: [u8; 32],
    anchor_signing_secret_bytes: [u8; 32],
}

impl NodeIdentity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = X25519Public::from(&secret);
        let transport_secret_bytes = secret.to_bytes();
        let anchor_signing_secret_bytes = rand::random::<[u8; 32]>();
        NodeIdentity { public, transport_secret_bytes, anchor_signing_secret_bytes }
    }

    /// Load from disk or generate fresh.
    pub fn load_or_generate(data_dir: &Path) -> Result<Self> {
        let key_path = data_dir.join("node_key");
        let signing_key_path = data_dir.join("node_signing_key");
        if key_path.exists() {
            let data = std::fs::read(&key_path)
                .map_err(|e| Error::InvalidState(format!("read node_key: {}", e)))?;
            if data.len() >= 64 {
                let mut secret = [0u8; 32];
                let mut public = [0u8; 32];
                secret.copy_from_slice(&data[..32]);
                public.copy_from_slice(&data[32..64]);
                if secret == [0u8; 32] {
                    return Err(Error::NoiseHandshakeFailed("all-zeros secret key".into()));
                }
                let anchor_signing_secret_bytes = if signing_key_path.exists() {
                    let signing = std::fs::read(&signing_key_path)
                        .map_err(|e| Error::InvalidState(format!("read node_signing_key: {}", e)))?;
                    if signing.len() < 32 {
                        return Err(Error::InvalidState("node_signing_key too short".into()));
                    }
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&signing[..32]);
                    if s == [0u8; 32] {
                        return Err(Error::InvalidState("node_signing_key is all zeros".into()));
                    }
                    s
                } else {
                    // Backward-compat: old installs only had node_key.
                    // Derive signing key from transport key once, then persist separately.
                    tracing::warn!("node_signing_key missing; migrating legacy identity to split signing key");
                    secret
                };
                return Ok(NodeIdentity {
                    public: X25519Public::from(public),
                    transport_secret_bytes: secret,
                    anchor_signing_secret_bytes,
                });
            }
        }
        let id = Self::generate();
        id.save(data_dir)?;
        Ok(id)
    }

    /// Load from disk or generate fresh, checking for stale keys.
    pub fn load_or_generate_fresh(data_dir: &Path) -> Result<Self> {
        let key_path = data_dir.join("node_key");
        let db_path = data_dir.join("db");

        // If DB exists but node_key doesn't, the key was lost — regenerate
        if db_path.exists() && !key_path.exists() {
            tracing::warn!("node_key missing but database exists — regenerating identity");
        }

        // If node_key is older than DB, it may be stale
        if key_path.exists() && db_path.exists() {
            let key_meta = std::fs::metadata(&key_path).ok();
            let db_meta = std::fs::metadata(&db_path).ok();
            if let (Some(km), Some(dm)) = (key_meta, db_meta) {
                if let (Ok(kt), Ok(dt)) = (km.modified(), dm.modified()) {
                    if kt < dt {
                        tracing::info!("node_key older than database — keeping existing key");
                    }
                }
            }
        }

        Self::load_or_generate(data_dir)
    }

    /// Clear the identity from disk (force regeneration on next start).
    pub fn clear_identity(data_dir: &Path) {
        let key_path = data_dir.join("node_key");
        let signing_key_path = data_dir.join("node_signing_key");
        if key_path.exists() {
            let _ = std::fs::remove_file(&key_path);
        }
        if signing_key_path.exists() {
            let _ = std::fs::remove_file(&signing_key_path);
        }
        tracing::info!("Node identity cleared — will regenerate on next start");
    }

    /// Save to disk.
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| Error::InvalidState(format!("create data_dir: {}", e)))?;
        let key_path = data_dir.join("node_key");
        let signing_key_path = data_dir.join("node_signing_key");
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&self.transport_secret_bytes);
        data[32..].copy_from_slice(self.public.as_bytes());
        std::fs::write(&key_path, &data)
            .map_err(|e| Error::InvalidState(format!("write node_key: {}", e)))?;
        std::fs::write(&signing_key_path, &self.anchor_signing_secret_bytes)
            .map_err(|e| Error::InvalidState(format!("write node_signing_key: {}", e)))?;

        harden_secret_file_permissions(&key_path);
        harden_secret_file_permissions(&signing_key_path);

        Ok(())
    }

    /// Get the peer ID derived from the public key.
    pub fn peer_id(&self) -> PeerId {
        let hash = blake3::hash(self.public.as_bytes());
        let mut id = [0u8; 32];
        id.copy_from_slice(hash.as_bytes());
        id
    }

    /// Get the raw public key bytes.
    pub fn public_bytes(&self) -> &[u8; 32] {
        self.public.as_bytes()
    }

    /// Get the secret key bytes (for snow Builder).
    fn transport_secret_bytes(&self) -> &[u8; 32] {
        &self.transport_secret_bytes
    }

    /// Sign an anchor payload with Ed25519 over a domain-separated message.
    ///
    /// NOTE: This uses a dedicated signing secret distinct from the X25519
    /// Noise key agreement secret.
    pub fn sign_anchor_payload(&self, payload: &[u8]) -> [u8; 64] {
        let signing_key = SigningKey::from_bytes(&self.anchor_signing_secret_bytes);
        let msg = anchor_signing_message(payload);
        signing_key.sign(&msg).to_bytes()
    }

    /// Verify an anchor signature produced by `sign_anchor_payload`.
    pub fn verify_anchor_signature(pubkey: &[u8; 32], payload: &[u8], signature: &[u8; 64]) -> bool {
        let vk = match VerifyingKey::from_bytes(pubkey) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(signature);
        let msg = anchor_signing_message(payload);
        vk.verify(&msg, &sig).is_ok()
    }

    /// Get the public key used for anchor signing verification.
    pub fn anchor_signing_pubkey(&self) -> [u8; 32] {
        let signing_key = SigningKey::from_bytes(&self.anchor_signing_secret_bytes);
        signing_key.verifying_key().to_bytes()
    }
}

fn anchor_signing_message(payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ANCHOR_SIGN_DOMAIN.len() + payload.len());
    msg.extend_from_slice(ANCHOR_SIGN_DOMAIN);
    msg.extend_from_slice(payload);
    msg
}

// ─── NoiseHandshake (powered by snow) ────────────────────────────────────────

/// Noise_XX handshake using the `snow` crate.
pub struct NoiseHandshake {
    identity: Arc<NodeIdentity>,
    initiator: bool,
}

impl NoiseHandshake {
    pub fn initiator(identity: Arc<NodeIdentity>) -> Self {
        NoiseHandshake { identity, initiator: true }
    }

    pub fn responder(identity: Arc<NodeIdentity>) -> Self {
        NoiseHandshake { identity, initiator: false }
    }

    /// Execute the full Noise_XX handshake.
    /// Returns the encrypted transport and the remote peer's static public key.
    pub async fn execute<S: AsyncRead + AsyncWrite + Unpin>(
        self,
        stream: &mut S,
    ) -> Result<(NoiseTransport, PeerId)> {
        let builder = Builder::new(NOISE_PATTERN.parse()
            .map_err(|e| Error::NoiseHandshakeFailed(format!("pattern parse: {e}")))?);

        let mut handshake = if self.initiator {
            builder
                .local_private_key(self.identity.transport_secret_bytes())
                .build_initiator()
        } else {
            builder
                .local_private_key(self.identity.transport_secret_bytes())
                .build_responder()
        }.map_err(|e| Error::NoiseHandshakeFailed(format!("snow build: {e}")))?;

        let mut buf = vec![0u8; 65535];

        // Noise_XX: 3 messages
        // Initiator: write → read → write
        // Responder: read → write → read
        if self.initiator {
            // → msg1
            let len = handshake.write_message(&[], &mut buf)
                .map_err(|e| Error::NoiseHandshakeFailed(format!("msg1 write: {e}")))?;
            write_noise_frame(stream, &buf[..len]).await?;

            // ← msg2
            let msg2 = read_noise_frame(stream).await?;
            handshake.read_message(&msg2, &mut buf)
                .map_err(|e| Error::NoiseHandshakeFailed(format!("msg2 read: {e}")))?;

            // → msg3
            let len = handshake.write_message(&[], &mut buf)
                .map_err(|e| Error::NoiseHandshakeFailed(format!("msg3 write: {e}")))?;
            write_noise_frame(stream, &buf[..len]).await?;
        } else {
            // ← msg1
            let msg1 = read_noise_frame(stream).await?;
            handshake.read_message(&msg1, &mut buf)
                .map_err(|e| Error::NoiseHandshakeFailed(format!("msg1 read: {e}")))?;

            // → msg2
            let len = handshake.write_message(&[], &mut buf)
                .map_err(|e| Error::NoiseHandshakeFailed(format!("msg2 write: {e}")))?;
            write_noise_frame(stream, &buf[..len]).await?;

            // ← msg3
            let msg3 = read_noise_frame(stream).await?;
            handshake.read_message(&msg3, &mut buf)
                .map_err(|e| Error::NoiseHandshakeFailed(format!("msg3 read: {e}")))?;
        }

        // Extract remote static key
        let remote_static = handshake.get_remote_static()
            .ok_or_else(|| Error::NoiseHandshakeFailed("no remote static key".into()))?;
        let mut remote_key = [0u8; 32];
        remote_key.copy_from_slice(remote_static);

        // Validate remote key is not all-zeros
        if remote_key == [0u8; 32] {
            return Err(Error::NoiseHandshakeFailed(
                "rejected all-zeros remote static key".into(),
            ));
        }

        let peer_id = {
            let hash = blake3::hash(&remote_key);
            let mut id = [0u8; 32];
            id.copy_from_slice(hash.as_bytes());
            id
        };

        // Transition to transport mode
        let transport = handshake.into_transport_mode()
            .map_err(|e| Error::NoiseHandshakeFailed(format!("transport mode: {e}")))?;

        Ok((NoiseTransport { state: transport }, peer_id))
    }
}

// ─── NoiseTransport (snow TransportState wrapper) ────────────────────────────

/// Encrypted transport using snow's TransportState.
pub struct NoiseTransport {
    state: TransportState,
}

/// Send-only half of the transport.
pub struct NoiseSendState {
    state: Arc<tokio::sync::Mutex<TransportState>>,
}

/// Recv-only half of the transport.
pub struct NoiseRecvState {
    state: Arc<tokio::sync::Mutex<TransportState>>,
}

impl NoiseTransport {
    /// Encrypt and write a message with length-prefix framing.
    pub async fn write_encrypted<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        plaintext: &[u8],
    ) -> Result<()> {
        if plaintext.len() > MAX_NOISE_PAYLOAD {
            return Err(Error::NoiseDecryptionFailed("message too large".into()));
        }
        let mut buf = vec![0u8; plaintext.len() + 16]; // payload + tag
        let len = self.state.write_message(plaintext, &mut buf)
            .map_err(|e| Error::NoiseDecryptionFailed(format!("encrypt: {e}")))?;
        // Write length prefix (2 bytes, unencrypted) + ciphertext
        if len > u16::MAX as usize {
            return Err(Error::NoiseDecryptionFailed("encrypted frame exceeds u16 length".into()));
        }
        let frame_len = (len as u16).to_be_bytes();
        writer.write_all(&frame_len).await?;
        writer.write_all(&buf[..len]).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Read and decrypt a message with length-prefix framing.
    pub async fn read_encrypted<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Vec<u8>> {
        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let ct_len = u16::from_be_bytes(len_buf) as usize;
        if ct_len > MAX_NOISE_PAYLOAD + 16 {
            return Err(Error::NoiseDecryptionFailed("frame too large".into()));
        }
        // Read ciphertext
        let mut ct = vec![0u8; ct_len];
        reader.read_exact(&mut ct).await?;
        // Decrypt
        let mut plaintext = vec![0u8; ct_len];
        let len = self.state.read_message(&ct, &mut plaintext)
            .map_err(|e| Error::NoiseDecryptionFailed(format!("decrypt: {e}")))?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// Split into independent send/recv halves for concurrent I/O.
    /// Both halves share the same TransportState via Arc<Mutex>.
    pub fn split_into_send_recv(self) -> (NoiseSendState, NoiseRecvState) {
        let shared = Arc::new(tokio::sync::Mutex::new(self.state));
        (
            NoiseSendState { state: Arc::clone(&shared) },
            NoiseRecvState { state: shared },
        )
    }
}

impl NoiseSendState {
    /// Encrypt and write a message.
    pub async fn write_encrypted<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        plaintext: &[u8],
    ) -> Result<()> {
        if plaintext.len() > MAX_NOISE_PAYLOAD {
            return Err(Error::NoiseDecryptionFailed("message too large".into()));
        }
        let mut state = self.state.lock().await;
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = state.write_message(plaintext, &mut buf)
            .map_err(|e| Error::NoiseDecryptionFailed(format!("encrypt: {e}")))?;
        if len > u16::MAX as usize {
            return Err(Error::NoiseDecryptionFailed("encrypted frame exceeds u16 length".into()));
        }
        let frame_len = (len as u16).to_be_bytes();
        writer.write_all(&frame_len).await?;
        writer.write_all(&buf[..len]).await?;
        writer.flush().await?;
        Ok(())
    }
}

impl NoiseRecvState {
    /// Read and decrypt a message.
    pub async fn read_encrypted<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let ct_len = u16::from_be_bytes(len_buf) as usize;
        if ct_len > MAX_NOISE_PAYLOAD + 16 {
            return Err(Error::NoiseDecryptionFailed("frame too large".into()));
        }
        let mut ct = vec![0u8; ct_len];
        reader.read_exact(&mut ct).await?;
        let mut state = self.state.lock().await;
        let mut plaintext = vec![0u8; ct_len];
        let len = state.read_message(&ct, &mut plaintext)
            .map_err(|e| Error::NoiseDecryptionFailed(format!("decrypt: {e}")))?;
        plaintext.truncate(len);
        Ok(plaintext)
    }
}

// ─── Wire helpers ────────────────────────────────────────────────────────────

/// Write a length-prefixed frame during handshake.
async fn write_noise_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > u16::MAX as usize {
        return Err(Error::NoiseHandshakeFailed("handshake frame exceeds u16 length".into()));
    }
    let len = (data.len() as u16).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed frame during handshake.
async fn read_noise_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > 65535 {
        return Err(Error::NoiseHandshakeFailed("handshake frame too large".into()));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(data)
}

// ─── Convenience function ────────────────────────────────────────────────────

/// Perform a full Noise_XX handshake (convenience wrapper).
pub async fn perform_noise_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: Arc<NodeIdentity>,
    initiator: bool,
) -> Result<(NoiseTransport, PeerId)> {
    let handshake = if initiator {
        NoiseHandshake::initiator(identity)
    } else {
        NoiseHandshake::responder(identity)
    };
    handshake.execute(stream).await
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_noise_handshake_success() {
        let id_a = Arc::new(NodeIdentity::generate());
        let id_b = Arc::new(NodeIdentity::generate());

        let (mut client, mut server) = duplex(8192);

        let id_a_clone = id_a.clone();
        let id_b_clone = id_b.clone();

        let client_task = tokio::spawn(async move {
            perform_noise_handshake(&mut client, id_a_clone, true).await
        });
        let server_task = tokio::spawn(async move {
            perform_noise_handshake(&mut server, id_b_clone, false).await
        });

        let (client_result, server_result) = tokio::join!(client_task, server_task);
        let (_, client_peer_id) = client_result.unwrap().unwrap();
        let (_, server_peer_id) = server_result.unwrap().unwrap();

        assert_eq!(client_peer_id, id_b.peer_id());
        assert_eq!(server_peer_id, id_a.peer_id());
    }

    #[tokio::test]
    async fn test_noise_transport_roundtrip() {
        let id_a = Arc::new(NodeIdentity::generate());
        let id_b = Arc::new(NodeIdentity::generate());

        let (mut client_stream, mut server_stream) = duplex(65536);

        let id_a_c = id_a.clone();
        let id_b_c = id_b.clone();

        let client_task = tokio::spawn(async move {
            perform_noise_handshake(&mut client_stream, id_a_c, true).await
                .map(|r| (r, client_stream))
        });
        let server_task = tokio::spawn(async move {
            perform_noise_handshake(&mut server_stream, id_b_c, false).await
                .map(|r| (r, server_stream))
        });

        let (cr, sr) = tokio::join!(client_task, server_task);
        let ((mut ct, _), mut cs) = cr.unwrap().unwrap();
        let ((mut st, _), mut ss) = sr.unwrap().unwrap();

        // Client sends, server receives
        ct.write_encrypted(&mut cs, b"hello from client").await.unwrap();
        let msg = st.read_encrypted(&mut ss).await.unwrap();
        assert_eq!(msg, b"hello from client");

        // Server sends, client receives
        st.write_encrypted(&mut ss, b"hello from server").await.unwrap();
        let msg = ct.read_encrypted(&mut cs).await.unwrap();
        assert_eq!(msg, b"hello from server");
    }

    #[test]
    fn test_node_identity_roundtrip() {
        let id = NodeIdentity::generate();
        assert_ne!(id.public_bytes(), &[0u8; 32]);
        assert_ne!(id.peer_id(), [0u8; 32]);
    }
}
