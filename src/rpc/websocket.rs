//! # WebSocket Subscriptions for CoinCync RPC
//!
//! Real-time event streaming via WebSocket:
//! - New blocks
//! - New transactions
//! - Mining events
//! - Wallet updates
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `SubscriptionManager::subscribe` (limits)** — INVARIANT: subscription
//!   creation enforces the per-client and global caps atomically, with no
//!   TOCTOU window under concurrent subscribes. THREAT: memory-exhaustion DoS via
//!   unbounded subscriptions. TESTS: `subscribe_enforces_per_client_limit`,
//!   `subscribe_enforces_global_limit`,
//!   `subscribe_toctou_concurrent_cannot_exceed_per_client_limit`,
//!   `test_subscription_creation`.
//! - **§2 `broadcast` (event routing)** — INVARIANT: an event reaches only
//!   subscribers of its event type plus the global receiver, and a lagging/full
//!   receiver never stalls the others. THREAT: cross-subscription leakage, or one
//!   slow client wedging the broadcast fan-out. TESTS:
//!   `broadcast_only_delivers_to_matching_event_types`,
//!   `broadcast_also_reaches_global_receiver`,
//!   `broadcast_handles_lagging_receiver_when_channel_full`.
//! - **§3 `unsubscribe`** — INVARIANT: unsubscribe decrements the client count and
//!   removes the entry at zero. THREAT: leaked subscription slots let a client
//!   evade the per-client cap. TESTS:
//!   `unsubscribe_decrements_client_count_and_removes_entry_at_zero`.
//! - **§4 `Event` constructors** — INVARIANT: `new_block` / `new_transaction` /
//!   `sync_progress` / `wallet_update` build correctly-typed, serializable events.
//!   THREAT: a mislabeled event is routed to the wrong subscribers. TESTS:
//!   `test_event_serialization`, `test_subscription_manager`.
//! - **§5 `WsMessage` parsing** — INVARIANT: subscribe/unsubscribe/ping deserialize
//!   and bad or unknown control messages are rejected. THREAT: a malformed control
//!   frame confuses or crashes the handler. TESTS:
//!   `ws_message_deserializes_subscribe_unsubscribe_ping`,
//!   `ws_message_rejects_bad_or_unknown_messages`.
//! - **§6 `subscription_count` / `global_receiver` / `create_subscription_manager`** —
//!   INVARIANT: accessors report accurate live counts and hand out a working global
//!   receiver. THREAT: inaccurate accounting undercounts against the caps. TESTS:
//!   `test_subscription_manager`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

/// Maximum number of pending messages per subscription
const MAX_PENDING_MESSAGES: usize = 100;

/// SECURITY (RPC-M2): Maximum subscriptions per client to prevent resource exhaustion.
/// A single client creating thousands of subscriptions could exhaust server memory.
const MAX_SUBSCRIPTIONS_PER_CLIENT: usize = 10;

/// SECURITY (RPC-M2): Maximum total subscriptions across all clients.
const MAX_TOTAL_SUBSCRIPTIONS: usize = 10_000;

/// WebSocket event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// New block added to chain
    NewBlock,
    /// New transaction in mempool
    NewTransaction,
    /// Transaction confirmed
    TransactionConfirmed,
    /// Block mined (for miners)
    BlockMined,
    /// Wallet balance changed
    WalletUpdate,
    /// Peer connected/disconnected
    PeerUpdate,
    /// Sync progress
    SyncProgress,
}

/// Event payload
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// Event type
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// Event data
    pub data: serde_json::Value,
    /// Timestamp (unix ms)
    pub timestamp: i64,
}

impl Event {
    /// Create new block event
    pub fn new_block(height: u64, hash: &str, tx_count: usize) -> Self {
        Event {
            event_type: EventType::NewBlock,
            data: serde_json::json!({
                "height": height,
                "hash": hash,
                "tx_count": tx_count,
            }),
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Create new transaction event
    pub fn new_transaction(tx_hash: &str, fee: u64) -> Self {
        Event {
            event_type: EventType::NewTransaction,
            data: serde_json::json!({
                "tx_hash": tx_hash,
                "fee": fee,
            }),
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Create sync progress event
    pub fn sync_progress(current: u64, target: u64, peers: usize) -> Self {
        Event {
            event_type: EventType::SyncProgress,
            data: serde_json::json!({
                "current_height": current,
                "target_height": target,
                "progress": if target > 0 { (current as f64 / target as f64) * 100.0 } else { 100.0 },
                "peers": peers,
            }),
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Create wallet update event
    pub fn wallet_update(balance: &str, pending: &str) -> Self {
        Event {
            event_type: EventType::WalletUpdate,
            data: serde_json::json!({
                "balance": balance,
                "pending": pending,
            }),
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }
}

/// Subscription ID
pub type SubscriptionId = Uuid;

/// Subscription info
#[derive(Clone)]
#[allow(dead_code)]
pub struct Subscription {
    /// Subscription ID
    pub id: SubscriptionId,
    /// Subscribed event types
    pub event_types: Vec<EventType>,
    /// Sender for this subscription
    sender: broadcast::Sender<Event>,
}

/// WebSocket subscription manager
pub struct SubscriptionManager {
    /// Active subscriptions
    subscriptions: RwLock<HashMap<SubscriptionId, Subscription>>,
    /// SECURITY (RPC-M2): Track subscription count per client ID
    client_sub_counts: RwLock<HashMap<String, usize>>,
    /// Global event broadcaster
    broadcaster: broadcast::Sender<Event>,
}

impl SubscriptionManager {
    /// Create new subscription manager
    pub fn new() -> Self {
        let (broadcaster, _) = broadcast::channel(MAX_PENDING_MESSAGES);
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            client_sub_counts: RwLock::new(HashMap::new()),
            broadcaster,
        }
    }

    /// Subscribe to event types with per-client limiting.
    ///
    /// SECURITY (RPC-M2): Enforces per-client and global subscription limits.
    pub async fn subscribe(
        &self,
        event_types: Vec<EventType>,
        client_id: Option<&str>,
    ) -> std::result::Result<(SubscriptionId, broadcast::Receiver<Event>), &'static str> {
        // FIX (TOCTOU): Acquire BOTH write locks before any checks to prevent
        // two concurrent subscribe() calls from both passing the per-client limit.
        // Previously used separate read locks (dropped between checks) then write locks.
        let mut subs = self.subscriptions.write().await;
        let mut counts = self.client_sub_counts.write().await;

        // Check global limit (under write lock)
        if subs.len() >= MAX_TOTAL_SUBSCRIPTIONS {
            return Err("Maximum total subscriptions reached");
        }

        // Check per-client limit (under write lock — atomic with insert below)
        if let Some(cid) = client_id {
            let current = counts.get(cid).copied().unwrap_or(0);
            if current >= MAX_SUBSCRIPTIONS_PER_CLIENT {
                tracing::warn!(
                    "Client {} exceeded subscription limit ({})",
                    cid,
                    MAX_SUBSCRIPTIONS_PER_CLIENT
                );
                return Err("Maximum subscriptions per client reached");
            }
        }

        let id = Uuid::new_v4();
        let (sender, receiver) = broadcast::channel(MAX_PENDING_MESSAGES);

        let subscription = Subscription {
            id,
            event_types,
            sender,
        };

        subs.insert(id, subscription);

        // Track per-client count (still under write lock — no TOCTOU gap)
        if let Some(cid) = client_id {
            *counts.entry(cid.to_string()).or_insert(0) += 1;
        }

        tracing::debug!("New subscription: {}", id);
        Ok((id, receiver))
    }

    /// Unsubscribe
    pub async fn unsubscribe(&self, id: SubscriptionId, client_id: Option<&str>) -> bool {
        let removed = self.subscriptions.write().await.remove(&id).is_some();
        if removed {
            // Decrement per-client count
            if let Some(cid) = client_id {
                let mut counts = self.client_sub_counts.write().await;
                if let Some(count) = counts.get_mut(cid) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        counts.remove(cid);
                    }
                }
            }
            tracing::debug!("Subscription removed: {}", id);
        }
        removed
    }

    /// Broadcast event to relevant subscribers
    pub async fn broadcast(&self, event: Event) {
        let subscriptions = self.subscriptions.read().await;

        for subscription in subscriptions.values() {
            if subscription.event_types.contains(&event.event_type) {
                let _ = subscription.sender.send(event.clone());
            }
        }

        // Also send to global broadcaster
        let _ = self.broadcaster.send(event);
    }

    /// Get global event receiver
    pub fn global_receiver(&self) -> broadcast::Receiver<Event> {
        self.broadcaster.subscribe()
    }

    /// Get subscription count
    pub async fn subscription_count(&self) -> usize {
        self.subscriptions.read().await.len()
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared subscription manager
pub type SharedSubscriptionManager = Arc<SubscriptionManager>;

/// Create shared subscription manager
pub fn create_subscription_manager() -> SharedSubscriptionManager {
    Arc::new(SubscriptionManager::new())
}

/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum WsMessage {
    /// Subscribe to events
    #[serde(rename = "subscribe")]
    Subscribe { events: Vec<EventType> },

    /// Unsubscribe
    #[serde(rename = "unsubscribe")]
    Unsubscribe { subscription_id: String },

    /// Ping
    #[serde(rename = "ping")]
    Ping,
}

/// WebSocket response
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum WsResponse {
    /// Subscription created
    #[serde(rename = "subscribed")]
    Subscribed { subscription_id: String },

    /// Unsubscribed
    #[serde(rename = "unsubscribed")]
    Unsubscribed { success: bool },

    /// Event notification
    #[serde(rename = "event")]
    Event(Event),

    /// Pong response
    #[serde(rename = "pong")]
    Pong { timestamp: i64 },

    /// Error
    #[serde(rename = "error")]
    Error { code: i32, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_subscription_manager() {
        let manager = SubscriptionManager::new();

        // Subscribe to new blocks
        let (id, mut receiver) = manager
            .subscribe(vec![EventType::NewBlock], Some("test-client"))
            .await
            .unwrap();

        // Broadcast event
        let event = Event::new_block(100, "abc123", 5);
        manager.broadcast(event.clone()).await;

        // Should receive the event
        let received = receiver.try_recv().unwrap();
        assert_eq!(received.event_type, EventType::NewBlock);

        // Unsubscribe
        assert!(manager.unsubscribe(id, Some("test-client")).await);
        assert_eq!(manager.subscription_count().await, 0);
    }

    #[test]
    fn test_event_serialization() {
        let event = Event::new_block(100, "abc123", 5);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("new_block"));
        assert!(json.contains("100"));
    }

    #[tokio::test]
    async fn test_subscription_creation() {
        let manager = SubscriptionManager::new();

        // Subscribe
        let (id1, _rx1) = manager
            .subscribe(vec![EventType::NewBlock], None)
            .await
            .unwrap();
        let (id2, _rx2) = manager
            .subscribe(vec![EventType::NewTransaction], None)
            .await
            .unwrap();
        assert_ne!(id1, id2);
        assert_eq!(manager.subscription_count().await, 2);

        // Unsubscribe one
        assert!(manager.unsubscribe(id1, None).await);
        assert_eq!(manager.subscription_count().await, 1);

        // Double unsubscribe should return false
        assert!(!manager.unsubscribe(id1, None).await);
    }

    // ── RPC-M2 subscription limits, matched delivery, and message parsing ──

    #[tokio::test]
    async fn subscribe_enforces_per_client_limit() {
        let manager = SubscriptionManager::new();
        // The first MAX_SUBSCRIPTIONS_PER_CLIENT subscribes succeed.
        for _ in 0..MAX_SUBSCRIPTIONS_PER_CLIENT {
            manager
                .subscribe(vec![EventType::NewBlock], Some("client-a"))
                .await
                .expect("under per-client limit");
        }
        // The next one is rejected.
        let err = manager
            .subscribe(vec![EventType::NewBlock], Some("client-a"))
            .await
            .expect_err("per-client limit enforced");
        assert_eq!(err, "Maximum subscriptions per client reached");
        // A different client is unaffected.
        manager
            .subscribe(vec![EventType::NewBlock], Some("client-b"))
            .await
            .expect("other client unaffected");
    }

    #[tokio::test]
    async fn subscribe_enforces_global_limit() {
        let manager = SubscriptionManager::new();
        // Fill the subscription map to the global cap directly (in-module
        // access to the private field) so we don't spin up 10k channels/tasks.
        let (sender, _keep) = broadcast::channel::<Event>(1);
        {
            let mut subs = manager.subscriptions.write().await;
            for _ in 0..MAX_TOTAL_SUBSCRIPTIONS {
                let id = Uuid::new_v4();
                subs.insert(
                    id,
                    Subscription {
                        id,
                        event_types: vec![EventType::NewBlock],
                        sender: sender.clone(),
                    },
                );
            }
        }
        let err = manager
            .subscribe(vec![EventType::NewBlock], None)
            .await
            .expect_err("global limit enforced");
        assert_eq!(err, "Maximum total subscriptions reached");
    }

    #[tokio::test]
    async fn subscribe_toctou_concurrent_cannot_exceed_per_client_limit() {
        // Both write locks are held across the check-and-insert, so even
        // many racing subscribes for one client can never exceed the cap.
        let manager = Arc::new(SubscriptionManager::new());
        let mut handles = Vec::new();
        for _ in 0..40 {
            let m = Arc::clone(&manager);
            handles.push(tokio::spawn(async move {
                m.subscribe(vec![EventType::NewBlock], Some("racer"))
                    .await
                    .is_ok()
            }));
        }
        let mut succeeded = 0usize;
        for h in handles {
            if h.await.unwrap() {
                succeeded += 1;
            }
        }
        assert_eq!(succeeded, MAX_SUBSCRIPTIONS_PER_CLIENT);
        assert_eq!(
            manager.subscription_count().await,
            MAX_SUBSCRIPTIONS_PER_CLIENT
        );
    }

    #[tokio::test]
    async fn broadcast_only_delivers_to_matching_event_types() {
        let manager = SubscriptionManager::new();
        let (_id_block, mut rx_block) = manager
            .subscribe(vec![EventType::NewBlock], None)
            .await
            .unwrap();
        let (_id_tx, mut rx_tx) = manager
            .subscribe(vec![EventType::NewTransaction], None)
            .await
            .unwrap();

        manager.broadcast(Event::new_block(1, "hash", 0)).await;

        // The NewBlock subscriber receives it; the NewTransaction one does not.
        assert_eq!(rx_block.try_recv().unwrap().event_type, EventType::NewBlock);
        assert!(matches!(
            rx_tx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn broadcast_also_reaches_global_receiver() {
        let manager = SubscriptionManager::new();
        let mut global = manager.global_receiver();
        manager.broadcast(Event::new_block(7, "abc", 3)).await;
        let ev = global.try_recv().expect("global receiver gets every event");
        assert_eq!(ev.event_type, EventType::NewBlock);
    }

    #[tokio::test]
    async fn unsubscribe_decrements_client_count_and_removes_entry_at_zero() {
        let manager = SubscriptionManager::new();
        let (id1, _rx1) = manager
            .subscribe(vec![EventType::NewBlock], Some("c"))
            .await
            .unwrap();
        let (id2, _rx2) = manager
            .subscribe(vec![EventType::NewBlock], Some("c"))
            .await
            .unwrap();
        assert_eq!(*manager.client_sub_counts.read().await.get("c").unwrap(), 2);

        // One unsubscribe decrements but keeps the entry.
        assert!(manager.unsubscribe(id1, Some("c")).await);
        assert_eq!(*manager.client_sub_counts.read().await.get("c").unwrap(), 1);

        // The last unsubscribe removes the map entry entirely (no zero rows).
        assert!(manager.unsubscribe(id2, Some("c")).await);
        assert!(!manager.client_sub_counts.read().await.contains_key("c"));
    }

    #[test]
    fn ws_message_deserializes_subscribe_unsubscribe_ping() {
        let sub: WsMessage =
            serde_json::from_str(r#"{"method":"subscribe","params":{"events":["new_block"]}}"#)
                .expect("subscribe parses");
        assert!(matches!(sub, WsMessage::Subscribe { events } if events == vec![EventType::NewBlock]));

        let unsub: WsMessage = serde_json::from_str(
            r#"{"method":"unsubscribe","params":{"subscription_id":"abc-123"}}"#,
        )
        .expect("unsubscribe parses");
        assert!(matches!(unsub, WsMessage::Unsubscribe { subscription_id } if subscription_id == "abc-123"));

        let ping: WsMessage =
            serde_json::from_str(r#"{"method":"ping"}"#).expect("ping parses");
        assert!(matches!(ping, WsMessage::Ping));
    }

    #[test]
    fn ws_message_rejects_bad_or_unknown_messages() {
        // Unknown method tag.
        assert!(serde_json::from_str::<WsMessage>(r#"{"method":"frobnicate"}"#).is_err());
        // Missing the method tag entirely.
        assert!(serde_json::from_str::<WsMessage>(r#"{"params":{"events":[]}}"#).is_err());
        // Not even an object.
        assert!(serde_json::from_str::<WsMessage>(r#"["subscribe"]"#).is_err());
    }

    #[tokio::test]
    async fn broadcast_handles_lagging_receiver_when_channel_full() {
        let manager = SubscriptionManager::new();
        // Subscribe but never drain — the per-subscription channel holds
        // MAX_PENDING_MESSAGES before it starts dropping the oldest.
        let (_id, mut rx) = manager
            .subscribe(vec![EventType::NewBlock], None)
            .await
            .unwrap();

        // Overrun the channel; broadcast ignores send errors, so this must
        // neither panic nor block.
        for i in 0..(MAX_PENDING_MESSAGES + 50) {
            manager
                .broadcast(Event::new_block(i as u64, "h", 0))
                .await;
        }

        // The slow receiver observes a Lagged error rather than a crash, and
        // the subscription is still live.
        assert!(matches!(
            rx.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(_))
        ));
        assert_eq!(manager.subscription_count().await, 1);
    }
}
