//! # WebSocket Subscriptions for CoinCync RPC
//!
//! Real-time event streaming via WebSocket:
//! - New blocks
//! - New transactions
//! - Mining events
//! - Wallet updates

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use serde::{Serialize, Deserialize};
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
                    cid, MAX_SUBSCRIPTIONS_PER_CLIENT
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
        let (id, mut receiver) = manager.subscribe(vec![EventType::NewBlock], Some("test-client")).await.unwrap();

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
        let (id1, _rx1) = manager.subscribe(vec![EventType::NewBlock], None).await.unwrap();
        let (id2, _rx2) = manager.subscribe(vec![EventType::NewTransaction], None).await.unwrap();
        assert_ne!(id1, id2);
        assert_eq!(manager.subscription_count().await, 2);

        // Unsubscribe one
        assert!(manager.unsubscribe(id1, None).await);
        assert_eq!(manager.subscription_count().await, 1);

        // Double unsubscribe should return false
        assert!(!manager.unsubscribe(id1, None).await);
    }
}
