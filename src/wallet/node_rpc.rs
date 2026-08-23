//! Typed JSON-RPC access used by wallet spend flows.
//!
//! The wallet CLI and auto-churn previously maintained separate ad-hoc
//! clients with different timeouts and authentication behaviour. This module
//! keeps transport policy in one place and exposes only the methods required
//! to build and submit a wallet-owned-decoy transaction.

use super::decoy_selection::CoveredRequest;
use crate::decoy::{DecoyDistributionSnapshot, ResolvedDecoySnapshot};
use crate::error::{Error, Result};
use crate::transaction::Transaction;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::fmt;
use std::time::Duration;

const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of asking a node to accept a transaction.
///
/// `Unknown` is intentionally distinct from `Rejected`: a transport failure
/// may happen after the node received the bytes. Callers must keep input
/// reservations for that case rather than making the inputs immediately
/// selectable again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmissionOutcome {
    Accepted,
    Rejected { reason: String },
    Unknown { reason: String },
}

/// Reusable, authenticated JSON-RPC client for wallet operations.
#[derive(Clone)]
pub struct NodeRpcClient {
    endpoint: String,
    client: reqwest::Client,
}

impl NodeRpcClient {
    /// Build a client using the wallet-wide default timeout.
    pub fn new(endpoint: impl Into<String>) -> Result<Self> {
        Self::with_timeout(endpoint, DEFAULT_RPC_TIMEOUT)
    }

    /// Build a client with an explicit timeout, mainly for embedding and tests.
    pub fn with_timeout(endpoint: impl Into<String>, timeout: Duration) -> Result<Self> {
        let endpoint = endpoint.into();
        if endpoint.trim().is_empty() {
            return Err(Error::ConfigError(
                "wallet RPC endpoint must not be empty".into(),
            ));
        }

        let mut headers = HeaderMap::new();
        if let Ok(api_key) = std::env::var("COINCYNC_RPC_API_KEY") {
            let api_key = api_key.trim();
            if !api_key.is_empty() {
                let mut value = HeaderValue::from_str(&format!("Bearer {api_key}"))
                    .map_err(|_| Error::ConfigError("invalid COINCYNC_RPC_API_KEY".into()))?;
                value.set_sensitive(true);
                headers.insert(AUTHORIZATION, value);
            }
        }

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .default_headers(headers)
            .build()
            .map_err(|error| Error::ConfigError(format!("build wallet RPC client: {error}")))?;

        Ok(Self { endpoint, client })
    }

    /// Configured JSON-RPC endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Fetch the canonical snapshot used for local decoy sampling.
    pub async fn decoy_distribution(&self) -> Result<DecoyDistributionSnapshot> {
        self.call_typed("get_decoy_distribution", json!([])).await
    }

    /// Resolve one typed covered request against the snapshot it was built
    /// from. Callers cannot accidentally pair locators with other metadata.
    pub async fn resolve_outputs(
        &self,
        request: &CoveredRequest,
    ) -> Result<ResolvedDecoySnapshot> {
        let snapshot = request.snapshot_id();
        self.call_typed(
            "get_outputs_by_locators",
            json!([
                snapshot.height(),
                snapshot.hash(),
                snapshot.policy_version(),
                request.locators(),
            ]),
        )
        .await
    }

    /// Serialize before reserving wallet inputs. A local encoding failure is
    /// definitive: no request can have reached the node, so callers must not
    /// create an in-flight reservation for it.
    pub(crate) fn encode_transaction(transaction: &Transaction) -> Result<String> {
        let bytes = borsh::to_vec(transaction).map_err(|error| {
            Error::SerializationError(format!("serialize transaction: {error}"))
        })?;
        Ok(hex::encode(bytes))
    }

    /// Submit already-encoded transaction bytes while preserving the
    /// distinction between a definitive node rejection and an indeterminate
    /// transport or response failure.
    pub(crate) async fn submit_encoded_transaction(
        &self,
        transaction_hex: &str,
    ) -> SubmissionOutcome {
        classify_submission_result(
            self.call_value("send_raw_transaction", json!([transaction_hex]))
                .await,
        )
    }

    /// Convenience entry point for callers that do not manage wallet input
    /// reservations themselves.
    pub async fn submit_transaction(&self, transaction: &Transaction) -> Result<SubmissionOutcome> {
        let encoded = Self::encode_transaction(transaction)?;
        Ok(self.submit_encoded_transaction(&encoded).await)
    }

    async fn call_typed<T>(&self, method: &str, params: Value) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let value = self
            .call_value(method, params)
            .await
            .map_err(|error| Error::RpcError(format!("{method}: {error}")))?;
        serde_json::from_value(value)
            .map_err(|error| Error::RpcError(format!("decode {method} response: {error}")))
    }

    async fn call_value(
        &self,
        method: &str,
        params: Value,
    ) -> std::result::Result<Value, RpcCallError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });

        let response = self
            .client
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|error| RpcCallError::Transport(error.to_string()))?;
        let status = response.status();
        let payload: Value = response
            .json()
            .await
            .map_err(|error| RpcCallError::Protocol(format!("invalid JSON response: {error}")))?;

        if let Some(error) = payload.get("error").filter(|error| !error.is_null()) {
            return Err(RpcCallError::Remote(remote_error_reason(error)));
        }
        if !status.is_success() {
            return Err(RpcCallError::Protocol(format!(
                "HTTP {status} without a JSON-RPC error"
            )));
        }

        payload
            .get("result")
            .cloned()
            .ok_or_else(|| RpcCallError::Protocol("response missing result".into()))
    }
}

fn classify_submission_result(
    result: std::result::Result<Value, RpcCallError>,
) -> SubmissionOutcome {
    match result {
        Ok(result) if submission_was_accepted(&result) => SubmissionOutcome::Accepted,
        Ok(result) => SubmissionOutcome::Rejected {
            reason: submission_rejection_reason(&result),
        },
        Err(RpcCallError::Remote(reason)) => SubmissionOutcome::Rejected { reason },
        Err(error) => SubmissionOutcome::Unknown {
            reason: error.to_string(),
        },
    }
}

fn remote_error_reason(error: &Value) -> String {
    error
        .get("message")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| error.to_string())
}

fn submission_was_accepted(result: &Value) -> bool {
    result
        .as_bool()
        .or_else(|| result.get("accepted").and_then(Value::as_bool))
        .unwrap_or(false)
}

fn submission_rejection_reason(result: &Value) -> String {
    ["reason", "message", "error"]
        .into_iter()
        .find_map(|field| result.get(field).and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| result.to_string())
}

#[derive(Debug)]
enum RpcCallError {
    Transport(String),
    Protocol(String),
    Remote(String),
}

impl fmt::Display for RpcCallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(reason) => write!(formatter, "transport failure: {reason}"),
            Self::Protocol(reason) => write!(formatter, "protocol failure: {reason}"),
            Self::Remote(reason) => write!(formatter, "node rejected request: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_endpoint_is_rejected() {
        assert!(NodeRpcClient::new("   ").is_err());
    }

    #[test]
    fn submission_acceptance_supports_boolean_and_object_results() {
        assert!(submission_was_accepted(&json!(true)));
        assert!(submission_was_accepted(&json!({"accepted": true})));
        assert!(!submission_was_accepted(&json!({"accepted": false})));
    }

    #[test]
    fn rejection_reason_prefers_human_readable_fields() {
        assert_eq!(
            submission_rejection_reason(&json!({"accepted": false, "reason": "fee too low"})),
            "fee too low"
        );
    }

    #[test]
    fn remote_error_reason_prefers_the_json_rpc_message() {
        assert_eq!(
            remote_error_reason(&json!({"code": -32002, "message": "tx rejected"})),
            "tx rejected"
        );
    }

    #[test]
    fn remote_submission_error_is_a_definitive_rejection() {
        assert_eq!(
            classify_submission_result(Err(RpcCallError::Remote("tx rejected".into()))),
            SubmissionOutcome::Rejected {
                reason: "tx rejected".into(),
            }
        );
    }

    #[test]
    fn transport_and_protocol_failures_keep_submission_unknown() {
        assert_eq!(
            classify_submission_result(Err(RpcCallError::Transport("timeout".into()))),
            SubmissionOutcome::Unknown {
                reason: "transport failure: timeout".into(),
            }
        );
        assert_eq!(
            classify_submission_result(Err(RpcCallError::Protocol("bad json".into()))),
            SubmissionOutcome::Unknown {
                reason: "protocol failure: bad json".into(),
            }
        );
    }
}
