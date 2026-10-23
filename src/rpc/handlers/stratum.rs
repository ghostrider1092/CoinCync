//! Pool operator RPCs: worker and share stats, the payout tally, the round close.

use std::sync::Arc;

use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::mining::stratum::StratumServer;

use super::RpcState;

fn pool(state: &RpcState) -> std::result::Result<Arc<StratumServer>, ErrorObjectOwned> {
    state.stratum.get().cloned().ok_or_else(|| {
        ErrorObjectOwned::owned(
            -32000,
            "stratum pool is not running (start the node with --stratum)",
            None::<()>,
        )
    })
}

pub(super) fn register(module: &mut RpcModule<RpcState>) -> Result<()> {
    module
        .register_async_method("get_stratum_stats", |_params, state, _ext| async move {
            let pool = pool(&state)?;
            let stats = pool.stats().await;
            let job = pool.current_job().await;
            Ok::<_, ErrorObjectOwned>(json!({
                "running": pool.is_running(),
                "share_difficulty": pool.config().share_difficulty,
                "job_id": job.as_ref().map(|j| j.job_id.clone()),
                "job_height": job.as_ref().map(|j| j.height),
                "connected_workers": stats.connected_workers,
                "total_shares": stats.total_shares,
                "valid_shares": stats.valid_shares,
                "stale_shares": stats.stale_shares,
                "invalid_shares": stats.invalid_shares,
                "blocks_found": stats.blocks_found,
                "block_pow_hits": stats.block_pow_hits,
                "work": stats.work,
                "hashrate": stats.hashrate,
                "workers": pool.worker_stats().await,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    module
        .register_async_method("get_stratum_tally", |_params, state, _ext| async move {
            let pool = pool(&state)?;
            let tally: serde_json::Map<String, Value> = pool
                .share_tally()
                .await
                .into_iter()
                .map(|(login, credit)| (login, Value::String(credit.to_string())))
                .collect();
            Ok::<_, ErrorObjectOwned>(json!({
                "logins": tally.len(),
                "tally": tally,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    module
        .register_async_method("close_stratum_round", |_params, state, _ext| async move {
            let pool = pool(&state)?;
            let round = pool
                .close_round()
                .await
                .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))?;
            Ok::<_, ErrorObjectOwned>(json!({
                "file": round.file.display().to_string(),
                "logins": round.logins,
                "credit": round.credit.to_string(),
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mining::stratum::StratumConfig;
    use jsonrpsee::rpc_params;

    fn state() -> RpcState {
        RpcState {
            chain: Arc::new(crate::chain::Blockchain::new()),
            mempool: crate::mempool::SharedMempool::new(),
            p2p: None,
            network_name: "test".to_string(),
            auth_enabled: false,
            minimize_metadata: false,
            stratum_public_bind_requested: false,
            stratum_public_bind_ack: false,
            stratum_native_tls_enabled: false,
            stratum_tls_proxy_ack: false,
            stratum_transport_hardened: false,
            stratum: Default::default(),
        }
    }

    fn code(err: jsonrpsee::MethodsError) -> i32 {
        match err {
            jsonrpsee::MethodsError::JsonRpc(e) => e.code(),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn stratum_rpcs_fail_cleanly_without_a_pool() {
        let mut module = RpcModule::new(state());
        register(&mut module).expect("register");
        for method in [
            "get_stratum_stats",
            "get_stratum_tally",
            "close_stratum_round",
        ] {
            let err = module
                .call::<_, Value>(method, rpc_params![])
                .await
                .expect_err(method);
            assert_eq!(code(err), -32000, "{method}");
        }
    }

    #[tokio::test]
    async fn stratum_rpcs_read_the_attached_pool() {
        let state = state();
        let pool = Arc::new(StratumServer::new(
            StratumConfig {
                tally_path: None,
                banlist_path: None,
                ..StratumConfig::default()
            },
            state.chain.clone(),
            state.mempool.clone(),
        ));
        assert!(state.stratum.set(pool).is_ok());
        let mut module = RpcModule::new(state);
        register(&mut module).expect("register");

        let stats: Value = module
            .call("get_stratum_stats", rpc_params![])
            .await
            .expect("stats");
        assert_eq!(stats["running"], false);
        assert_eq!(
            stats["share_difficulty"],
            StratumConfig::default().share_difficulty
        );
        assert_eq!(stats["connected_workers"], 0);
        assert_eq!(stats["hashrate"], 0.0);
        assert!(stats["job_id"].is_null());
        assert_eq!(stats["workers"].as_array().map(Vec::len), Some(0));

        let tally: Value = module
            .call("get_stratum_tally", rpc_params![])
            .await
            .expect("tally");
        assert_eq!(tally["logins"], 0);
        assert!(tally["tally"]
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(false));

        let err = module
            .call::<_, Value>("close_stratum_round", rpc_params![])
            .await
            .expect_err("empty round");
        assert_eq!(code(err), -32000);
    }
}
