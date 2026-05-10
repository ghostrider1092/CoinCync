//! SQLite drip-log persistence + rate-limit queries.
//!
//! Schema is intentionally tiny: one append-only table tracking every
//! drip the faucet has emitted, with `(address, ip, ts, tx_hash,
//! amount_atomic)`. Rate-limit checks are `MAX(ts) WHERE address = ?`
//! and `MAX(ts) WHERE ip = ?` indexed reads. Stats endpoint reads
//! aggregate counts over the same table.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::Mutex;

#[derive(thiserror::Error, Debug)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type DbResult<T> = std::result::Result<T, DbError>;

pub struct DripDb {
    /// Single-writer lock over the connection. SQLite handles
    /// concurrent reads internally; serializing writes through one
    /// Mutex avoids `SQLITE_BUSY` retries entirely.
    conn: Mutex<Connection>,
}

#[derive(Debug)]
pub struct Stats {
    pub total_drips: i64,
    pub total_atomic: i64,
    pub last_drip_ts: Option<i64>,
}

impl DripDb {
    pub fn open(path: &Path) -> DbResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS drip_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                address       TEXT    NOT NULL,
                ip            TEXT    NOT NULL,
                ts            INTEGER NOT NULL,
                tx_hash       TEXT,
                amount_atomic INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_drip_address ON drip_log(address, ts DESC);
            CREATE INDEX IF NOT EXISTS idx_drip_ip      ON drip_log(ip, ts DESC);
            "#,
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Returns the most-recent drip timestamp for `address` if any,
    /// otherwise `None`.
    pub async fn last_drip_for_address(&self, address: &str) -> DbResult<Option<i64>> {
        let conn = self.conn.lock().await;
        let row: Option<i64> = conn
            .query_row(
                "SELECT ts FROM drip_log WHERE address = ? ORDER BY ts DESC LIMIT 1",
                params![address],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row)
    }

    /// Returns the most-recent drip timestamp from `ip` if any.
    pub async fn last_drip_for_ip(&self, ip: &str) -> DbResult<Option<i64>> {
        let conn = self.conn.lock().await;
        let row: Option<i64> = conn
            .query_row(
                "SELECT ts FROM drip_log WHERE ip = ? ORDER BY ts DESC LIMIT 1",
                params![ip],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row)
    }

    /// Append a drip-log entry.
    pub async fn record_drip(
        &self,
        address: &str,
        ip: &str,
        ts: i64,
        tx_hash: Option<&str>,
        amount_atomic: u64,
    ) -> DbResult<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO drip_log (address, ip, ts, tx_hash, amount_atomic) VALUES (?, ?, ?, ?, ?)",
            params![address, ip, ts, tx_hash, amount_atomic as i64],
        )?;
        Ok(())
    }

    /// Aggregate stats — used by `/faucet/stats`.
    pub async fn stats(&self) -> DbResult<Stats> {
        let conn = self.conn.lock().await;
        let (total_drips, total_atomic, last_drip_ts): (i64, i64, Option<i64>) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(amount_atomic), 0), MAX(ts) FROM drip_log",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        Ok(Stats {
            total_drips,
            total_atomic,
            last_drip_ts,
        })
    }
}
