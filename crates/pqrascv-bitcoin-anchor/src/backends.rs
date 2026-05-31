//! Live-network broadcaster reference implementations.
//!
//! All three backends are gated behind the `live-network` feature. Even when
//! the feature is enabled, constructing a backend requires an explicit
//! URL/env var, and `cargo test` performs no network I/O unless an integration
//! test is run with the relevant env var set.
//!
//! Idempotency notes per backend (what "already known" looks like):
//! - **Bitcoin Core RPC**: `sendrawtransaction` returns RPC error
//!   `-27 transaction already in block chain` or the mempool-conflict family;
//!   we treat "already in block chain"/"txn-already-known"/"txn-already-in-mempool"
//!   as success and recompute the txid locally.
//! - **Esplora**: `POST /tx` returns HTTP 400 with a body mentioning
//!   `txn-already-known` / `Transaction already in block chain`; treated as
//!   success.
//! - **Electrum**: `blockchain.transaction.broadcast` returns a JSON-RPC error
//!   whose message contains `already`/`txn-already-known`; treated as success.
//!
//! These string matches are heuristic — different node versions phrase errors
//! differently. The local txid is always computed from the transaction bytes,
//! never trusted from the server.

#![cfg(feature = "live-network")]

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Transaction, Txid};
use serde_json::json;

use crate::broadcast::{BroadcastError, Broadcaster, FeeRate, RetryConfig};

/// Returns `true` if a backend error message indicates the tx is already known
/// to the network (mempool or chain), which we treat as idempotent success.
fn is_already_known(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("already in block chain")
        || m.contains("already-in-mempool")
        || m.contains("txn-already-known")
        || m.contains("txn-already-in-mempool")
        || m.contains("transaction already in block chain")
        || m.contains("already known")
}

// ── Bitcoin Core JSON-RPC ─────────────────────────────────────────────────

/// Broadcaster backed by a Bitcoin Core node's JSON-RPC interface.
#[derive(Debug, Clone)]
pub struct BitcoinCoreRpc {
    url: String,
    auth: Option<(String, String)>,
    retry: RetryConfig,
}

impl BitcoinCoreRpc {
    /// Creates a client for the given JSON-RPC URL (e.g.
    /// `http://127.0.0.1:8332`). Optional `(user, pass)` cookie/basic auth.
    #[must_use]
    pub fn new(url: impl Into<String>, auth: Option<(String, String)>) -> Self {
        Self {
            url: url.into(),
            auth,
            retry: RetryConfig::default(),
        }
    }

    /// Builds from `BITCOIN_RPC_URL` (and optional `BITCOIN_RPC_USER` /
    /// `BITCOIN_RPC_PASS`).
    ///
    /// # Errors
    /// [`BroadcastError::Configuration`] if `BITCOIN_RPC_URL` is unset.
    pub fn from_env() -> Result<Self, BroadcastError> {
        let url = std::env::var("BITCOIN_RPC_URL")
            .map_err(|_| BroadcastError::Configuration("BITCOIN_RPC_URL not set".into()))?;
        let auth = match (
            std::env::var("BITCOIN_RPC_USER"),
            std::env::var("BITCOIN_RPC_PASS"),
        ) {
            (Ok(u), Ok(p)) => Some((u, p)),
            _ => None,
        };
        Ok(Self::new(url, auth))
    }

    fn call(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, BroadcastError> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "pqrascv",
            "method": method,
            "params": params,
        });
        let mut req = ureq::post(&self.url).set("content-type", "application/json");
        if let Some((u, p)) = &self.auth {
            let token = base64_basic(u, p);
            req = req.set("authorization", &format!("Basic {token}"));
        }
        let resp = req.send_json(body);
        match resp {
            Ok(r) => {
                let v: serde_json::Value = r
                    .into_json()
                    .map_err(|e| BroadcastError::Transient(format!("rpc decode: {e}")))?;
                if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
                    let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("");
                    return Err(classify_rpc_error(msg));
                }
                Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
            }
            // ureq surfaces HTTP error statuses (incl. 500 with a JSON-RPC error
            // body for sendrawtransaction) as Error::Status.
            Err(ureq::Error::Status(_, r)) => {
                let v: serde_json::Value = r
                    .into_json()
                    .map_err(|e| BroadcastError::Transient(format!("rpc status decode: {e}")))?;
                let msg = v
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("");
                Err(classify_rpc_error(msg))
            }
            Err(e) => Err(BroadcastError::Transient(format!("rpc transport: {e}"))),
        }
    }
}

fn classify_rpc_error(msg: &str) -> BroadcastError {
    if is_already_known(msg) {
        // Caller (broadcast) interprets this sentinel as idempotent success.
        BroadcastError::Transient(format!("ALREADY_KNOWN:{msg}"))
    } else {
        BroadcastError::Rejected(msg.to_string())
    }
}

impl Broadcaster for BitcoinCoreRpc {
    fn broadcast(&self, tx: &Transaction) -> Result<Txid, BroadcastError> {
        let txid = tx.compute_txid();
        let hex = serialize_hex(tx);
        let attempt = || -> Result<Txid, BroadcastError> {
            match self.call("sendrawtransaction", &json!([hex])) {
                Ok(_) => Ok(txid),
                Err(BroadcastError::Transient(m)) if m.starts_with("ALREADY_KNOWN:") => Ok(txid),
                Err(e) => Err(e),
            }
        };
        crate::broadcast::retry_broadcast(self.retry, attempt, |ms| {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        })
    }

    fn estimate_fee(&self, target_blocks: u16) -> Result<FeeRate, BroadcastError> {
        let v = self.call("estimatesmartfee", &json!([target_blocks]))?;
        // estimatesmartfee returns feerate in BTC/kvB.
        let btc_per_kvb = v
            .get("feerate")
            .and_then(serde_json::Value::as_f64)
            .ok_or(BroadcastError::FeeEstimationUnavailable)?;
        Ok(btc_per_kvb_to_sat_per_vb(btc_per_kvb))
    }
}

// ── Esplora REST ──────────────────────────────────────────────────────────

/// Broadcaster backed by an Esplora REST endpoint (Blockstream-compatible).
#[derive(Debug, Clone)]
pub struct Esplora {
    base_url: String,
    retry: RetryConfig,
}

impl Esplora {
    /// Creates a client for an Esplora base URL (e.g.
    /// `https://blockstream.info/api`).
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            retry: RetryConfig::default(),
        }
    }

    /// Builds from `ESPLORA_URL`.
    ///
    /// # Errors
    /// [`BroadcastError::Configuration`] if `ESPLORA_URL` is unset.
    pub fn from_env() -> Result<Self, BroadcastError> {
        let url = std::env::var("ESPLORA_URL")
            .map_err(|_| BroadcastError::Configuration("ESPLORA_URL not set".into()))?;
        Ok(Self::new(url))
    }
}

impl Broadcaster for Esplora {
    fn broadcast(&self, tx: &Transaction) -> Result<Txid, BroadcastError> {
        let txid = tx.compute_txid();
        let hex = serialize_hex(tx);
        let url = format!("{}/tx", self.base_url.trim_end_matches('/'));
        let attempt = || -> Result<Txid, BroadcastError> {
            match ureq::post(&url)
                .set("content-type", "text/plain")
                .send_string(&hex)
            {
                Ok(_) => Ok(txid),
                Err(ureq::Error::Status(_, r)) => {
                    let body = r.into_string().unwrap_or_default();
                    if is_already_known(&body) {
                        Ok(txid)
                    } else {
                        Err(BroadcastError::Rejected(body))
                    }
                }
                Err(e) => Err(BroadcastError::Transient(format!("esplora transport: {e}"))),
            }
        };
        crate::broadcast::retry_broadcast(self.retry, attempt, |ms| {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        })
    }

    fn estimate_fee(&self, target_blocks: u16) -> Result<FeeRate, BroadcastError> {
        let url = format!("{}/fee-estimates", self.base_url.trim_end_matches('/'));
        let v: serde_json::Value = ureq::get(&url)
            .call()
            .map_err(|e| BroadcastError::Transient(format!("esplora fee transport: {e}")))?
            .into_json()
            .map_err(|e| BroadcastError::Transient(format!("esplora fee decode: {e}")))?;
        // Map is { "<target>": sat_per_vb }. Pick the closest target <= request,
        // else the smallest available target.
        let obj = v.as_object().ok_or(BroadcastError::FeeEstimationUnavailable)?;
        let mut best: Option<(u16, f64)> = None;
        for (k, val) in obj {
            if let (Ok(t), Some(rate)) = (k.parse::<u16>(), val.as_f64()) {
                if t <= target_blocks {
                    match best {
                        Some((bt, _)) if bt >= t => {}
                        _ => best = Some((t, rate)),
                    }
                }
            }
        }
        let rate = best
            .map(|(_, r)| r)
            .or_else(|| obj.values().find_map(serde_json::Value::as_f64))
            .ok_or(BroadcastError::FeeEstimationUnavailable)?;
        Ok(FeeRate::from_sat_per_vb(f64_to_sat(rate.ceil())))
    }
}

// ── Electrum JSON-RPC over HTTP shim ──────────────────────────────────────

/// Broadcaster backed by an Electrum server.
///
/// For dependency minimalism this reference impl speaks Electrum's JSON-RPC
/// over an HTTP(S) proxy URL rather than pulling the full TCP/TLS
/// `electrum-client` stack. Point `url` at an Electrum-RPC-over-HTTP gateway.
#[derive(Debug, Clone)]
pub struct Electrum {
    url: String,
    retry: RetryConfig,
}

impl Electrum {
    /// Creates a client for an Electrum JSON-RPC-over-HTTP URL.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            retry: RetryConfig::default(),
        }
    }

    /// Builds from `ELECTRUM_URL`.
    ///
    /// # Errors
    /// [`BroadcastError::Configuration`] if `ELECTRUM_URL` is unset.
    pub fn from_env() -> Result<Self, BroadcastError> {
        let url = std::env::var("ELECTRUM_URL")
            .map_err(|_| BroadcastError::Configuration("ELECTRUM_URL not set".into()))?;
        Ok(Self::new(url))
    }

    fn call(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, BroadcastError> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp = ureq::post(&self.url)
            .set("content-type", "application/json")
            .send_json(body)
            .map_err(|e| match e {
                ureq::Error::Status(_, r) => {
                    let b = r.into_string().unwrap_or_default();
                    BroadcastError::Transient(format!("electrum status: {b}"))
                }
                other @ ureq::Error::Transport(_) => {
                    BroadcastError::Transient(format!("electrum transport: {other}"))
                }
            })?;
        let v: serde_json::Value = resp
            .into_json()
            .map_err(|e| BroadcastError::Transient(format!("electrum decode: {e}")))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or(&err.to_string())
                .to_string();
            if is_already_known(&msg) {
                return Err(BroadcastError::Transient(format!("ALREADY_KNOWN:{msg}")));
            }
            return Err(BroadcastError::Rejected(msg));
        }
        Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }
}

impl Broadcaster for Electrum {
    fn broadcast(&self, tx: &Transaction) -> Result<Txid, BroadcastError> {
        let txid = tx.compute_txid();
        let hex = serialize_hex(tx);
        let attempt = || -> Result<Txid, BroadcastError> {
            match self.call("blockchain.transaction.broadcast", &json!([hex])) {
                Ok(_) => Ok(txid),
                Err(BroadcastError::Transient(m)) if m.starts_with("ALREADY_KNOWN:") => Ok(txid),
                Err(e) => Err(e),
            }
        };
        crate::broadcast::retry_broadcast(self.retry, attempt, |ms| {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        })
    }

    fn estimate_fee(&self, target_blocks: u16) -> Result<FeeRate, BroadcastError> {
        // blockchain.estimatefee returns BTC/kvB (legacy) for the target.
        let v = self.call("blockchain.estimatefee", &json!([target_blocks]))?;
        let btc_per_kvb = v.as_f64().ok_or(BroadcastError::FeeEstimationUnavailable)?;
        if btc_per_kvb < 0.0 {
            return Err(BroadcastError::FeeEstimationUnavailable);
        }
        Ok(btc_per_kvb_to_sat_per_vb(btc_per_kvb))
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

/// Saturating, sign-safe conversion of a non-negative `f64` sat count to `u64`.
///
/// Negative inputs map to 0; values above `u64::MAX` saturate. Used only for
/// fee rates, which are small positive numbers in practice.
fn f64_to_sat(v: f64) -> u64 {
    if v <= 0.0 {
        0
    } else if v >= 18_446_744_073_709_551_615.0 {
        u64::MAX
    } else {
        // Safe: bounded to [0, u64::MAX) and non-negative by the guards above.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            v as u64
        }
    }
}

/// Converts BTC/kvB (as returned by Core/Electrum) to sat/vB, rounding up and
/// flooring at 1 sat/vB.
fn btc_per_kvb_to_sat_per_vb(btc_per_kvb: f64) -> FeeRate {
    // 1 BTC = 100_000_000 sat. Convert to whole sats per kvB first and round to
    // the nearest integer to absorb binary-float representation error (e.g.
    // 0.00001 * 1e8 == 1000.0000000000001), THEN divide by 1000 (vB per kvB)
    // with integer ceiling. Doing the division in floating point would let that
    // tiny error tip an exact 1.0 up to 2 after `.ceil()`.
    let total_sats_per_kvb = f64_to_sat((btc_per_kvb * 100_000_000.0).round());
    // Integer ceil-divide by 1000 (vB per kvB), then floor at 1 sat/vB.
    FeeRate::from_sat_per_vb(total_sats_per_kvb.div_ceil(1000).max(1))
}

/// Minimal base64 (standard alphabet) for HTTP Basic auth, avoiding an extra
/// dependency.
fn base64_basic(user: &str, pass: &str) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{user}:{pass}");
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_known_detection() {
        assert!(is_already_known("Transaction already in block chain"));
        assert!(is_already_known("txn-already-known"));
        assert!(is_already_known("txn-already-in-mempool"));
        assert!(!is_already_known("bad-txns-inputs-missingorspent"));
    }

    #[test]
    fn fee_conversion_floors_at_one() {
        // 0.00001 BTC/kvB = 1000 sat/kvB = 1 sat/vB
        assert_eq!(btc_per_kvb_to_sat_per_vb(0.00001).sat_per_vb(), 1);
        // very small => floored to 1
        assert_eq!(btc_per_kvb_to_sat_per_vb(0.000_000_1).sat_per_vb(), 1);
        // 0.0001 BTC/kvB = 10 sat/vB
        assert_eq!(btc_per_kvb_to_sat_per_vb(0.0001).sat_per_vb(), 10);
    }

    #[test]
    fn base64_basic_matches_known_vector() {
        // "Aladdin:open sesame" => well-known RFC 7617 example.
        assert_eq!(base64_basic("Aladdin", "open sesame"), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }
}
