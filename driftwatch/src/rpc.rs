use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use tokio::sync::mpsc::Sender;

/// Poll forever, sending each Sample down the channel (for the correlator).
pub async fn poll_stream(mut poller: RpcPoller, interval_secs: u64, tx: Sender<Sample>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        ticker.tick().await;
        if tx.send(poller.sample().await).await.is_err() {
            return; // receiver gone -> shutting down
        }
    }
}

/// One poll's worth of validator-layer signal.
#[derive(Debug, Clone)]
pub struct ValidatorSample {
    pub epoch: u64,
    pub network_slot: u64, // current tip
    pub my_last_vote: u64, // my vote account's lastVote slot
    pub vote_lag: i64,     // network_slot - my_last_vote (the fast signal)
    pub credits: u64,      // my epoch credits (this epoch)
    pub delinquent: bool,  // am I in the delinquent set
    pub healthy: bool,     // getHealth == "ok"
}

/// One poll tick. An unreachable RPC is a Down SAMPLE, not an error:
/// outages belong on the same timeline the correlator reads.
#[derive(Debug, Clone)]
pub enum Sample {
    Up(ValidatorSample),
    Down { reason: String },
}

/// Thin JSON-RPC client over the validator's HTTP endpoint.
pub struct RpcPoller {
    url: String,
    client: reqwest::Client,
    // vote account to track; auto-discovered when not set
    vote_pubkey: Option<String>,
}

impl RpcPoller {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client"),
            vote_pubkey: None,
        }
    }

    pub fn with_vote_pubkey(mut self, pk: impl Into<String>) -> Self {
        self.vote_pubkey = Some(pk.into());
        self
    }

    /// One JSON-RPC round trip; returns the `result` field.
    pub(crate) async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("{method}: request failed"))?
            .json()
            .await
            .with_context(|| format!("{method}: bad JSON"))?;
        if let Some(err) = resp.get("error") {
            return Err(anyhow!("{method}: rpc error: {err}"));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method}: no result field"))
    }

    /// One tick; errors become a Down sample.
    pub async fn sample(&mut self) -> Sample {
        match self.poll().await {
            Ok(s) => Sample::Up(s),
            Err(e) => Sample::Down {
                reason: format!("{e:#}"),
            },
        }
    }

    async fn poll(&mut self) -> Result<ValidatorSample> {
        // getHealth: "ok" or an rpc error body
        let healthy = matches!(
            self.call("getHealth", json!([])).await,
            Ok(Value::String(s)) if s == "ok"
        );

        let epoch_info = self.call("getEpochInfo", json!([])).await?;
        let epoch = epoch_info["epoch"].as_u64().context("epoch")?;
        let network_slot = epoch_info["absoluteSlot"]
            .as_u64()
            .context("absoluteSlot")?;

        // filter server-side when we know the pubkey
        let params = match &self.vote_pubkey {
            Some(pk) => json!([{ "votePubkey": pk }]),
            None => json!([]),
        };
        let vote_accounts = self.call("getVoteAccounts", params).await?;

        // check current first, then delinquent
        let (acct, delinquent) = ["current", "delinquent"]
            .iter()
            .find_map(|set| {
                let arr = vote_accounts[*set].as_array()?;
                let acct = match &self.vote_pubkey {
                    Some(pk) => arr.iter().find(|a| a["votePubkey"] == *pk.as_str()),
                    None => arr.first(), // test-validator: single built-in account
                }?;
                Some((acct.clone(), *set == "delinquent"))
            })
            .ok_or_else(|| anyhow!("vote account not found in getVoteAccounts"))?;

        // cache the discovered pubkey
        if self.vote_pubkey.is_none() {
            if let Some(pk) = acct["votePubkey"].as_str() {
                self.vote_pubkey = Some(pk.to_string());
            }
        }

        let my_last_vote = acct["lastVote"].as_u64().context("lastVote")?;

        // epochCredits entry: [epoch, cumulative, prev]; this epoch = cum - prev
        let credits = acct["epochCredits"]
            .as_array()
            .and_then(|entries| entries.last())
            .and_then(|e| {
                let cum = e[1].as_u64()?;
                let prev = e[2].as_u64()?;
                Some(cum.saturating_sub(prev))
            })
            .unwrap_or(0); // empty early on a fresh test-validator — fine

        Ok(ValidatorSample {
            epoch,
            network_slot,
            my_last_vote,
            vote_lag: network_slot as i64 - my_last_vote as i64,
            credits,
            delinquent,
            healthy,
        })
    }
}
