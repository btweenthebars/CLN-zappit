use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const STATE_VERSION: u32 = 1;
pub const MAX_DECISIONS: usize = 1_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    pub enabled: bool,
    pub min_channel_sat: u64,
    pub min_public_channels: usize,
    pub min_distinct_peers: usize,
    pub min_public_capacity_sat: u64,
    pub min_oldest_channel_blocks: u64,
    pub reject_private: bool,
    pub fail_open: bool,
    pub rejection_window_seconds: u64,
    pub ban_after_rejections: usize,
    pub ban_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    pub peer_id: String,
    pub protocol: String,
    pub funding_msat: u64,
    pub announced: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphStats {
    pub public_channels: usize,
    pub distinct_peers: usize,
    pub public_capacity_sat: u64,
    pub oldest_channel_blocks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub timestamp: u64,
    pub peer_id: String,
    pub protocol: String,
    pub funding_msat: u64,
    pub announced: bool,
    pub accepted: bool,
    pub reason: String,
    pub message: String,
    pub graph: Option<GraphStats>,
    pub banned_until: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeState {
    pub version: u32,
    #[serde(default)]
    pub allowlist: BTreeSet<String>,
    #[serde(default)]
    pub denylist: BTreeSet<String>,
    #[serde(default)]
    pub bans: BTreeMap<String, u64>,
    #[serde(default)]
    pub rejected_attempts: BTreeMap<String, Vec<u64>>,
    #[serde(default)]
    pub decisions: Vec<PolicyDecision>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            allowlist: BTreeSet::new(),
            denylist: BTreeSet::new(),
            bans: BTreeMap::new(),
            rejected_attempts: BTreeMap::new(),
            decisions: Vec::new(),
        }
    }
}

impl RuntimeState {
    pub fn prune(&mut self, now: u64, window_seconds: u64) {
        self.bans.retain(|_, until| *until > now);
        self.rejected_attempts.retain(|_, attempts| {
            attempts.retain(|timestamp| timestamp.saturating_add(window_seconds) >= now);
            !attempts.is_empty()
        });
        if self.decisions.len() > MAX_DECISIONS {
            self.decisions.truncate(MAX_DECISIONS);
        }
    }

    pub fn record_rejection(
        &mut self,
        peer_id: &str,
        now: u64,
        config: &PolicyConfig,
    ) -> Option<u64> {
        self.prune(now, config.rejection_window_seconds);
        let attempts = self
            .rejected_attempts
            .entry(peer_id.to_owned())
            .or_default();
        attempts.push(now);
        if config.ban_after_rejections > 0 && attempts.len() >= config.ban_after_rejections {
            let until = now.saturating_add(config.ban_seconds);
            self.bans.insert(peer_id.to_owned(), until);
            Some(until)
        } else {
            self.bans.get(peer_id).copied()
        }
    }

    pub fn push_decision(&mut self, decision: PolicyDecision) {
        self.decisions.insert(0, decision);
        self.decisions.truncate(MAX_DECISIONS);
    }
}

pub fn normalize_node_id(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    ((value.starts_with("02") || value.starts_with("03"))
        && value.len() == 66
        && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some(value)
}

pub fn parse_msat(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(text)) => text.strip_suffix("msat").unwrap_or(text).parse().ok(),
        Some(Value::Object(object)) => parse_msat(object.get("msat")),
        _ => None,
    }
}

pub fn graph_stats(channels: &[Value], blockheight: u64, local_id: &str) -> GraphStats {
    let mut scids = BTreeSet::new();
    let mut peers = BTreeSet::new();
    let mut capacity_sat = 0_u64;
    let mut oldest_blocks = 0_u64;
    for channel in channels {
        if channel.get("active").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let Some(destination) = channel.get("destination").and_then(Value::as_str) else {
            continue;
        };
        if destination.eq_ignore_ascii_case(local_id) {
            continue;
        }
        let Some(scid) = channel.get("short_channel_id").and_then(Value::as_str) else {
            continue;
        };
        if !scids.insert(scid.to_owned()) {
            continue;
        }
        peers.insert(destination.to_ascii_lowercase());
        capacity_sat = capacity_sat
            .saturating_add(parse_msat(channel.get("amount_msat")).unwrap_or(0) / 1_000);
        let opening_height = scid
            .split('x')
            .next()
            .and_then(|part| part.parse::<u64>().ok());
        if let Some(opening_height) = opening_height {
            oldest_blocks = oldest_blocks.max(blockheight.saturating_sub(opening_height));
        }
    }
    GraphStats {
        public_channels: scids.len(),
        distinct_peers: peers.len(),
        public_capacity_sat: capacity_sat,
        oldest_channel_blocks: oldest_blocks,
    }
}

pub fn evaluate(
    config: &PolicyConfig,
    runtime: &RuntimeState,
    request: &OpenRequest,
    graph: Result<&GraphStats, &str>,
    now: u64,
) -> (bool, &'static str, String) {
    if !config.enabled {
        return (true, "disabled", "Admission policy is disabled.".to_owned());
    }
    if runtime.denylist.contains(&request.peer_id) {
        return (
            false,
            "denylisted",
            "Peer is explicitly denylisted.".to_owned(),
        );
    }
    if let Some(until) = runtime
        .bans
        .get(&request.peer_id)
        .filter(|until| **until > now)
    {
        return (
            false,
            "temporarily_banned",
            format!("Peer is temporarily banned until {until}."),
        );
    }
    if runtime.allowlist.contains(&request.peer_id) {
        return (
            true,
            "allowlisted",
            "Peer is explicitly allowlisted.".to_owned(),
        );
    }
    if request.funding_msat / 1_000 < config.min_channel_sat {
        return (
            false,
            "channel_too_small",
            format!(
                "Incoming channels must fund at least {}sat.",
                config.min_channel_sat
            ),
        );
    }
    if config.reject_private && !request.announced {
        return (
            false,
            "private_disallowed",
            "Private channels from unknown peers are not accepted.".to_owned(),
        );
    }
    let stats = match graph {
        Ok(stats) => stats,
        Err(error) if config.fail_open => {
            return (
                true,
                "graph_unavailable_fail_open",
                format!("Graph check failed open: {error}"),
            )
        }
        Err(error) => {
            return (
                false,
                "graph_unavailable",
                format!("Could not verify public graph history: {error}"),
            )
        }
    };
    if stats.public_channels < config.min_public_channels {
        return (
            false,
            "insufficient_public_channels",
            format!(
                "Peer has {} other active public channel(s); {} required.",
                stats.public_channels, config.min_public_channels
            ),
        );
    }
    if stats.distinct_peers < config.min_distinct_peers {
        return (
            false,
            "insufficient_distinct_peers",
            format!(
                "Peer has {} other public counterparty/counterparties; {} required.",
                stats.distinct_peers, config.min_distinct_peers
            ),
        );
    }
    if stats.public_capacity_sat < config.min_public_capacity_sat {
        return (
            false,
            "insufficient_public_capacity",
            format!(
                "Peer has {}sat other public capacity; {}sat required.",
                stats.public_capacity_sat, config.min_public_capacity_sat
            ),
        );
    }
    if stats.oldest_channel_blocks < config.min_oldest_channel_blocks {
        return (
            false,
            "insufficient_channel_age",
            format!(
                "Peer's oldest active public channel is {} block(s) old; {} required.",
                stats.oldest_channel_blocks, config.min_oldest_channel_blocks
            ),
        );
    }
    (
        true,
        "policy_satisfied",
        "Peer satisfies the incoming-channel policy.".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    fn config() -> PolicyConfig {
        PolicyConfig {
            enabled: true,
            min_channel_sat: 2_000_000,
            min_public_channels: 1,
            min_distinct_peers: 1,
            min_public_capacity_sat: 1_000_000,
            min_oldest_channel_blocks: 100,
            reject_private: true,
            fail_open: false,
            rejection_window_seconds: 3_600,
            ban_after_rejections: 3,
            ban_seconds: 86_400,
        }
    }

    fn request(peer_id: &str) -> OpenRequest {
        OpenRequest {
            peer_id: peer_id.to_owned(),
            protocol: "v1".to_owned(),
            funding_msat: 2_000_000_000,
            announced: true,
        }
    }

    #[test]
    fn counts_unique_active_public_channels_other_than_ours() {
        let stats = graph_stats(
            &[
                json!({"source":"02peer", "destination":"03other", "short_channel_id":"900x1x0", "active":true, "amount_msat":2_000_000_000_u64}),
                json!({"source":"02peer", "destination":"03ours", "short_channel_id":"950x1x0", "active":true, "amount_msat":9_000_000_000_u64}),
                json!({"source":"02peer", "destination":"03dead", "short_channel_id":"800x1x0", "active":false, "amount_msat":8_000_000_000_u64}),
            ],
            1_100,
            "03ours",
        );
        assert_eq!(
            stats,
            GraphStats {
                public_channels: 1,
                distinct_peers: 1,
                public_capacity_sat: 2_000_000,
                oldest_channel_blocks: 200
            }
        );
    }

    #[test]
    fn rejects_graph_empty_unknown_peers_but_allows_explicit_entries() {
        let peer = format!("02{}", "11".repeat(32));
        let empty = GraphStats::default();
        let mut runtime = RuntimeState::default();
        assert_eq!(
            evaluate(&config(), &runtime, &request(&peer), Ok(&empty), 10).1,
            "insufficient_public_channels"
        );
        runtime.allowlist.insert(peer.clone());
        assert_eq!(
            evaluate(&config(), &runtime, &request(&peer), Ok(&empty), 10).1,
            "allowlisted"
        );
        runtime.denylist.insert(peer.clone());
        assert_eq!(
            evaluate(&config(), &runtime, &request(&peer), Ok(&empty), 10).1,
            "denylisted"
        );
    }

    #[test]
    fn applies_size_privacy_graph_and_fail_closed_rules() {
        let peer = format!("03{}", "22".repeat(32));
        let stats = GraphStats {
            public_channels: 2,
            distinct_peers: 2,
            public_capacity_sat: 4_000_000,
            oldest_channel_blocks: 200,
        };
        assert!(
            evaluate(
                &config(),
                &RuntimeState::default(),
                &request(&peer),
                Ok(&stats),
                10
            )
            .0
        );
        let mut small = request(&peer);
        small.funding_msat = 1_999_999_000;
        assert_eq!(
            evaluate(&config(), &RuntimeState::default(), &small, Ok(&stats), 10).1,
            "channel_too_small"
        );
        let mut private = request(&peer);
        private.announced = false;
        assert_eq!(
            evaluate(
                &config(),
                &RuntimeState::default(),
                &private,
                Ok(&stats),
                10
            )
            .1,
            "private_disallowed"
        );
        assert_eq!(
            evaluate(
                &config(),
                &RuntimeState::default(),
                &request(&peer),
                Err("timeout"),
                10
            )
            .1,
            "graph_unavailable"
        );
    }

    #[test]
    fn rate_limits_repeated_rejections_into_a_temporary_ban() {
        let peer = format!("02{}", "33".repeat(32));
        let mut runtime = RuntimeState::default();
        assert_eq!(runtime.record_rejection(&peer, 100, &config()), None);
        assert_eq!(runtime.record_rejection(&peer, 101, &config()), None);
        assert_eq!(
            runtime.record_rejection(&peer, 102, &config()),
            Some(86_502)
        );
        assert_eq!(
            evaluate(
                &config(),
                &runtime,
                &request(&peer),
                Ok(&GraphStats::default()),
                103
            )
            .1,
            "temporarily_banned"
        );
        runtime.prune(90_000, config().rejection_window_seconds);
        assert!(!runtime.bans.contains_key(&peer));
    }
}
