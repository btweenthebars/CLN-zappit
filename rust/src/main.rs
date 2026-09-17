mod model;
mod node_rpc;

use anyhow::{bail, ensure, Context, Result};
use cln_plugin::{
    messages::NotificationTopic,
    options::{DefaultBooleanConfigOption, DefaultIntegerConfigOption, StringArrayConfigOption},
    Builder, Error, Plugin, RpcMethodBuilder,
};
use model::{
    evaluate, graph_stats, normalize_node_id, parse_msat, GraphStats, OpenRequest, PolicyConfig,
    PolicyDecision, RuntimeState, STATE_VERSION,
};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

const OPT_ENABLED: DefaultBooleanConfigOption = DefaultBooleanConfigOption::new_bool_with_default(
    "cln-zappit-enabled",
    true,
    "Enforce the incoming-channel admission policy",
);
const OPT_MIN_CHANNEL_SAT: DefaultIntegerConfigOption =
    DefaultIntegerConfigOption::new_i64_with_default(
        "cln-zappit-min-channel-sat",
        2_000_000,
        "Minimum remote contribution accepted, in satoshi",
    );
const OPT_MIN_PUBLIC_CHANNELS: DefaultIntegerConfigOption =
    DefaultIntegerConfigOption::new_i64_with_default(
        "cln-zappit-min-public-channels",
        1,
        "Minimum other active public channels required from an unknown peer",
    );
const OPT_MIN_DISTINCT_PEERS: DefaultIntegerConfigOption =
    DefaultIntegerConfigOption::new_i64_with_default(
        "cln-zappit-min-distinct-peers",
        1,
        "Minimum distinct public counterparties required from an unknown peer",
    );
const OPT_MIN_PUBLIC_CAPACITY_SAT: DefaultIntegerConfigOption =
    DefaultIntegerConfigOption::new_i64_with_default(
        "cln-zappit-min-public-capacity-sat",
        0,
        "Minimum other active public capacity required, in satoshi",
    );
const OPT_MIN_OLDEST_BLOCKS: DefaultIntegerConfigOption =
    DefaultIntegerConfigOption::new_i64_with_default(
        "cln-zappit-min-oldest-channel-blocks",
        0,
        "Minimum age of the peer's oldest active public channel, in blocks",
    );
const OPT_REJECT_PRIVATE: DefaultBooleanConfigOption =
    DefaultBooleanConfigOption::new_bool_with_default(
        "cln-zappit-reject-private",
        true,
        "Reject unannounced channel proposals from unknown peers",
    );
const OPT_FAIL_OPEN: DefaultBooleanConfigOption = DefaultBooleanConfigOption::new_bool_with_default(
    "cln-zappit-fail-open",
    false,
    "Accept when public graph inspection fails instead of rejecting",
);
const OPT_REJECTION_WINDOW: DefaultIntegerConfigOption =
    DefaultIntegerConfigOption::new_i64_with_default(
        "cln-zappit-rejection-window-seconds",
        3_600,
        "Window used to count repeated rejected attempts",
    );
const OPT_BAN_AFTER: DefaultIntegerConfigOption = DefaultIntegerConfigOption::new_i64_with_default(
    "cln-zappit-ban-after-rejections",
    3,
    "Rejected attempts in the window before a temporary ban; zero disables bans",
);
const OPT_BAN_SECONDS: DefaultIntegerConfigOption =
    DefaultIntegerConfigOption::new_i64_with_default(
        "cln-zappit-ban-seconds",
        86_400,
        "Duration of a temporary peer ban, in seconds",
    );
const OPT_ALLOW_NODE: StringArrayConfigOption = StringArrayConfigOption::new_str_arr_no_default(
    "cln-zappit-allow-node",
    "Node pubkey to allow regardless of graph policy; repeatable",
);
const OPT_DENY_NODE: StringArrayConfigOption = StringArrayConfigOption::new_str_arr_no_default(
    "cln-zappit-deny-node",
    "Node pubkey to reject regardless of graph policy; repeatable",
);

#[derive(Clone)]
struct PolicyState {
    rpc_path: PathBuf,
    state_path: PathBuf,
    local_node_id: String,
    config: PolicyConfig,
    runtime: Arc<Mutex<RuntimeState>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_runtime(path: &Path) -> Result<RuntimeState> {
    if !path.exists() {
        return Ok(RuntimeState::default());
    }
    #[cfg(unix)]
    ensure!(
        fs::metadata(path)?.permissions().mode() & 0o077 == 0,
        "refusing to read {}: policy state must have mode 0600",
        path.display()
    );
    let state: RuntimeState = serde_json::from_slice(&fs::read(path)?)
        .with_context(|| format!("parsing policy state {}", path.display()))?;
    ensure!(
        state.version == STATE_VERSION,
        "unsupported policy state version {}",
        state.version
    );
    Ok(state)
}

fn save_runtime(path: &Path, state: &RuntimeState) -> Result<()> {
    let parent = path.parent().context("policy state path has no parent")?;
    fs::create_dir_all(parent)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_extension(format!("json.{}.{nonce}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("creating temporary policy state {}", temporary.display()))?;
    let result = (|| -> Result<()> {
        serde_json::to_writer_pretty(&mut file, state)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn request_object<'a>(params: &'a Value, hook_name: &str) -> &'a Value {
    params.get(hook_name).unwrap_or(params)
}

fn parse_open_request(params: &Value, hook_name: &str, protocol: &str) -> Result<OpenRequest> {
    let value = request_object(params, hook_name);
    let peer_id = value
        .get("id")
        .and_then(Value::as_str)
        .and_then(normalize_node_id)
        .context("channel-open hook omitted a valid peer id")?;
    let funding_field = if protocol == "v2" {
        "their_funding_msat"
    } else {
        "funding_msat"
    };
    let funding_msat = parse_msat(value.get(funding_field))
        .with_context(|| format!("channel-open hook omitted {funding_field}"))?;
    let flags = value
        .get("channel_flags")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Ok(OpenRequest {
        peer_id,
        protocol: protocol.to_owned(),
        funding_msat,
        announced: flags & 1 == 1,
    })
}

async fn inspect_graph(state: &PolicyState, peer_id: &str) -> Result<GraphStats> {
    let value = node_rpc::call(
        &state.rpc_path,
        "listchannels",
        json!({"source": peer_id}),
        Duration::from_secs(4),
    )
    .await?;
    let channels = value
        .get("channels")
        .and_then(Value::as_array)
        .context("listchannels omitted channels")?;
    let info = node_rpc::call(
        &state.rpc_path,
        "getinfo",
        json!({}),
        Duration::from_secs(4),
    )
    .await?;
    let blockheight = info
        .get("blockheight")
        .and_then(Value::as_u64)
        .context("getinfo omitted blockheight")?;
    Ok(graph_stats(channels, blockheight, &state.local_node_id))
}

async fn process_open(
    plugin: Plugin<PolicyState>,
    params: Value,
    hook_name: &str,
    protocol: &str,
) -> Result<Value, Error> {
    let state = plugin.state();
    let request = parse_open_request(&params, hook_name, protocol)?;
    let timestamp = now();
    let snapshot = {
        let mut runtime = state.runtime.lock().await;
        runtime.prune(timestamp, state.config.rejection_window_seconds);
        runtime.clone()
    };

    let skip_graph = !state.config.enabled
        || snapshot.denylist.contains(&request.peer_id)
        || snapshot
            .bans
            .get(&request.peer_id)
            .is_some_and(|until| *until > timestamp)
        || snapshot.allowlist.contains(&request.peer_id)
        || request.funding_msat / 1_000 < state.config.min_channel_sat
        || (state.config.reject_private && !request.announced);
    let graph = if skip_graph {
        None
    } else {
        Some(inspect_graph(state, &request.peer_id).await)
    };
    let graph_reference = match &graph {
        Some(Ok(stats)) => Ok(stats),
        Some(Err(error)) => Err(error.to_string()),
        None => Err("graph inspection was not required".to_owned()),
    };
    let (accepted, reason, message) = evaluate(
        &state.config,
        &snapshot,
        &request,
        match &graph_reference {
            Ok(stats) => Ok(*stats),
            Err(error) => Err(error.as_str()),
        },
        timestamp,
    );

    let decision = {
        let mut runtime = state.runtime.lock().await;
        let banned_until = if accepted {
            runtime.bans.get(&request.peer_id).copied()
        } else {
            runtime.record_rejection(&request.peer_id, timestamp, &state.config)
        };
        let decision = PolicyDecision {
            timestamp,
            peer_id: request.peer_id.clone(),
            protocol: request.protocol.clone(),
            funding_msat: request.funding_msat,
            announced: request.announced,
            accepted,
            reason: reason.to_owned(),
            message: message.clone(),
            graph: graph.and_then(Result::ok),
            banned_until,
        };
        runtime.push_decision(decision.clone());
        save_runtime(&state.state_path, &runtime)
            .with_context(|| "persisting channel admission decision")?;
        decision
    };

    if let Err(error) = plugin
        .send_custom_notification(
            "cln_zappit_decision".to_owned(),
            serde_json::to_value(&decision)?,
        )
        .await
    {
        log::warn!("could not publish cln_zappit_decision: {error:#}");
    }
    if accepted {
        log::info!(
            "accepted {} channel proposal from {}: {}",
            protocol,
            request.peer_id,
            message
        );
        Ok(json!({"result": "continue"}))
    } else {
        log::warn!(
            "rejected {} channel proposal from {}: {}",
            protocol,
            request.peer_id,
            message
        );
        Ok(json!({"result": "reject", "error_message": format!("cln-zappit: {message}")}))
    }
}

async fn openchannel(plugin: Plugin<PolicyState>, params: Value) -> Result<Value, Error> {
    process_open(plugin, params, "openchannel", "v1").await
}

async fn openchannel2(plugin: Plugin<PolicyState>, params: Value) -> Result<Value, Error> {
    process_open(plugin, params, "openchannel2", "v2").await
}

fn rpc_node_id(params: &Value) -> Result<String> {
    params
        .get("node_id")
        .and_then(Value::as_str)
        .and_then(normalize_node_id)
        .context("node_id must be a compressed public key")
}

async fn mutate_list(
    plugin: Plugin<PolicyState>,
    params: Value,
    list: &str,
) -> Result<Value, Error> {
    let node_id = rpc_node_id(&params)?;
    let enabled = params
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut runtime = plugin.state().runtime.lock().await;
    match (list, enabled) {
        ("allow", true) => {
            runtime.denylist.remove(&node_id);
            runtime.bans.remove(&node_id);
            runtime.allowlist.insert(node_id.clone());
        }
        ("allow", false) => {
            runtime.allowlist.remove(&node_id);
        }
        ("deny", true) => {
            runtime.allowlist.remove(&node_id);
            runtime.denylist.insert(node_id.clone());
        }
        ("deny", false) => {
            runtime.denylist.remove(&node_id);
        }
        _ => bail!("unknown policy list"),
    }
    save_runtime(&plugin.state().state_path, &runtime)?;
    Ok(json!({"node_id": node_id, "list": list, "enabled": enabled}))
}

async fn allow_node(plugin: Plugin<PolicyState>, params: Value) -> Result<Value, Error> {
    mutate_list(plugin, params, "allow").await
}

async fn deny_node(plugin: Plugin<PolicyState>, params: Value) -> Result<Value, Error> {
    mutate_list(plugin, params, "deny").await
}

async fn unban_node(plugin: Plugin<PolicyState>, params: Value) -> Result<Value, Error> {
    let node_id = rpc_node_id(&params)?;
    let mut runtime = plugin.state().runtime.lock().await;
    let removed = runtime.bans.remove(&node_id).is_some();
    runtime.rejected_attempts.remove(&node_id);
    save_runtime(&plugin.state().state_path, &runtime)?;
    Ok(json!({"node_id": node_id, "unbanned": removed}))
}

async fn status(plugin: Plugin<PolicyState>, _params: Value) -> Result<Value, Error> {
    let timestamp = now();
    let mut runtime = plugin.state().runtime.lock().await;
    runtime.prune(timestamp, plugin.state().config.rejection_window_seconds);
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "enabled": plugin.state().config.enabled,
        "config": {
            "min_channel_sat": plugin.state().config.min_channel_sat,
            "min_public_channels": plugin.state().config.min_public_channels,
            "min_distinct_peers": plugin.state().config.min_distinct_peers,
            "min_public_capacity_sat": plugin.state().config.min_public_capacity_sat,
            "min_oldest_channel_blocks": plugin.state().config.min_oldest_channel_blocks,
            "reject_private": plugin.state().config.reject_private,
            "fail_open": plugin.state().config.fail_open,
            "rejection_window_seconds": plugin.state().config.rejection_window_seconds,
            "ban_after_rejections": plugin.state().config.ban_after_rejections,
            "ban_seconds": plugin.state().config.ban_seconds,
        },
        "allowlist": runtime.allowlist,
        "denylist": runtime.denylist,
        "bans": runtime.bans,
        "decision_count": runtime.decisions.len(),
        "state_file": plugin.state().state_path,
    }))
}

async fn decisions(plugin: Plugin<PolicyState>, params: Value) -> Result<Value, Error> {
    let limit = params
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .clamp(1, 200) as usize;
    let runtime = plugin.state().runtime.lock().await;
    Ok(json!({"decisions": runtime.decisions.iter().take(limit).collect::<Vec<_>>() }))
}

fn nonnegative(value: i64, name: &str) -> Result<u64> {
    ensure!(value >= 0, "{name} cannot be negative");
    Ok(value as u64)
}

fn validate_nodes(values: Option<Vec<String>>, option: &str) -> Result<Vec<String>> {
    values
        .unwrap_or_default()
        .into_iter()
        .map(|value| {
            normalize_node_id(&value)
                .with_context(|| format!("{option} contains an invalid node id"))
        })
        .collect()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let Some(configured) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(OPT_ENABLED)
        .option(OPT_MIN_CHANNEL_SAT)
        .option(OPT_MIN_PUBLIC_CHANNELS)
        .option(OPT_MIN_DISTINCT_PEERS)
        .option(OPT_MIN_PUBLIC_CAPACITY_SAT)
        .option(OPT_MIN_OLDEST_BLOCKS)
        .option(OPT_REJECT_PRIVATE)
        .option(OPT_FAIL_OPEN)
        .option(OPT_REJECTION_WINDOW)
        .option(OPT_BAN_AFTER)
        .option(OPT_BAN_SECONDS)
        .option(OPT_ALLOW_NODE)
        .option(OPT_DENY_NODE)
        .hook("openchannel", openchannel)
        .hook("openchannel2", openchannel2)
        .rpcmethod_from_builder(
            RpcMethodBuilder::new("cln-zappit-status", status)
                .description("Show incoming-channel policy, lists, bans, and audit coverage"),
        )
        .rpcmethod_from_builder(
            RpcMethodBuilder::new("cln-zappit-decisions", decisions)
                .description("List recent incoming-channel admission decisions")
                .usage("[limit]"),
        )
        .rpcmethod_from_builder(
            RpcMethodBuilder::new("cln-zappit-allow", allow_node)
                .description("Add or remove a persistent node allowlist entry")
                .usage("node_id [enabled]"),
        )
        .rpcmethod_from_builder(
            RpcMethodBuilder::new("cln-zappit-deny", deny_node)
                .description("Add or remove a persistent node denylist entry")
                .usage("node_id [enabled]"),
        )
        .rpcmethod_from_builder(
            RpcMethodBuilder::new("cln-zappit-unban", unban_node)
                .description("Clear a peer's temporary ban and rejection counter")
                .usage("node_id"),
        )
        .notification(NotificationTopic::new("cln_zappit_decision"))
        .configure()
        .await?
    else {
        return Ok(());
    };

    let config = PolicyConfig {
        enabled: configured.option(&OPT_ENABLED)?,
        min_channel_sat: nonnegative(
            configured.option(&OPT_MIN_CHANNEL_SAT)?,
            OPT_MIN_CHANNEL_SAT.name,
        )?,
        min_public_channels: nonnegative(
            configured.option(&OPT_MIN_PUBLIC_CHANNELS)?,
            OPT_MIN_PUBLIC_CHANNELS.name,
        )? as usize,
        min_distinct_peers: nonnegative(
            configured.option(&OPT_MIN_DISTINCT_PEERS)?,
            OPT_MIN_DISTINCT_PEERS.name,
        )? as usize,
        min_public_capacity_sat: nonnegative(
            configured.option(&OPT_MIN_PUBLIC_CAPACITY_SAT)?,
            OPT_MIN_PUBLIC_CAPACITY_SAT.name,
        )?,
        min_oldest_channel_blocks: nonnegative(
            configured.option(&OPT_MIN_OLDEST_BLOCKS)?,
            OPT_MIN_OLDEST_BLOCKS.name,
        )?,
        reject_private: configured.option(&OPT_REJECT_PRIVATE)?,
        fail_open: configured.option(&OPT_FAIL_OPEN)?,
        rejection_window_seconds: nonnegative(
            configured.option(&OPT_REJECTION_WINDOW)?,
            OPT_REJECTION_WINDOW.name,
        )?,
        ban_after_rejections: nonnegative(configured.option(&OPT_BAN_AFTER)?, OPT_BAN_AFTER.name)?
            as usize,
        ban_seconds: nonnegative(configured.option(&OPT_BAN_SECONDS)?, OPT_BAN_SECONDS.name)?,
    };
    ensure!(
        config.rejection_window_seconds > 0,
        "rejection window must be positive"
    );
    ensure!(config.ban_seconds > 0, "ban duration must be positive");

    let configuration = configured.configuration();
    let rpc_path = PathBuf::from(&configuration.lightning_dir).join(&configuration.rpc_file);
    let state_path = PathBuf::from(&configuration.lightning_dir).join("cln-zappit.json");
    let info = node_rpc::call(&rpc_path, "getinfo", json!({}), Duration::from_secs(10)).await?;
    let local_node_id = info
        .get("id")
        .and_then(Value::as_str)
        .and_then(normalize_node_id)
        .context("getinfo omitted a valid local node id")?;
    let mut runtime = load_runtime(&state_path)?;
    runtime.allowlist.extend(validate_nodes(
        configured.option(&OPT_ALLOW_NODE)?,
        OPT_ALLOW_NODE.name,
    )?);
    runtime.denylist.extend(validate_nodes(
        configured.option(&OPT_DENY_NODE)?,
        OPT_DENY_NODE.name,
    )?);
    for denied in runtime.denylist.clone() {
        runtime.allowlist.remove(&denied);
    }
    runtime.prune(now(), config.rejection_window_seconds);
    save_runtime(&state_path, &runtime)?;

    let state = PolicyState {
        rpc_path,
        state_path,
        local_node_id,
        config,
        runtime: Arc::new(Mutex::new(runtime)),
    };
    configured.start(state).await?.join().await
}
