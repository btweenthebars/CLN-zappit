#!/usr/bin/env python3
"""
CLN-zappit: Defensive incoming-channel admission policy for Core Lightning.

Intercepts incoming v1 (openchannel) and v2 (openchannel2) channel proposals,
evaluating them against public network gossip, size limits, privacy rules,
and anti-spam peer bans before returning continue or reject.

Zero external dependencies - runs on Python 3.8+ using standard library only.
"""

import configparser
import json
import logging
import os
import re
import socket
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

STATE_VERSION = 1
MAX_DECISIONS = 1000
DEFAULT_CONFIG_FILENAME = "cln-zappit.conf"
DEFAULT_STATE_FILENAME = "cln-zappit.json"

NODE_ID_REGEX = re.compile(r"^(02|03)[0-9a-fA-F]{64}$")


def normalize_node_id(value: Optional[str]) -> Optional[str]:
    """Normalize a node pubkey to 66 lowercase hex characters."""
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    return cleaned if NODE_ID_REGEX.match(cleaned) else None


def parse_msat(value: Any) -> Optional[int]:
    """Parse a CLN millisatoshi value from int, string ('1000msat'), or object {'msat': ...}."""
    if value is None:
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        cleaned = value.strip().lower()
        if cleaned.endswith("msat"):
            cleaned = cleaned[:-4]
        try:
            val = int(cleaned)
            return val if val >= 0 else None
        except ValueError:
            return None
    if isinstance(value, dict) and "msat" in value:
        return parse_msat(value["msat"])
    return None


@dataclass
class PolicyConfig:
    enabled: bool = True
    min_channel_sat: int = 2_000_000
    min_public_channels: int = 1
    min_distinct_peers: int = 1
    min_public_capacity_sat: int = 0
    min_oldest_channel_blocks: int = 0
    reject_private: bool = True
    fail_open: bool = False
    rejection_window_seconds: int = 3600
    ban_after_rejections: int = 3
    ban_seconds: int = 86400
    allowlist: Set[str] = field(default_factory=set)
    denylist: Set[str] = field(default_factory=set)


@dataclass
class GraphStats:
    public_channels: int = 0
    distinct_peers: int = 0
    public_capacity_sat: int = 0
    oldest_channel_blocks: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OpenRequest:
    peer_id: str
    protocol: str  # 'v1' or 'v2'
    funding_msat: int
    announced: bool


@dataclass
class PolicyDecision:
    timestamp: int
    peer_id: str
    protocol: str
    funding_msat: int
    announced: bool
    accepted: bool
    reason: str
    message: str
    graph: Optional[GraphStats] = None
    banned_until: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.graph:
            d["graph"] = self.graph.to_dict()
        return d


@dataclass
class RuntimeState:
    version: int = STATE_VERSION
    allowlist: Set[str] = field(default_factory=set)
    denylist: Set[str] = field(default_factory=set)
    bans: Dict[str, int] = field(default_factory=dict)  # peer_id -> banned_until_ts
    rejected_attempts: Dict[str, List[int]] = field(default_factory=dict)  # peer_id -> [ts, ...]
    decisions: List[PolicyDecision] = field(default_factory=list)

    def prune(self, now: int, window_seconds: int):
        # Remove expired bans
        self.bans = {k: v for k, v in self.bans.items() if v > now}
        # Remove old rejected attempts outside the rolling window
        new_attempts: Dict[str, List[int]] = {}
        for peer, timestamps in self.rejected_attempts.items():
            valid = [ts for ts in timestamps if ts + window_seconds >= now]
            if valid:
                new_attempts[peer] = valid
        self.rejected_attempts = new_attempts
        # Keep decisions bounded
        if len(self.decisions) > MAX_DECISIONS:
            self.decisions = self.decisions[:MAX_DECISIONS]

    def record_rejection(self, peer_id: str, now: int, config: PolicyConfig) -> Optional[int]:
        self.prune(now, config.rejection_window_seconds)
        attempts = self.rejected_attempts.setdefault(peer_id, [])
        attempts.append(now)
        if config.ban_after_rejections > 0 and len(attempts) >= config.ban_after_rejections:
            banned_until = now + config.ban_seconds
            self.bans[peer_id] = banned_until
            return banned_until
        return self.bans.get(peer_id)

    def push_decision(self, decision: PolicyDecision):
        self.decisions.insert(0, decision)
        if len(self.decisions) > MAX_DECISIONS:
            self.decisions = self.decisions[:MAX_DECISIONS]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "allowlist": sorted(list(self.allowlist)),
            "denylist": sorted(list(self.denylist)),
            "bans": self.bans,
            "rejected_attempts": self.rejected_attempts,
            "decisions": [d.to_dict() for d in self.decisions],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuntimeState":
        state = cls(
            version=data.get("version", STATE_VERSION),
            allowlist=set(data.get("allowlist", [])),
            denylist=set(data.get("denylist", [])),
            bans=data.get("bans", {}),
            rejected_attempts=data.get("rejected_attempts", {}),
        )
        decisions: List[PolicyDecision] = []
        for item in data.get("decisions", []):
            try:
                graph_data = item.get("graph")
                graph = GraphStats(**graph_data) if graph_data else None
                decisions.append(
                    PolicyDecision(
                        timestamp=item["timestamp"],
                        peer_id=item["peer_id"],
                        protocol=item["protocol"],
                        funding_msat=item["funding_msat"],
                        announced=item["announced"],
                        accepted=item["accepted"],
                        reason=item["reason"],
                        message=item["message"],
                        graph=graph,
                        banned_until=item.get("banned_until"),
                    )
                )
            except Exception:
                continue
        state.decisions = decisions
        return state


def compute_graph_stats(channels: List[Dict[str, Any]], blockheight: int, local_node_id: str) -> GraphStats:
    """Analyze peer's public channels from listchannels response."""
    scids: Set[str] = set()
    peers: Set[str] = set()
    capacity_sat = 0
    oldest_blocks = 0
    local_id_lower = local_node_id.lower()

    for ch in channels:
        if ch.get("active") is False:
            continue
        dest = ch.get("destination")
        if not dest or not isinstance(dest, str) or dest.lower() == local_id_lower:
            continue
        scid = ch.get("short_channel_id")
        if not scid or not isinstance(scid, str):
            continue
        if scid in scids:
            continue

        scids.add(scid)
        peers.add(dest.lower())
        amount_sat = (parse_msat(ch.get("amount_msat")) or 0) // 1000
        capacity_sat += amount_sat

        try:
            opening_height = int(scid.split("x")[0])
            if blockheight >= opening_height:
                age = blockheight - opening_height
                if age > oldest_blocks:
                    oldest_blocks = age
        except (ValueError, IndexError):
            pass

    return GraphStats(
        public_channels=len(scids),
        distinct_peers=len(peers),
        public_capacity_sat=capacity_sat,
        oldest_channel_blocks=oldest_blocks,
    )


def evaluate(
    config: PolicyConfig,
    runtime: RuntimeState,
    request: OpenRequest,
    graph: Optional[GraphStats],
    graph_error: Optional[str],
    now: int,
) -> Tuple[bool, str, str]:
    """
    Evaluate an incoming channel proposal against admission rules.
    Returns: (accepted: bool, reason: str, message: str)
    """
    if not config.enabled:
        return True, "disabled", "Admission policy is disabled."

    # 1. Denylist check (takes precedence over everything)
    if request.peer_id in config.denylist or request.peer_id in runtime.denylist:
        return False, "denylisted", "Peer is explicitly denylisted."

    # 2. Active temporary ban check
    ban_until = runtime.bans.get(request.peer_id)
    if ban_until and ban_until > now:
        return False, "temporarily_banned", f"Peer is temporarily banned until {ban_until}."

    # 3. Allowlist check (bypasses graph, size, and privacy checks)
    if request.peer_id in config.allowlist or request.peer_id in runtime.allowlist:
        return True, "allowlisted", "Peer is explicitly allowlisted."

    # 4. Minimum channel funding check
    funding_sat = request.funding_msat // 1000
    if funding_sat < config.min_channel_sat:
        return (
            False,
            "channel_too_small",
            f"Incoming channels must fund at least {config.min_channel_sat}sat.",
        )

    # 5. Private channel rejection check
    if config.reject_private and not request.announced:
        return (
            False,
            "private_disallowed",
            "Private channels from unknown peers are not accepted.",
        )

    # 6. Gossip graph inspection check
    if graph_error:
        if config.fail_open:
            return True, "graph_unavailable_fail_open", f"Graph check failed open: {graph_error}"
        return False, "graph_unavailable", f"Could not verify public graph history: {graph_error}"

    stats = graph or GraphStats()

    if stats.public_channels < config.min_public_channels:
        return (
            False,
            "insufficient_public_channels",
            f"Peer has {stats.public_channels} other active public channel(s); {config.min_public_channels} required.",
        )

    if stats.distinct_peers < config.min_distinct_peers:
        return (
            False,
            "insufficient_distinct_peers",
            f"Peer has {stats.distinct_peers} other public counterparty/counterparties; {config.min_distinct_peers} required.",
        )

    if stats.public_capacity_sat < config.min_public_capacity_sat:
        return (
            False,
            "insufficient_public_capacity",
            f"Peer has {stats.public_capacity_sat}sat other public capacity; {config.min_public_capacity_sat}sat required.",
        )

    if stats.oldest_channel_blocks < config.min_oldest_channel_blocks:
        return (
            False,
            "insufficient_channel_age",
            f"Peer's oldest active public channel is {stats.oldest_channel_blocks} block(s) old; {config.min_oldest_channel_blocks} required.",
        )

    return True, "policy_satisfied", "Peer satisfies the incoming-channel policy."


def load_config_file(path: str) -> PolicyConfig:
    """Parse policy settings from a dedicated INI/conf file."""
    config = PolicyConfig()
    if not os.path.exists(path):
        return config

    parser = configparser.ConfigParser(allow_no_value=True)
    parser.read(path)

    if parser.has_section("policy"):
        sec = parser["policy"]
        if "enabled" in sec:
            config.enabled = sec.getboolean("enabled", fallback=config.enabled)
        if "min_channel_sat" in sec:
            config.min_channel_sat = sec.getint("min_channel_sat", fallback=config.min_channel_sat)
        if "reject_private" in sec:
            config.reject_private = sec.getboolean("reject_private", fallback=config.reject_private)
        if "min_public_channels" in sec:
            config.min_public_channels = sec.getint("min_public_channels", fallback=config.min_public_channels)
        if "min_distinct_peers" in sec:
            config.min_distinct_peers = sec.getint("min_distinct_peers", fallback=config.min_distinct_peers)
        if "min_public_capacity_sat" in sec:
            config.min_public_capacity_sat = sec.getint("min_public_capacity_sat", fallback=config.min_public_capacity_sat)
        if "min_oldest_channel_blocks" in sec:
            config.min_oldest_channel_blocks = sec.getint("min_oldest_channel_blocks", fallback=config.min_oldest_channel_blocks)
        if "fail_open" in sec:
            config.fail_open = sec.getboolean("fail_open", fallback=config.fail_open)

    if parser.has_section("rate_limit"):
        sec = parser["rate_limit"]
        if "rejection_window_seconds" in sec:
            config.rejection_window_seconds = sec.getint("rejection_window_seconds", fallback=config.rejection_window_seconds)
        if "ban_after_rejections" in sec:
            config.ban_after_rejections = sec.getint("ban_after_rejections", fallback=config.ban_after_rejections)
        if "ban_seconds" in sec:
            config.ban_seconds = sec.getint("ban_seconds", fallback=config.ban_seconds)

    if parser.has_section("allowlist"):
        for key in parser["allowlist"]:
            node = normalize_node_id(key)
            if node:
                config.allowlist.add(node)

    if parser.has_section("denylist"):
        for key in parser["denylist"]:
            node = normalize_node_id(key)
            if node:
                config.denylist.add(node)

    return config


def load_runtime_state(path: str) -> RuntimeState:
    """Load persistent runtime state (bans, allow/deny lists, decisions) with mode 0600 check."""
    if not os.path.exists(path):
        return RuntimeState()
    # Check permissions on POSIX
    if hasattr(os, "stat"):
        mode = os.stat(path).st_mode
        if mode & 0o077 != 0:
            logging.warning("Policy state file %s has overly permissive mode %o (expected 0600)", path, mode & 0o777)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return RuntimeState.from_dict(data)
    except Exception as e:
        logging.error("Failed to read runtime state from %s: %s", path, e)
        return RuntimeState()


def save_runtime_state(path: str, state: RuntimeState) -> None:
    """Atomically save runtime state to file with mode 0600."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(prefix="cln-zappit-state-", suffix=".tmp", dir=parent)
    try:
        os.fchmod(temp_fd, 0o600)
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            json.dump(state.to_dict(), f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception as e:
        logging.error("Failed to save runtime state to %s: %s", path, e)
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


class ClnUnixRpcClient:
    """Minimal Unix domain socket JSON-RPC client for Core Lightning."""

    def __init__(self, rpc_file_path: str, timeout: float = 10.0):
        self.rpc_file_path = rpc_file_path
        self.timeout = timeout

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": f"cln-zappit-{int(time.time() * 1000)}",
            "method": method,
            "params": params or {},
        }
        raw_req = json.dumps(payload).encode("utf-8") + b"\n"

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.rpc_file_path)
            sock.sendall(raw_req)

            buffer = b""
            decoder = json.JSONDecoder()
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buffer += chunk
                try:
                    text = buffer.decode("utf-8")
                    result, _ = decoder.raw_decode(text)
                    if "error" in result and result["error"]:
                        raise RuntimeError(f"CLN RPC {method} error: {result['error']}")
                    return result.get("result", {})
                except (ValueError, UnicodeDecodeError):
                    continue
            raise RuntimeError(f"CLN RPC {method} returned truncated or empty response")
        finally:
            sock.close()


class ClnZappitPlugin:
    """Core Lightning Plugin Controller."""

    def __init__(self):
        self.config_path: Optional[str] = None
        self.config: PolicyConfig = PolicyConfig()
        self.state_path: Optional[str] = None
        self.state: RuntimeState = RuntimeState()
        self.rpc_client: Optional[ClnUnixRpcClient] = None
        self.local_node_id: Optional[str] = None

    def find_config_file(self, lightning_dir: str) -> Optional[str]:
        candidates = [
            os.path.join(lightning_dir, DEFAULT_CONFIG_FILENAME),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_CONFIG_FILENAME),
            os.path.expanduser(f"~/.lightning/{DEFAULT_CONFIG_FILENAME}"),
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def reload_config(self) -> Dict[str, Any]:
        if self.config_path and os.path.exists(self.config_path):
            self.config = load_config_file(self.config_path)
            return {"reloaded": True, "config_path": self.config_path, "enabled": self.config.enabled}
        return {"reloaded": False, "reason": "No config file found"}

    def handle_getmanifest(self) -> Dict[str, Any]:
        return {
            "dynamic": True,
            "hooks": [
                "openchannel",
                "openchannel2",
            ],
            "options": [
                {
                    "name": "cln-zappit-config",
                    "type": "string",
                    "description": "Path to cln-zappit.conf configuration file",
                },
                {
                    "name": "cln-zappit-enabled",
                    "type": "bool",
                    "default": True,
                    "description": "Enforce incoming-channel admission policy",
                },
                {
                    "name": "cln-zappit-min-channel-sat",
                    "type": "int",
                    "default": 2000000,
                    "description": "Minimum remote funding accepted (sats)",
                },
                {
                    "name": "cln-zappit-min-public-channels",
                    "type": "int",
                    "default": 1,
                    "description": "Minimum other active public channels required",
                },
                {
                    "name": "cln-zappit-min-distinct-peers",
                    "type": "int",
                    "default": 1,
                    "description": "Minimum distinct counterparties required",
                },
                {
                    "name": "cln-zappit-min-public-capacity-sat",
                    "type": "int",
                    "default": 0,
                    "description": "Minimum total public capacity required (sats)",
                },
                {
                    "name": "cln-zappit-min-oldest-channel-blocks",
                    "type": "int",
                    "default": 0,
                    "description": "Minimum age of oldest channel in blocks",
                },
                {
                    "name": "cln-zappit-reject-private",
                    "type": "bool",
                    "default": True,
                    "description": "Reject unannounced private channel proposals",
                },
                {
                    "name": "cln-zappit-fail-open",
                    "type": "bool",
                    "default": False,
                    "description": "Accept proposals if graph inspection fails",
                },
            ],
            "rpcmethods": [
                {
                    "name": "cln-zappit-status",
                    "usage": "",
                    "description": "Show current admission policy, ban counts, and summary stats",
                },
                {
                    "name": "cln-zappit-decisions",
                    "usage": "[limit]",
                    "description": "Show recent channel admission decisions",
                },
                {
                    "name": "cln-zappit-allow",
                    "usage": "node_id [enabled]",
                    "description": "Add or remove a node from the admission allowlist",
                },
                {
                    "name": "cln-zappit-deny",
                    "usage": "node_id [enabled]",
                    "description": "Add or remove a node from the admission denylist",
                },
                {
                    "name": "cln-zappit-unban",
                    "usage": "node_id",
                    "description": "Lift a temporary rate-limit ban on a node",
                },
                {
                    "name": "cln-zappit-reload",
                    "usage": "",
                    "description": "Hot-reload admission policy configuration from disk",
                },
            ],
            "notifications": [
                {"method": "cln_zappit_decision"},
            ],
        }

    def handle_init(self, params: Dict[str, Any]) -> Dict[str, Any]:
        config_options = params.get("options", {})
        cln_config = params.get("configuration", {})
        lightning_dir = cln_config.get("lightning-dir", ".")
        rpc_file = cln_config.get("rpc-file")

        # 1. Determine config file path
        custom_path = config_options.get("cln-zappit-config")
        if custom_path and isinstance(custom_path, str) and os.path.exists(custom_path):
            self.config_path = custom_path
        else:
            self.config_path = self.find_config_file(lightning_dir)

        # 2. Load config file
        if self.config_path:
            self.config = load_config_file(self.config_path)
            logging.info("CLN-zappit: loaded configuration from %s", self.config_path)
        else:
            self.config = PolicyConfig()
            logging.info("CLN-zappit: using default policy configuration")

        # 3. CLI options override config file if explicitly supplied
        if "cln-zappit-enabled" in config_options:
            self.config.enabled = bool(config_options["cln-zappit-enabled"])
        if "cln-zappit-min-channel-sat" in config_options:
            self.config.min_channel_sat = int(config_options["cln-zappit-min-channel-sat"])
        if "cln-zappit-min-public-channels" in config_options:
            self.config.min_public_channels = int(config_options["cln-zappit-min-public-channels"])
        if "cln-zappit-min-distinct-peers" in config_options:
            self.config.min_distinct_peers = int(config_options["cln-zappit-min-distinct-peers"])
        if "cln-zappit-min-public-capacity-sat" in config_options:
            self.config.min_public_capacity_sat = int(config_options["cln-zappit-min-public-capacity-sat"])
        if "cln-zappit-min-oldest-channel-blocks" in config_options:
            self.config.min_oldest_channel_blocks = int(config_options["cln-zappit-min-oldest-channel-blocks"])
        if "cln-zappit-reject-private" in config_options:
            self.config.reject_private = bool(config_options["cln-zappit-reject-private"])
        if "cln-zappit-fail-open" in config_options:
            self.config.fail_open = bool(config_options["cln-zappit-fail-open"])

        # 4. State storage path
        self.state_path = os.path.join(lightning_dir, DEFAULT_STATE_FILENAME)
        self.state = load_runtime_state(self.state_path)

        # 5. Initialize RPC client
        if rpc_file:
            rpc_path = rpc_file if os.path.isabs(rpc_file) else os.path.join(lightning_dir, rpc_file)
            self.rpc_client = ClnUnixRpcClient(rpc_path)
            try:
                getinfo = self.rpc_client.call("getinfo")
                self.local_node_id = getinfo.get("id")
            except Exception as e:
                logging.warning("CLN-zappit: could not query getinfo at startup: %s", e)

        return {}

    def inspect_graph(self, peer_id: str) -> Tuple[Optional[GraphStats], Optional[str]]:
        if not self.rpc_client:
            return None, "RPC client not initialized"
        try:
            channels_resp = self.rpc_client.call("listchannels", {"source": peer_id})
            channels = channels_resp.get("channels", [])

            getinfo = self.rpc_client.call("getinfo")
            blockheight = int(getinfo.get("blockheight", 0))
            local_id = self.local_node_id or getinfo.get("id", "")

            stats = compute_graph_stats(channels, blockheight, local_id)
            return stats, None
        except Exception as e:
            return None, str(e)

    def handle_open_channel_hook(self, payload: Dict[str, Any], protocol: str) -> Dict[str, Any]:
        """Hook callback for openchannel (v1) and openchannel2 (v2)."""
        now = int(time.time())
        inner = payload.get(f"openchannel{'' if protocol == 'v1' else '2'}", payload)

        peer_id = normalize_node_id(inner.get("id"))
        if not peer_id:
            return {"result": "reject", "error_message": "Invalid peer ID"}

        funding_key = "funding_msat" if protocol == "v1" else "their_funding_msat"
        funding_msat = parse_msat(inner.get(funding_key)) or 0
        channel_flags = int(inner.get("channel_flags", 0))
        announced = (channel_flags & 1) == 1

        req = OpenRequest(
            peer_id=peer_id,
            protocol=protocol,
            funding_msat=funding_msat,
            announced=announced,
        )

        graph_stats_res, graph_err = self.inspect_graph(peer_id)
        accepted, reason, message = evaluate(
            self.config, self.state, req, graph_stats_res, graph_err, now
        )

        banned_until: Optional[int] = None
        if not accepted and reason not in ("denylisted", "temporarily_banned"):
            banned_until = self.state.record_rejection(peer_id, now, self.config)

        decision = PolicyDecision(
            timestamp=now,
            peer_id=peer_id,
            protocol=protocol,
            funding_msat=funding_msat,
            announced=announced,
            accepted=accepted,
            reason=reason,
            message=message,
            graph=graph_stats_res,
            banned_until=banned_until,
        )
        self.state.push_decision(decision)

        if self.state_path:
            save_runtime_state(self.state_path, self.state)

        # Emit custom notification
        self.emit_notification("cln_zappit_decision", decision.to_dict())

        if accepted:
            return {"result": "continue"}
        return {"result": "reject", "error_message": message}

    def emit_notification(self, method: str, params: Dict[str, Any]):
        notification = {"jsonrpc": "2.0", "method": method, "params": params}
        sys.stdout.write(json.dumps(notification) + "\n\n")
        sys.stdout.flush()

    # --- Dynamic RPC Command Handlers ---

    def rpc_status(self, _params: Dict[str, Any]) -> Dict[str, Any]:
        now = int(time.time())
        self.state.prune(now, self.config.rejection_window_seconds)
        return {
            "enabled": self.config.enabled,
            "config_file": self.config_path,
            "min_channel_sat": self.config.min_channel_sat,
            "min_public_channels": self.config.min_public_channels,
            "min_distinct_peers": self.config.min_distinct_peers,
            "min_public_capacity_sat": self.config.min_public_capacity_sat,
            "min_oldest_channel_blocks": self.config.min_oldest_channel_blocks,
            "reject_private": self.config.reject_private,
            "fail_open": self.config.fail_open,
            "ban_after_rejections": self.config.ban_after_rejections,
            "ban_seconds": self.config.ban_seconds,
            "active_bans_count": len(self.state.bans),
            "allowlist_count": len(self.config.allowlist | self.state.allowlist),
            "denylist_count": len(self.config.denylist | self.state.denylist),
            "total_decisions_recorded": len(self.state.decisions),
        }

    def rpc_decisions(self, params: Any) -> Dict[str, Any]:
        limit = 50
        if isinstance(params, dict):
            limit = int(params.get("limit", 50))
        elif isinstance(params, list) and params:
            limit = int(params[0])
        limit = max(1, min(limit, MAX_DECISIONS))
        return {"decisions": [d.to_dict() for d in self.state.decisions[:limit]]}

    def rpc_allow(self, params: Any) -> Dict[str, Any]:
        node_id, enabled = self._parse_node_and_toggle(params)
        if not node_id:
            raise ValueError("node_id must be a valid 33-byte hex pubkey")
        if enabled:
            self.state.allowlist.add(node_id)
            self.state.denylist.discard(node_id)
        else:
            self.state.allowlist.discard(node_id)
        if self.state_path:
            save_runtime_state(self.state_path, self.state)
        return {"node_id": node_id, "allowlisted": enabled}

    def rpc_deny(self, params: Any) -> Dict[str, Any]:
        node_id, enabled = self._parse_node_and_toggle(params)
        if not node_id:
            raise ValueError("node_id must be a valid 33-byte hex pubkey")
        if enabled:
            self.state.denylist.add(node_id)
            self.state.allowlist.discard(node_id)
        else:
            self.state.denylist.discard(node_id)
        if self.state_path:
            save_runtime_state(self.state_path, self.state)
        return {"node_id": node_id, "denylisted": enabled}

    def rpc_unban(self, params: Any) -> Dict[str, Any]:
        node_id, _ = self._parse_node_and_toggle(params)
        if not node_id:
            raise ValueError("node_id must be a valid 33-byte hex pubkey")
        removed = self.state.bans.pop(node_id, None) is not None
        self.state.rejected_attempts.pop(node_id, None)
        if self.state_path:
            save_runtime_state(self.state_path, self.state)
        return {"node_id": node_id, "unbanned": removed}

    def rpc_reload(self, _params: Any) -> Dict[str, Any]:
        return self.reload_config()

    @staticmethod
    def _parse_node_and_toggle(params: Any) -> Tuple[Optional[str], bool]:
        node_id: Optional[str] = None
        enabled = True
        if isinstance(params, dict):
            node_id = normalize_node_id(params.get("node_id") or params.get("id"))
            if "enabled" in params:
                enabled = bool(params["enabled"])
        elif isinstance(params, list):
            if params:
                node_id = normalize_node_id(str(params[0]))
            if len(params) > 1:
                val = str(params[1]).lower()
                enabled = val not in ("false", "0", "no")
        return node_id, enabled

    # --- Main Event Loop ---

    def run(self):
        """Standard JSON-RPC event loop over stdin/stdout."""
        decoder = json.JSONDecoder()
        buffer = ""

        while True:
            line = sys.stdin.readline()
            if not line:
                break
            buffer += line
            while buffer:
                buffer = buffer.lstrip()
                if not buffer:
                    break
                try:
                    req, idx = decoder.raw_decode(buffer)
                    buffer = buffer[idx:].lstrip()
                    self._dispatch_request(req)
                except ValueError:
                    # Need more input
                    break

    def _dispatch_request(self, req: Dict[str, Any]):
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        # Notifications (no id)
        if req_id is None:
            return

        try:
            if method == "getmanifest":
                res = self.handle_getmanifest()
            elif method == "init":
                res = self.handle_init(params)
            elif method == "openchannel":
                res = self.handle_open_channel_hook(params, "v1")
            elif method == "openchannel2":
                res = self.handle_open_channel_hook(params, "v2")
            elif method == "cln-zappit-status":
                res = self.rpc_status(params)
            elif method == "cln-zappit-decisions":
                res = self.rpc_decisions(params)
            elif method == "cln-zappit-allow":
                res = self.rpc_allow(params)
            elif method == "cln-zappit-deny":
                res = self.rpc_deny(params)
            elif method == "cln-zappit-unban":
                res = self.rpc_unban(params)
            elif method == "cln-zappit-reload":
                res = self.rpc_reload(params)
            else:
                self._send_error(req_id, -32601, f"Unknown method: {method}")
                return

            self._send_response(req_id, res)
        except Exception as e:
            logging.exception("Error processing request %s", method)
            self._send_error(req_id, -32000, str(e))

    @staticmethod
    def _send_response(req_id: Any, result: Any):
        resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
        sys.stdout.write(json.dumps(resp) + "\n\n")
        sys.stdout.flush()

    @staticmethod
    def _send_error(req_id: Any, code: int, message: str):
        resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
        sys.stdout.write(json.dumps(resp) + "\n\n")
        sys.stdout.flush()


if __name__ == "__main__":
    plugin = ClnZappitPlugin()
    plugin.run()
