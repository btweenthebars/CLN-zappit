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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)

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


def to_bool(value: Any, default: bool = False) -> bool:
    """Parse boolean from bool, int, or string ('true', 'false', '0', '1', 'no', 'off')."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        val = value.strip().lower()
        if val in ("1", "true", "yes", "on", "enable", "enabled"):
            return True
        if val in ("0", "false", "no", "off", "disable", "disabled"):
            return False
    return bool(value)


def parse_msat(value: Any) -> Optional[int]:
    """Parse a CLN millisatoshi value from int, float, string ('1000msat', '1000sat'), or dict."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        val = int(value)
        return val if val >= 0 else None
    if isinstance(value, str):
        cleaned = value.strip().lower()
        if cleaned.endswith("msat"):
            cleaned = cleaned[:-4]
            try:
                val = int(cleaned)
                return val if val >= 0 else None
            except ValueError:
                return None
        elif cleaned.endswith("sats") or cleaned.endswith("sat"):
            cleaned = cleaned[:-4] if cleaned.endswith("sats") else cleaned[:-3]
            try:
                val = int(cleaned)
                return (val * 1000) if val >= 0 else None
            except ValueError:
                return None
        else:
            try:
                val = int(cleaned)
                return val if val >= 0 else None
            except ValueError:
                return None
    if isinstance(value, dict):
        if "msat" in value:
            return parse_msat(value["msat"])
        if "sat" in value or "sats" in value:
            sat_val = value.get("sat") if "sat" in value else value.get("sats")
            parsed_sat = parse_msat(sat_val)
            return (parsed_sat * 1000) if parsed_sat is not None else None
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
    generic_reject: bool = True
    reject_message: str = "Channel proposal declined."
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
        if "generic_reject" in sec:
            config.generic_reject = sec.getboolean("generic_reject", fallback=config.generic_reject)
        if "reject_message" in sec:
            val = sec.get("reject_message", fallback=config.reject_message)
            if val:
                config.reject_message = val.strip().strip('"').strip("'")

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
        self.lightning_dir: str = "."
        self.network: Optional[str] = None

    def find_config_file(self, lightning_dir: str, network: Optional[str] = None) -> Optional[str]:
        expanded_dir = os.path.expanduser(lightning_dir)
        parent_dir = os.path.dirname(expanded_dir)
        candidates = [
            os.path.join(expanded_dir, DEFAULT_CONFIG_FILENAME),
            os.path.join(parent_dir, DEFAULT_CONFIG_FILENAME),
        ]
        if network:
            candidates.append(os.path.join(expanded_dir, network, DEFAULT_CONFIG_FILENAME))
            candidates.append(os.path.join(parent_dir, network, DEFAULT_CONFIG_FILENAME))
        candidates.extend([
            os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_CONFIG_FILENAME),
            os.path.expanduser(f"~/.lightning/{DEFAULT_CONFIG_FILENAME}"),
        ])
        if network:
            candidates.append(os.path.expanduser(f"~/.lightning/{network}/{DEFAULT_CONFIG_FILENAME}"))
        for path in candidates:
            if os.path.isfile(path):
                return os.path.abspath(path)
        return None

    def reload_config(self) -> Dict[str, Any]:
        if not self.config_path:
            self.config_path = self.find_config_file(self.lightning_dir, self.network)
        if self.config_path and os.path.isfile(self.config_path):
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
                    "description": "Enforce incoming-channel admission policy (overrides config file)",
                },
                {
                    "name": "cln-zappit-min-channel-sat",
                    "type": "int",
                    "description": "Minimum remote funding accepted in sats (overrides config file)",
                },
                {
                    "name": "cln-zappit-min-public-channels",
                    "type": "int",
                    "description": "Minimum other active public channels required (overrides config file)",
                },
                {
                    "name": "cln-zappit-min-distinct-peers",
                    "type": "int",
                    "description": "Minimum distinct counterparties required (overrides config file)",
                },
                {
                    "name": "cln-zappit-min-public-capacity-sat",
                    "type": "int",
                    "description": "Minimum total public capacity required in sats (overrides config file)",
                },
                {
                    "name": "cln-zappit-min-oldest-channel-blocks",
                    "type": "int",
                    "description": "Minimum age of oldest channel in blocks (overrides config file)",
                },
                {
                    "name": "cln-zappit-reject-private",
                    "type": "bool",
                    "description": "Reject unannounced private channel proposals (overrides config file)",
                },
                {
                    "name": "cln-zappit-fail-open",
                    "type": "bool",
                    "description": "Accept proposals if graph inspection fails (overrides config file)",
                },
                {
                    "name": "cln-zappit-generic-reject",
                    "type": "bool",
                    "description": "Send generic error message to remote peers (overrides config file)",
                },
                {
                    "name": "cln-zappit-reject-message",
                    "type": "string",
                    "description": "Generic rejection message sent to remote peers (overrides config file)",
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
        self.lightning_dir = os.path.expanduser(cln_config.get("lightning-dir", "."))
        self.network = cln_config.get("network")
        rpc_file = cln_config.get("rpc-file")

        # 1. Determine config file path
        custom_path = config_options.get("cln-zappit-config")
        if custom_path and isinstance(custom_path, str):
            custom_path = os.path.expanduser(custom_path)
            if os.path.isfile(custom_path):
                self.config_path = os.path.abspath(custom_path)
        if not self.config_path:
            self.config_path = self.find_config_file(self.lightning_dir, self.network)

        # 2. Load config file
        if self.config_path:
            self.config = load_config_file(self.config_path)
            logging.info("CLN-zappit: loaded configuration from %s", self.config_path)
        else:
            self.config = PolicyConfig()
            logging.info("CLN-zappit: using default policy configuration")

        # 3. CLI options override config file only if explicitly supplied by user (non-None)
        if config_options.get("cln-zappit-enabled") is not None:
            self.config.enabled = to_bool(config_options["cln-zappit-enabled"], self.config.enabled)
        if config_options.get("cln-zappit-min-channel-sat") is not None:
            try:
                self.config.min_channel_sat = int(config_options["cln-zappit-min-channel-sat"])
            except (ValueError, TypeError):
                pass
        if config_options.get("cln-zappit-min-public-channels") is not None:
            try:
                self.config.min_public_channels = int(config_options["cln-zappit-min-public-channels"])
            except (ValueError, TypeError):
                pass
        if config_options.get("cln-zappit-min-distinct-peers") is not None:
            try:
                self.config.min_distinct_peers = int(config_options["cln-zappit-min-distinct-peers"])
            except (ValueError, TypeError):
                pass
        if config_options.get("cln-zappit-min-public-capacity-sat") is not None:
            try:
                self.config.min_public_capacity_sat = int(config_options["cln-zappit-min-public-capacity-sat"])
            except (ValueError, TypeError):
                pass
        if config_options.get("cln-zappit-min-oldest-channel-blocks") is not None:
            try:
                self.config.min_oldest_channel_blocks = int(config_options["cln-zappit-min-oldest-channel-blocks"])
            except (ValueError, TypeError):
                pass
        if config_options.get("cln-zappit-reject-private") is not None:
            self.config.reject_private = to_bool(config_options["cln-zappit-reject-private"], self.config.reject_private)
        if config_options.get("cln-zappit-fail-open") is not None:
            self.config.fail_open = to_bool(config_options["cln-zappit-fail-open"], self.config.fail_open)
        if config_options.get("cln-zappit-generic-reject") is not None:
            self.config.generic_reject = to_bool(config_options["cln-zappit-generic-reject"], self.config.generic_reject)
        if config_options.get("cln-zappit-reject-message") is not None:
            self.config.reject_message = str(config_options["cln-zappit-reject-message"]).strip()

        # 4. State storage path (co-located with config_path if available)
        if self.config_path:
            state_dir = os.path.dirname(self.config_path)
        else:
            state_dir = self.lightning_dir
        self.state_path = os.path.join(state_dir, DEFAULT_STATE_FILENAME)
        self.state = load_runtime_state(self.state_path)
        if not os.path.exists(self.state_path):
            save_runtime_state(self.state_path, self.state)

        # 5. Initialize RPC client
        if rpc_file:
            rpc_path = rpc_file if os.path.isabs(rpc_file) else os.path.join(self.lightning_dir, rpc_file)
            self.rpc_client = ClnUnixRpcClient(rpc_path)
            try:
                getinfo = self.rpc_client.call("getinfo")
                self.local_node_id = getinfo.get("id")
            except Exception as e:
                logging.warning("CLN-zappit: could not query getinfo at startup: %s", e)

        return {}

    def should_inspect_graph(self, req: OpenRequest, now: int) -> bool:
        """Skip expensive gossip RPC calls if channel is already decided by fast local rules."""
        if not self.config.enabled:
            return False
        # 1. Denylist check
        if req.peer_id in self.config.denylist or req.peer_id in self.state.denylist:
            return False
        # 2. Ban check
        ban_until = self.state.bans.get(req.peer_id)
        if ban_until and ban_until > now:
            return False
        # 3. Allowlist check
        if req.peer_id in self.config.allowlist or req.peer_id in self.state.allowlist:
            return False
        # 4. Minimum channel funding check
        if (req.funding_msat // 1000) < self.config.min_channel_sat:
            return False
        # 5. Private channel rejection check
        if self.config.reject_private and not req.announced:
            return False
        # 6. If all graph criteria are disabled, no inspection needed
        if (
            self.config.min_public_channels == 0
            and self.config.min_distinct_peers == 0
            and self.config.min_public_capacity_sat == 0
            and self.config.min_oldest_channel_blocks == 0
        ):
            return False
        return True

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

        funding_msat: Optional[int] = None
        if protocol == "v2":
            funding_msat = parse_msat(inner.get("their_funding_msat"))
            if funding_msat is None:
                funding_msat = parse_msat(inner.get("their_funding_satoshis"))
        else:
            funding_msat = parse_msat(inner.get("funding_msat"))
            if funding_msat is None:
                funding_msat = parse_msat(inner.get("funding_satoshis"))
        funding_msat = funding_msat or 0

        raw_flags = inner.get("channel_flags")
        try:
            channel_flags = int(raw_flags) if raw_flags is not None else 0
        except (ValueError, TypeError):
            channel_flags = 0
        announced = (channel_flags & 1) == 1

        req = OpenRequest(
            peer_id=peer_id,
            protocol=protocol,
            funding_msat=funding_msat,
            announced=announced,
        )

        if self.should_inspect_graph(req, now):
            graph_stats_res, graph_err = self.inspect_graph(peer_id)
        else:
            graph_stats_res, graph_err = None, None

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

        # Log decision to lightningd log (stderr)
        if accepted:
            logging.info(
                "CLN-zappit: ACCEPTED %s channel from %s (funding: %d sat, announced: %s, reason: %s)",
                protocol,
                peer_id,
                funding_msat // 1000,
                announced,
                reason,
            )
        else:
            ban_info = f", auto-banned until {banned_until}" if banned_until else ""
            logging.warning(
                "CLN-zappit: REJECTED %s channel from %s (funding: %d sat, announced: %s, reason: %s, message: %s%s)",
                protocol,
                peer_id,
                funding_msat // 1000,
                announced,
                reason,
                message,
                ban_info,
            )

        # Emit custom notification
        self.emit_notification("cln_zappit_decision", decision.to_dict())

        if accepted:
            return {"result": "continue"}
        
        peer_error = self.config.reject_message if self.config.generic_reject else message
        return {"result": "reject", "error_message": peer_error}

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
            "state_file": self.state_path,
            "min_channel_sat": self.config.min_channel_sat,
            "min_public_channels": self.config.min_public_channels,
            "min_distinct_peers": self.config.min_distinct_peers,
            "min_public_capacity_sat": self.config.min_public_capacity_sat,
            "min_oldest_channel_blocks": self.config.min_oldest_channel_blocks,
            "reject_private": self.config.reject_private,
            "fail_open": self.config.fail_open,
            "generic_reject": self.config.generic_reject,
            "reject_message": self.config.reject_message,
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
                enabled = to_bool(params["enabled"], True)
        elif isinstance(params, list):
            if params:
                node_id = normalize_node_id(str(params[0]))
            if len(params) > 1:
                enabled = to_bool(params[1], True)
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
