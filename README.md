# CLN-zappit

**CLN-zappit** is a defensive, configuration-driven channel admission plugin for [Core Lightning](https://github.com/ElementsProject/lightning) (CLN). It protects your node against spam, dust channels, unannounced/private channel clutter, and sybil counterparties by evaluating incoming v1 (`openchannel`) and v2 dual-funded (`openchannel2`) channel proposals before funding.

All policy customization lives in a clean, self-documenting configuration file (`cln-zappit.conf`) that can be reloaded at runtime without restarting your node.

---

## Key Features

- **Zero External Dependencies**: Pure Python 3.8+ implementation (`cln_zappit.py`) using only standard library modules. Runs out of the box without `pip` or compilation.
- **Dual Protocol Hooks**: Intercepts both legacy single-funded (`openchannel`) and modern dual-funded v2 (`openchannel2`) proposals.
- **Config-First Architecture**: Customize all thresholds, privacy rules, peer ban limits, and allowlists/denylists in `cln-zappit.conf`.
- **Public Graph Verification**: Queries your node's gossip graph (`listchannels`) to verify that unknown peers maintain genuine public channels, distinct counterparties, aggregate capacity, and established channel age.
- **Automated Anti-Spam Rate Limiting**: Tracks repeated failed proposals within a rolling window and automatically applies temporary bans (e.g. 24 hours after 3 rejections).
- **Allowlist & Denylist**: Explicit allowlist bypasses all checks; denylist unconditionally rejects banned peers.
- **Atomic & Secure State**: Persistent bans, allow/deny entries, and decision logs are stored in `cln-zappit.json` using atomic replacement and mode `0600` permissions.
- **Hot-Reload RPC**: Tweak your config file on disk and apply changes immediately using `lightning-cli cln-zappit-reload`.
- **Companion Rust Implementation**: Full Rust implementation available under `rust/` for environments using Cargo or Nix flakes.

---

## Default Policy Rules

1. **Remote Funding Threshold**: Proposed remote funding must be at least **2,000,000 sats** (configurable).
2. **Reject Private Channels**: Unannounced/private channel proposals from unknown peers are rejected.
3. **Public Graph Footprint**: Peers must maintain at least **1 active public channel** to a distinct counterparty.
4. **Graph Failure Defensive Default**: If graph queries fail (e.g. node syncing), proposals are defensively rejected (`fail_open = false`).
5. **Anti-Spam Ban**: 3 rejected attempts within 1 hour trigger a temporary **24-hour ban**.
6. **Allowlist Bypass**: Allowed peers bypass size, privacy, and graph checks.
7. **Denylist Precedence**: Denylisted peers are unconditionally rejected.

---

## Quickstart & Installation

### Option 1: Load Automatically on Startup (Recommended)

1. Clone the repository to your node:
   ```bash
   git clone https://github.com/btweenthebars/CLN-zappit.git /path/to/CLN-zappit
   ```

2. Copy and customize the configuration file:
   ```bash
   cp /path/to/CLN-zappit/cln-zappit.conf.example ~/.lightning/cln-zappit.conf
   chmod 0600 ~/.lightning/cln-zappit.conf
   ```

3. Add the plugin to your Core Lightning config (`~/.lightning/config` or `~/.lightning/bitcoin/config`):
   ```ini
   plugin=/path/to/CLN-zappit/cln_zappit.py
   cln-zappit-config=/path/to/CLN-zappit/cln-zappit.conf
   ```

### Option 2: Load Dynamically at Runtime

Load without restarting `lightningd`:
```bash
lightning-cli plugin start /path/to/CLN-zappit/cln_zappit.py cln-zappit-config=/path/to/CLN-zappit/cln-zappit.conf
```

To stop or restart:
```bash
lightning-cli plugin stop /path/to/CLN-zappit/cln_zappit.py
```

---

## Configuration (`cln-zappit.conf`)

A complete example is provided in [`cln-zappit.conf.example`](cln-zappit.conf.example):

```ini
[policy]
# Master switch for admission checks (true / false)
enabled = true

# Minimum remote funding accepted from incoming proposals (sats)
min_channel_sat = 2000000

# Reject unannounced private channels from unknown peers
reject_private = true

# Minimum other active public channels required on the peer
min_public_channels = 1

# Minimum distinct counterparties the peer must maintain
min_distinct_peers = 1

# Minimum total public capacity the peer must maintain in sats (0 disables)
min_public_capacity_sat = 0

# Minimum age of peer's oldest active public channel in blocks (0 disables)
min_oldest_channel_blocks = 0

# Defensive fail-open toggle if graph lookup encounters an error
fail_open = false

[rate_limit]
# Window to track repeated rejections (seconds)
rejection_window_seconds = 3600

# Rejections in window before temporary ban (0 disables bans)
ban_after_rejections = 3

# Duration of temporary peer ban (86400s = 24 hours)
ban_seconds = 86400

[allowlist]
# Pubkeys that bypass all admission checks
02065e25c272203440b66ea0ec2ff466d0172fae0e5a8891fa3374d081f9381939 = true

[denylist]
# Pubkeys unconditionally rejected
03271338633d06ae4e76420c3ff503d64f2736551061133642cc3b9828ea2c538f = true
```

---

## RPC Commands

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `cln-zappit-status` | _none_ | View current policy rules, active bans count, and decision stats |
| `cln-zappit-decisions` | `[limit=50]` | View detailed log of recent accepted and rejected channel attempts |
| `cln-zappit-allow` | `node_id [enabled=true]` | Add or remove a peer pubkey from the runtime allowlist |
| `cln-zappit-deny` | `node_id [enabled=true]` | Add or remove a peer pubkey from the runtime denylist |
| `cln-zappit-unban` | `node_id` | Lift a temporary rate-limit ban on a node |
| `cln-zappit-reload` | _none_ | Hot-reload the configuration file from disk |

### Example RPC Output

#### `lightning-cli cln-zappit-status`
```json
{
  "enabled": true,
  "config_file": "/home/bitcoin/.lightning/cln-zappit.conf",
  "min_channel_sat": 2000000,
  "min_public_channels": 1,
  "min_distinct_peers": 1,
  "min_public_capacity_sat": 0,
  "min_oldest_channel_blocks": 0,
  "reject_private": true,
  "fail_open": false,
  "ban_after_rejections": 3,
  "ban_seconds": 86400,
  "active_bans_count": 1,
  "allowlist_count": 2,
  "denylist_count": 1,
  "total_decisions_recorded": 14
}
```

#### `lightning-cli cln-zappit-reload`
```json
{
  "reloaded": true,
  "config_path": "/home/bitcoin/.lightning/cln-zappit.conf",
  "enabled": true
}
```

---

## Notifications

Whenever a channel proposal is evaluated, CLN-zappit emits a `cln_zappit_decision` custom notification over the CLN plugin bus:

```json
{
  "timestamp": 1758123456,
  "peer_id": "02065e...",
  "protocol": "v2",
  "funding_msat": 2500000000,
  "announced": true,
  "accepted": true,
  "reason": "policy_satisfied",
  "message": "Peer satisfies the incoming-channel policy.",
  "graph": {
    "public_channels": 4,
    "distinct_peers": 3,
    "public_capacity_sat": 12000000,
    "oldest_channel_blocks": 15200
  },
  "banned_until": null
}
```

---

## Running Tests

Execute the unit test suite with Python's built-in `unittest`:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

```
...............
----------------------------------------------------------------------
Ran 15 tests in 0.001s

OK
```

---

## Rust Implementation

A companion Rust version of the plugin is available in the [`rust/`](rust/) directory. It can be compiled using Cargo:

```bash
cd rust
cargo build --release
```

Then point Core Lightning to the compiled binary:
```ini
plugin=/path/to/CLN-zappit/rust/target/release/cln-zappit-policy
```

---

## License

MIT License. Copyright (c) 2026 btweenthebars.
