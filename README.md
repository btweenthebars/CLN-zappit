# CLN-zappit

Defensive incoming-channel admission policy plugin for [Core Lightning](https://github.com/ElementsProject/lightning) (CLN). Protects your node against spam, dust channels, unannounced private channels, and sybil peers by intercepting incoming v1 (`openchannel`) and v2 dual-funding (`openchannel2`) channel proposals.

---

## How to Build

### Python Version (Default & Recommended)
**No build or compilation required.** CLN-zappit is a zero-dependency Python 3.8+ plugin using only the Python standard library.

Simply make sure it is executable:
```bash
chmod +x cln_zappit.py
```

### Rust Version (Optional)
If you prefer running a native binary:

```bash
cd rust
cargo build --release
```
The compiled binary will be located at `rust/target/release/cln-zappit-policy`.

---

## How to Run

### 1. Configuration Setup
Copy the example configuration file to your Lightning directory:

```bash
cp cln-zappit.conf.example ~/.lightning/cln-zappit.conf
chmod 0600 ~/.lightning/cln-zappit.conf
```

Edit `~/.lightning/cln-zappit.conf` to set your desired thresholds:
```ini
[policy]
enabled = true
min_channel_sat = 2000000        # Minimum incoming funding in sats
reject_private = true            # Reject unannounced private channels
min_public_channels = 1          # Minimum active public channels peer must have
min_distinct_peers = 1           # Minimum distinct peers peer must have
min_public_capacity_sat = 0      # Minimum public capacity (0 = disabled)
min_oldest_channel_blocks = 0    # Minimum channel age in blocks (0 = disabled)
fail_open = false                # If graph inspection fails: false = reject, true = accept

[rate_limit]
rejection_window_seconds = 3600  # Window to track repeated rejections
ban_after_rejections = 3         # Rejections before temporary ban
ban_seconds = 86400              # Ban duration (86400s = 24h)

[allowlist]
# 02065e25c272203440b66ea0ec2ff466d0172fae0e5a8891fa3374d081f9381939 = true

[denylist]
# 03271338633d06ae4e76420c3ff503d64f2736551061133642cc3b9828ea2c538f = true
```

### 2. Run with Core Lightning

#### Method A: Start Automatically with CLN
Add these lines to your Core Lightning config (`~/.lightning/config` or `~/.lightning/bitcoin/config`):

```ini
plugin=/path/to/CLN-zappit/cln_zappit.py
cln-zappit-config=/path/to/cln-zappit.conf
```
*(Or use `plugin=/path/to/CLN-zappit/rust/target/release/cln-zappit-policy` for the Rust binary).*

#### Method B: Start Dynamically via `lightning-cli`
Start without restarting `lightningd`:

```bash
lightning-cli plugin start /path/to/CLN-zappit/cln_zappit.py cln-zappit-config=/path/to/cln-zappit.conf
```

To stop:
```bash
lightning-cli plugin stop /path/to/CLN-zappit/cln_zappit.py
```

### 3. Verification & Management
Once running, control the plugin via `lightning-cli`:

```bash
# Check status, active bans, and policy settings
lightning-cli cln-zappit-status

# Hot-reload configuration without restarting CLN
lightning-cli cln-zappit-reload

# View recent channel decisions
lightning-cli cln-zappit-decisions

# Add/remove peer from allowlist or denylist
lightning-cli cln-zappit-allow <node_pubkey>
lightning-cli cln-zappit-deny <node_pubkey>

# Unban a peer early
lightning-cli cln-zappit-unban <node_pubkey>
```

---

## Running Tests

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

---

## License

MIT License. Copyright (c) 2026 btweenthebars.
