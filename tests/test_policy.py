import os
import stat
import tempfile
import time
import unittest

from cln_zappit import (
    GraphStats,
    OpenRequest,
    PolicyConfig,
    PolicyDecision,
    RuntimeState,
    compute_graph_stats,
    evaluate,
    load_config_file,
    load_runtime_state,
    normalize_node_id,
    parse_msat,
    save_runtime_state,
    to_bool,
    ClnZappitPlugin,
)

SAMPLE_PEER_A = "02065e25c272203440b66ea0ec2ff466d0172fae0e5a8891fa3374d081f9381939"
SAMPLE_PEER_B = "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f"
SAMPLE_PEER_C = "03271338633d06ae4e76420c3ff503d64f2736551061133642cc3b9828ea2c538f"
LOCAL_NODE_ID = "021111111111111111111111111111111111111111111111111111111111111111"


class TestPolicyEvaluation(unittest.TestCase):
    def setUp(self):
        self.config = PolicyConfig(
            enabled=True,
            min_channel_sat=2_000_000,
            min_public_channels=1,
            min_distinct_peers=1,
            min_public_capacity_sat=1_000_000,
            min_oldest_channel_blocks=144,
            reject_private=True,
            fail_open=False,
            rejection_window_seconds=3600,
            ban_after_rejections=3,
            ban_seconds=86400,
        )
        self.runtime = RuntimeState()
        self.valid_graph = GraphStats(
            public_channels=5,
            distinct_peers=3,
            public_capacity_sat=10_000_000,
            oldest_channel_blocks=500,
        )

    def test_normalize_node_id(self):
        self.assertEqual(normalize_node_id(SAMPLE_PEER_A), SAMPLE_PEER_A.lower())
        self.assertEqual(normalize_node_id(SAMPLE_PEER_A.upper()), SAMPLE_PEER_A.lower())
        self.assertIsNone(normalize_node_id("bad_pubkey"))
        self.assertIsNone(normalize_node_id("04" + "11" * 32))  # uncompressed prefix

    def test_parse_msat(self):
        self.assertEqual(parse_msat(1000), 1000)
        self.assertEqual(parse_msat("5000msat"), 5000)
        self.assertEqual(parse_msat({"msat": 7000}), 7000)
        self.assertIsNone(parse_msat(-5))
        self.assertIsNone(parse_msat("invalid"))

    def test_satisfies_policy(self):
        req = OpenRequest(
            peer_id=SAMPLE_PEER_A,
            protocol="v2",
            funding_msat=2_500_000_000,
            announced=True,
        )
        ok, reason, _ = evaluate(self.config, self.runtime, req, self.valid_graph, None, 1000)
        self.assertTrue(ok)
        self.assertEqual(reason, "policy_satisfied")

    def test_disabled_policy_accepts_anything(self):
        self.config.enabled = False
        req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v1", funding_msat=1000, announced=False)
        ok, reason, _ = evaluate(self.config, self.runtime, req, None, "error", 1000)
        self.assertTrue(ok)
        self.assertEqual(reason, "disabled")

    def test_denylist_takes_precedence(self):
        self.config.denylist.add(SAMPLE_PEER_A)
        self.config.allowlist.add(SAMPLE_PEER_A)  # even if in allowlist!
        req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v2", funding_msat=5_000_000_000, announced=True)
        ok, reason, msg = evaluate(self.config, self.runtime, req, self.valid_graph, None, 1000)
        self.assertFalse(ok)
        self.assertEqual(reason, "denylisted")
        self.assertIn("denylisted", msg)

    def test_temporary_ban(self):
        self.runtime.bans[SAMPLE_PEER_A] = 2000
        req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v2", funding_msat=5_000_000_000, announced=True)
        # Banned at t=1500
        ok, reason, _ = evaluate(self.config, self.runtime, req, self.valid_graph, None, 1500)
        self.assertFalse(ok)
        self.assertEqual(reason, "temporarily_banned")
        # Ban expired at t=2500
        ok, reason, _ = evaluate(self.config, self.runtime, req, self.valid_graph, None, 2500)
        self.assertTrue(ok)

    def test_allowlist_bypasses_all_checks(self):
        self.config.allowlist.add(SAMPLE_PEER_A)
        # Tiny funding, private channel, no public graph
        req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v1", funding_msat=50_000_000, announced=False)
        ok, reason, _ = evaluate(self.config, self.runtime, req, None, "graph offline", 1000)
        self.assertTrue(ok)
        self.assertEqual(reason, "allowlisted")

    def test_rejection_for_small_funding(self):
        req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v2", funding_msat=1_999_999_000, announced=True)
        ok, reason, msg = evaluate(self.config, self.runtime, req, self.valid_graph, None, 1000)
        self.assertFalse(ok)
        self.assertEqual(reason, "channel_too_small")
        self.assertIn("2000000sat", msg)

    def test_rejection_for_private_channel(self):
        req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v2", funding_msat=5_000_000_000, announced=False)
        ok, reason, _ = evaluate(self.config, self.runtime, req, self.valid_graph, None, 1000)
        self.assertFalse(ok)
        self.assertEqual(reason, "private_disallowed")

        # When reject_private is disabled, it should pass
        self.config.reject_private = False
        ok, reason, _ = evaluate(self.config, self.runtime, req, self.valid_graph, None, 1000)
        self.assertTrue(ok)

    def test_rejection_for_insufficient_graph(self):
        req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v2", funding_msat=5_000_000_000, announced=True)

        # 0 public channels
        bad_graph = GraphStats(public_channels=0, distinct_peers=1, public_capacity_sat=5_000_000, oldest_channel_blocks=200)
        ok, reason, _ = evaluate(self.config, self.runtime, req, bad_graph, None, 1000)
        self.assertFalse(ok)
        self.assertEqual(reason, "insufficient_public_channels")

        # 0 distinct peers
        bad_graph = GraphStats(public_channels=2, distinct_peers=0, public_capacity_sat=5_000_000, oldest_channel_blocks=200)
        ok, reason, _ = evaluate(self.config, self.runtime, req, bad_graph, None, 1000)
        self.assertFalse(ok)
        self.assertEqual(reason, "insufficient_distinct_peers")

        # low capacity
        bad_graph = GraphStats(public_channels=2, distinct_peers=2, public_capacity_sat=500_000, oldest_channel_blocks=200)
        ok, reason, _ = evaluate(self.config, self.runtime, req, bad_graph, None, 1000)
        self.assertFalse(ok)
        self.assertEqual(reason, "insufficient_public_capacity")

        # too young channel age
        bad_graph = GraphStats(public_channels=2, distinct_peers=2, public_capacity_sat=5_000_000, oldest_channel_blocks=50)
        ok, reason, _ = evaluate(self.config, self.runtime, req, bad_graph, None, 1000)
        self.assertFalse(ok)
        self.assertEqual(reason, "insufficient_channel_age")

    def test_fail_open_behavior(self):
        req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v2", funding_msat=5_000_000_000, announced=True)

        # fail_open = False (default)
        self.config.fail_open = False
        ok, reason, _ = evaluate(self.config, self.runtime, req, None, "network timeout", 1000)
        self.assertFalse(ok)
        self.assertEqual(reason, "graph_unavailable")

        # fail_open = True
        self.config.fail_open = True
        ok, reason, _ = evaluate(self.config, self.runtime, req, None, "network timeout", 1000)
        self.assertTrue(ok)
        self.assertEqual(reason, "graph_unavailable_fail_open")

    def test_rate_limiting_and_auto_ban(self):
        now = 1000
        # 1st rejection
        ban = self.runtime.record_rejection(SAMPLE_PEER_A, now, self.config)
        self.assertIsNone(ban)

        # 2nd rejection
        ban = self.runtime.record_rejection(SAMPLE_PEER_A, now + 10, self.config)
        self.assertIsNone(ban)

        # 3rd rejection -> triggers ban!
        ban = self.runtime.record_rejection(SAMPLE_PEER_A, now + 20, self.config)
        self.assertIsNotNone(ban)
        self.assertEqual(ban, now + 20 + self.config.ban_seconds)
        self.assertEqual(self.runtime.bans[SAMPLE_PEER_A], ban)


class TestGraphStatsComputation(unittest.TestCase):
    def test_compute_graph_stats(self):
        channels = [
            {
                "short_channel_id": "800000x100x1",
                "destination": SAMPLE_PEER_B,
                "amount_msat": "2000000000msat",
                "active": True,
            },
            {
                "short_channel_id": "800000x100x1",  # duplicate scid (reverse direction)
                "destination": SAMPLE_PEER_B,
                "amount_msat": "2000000000msat",
                "active": True,
            },
            {
                "short_channel_id": "850000x200x1",
                "destination": SAMPLE_PEER_C,
                "amount_msat": 3_000_000_000,
                "active": True,
            },
            {
                "short_channel_id": "900000x300x1",
                "destination": LOCAL_NODE_ID,  # channel with our own node - should be ignored!
                "amount_msat": "1000000000msat",
                "active": True,
            },
            {
                "short_channel_id": "820000x400x1",
                "destination": "02" + "44" * 32,
                "amount_msat": "1000000000msat",
                "active": False,  # inactive - should be ignored!
            },
        ]
        stats = compute_graph_stats(channels, blockheight=860000, local_node_id=LOCAL_NODE_ID)
        self.assertEqual(stats.public_channels, 2)
        self.assertEqual(stats.distinct_peers, 2)
        self.assertEqual(stats.public_capacity_sat, 5_000_000)
        self.assertEqual(stats.oldest_channel_blocks, 60000)  # 860000 - 800000


class TestConfigAndStatePersistence(unittest.TestCase):
    def test_load_config_file(self):
        content = """
[policy]
enabled = false
min_channel_sat = 5000000
reject_private = false
min_public_channels = 3
min_distinct_peers = 2
min_public_capacity_sat = 15000000
min_oldest_channel_blocks = 1000
fail_open = true

[rate_limit]
rejection_window_seconds = 7200
ban_after_rejections = 5
ban_seconds = 172800

[allowlist]
02065e25c272203440b66ea0ec2ff466d0172fae0e5a8891fa3374d081f9381939 = true

[denylist]
03271338633d06ae4e76420c3ff503d64f2736551061133642cc3b9828ea2c538f = true
"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf") as f:
            f.write(content)
            temp_path = f.name

        try:
            cfg = load_config_file(temp_path)
            self.assertFalse(cfg.enabled)
            self.assertEqual(cfg.min_channel_sat, 5000000)
            self.assertFalse(cfg.reject_private)
            self.assertEqual(cfg.min_public_channels, 3)
            self.assertEqual(cfg.min_distinct_peers, 2)
            self.assertEqual(cfg.min_public_capacity_sat, 15000000)
            self.assertEqual(cfg.min_oldest_channel_blocks, 1000)
            self.assertTrue(cfg.fail_open)
            self.assertEqual(cfg.rejection_window_seconds, 7200)
            self.assertEqual(cfg.ban_after_rejections, 5)
            self.assertEqual(cfg.ban_seconds, 172800)
            self.assertIn(SAMPLE_PEER_A, cfg.allowlist)
            self.assertIn(SAMPLE_PEER_C, cfg.denylist)
        finally:
            os.remove(temp_path)

    def test_state_saving_and_loading_atomic_permissions(self):
        state = RuntimeState(
            allowlist={SAMPLE_PEER_A},
            denylist={SAMPLE_PEER_C},
            bans={SAMPLE_PEER_B: 999999},
            decisions=[
                PolicyDecision(
                    timestamp=1000,
                    peer_id=SAMPLE_PEER_B,
                    protocol="v1",
                    funding_msat=1000000000,
                    announced=True,
                    accepted=False,
                    reason="channel_too_small",
                    message="Funding too low",
                )
            ],
        )

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            temp_path = f.name

        try:
            save_runtime_state(temp_path, state)
            mode = stat.S_IMODE(os.stat(temp_path).st_mode)
            self.assertEqual(mode, 0o600)

            loaded = load_runtime_state(temp_path)
            self.assertEqual(loaded.allowlist, {SAMPLE_PEER_A})
            self.assertEqual(loaded.denylist, {SAMPLE_PEER_C})
            self.assertEqual(loaded.bans[SAMPLE_PEER_B], 999999)
            self.assertEqual(len(loaded.decisions), 1)
            self.assertEqual(loaded.decisions[0].reason, "channel_too_small")
        finally:
            os.remove(temp_path)


class TestRobustnessAndEdgeCases(unittest.TestCase):
    def test_to_bool_parsing(self):
        self.assertTrue(to_bool(True))
        self.assertTrue(to_bool(1))
        self.assertTrue(to_bool("true"))
        self.assertTrue(to_bool("TRUE"))
        self.assertTrue(to_bool("yes"))
        self.assertTrue(to_bool("on"))
        self.assertTrue(to_bool("enable"))
        self.assertTrue(to_bool("enabled"))

        self.assertFalse(to_bool(False))
        self.assertFalse(to_bool(0))
        self.assertFalse(to_bool("false"))
        self.assertFalse(to_bool("FALSE"))
        self.assertFalse(to_bool("no"))
        self.assertFalse(to_bool("off"))
        self.assertFalse(to_bool("disable"))
        self.assertFalse(to_bool("disabled"))
        self.assertFalse(to_bool(None, default=False))
        self.assertTrue(to_bool(None, default=True))

    def test_parse_msat_extended(self):
        # sat and sats suffix
        self.assertEqual(parse_msat("5000sat"), 5_000_000)
        self.assertEqual(parse_msat("2500sats"), 2_500_000)
        # float
        self.assertEqual(parse_msat(1000.0), 1000)
        # dict with sat
        self.assertEqual(parse_msat({"sat": 500}), 500_000)
        self.assertEqual(parse_msat({"sats": "200"}), 200_000)
        # dict with msat
        self.assertEqual(parse_msat({"msat": "3000msat"}), 3000)

    def test_should_inspect_graph_short_circuits(self):
        plugin = ClnZappitPlugin()
        plugin.config = PolicyConfig(
            enabled=True,
            min_channel_sat=1_000_000,
            reject_private=True,
            min_public_channels=1,
        )
        now = 1000

        # Small channel -> should not inspect graph
        small_req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v2", funding_msat=500_000_000, announced=True)
        self.assertFalse(plugin.should_inspect_graph(small_req, now))

        # Private unannounced channel -> should not inspect graph
        private_req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v2", funding_msat=2_000_000_000, announced=False)
        self.assertFalse(plugin.should_inspect_graph(private_req, now))

        # Denylisted peer -> should not inspect graph
        plugin.config.denylist.add(SAMPLE_PEER_A)
        good_req = OpenRequest(peer_id=SAMPLE_PEER_A, protocol="v2", funding_msat=2_000_000_000, announced=True)
        self.assertFalse(plugin.should_inspect_graph(good_req, now))
        plugin.config.denylist.clear()

        # Banned peer -> should not inspect graph
        plugin.state.bans[SAMPLE_PEER_A] = now + 1000
        self.assertFalse(plugin.should_inspect_graph(good_req, now))
        plugin.state.bans.clear()

        # Allowlisted peer -> should not inspect graph
        plugin.config.allowlist.add(SAMPLE_PEER_A)
        self.assertFalse(plugin.should_inspect_graph(good_req, now))
        plugin.config.allowlist.clear()

        # Normal valid proposal -> should inspect graph!
        self.assertTrue(plugin.should_inspect_graph(good_req, now))

    def test_parse_node_and_toggle(self):
        # Dict with boolean string
        node, enabled = ClnZappitPlugin._parse_node_and_toggle({"id": SAMPLE_PEER_A, "enabled": "false"})
        self.assertEqual(node, SAMPLE_PEER_A.lower())
        self.assertFalse(enabled)

        # List with boolean string
        node, enabled = ClnZappitPlugin._parse_node_and_toggle([SAMPLE_PEER_A, "off"])
        self.assertEqual(node, SAMPLE_PEER_A.lower())
        self.assertFalse(enabled)

        node, enabled = ClnZappitPlugin._parse_node_and_toggle([SAMPLE_PEER_A, "true"])
        self.assertEqual(node, SAMPLE_PEER_A.lower())
        self.assertTrue(enabled)

    def test_generic_reject_hides_reason(self):
        plugin = ClnZappitPlugin()
        plugin.config = PolicyConfig(
            enabled=True,
            min_channel_sat=5_000_000,
            generic_reject=True,
            reject_message="Custom declined.",
        )
        # Low funding proposal
        payload = {
            "openchannel": {
                "id": SAMPLE_PEER_A,
                "funding_msat": 1_000_000_000,  # 1M sat, less than 5M
                "channel_flags": 1,
            }
        }
        res = plugin.handle_open_channel_hook(payload, "v1")
        self.assertEqual(res["result"], "reject")
        # Peer receives generic message, not internal reason
        self.assertEqual(res["error_message"], "Custom declined.")

        # If generic_reject is disabled, peer receives detailed message
        plugin.config.generic_reject = False
        res = plugin.handle_open_channel_hook(payload, "v1")
        self.assertEqual(res["result"], "reject")
        self.assertIn("5000000sat", res["error_message"])

    def test_init_discovers_config_and_preserves_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            conf_path = os.path.join(temp_dir, "cln-zappit.conf")
            with open(conf_path, "w") as f:
                f.write("[policy]\nmin_channel_sat = 7777777\nreject_private = false\n")

            # 1. Direct discovery in lightning-dir
            plugin = ClnZappitPlugin()
            plugin.handle_init({
                "options": {},
                "configuration": {
                    "lightning-dir": temp_dir,
                    "network": "bitcoin",
                }
            })
            self.assertEqual(plugin.config_path, os.path.abspath(conf_path))
            self.assertEqual(plugin.config.min_channel_sat, 7777777)
            self.assertFalse(plugin.config.reject_private)

            # 2. Parent directory discovery (e.g. lightning-dir is ~/cln/bitcoin)
            net_subdir = os.path.join(temp_dir, "bitcoin")
            os.makedirs(net_subdir, exist_ok=True)
            plugin2 = ClnZappitPlugin()
            plugin2.handle_init({
                "options": {},
                "configuration": {
                    "lightning-dir": net_subdir,
                    "network": "bitcoin",
                }
            })
            self.assertEqual(plugin2.config_path, os.path.abspath(conf_path))
            self.assertEqual(plugin2.config.min_channel_sat, 7777777)


if __name__ == "__main__":
    unittest.main()
