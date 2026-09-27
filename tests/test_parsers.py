"""Parser + ghost-detection tests for nethtop++.

Zero-dependency (stdlib unittest only). The `++` in the filename defeats plain
`import nethtop`, so the module is loaded explicitly via importlib. Parser
methods under test are pure static functions of text, so no terminal, no
psutil process trees, and no live tools are required.
"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load_module():
    sys.path.insert(0, str(REPO_ROOT))  # for platform_utils
    spec = importlib.util.spec_from_file_location("nethtop", REPO_ROOT / "nethtop++.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nethtop = _load_module()
App = nethtop.NetTopPlusPlusApp


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class CanonicalAddrTests(unittest.TestCase):
    """_canonical_addr must reduce every real address format to host:port."""

    def test_macos_ipv4_dot_form(self):
        self.assertEqual(App._canonical_addr("10.0.0.120.65360"), "10.0.0.120:65360")

    def test_macos_ipv6_dot_form(self):
        # macOS netstat prints IPv6 with a dot before the port.
        self.assertEqual(App._canonical_addr("fe80::1.546"), "fe80::1:546")

    def test_lsof_bracketed_ipv6(self):
        self.assertEqual(App._canonical_addr("[::1]:80"), "::1:80")

    def test_wildcards(self):
        self.assertEqual(App._canonical_addr("*.*"), "*:*")
        self.assertEqual(App._canonical_addr("*.49152"), "*:49152")

    def test_colon_forms_unchanged(self):
        self.assertEqual(App._canonical_addr("10.0.0.120:49152"), "10.0.0.120:49152")
        self.assertEqual(App._canonical_addr("0.0.0.0:22"), "0.0.0.0:22")
        self.assertEqual(App._canonical_addr("*:49152"), "*:49152")

    def test_empty(self):
        self.assertEqual(App._canonical_addr(""), "")


class ParseNetstatAddrTests(unittest.TestCase):
    def test_macos_dot(self):
        self.assertEqual(App._parse_netstat_addr("10.0.0.120.65360"), ("10.0.0.120", 65360))

    def test_colon(self):
        self.assertEqual(App._parse_netstat_addr("8.8.8.8:443"), ("8.8.8.8", 443))

    def test_non_port_returns_none(self):
        self.assertIsNone(App._parse_netstat_addr("no-port-here"))
        self.assertIsNone(App._parse_netstat_addr(""))

    def test_ipv6_dot(self):
        self.assertEqual(App._parse_netstat_addr("fe80::1.546"), ("fe80::1", 546))


class MacOSNetstatParseTests(unittest.TestCase):
    def setUp(self):
        self.parsed = App._parse_netstat_output(_fixture("macos_netstat_anv.txt"))

    def test_dot_separated_addrs_canonicalized(self):
        self.assertIn(
            ("TCP", "127.0.0.1:49263", "127.0.0.1:65367"),
            self.parsed,
        )
        self.assertEqual(
            self.parsed[("TCP", "127.0.0.1:49263", "127.0.0.1:65367")]["state"],
            "ESTABLISHED",
        )

    def test_external_ip_canonicalized(self):
        self.assertIn(("TCP", "10.0.0.120:65360", "8.8.8.8:443"), self.parsed)

    def test_listener_wildcards_match_lsof_shape(self):
        # netstat `*.49152` + `*.*` must land as `*:49152` + `*:*`, the exact
        # keys lsof produces — otherwise every listener reads as a ghost.
        self.assertIn(("TCP", "*:49152", "*:*"), self.parsed)
        self.assertEqual(self.parsed[("TCP", "*:49152", "*:*")]["state"], "LISTEN")

    def test_unix_domain_sockets_filtered(self):
        self.assertFalse(any(key[0].startswith("unix") for key in self.parsed))

    def test_proto_display_preserved(self):
        self.assertEqual(self.parsed[("TCP", "*:49152", "*:*")]["proto"], "TCP6")


class LinuxProcNetParseTests(unittest.TestCase):
    def test_tcp_table(self):
        tables = [("TCP", _fixture("linux_proc_net_tcp.txt"))]
        parsed = App._parse_proc_net_output(tables)
        self.assertIn(("TCP", "127.0.0.1:8080", "*:*"), parsed)
        self.assertEqual(parsed[("TCP", "127.0.0.1:8080", "*:*")]["state"], "LISTEN")
        # 640AA8C0 little-endian = 192.168.10.100, 08080808 = 8.8.8.8, 01BB = 443
        self.assertIn(("TCP", "192.168.10.100:51966", "8.8.8.8:443"), parsed)
        self.assertEqual(parsed[("TCP", "192.168.10.100:51966", "8.8.8.8:443")]["state"], "ESTABLISHED")

    def test_ipv6_rows(self):
        tables = [("TCP6", _fixture("linux_proc_net_tcp.txt"))]
        parsed = App._parse_proc_net_output(tables)
        # all-zero IPv6 is a wildcard bind -> "*", matching what lsof prints
        self.assertIn(("TCP", "*:5796", "*:*"), parsed)
        # ::1:80 — compressed, matching lsof's canonical "[::1]:80" -> "::1:80"
        self.assertIn(("TCP", "::1:80", "*:*"), parsed)

    def test_udp_state_unconn(self):
        tables = [("UDP", _fixture("linux_proc_net_udp.txt"))]
        parsed = App._parse_proc_net_output(tables)
        self.assertEqual(parsed[("UDP", "127.0.0.1:53", "*:*")]["state"], "UNCONN")


class LsofParseTests(unittest.TestCase):
    def test_macos_lsof(self):
        parsed = App._parse_lsof_output(_fixture("lsof_macos.txt"))
        # listener: no ->, remote normalizes to *:*
        self.assertIn(("TCP", "*:49152", "*:*"), parsed)
        self.assertEqual(parsed[("TCP", "*:49152", "*:*")]["pid"], "641")
        # established pair with pid
        self.assertIn(("TCP", "10.0.0.120:49152", "10.0.0.145:49662"), parsed)
        self.assertEqual(parsed[("TCP", "10.0.0.120:49152", "10.0.0.145:49662")]["pid"], "641")
        # UDP socket
        self.assertIn(("UDP", "*:3722", "*:*"), parsed)

    def test_linux_lsof(self):
        parsed = App._parse_lsof_output(_fixture("lsof_linux.txt"))
        self.assertIn(("TCP", "*:8080", "*:*"), parsed)
        self.assertEqual(parsed[("TCP", "*:8080", "*:*")]["pid"], "1122")
        self.assertIn(("TCP", "192.168.10.100:51966", "8.8.8.8:443"), parsed)


class KernelUserlandMatchTests(unittest.TestCase):
    """The canonical-key comparison must NOT flag listeners/UDP as ghosts.

    This is the bug the hardening pass fixes: before canonicalization, macOS
    netstat (dot form) and lsof (colon form) never produced equal keys, so the
    ghost detector treated nearly every socket as a ghost.
    """

    def test_listener_matches(self):
        kernel = App._parse_netstat_output(_fixture("macos_netstat_anv.txt"))
        userland = App._parse_lsof_output(_fixture("lsof_macos.txt"))
        # Both sides keyed ("TCP", "*:49152", "*:*") -> not a ghost.
        self.assertIn(("TCP", "*:49152", "*:*"), kernel)
        self.assertIn(("TCP", "*:49152", "*:*"), userland)
        self.assertNotIn(("TCP", "*:49152", "*:*"), {k for k in kernel if k not in userland})


class LinuxKernelUserlandMatchTests(unittest.TestCase):
    """The Linux sibling of the macOS canonical-key test.

    The hardening pass canonicalized key spelling for macOS, where netstat uses
    the dot form and lsof the colon form. The Linux /proc parser was left
    emitting 0.0.0.0:0 for an absent peer and 0.0.0.0 for a wildcard bind, while
    lsof emits *:* and *, so on Linux every listener that both tools could
    plainly see was scored as a ghost.
    """

    WILDCARD_ROW = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
        "   uid  timeout inode\n"
        "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
        "     0        0 90001 1 0000000000000000 100 0 0 10 0\n"
    )

    def test_shared_socket_is_not_a_ghost(self):
        kernel = App._parse_proc_net_output([("TCP", _fixture("linux_proc_net_tcp.txt"))])
        userland = App._parse_lsof_output(_fixture("lsof_linux.txt"))
        self.assertIn(("TCP", "192.168.10.100:51966", "8.8.8.8:443"), kernel)
        self.assertIn(("TCP", "192.168.10.100:51966", "8.8.8.8:443"), userland)
        self.assertNotIn(("TCP", "192.168.10.100:51966", "8.8.8.8:443"),
                         {k for k in kernel if k not in userland})

    def test_wildcard_bind_matches_across_parsers(self):
        """A wildcard listener is 0.0.0.0 in /proc and * in lsof."""
        kernel = App._parse_proc_net_output([("TCP", self.WILDCARD_ROW)])
        userland = App._parse_lsof_output(_fixture("lsof_linux.txt"))
        self.assertIn(("TCP", "*:8080", "*:*"), kernel)
        self.assertIn(("TCP", "*:8080", "*:*"), userland)
        self.assertEqual([k for k in kernel if k not in userland], [])

    def test_no_parser_leaks_a_raw_null_endpoint(self):
        kernel = App._parse_proc_net_output([
            ("TCP", _fixture("linux_proc_net_tcp.txt")),
            ("UDP", _fixture("linux_proc_net_udp.txt")),
        ])
        userland = App._parse_lsof_output(_fixture("lsof_linux.txt"))
        for key in kernel:
            self.assertNotIn(key[2], ("0.0.0.0:0", ":::0", "::0"),
                             "a raw null remote leaked into a kernel key")
        for key in userland:
            # A real peer keeps its address; only a null peer collapses.
            self.assertNotEqual(key[2], "", "lsof peer must never be empty")
            self.assertNotIn(key[2], ("0.0.0.0:0", ":::0", "*.*"),
                             "a raw null peer leaked into an lsof key")
        # the listener really is canonicalized, and keeps its pid
        self.assertEqual(userland[("TCP", "*:8080", "*:*")]["pid"], "1122")


class GhostConfidenceTests(unittest.TestCase):
    def test_owned_process_lowers_confidence(self):
        conf, reasons = App._ghost_confidence({"state": "ESTABLISHED"}, 1234, 0)
        self.assertLess(conf, 0.3)
        self.assertTrue(any("tool race" in r for r in reasons))

    def test_unowned_listener_scores_high(self):
        conf, _ = App._ghost_confidence({"state": "LISTEN"}, None, 0)
        self.assertGreaterEqual(conf, 0.6)

    def test_persistence_raises_confidence(self):
        fresh, _ = App._ghost_confidence({"state": "LISTEN"}, None, 0)
        aged, reasons = App._ghost_confidence({"state": "LISTEN"}, None, 3)
        self.assertGreater(aged, fresh)
        self.assertTrue(any("persistent" in r for r in reasons))

    def test_confidence_bounded(self):
        for state in ("LISTEN", "ESTABLISHED", "", "TIME_WAIT"):
            for pid in (None, 5):
                for persistence in (0, 5):
                    for unprivileged in (False, True):
                        conf, _ = App._ghost_confidence({"state": state}, pid, persistence, unprivileged=unprivileged)
                        self.assertGreaterEqual(conf, 0.0)
                        self.assertLessEqual(conf, 1.0)

    def test_unprivileged_scan_deflates_confidence(self):
        privileged, _ = App._ghost_confidence({"state": "LISTEN"}, None, 0)
        unprivileged, reasons = App._ghost_confidence({"state": "LISTEN"}, None, 0, unprivileged=True)
        self.assertLess(unprivileged, privileged)
        self.assertTrue(any("another user" in r for r in reasons))


class GhostDetectionUnavailableTests(unittest.TestCase):
    """Missing tools must yield an 'unavailable' report — never ghost verdicts."""

    def _stub_app(self, dep_availability):
        stub = types.SimpleNamespace()
        stub.dep_availability = dep_availability
        stub.ghost_entries = []
        stub.show_ghost_overlay = False
        stub.ghost_cursor = 0
        stub.ghost_detection_unavailable = False
        stub.ghost_persistence = {}
        stub.recorded = []
        stub.is_root = False
        stub._detect_ghost_sockets = types.MethodType(App._detect_ghost_sockets, stub)
        stub._ghost_unavailable = types.MethodType(App._ghost_unavailable, stub)
        stub._parse_netstat_output = App._parse_netstat_output
        stub._parse_lsof_output = App._parse_lsof_output
        stub._record_alert = lambda alert: stub.recorded.append(alert)
        stub._run_command = lambda *a, **k: ""  # must never be reached for these tests
        # Linux ground truth is unreadable in a unit test, so force the netstat
        # fallback these tests were written against.
        stub._read_proc_net_tables = lambda: None
        stub._build_socket_pid_index = lambda: {}
        return stub

    def test_missing_lsof_reports_unavailable(self):
        stub = self._stub_app({"lsof": False, "netstat": True})
        stub._detect_ghost_sockets()
        self.assertTrue(stub.ghost_detection_unavailable)
        self.assertEqual(stub.ghost_entries, [])
        self.assertTrue(any("unavailable" in a.summary for a in stub.recorded))

    def test_missing_netstat_reports_unavailable(self):
        stub = self._stub_app({"lsof": True, "netstat": False})
        stub._detect_ghost_sockets()
        self.assertTrue(stub.ghost_detection_unavailable)
        self.assertTrue(any("unavailable" in a.summary for a in stub.recorded))

    def test_empty_lsof_output_is_unavailable_not_all_ghosts(self):
        # The original bug: empty lsof result was treated as authoritative,
        # labeling every kernel socket a ghost.
        stub = self._stub_app({"lsof": True, "netstat": True})
        stub._run_command = lambda cmd, timeout=7: _fixture("macos_netstat_anv.txt") if "netstat" in cmd[0] else ""
        stub._detect_ghost_sockets()
        self.assertTrue(stub.ghost_detection_unavailable)
        self.assertEqual(stub.ghost_entries, [])
        self.assertTrue(any("returned no data" in a.summary for a in stub.recorded))


class GhostDetectionPipelineTests(unittest.TestCase):
    """End-to-end: kernel + lsof inventories -> entries with confidence."""

    def test_full_pipeline_flags_only_true_mismatches(self):
        stub = types.SimpleNamespace()
        stub.dep_availability = {"lsof": True, "netstat": True}
        stub.ghost_entries = []
        stub.show_ghost_overlay = False
        stub.ghost_cursor = 0
        stub.ghost_detection_unavailable = False
        stub.ghost_persistence = {}
        stub.recorded = []
        stub.is_root = True  # privileged pipeline: deterministic full-strength scores

        def run_command(cmd, timeout=7):
            if cmd[0] == "netstat":
                return _fixture("macos_netstat_anv.txt")
            return _fixture("lsof_macos.txt")

        stub._run_command = run_command
        stub._detect_ghost_sockets = types.MethodType(App._detect_ghost_sockets, stub)
        stub._ghost_unavailable = types.MethodType(App._ghost_unavailable, stub)
        stub._parse_netstat_output = App._parse_netstat_output
        stub._parse_lsof_output = App._parse_lsof_output
        stub._ghost_confidence = App._ghost_confidence
        stub._parse_netstat_addr = App._parse_netstat_addr
        stub._read_proc_net_tables = lambda: None
        stub._build_socket_pid_index = lambda: {}
        stub._record_alert = lambda alert: stub.recorded.append(alert)

        alerts = stub._detect_ghost_sockets()

        self.assertFalse(stub.ghost_detection_unavailable)
        ghost_keys = {(e["local"], e["remote"]) for e in stub.ghost_entries}
        # The listener (present in both fixtures) must NOT be a ghost.
        self.assertNotIn(("*:49152", "*:*"), ghost_keys)
        # Entries carry confidence + reasons and are sorted high-first.
        confidences = [e["confidence"] for e in stub.ghost_entries]
        self.assertEqual(confidences, sorted(confidences, reverse=True))
        for entry in stub.ghost_entries:
            self.assertIn("confidence", entry)
            self.assertTrue(entry["reasons"])
        self.assertEqual(len(alerts), 1)
        self.assertIn("ghost sockets detected", alerts[0].summary)



class GhostScanCostTests(unittest.TestCase):
    """Regression: the process table is swept ONCE per scan, never per ghost.

    The first version of ghost detection called _identify_process_for_socket
    inside the ghost loop, and that walks every process on the box. On a
    530-process machine with 122 ghosts that is ~65k connection collections and
    measured 78 seconds inside update_data(), all of it before the first paint,
    so the UI sat on a blank screen. This test fails if the per-ghost walk comes
    back, because it makes calling that method an error.
    """

    def test_process_table_swept_once_for_many_ghosts(self):
        stub = types.SimpleNamespace()
        stub.dep_availability = {"lsof": True, "netstat": True}
        stub.ghost_entries = []
        stub.show_ghost_overlay = False
        stub.ghost_cursor = 0
        stub.ghost_detection_unavailable = False
        stub.ghost_persistence = {}
        stub.recorded = []
        stub.is_root = True

        def run_command(cmd, timeout=7):
            if cmd[0] == "netstat":
                return _fixture("macos_netstat_anv.txt")
            return _fixture("lsof_macos.txt")

        builds = []
        stub._run_command = run_command
        stub._read_proc_net_tables = lambda: None
        stub._detect_ghost_sockets = types.MethodType(App._detect_ghost_sockets, stub)
        stub._ghost_unavailable = types.MethodType(App._ghost_unavailable, stub)
        stub._parse_netstat_output = App._parse_netstat_output
        stub._parse_lsof_output = App._parse_lsof_output
        stub._parse_netstat_addr = App._parse_netstat_addr
        stub._ghost_confidence = App._ghost_confidence
        stub._record_alert = lambda alert: stub.recorded.append(alert)
        stub._build_socket_pid_index = lambda: (builds.append(1), {})[1]
        stub._identify_process_for_socket = lambda *a, **k: self.fail(
            "per-ghost process-table walk is back: that is the 78s first-paint freeze"
        )

        stub._detect_ghost_sockets()

        self.assertTrue(stub.ghost_entries, "fixtures should yield ghosts to score")
        self.assertEqual(len(builds), 1, "socket index must be built once per scan")


if __name__ == "__main__":
    unittest.main()
