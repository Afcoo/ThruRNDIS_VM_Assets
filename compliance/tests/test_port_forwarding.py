# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "script/initramfs/port-forwarding"
sys.path.insert(0, str(ROOT / "script/lib"))

import build_assets  # noqa: E402

SHELL_HARNESS = r'''
bb() {
    if [ "$1" = cat ]; then
        printf '%s\n' "$MOCK_CMDLINE"
    else
        command "$@"
    fi
}
log_console() { :; }
BB=bb
RNDIS_IFACE=usb0
INGRESS_IFACE=eth0
HOST_LINK_HOST_IPV4=192.168.100.2
HOST_LINK_GUEST_IPV4=192.168.100.1
NFT_TABLE=thrurndis
. "$1"
'''


def run_module(probe: str, *, cmdline: str, states: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/sh", "-c", SHELL_HARNESS + probe, "sh", str(MODULE)],
        check=False,
        text=True,
        capture_output=True,
        env={**os.environ, "MOCK_CMDLINE": cmdline, "MOCK_CT_STATES": states},
    )


class PortForwardingTests(unittest.TestCase):
    def test_module_is_packaged_and_wired_into_the_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owners: dict[str, str] = {}
            build_assets.install_project_files(root, owners)
            installed = root / "usr/local/libexec/thrurndis/port-forwarding"

            self.assertEqual(installed.read_bytes(), MODULE.read_bytes())
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o644)
            self.assertEqual(owners[str(installed.relative_to(root))], "project")

        gateway = (ROOT / "script/initramfs/eth0-usb0-gateway").read_text()
        self.assertIn('. "$PORT_FORWARDING_MODULE"', gateway)
        for code in ("invalid-state", "nft-unavailable", "nft-install", "rule-status"):
            self.assertIn(f"thrurndis_pf_announce_error_state {code}", gateway)

    def test_boot_argument_parser_rejects_malformed_duplicates(self) -> None:
        probe = r'''
if thrurndis_pf_load_configuration; then result=ok; else result=error; fi
printf '%s\t%s\t%s\t%s\n' "$result" "$THRURNDIS_PF_ENABLED" \
    "$THRURNDIS_PF_EXTERNAL_PORT" "$THRURNDIS_PF_MAC_PORT"
'''

        cases = {
            "console=hvc0": "ok\t0",
            "thrurndis.tcp_port_forward=8080:3000": "ok\t0",
            "thrurndis.port_forward": "error\t0",
            "thrurndis.port_forward thrurndis.port_forward=8080:3000": "error\t0",
            "thrurndis.port_forward=8080:3000": "ok\t1\t8080\t3000",
        }
        for command_line, expected in cases.items():
            with self.subTest(command_line=command_line):
                self.assertEqual(
                    run_module(probe, cmdline=command_line).stdout.strip(),
                    expected,
                )

    def test_rule_fragments_always_include_tcp_and_udp(self) -> None:
        probe = r'''
thrurndis_pf_prepare_nft_rules || exit 1
printf '%s\n%s\n%s\n' "$THRURNDIS_PF_PREROUTING_RULES" \
    "$THRURNDIS_PF_FORWARD_RULES" "$THRURNDIS_PF_POSTROUTING_RULES"
'''
        result = run_module(
            probe,
            cmdline="thrurndis.port_forward=8080:3000",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for protocol in ("tcp", "udp"):
            self.assertIn(f"{protocol} dport 8080", result.stdout)
            self.assertGreaterEqual(result.stdout.count(f"{protocol} dport 3000"), 2)

    def test_rule_status_fails_when_udp_rules_are_missing(self) -> None:
        probe = r'''
thrurndis_pf_prepare_nft_rules || exit 1
nft() {
    case "$5" in
        prerouting) printf '%s\n' "$THRURNDIS_PF_PREROUTING_RULES" ;;
        forward) printf '%s\n' "$THRURNDIS_PF_FORWARD_RULES" ;;
        postrouting) printf '%s\n' "$THRURNDIS_PF_POSTROUTING_RULES" ;;
    esac | "$BB" grep -v "udp dport"
}
thrurndis_pf_rules_ready
'''
        result = run_module(
            probe,
            cmdline="thrurndis.port_forward=8080:3000",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing udp", result.stdout)

    def test_rule_status_requires_exact_connection_states(self) -> None:
        probe = r'''
thrurndis_pf_prepare_nft_rules || exit 1
nft() {
    case "${5:-}" in
        prerouting) printf '%s\n' "$THRURNDIS_PF_PREROUTING_RULES" ;;
        forward) printf '%s\n' "$THRURNDIS_PF_FORWARD_RULES" |
            "$BB" sed "s/ct state new,established/ct state $MOCK_CT_STATES/" ;;
        postrouting) printf '%s\n' "$THRURNDIS_PF_POSTROUTING_RULES" ;;
    esac
}
thrurndis_pf_rules_ready
'''
        command_line = "thrurndis.port_forward=8080:3000"
        cases = {
            "established": False,
            "new,established,related": False,
            "new,established": True,
            "established,new": True,
        }
        for states, expected in cases.items():
            with self.subTest(states=states):
                result = run_module(probe, cmdline=command_line, states=states)
                self.assertEqual(result.returncode == 0, expected, result.stdout)
