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


def run_module(
    probe: str,
    *,
    cmdline: str,
    states: str = "",
    rule_mutation: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/sh", "-c", SHELL_HARNESS + probe, "sh", str(MODULE)],
        check=False,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "MOCK_CMDLINE": cmdline,
            "MOCK_CT_STATES": states,
            "MOCK_RULE_MUTATION": rule_mutation,
        },
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
        self.assertIn("$THRURNDIS_PF_SET_DEFINITION", gateway)
        for code in (
            "invalid-state",
            "nft-unavailable",
            "nft-install",
            "rule-status",
            "mdns-unready",
        ):
            self.assertIn(
                f"thrurndis_pf_announce_error_state {code}",
                gateway,
            )

        prerouting = gateway[
            gateway.index("chain prerouting {"):gateway.index("chain forward {")
        ]
        self.assertLess(
            prerouting.index(
                'iifname "$RNDIS_IFACE" ip daddr 224.0.0.251 udp dport 5353 return'
            ),
            prerouting.index("$THRURNDIS_PF_PREROUTING_RULES"),
        )

    def test_boot_argument_parser_requires_canonical_port_set(self) -> None:
        probe = r'''
if thrurndis_pf_load_configuration; then result=ok; else result=error; fi
printf '%s\t%s\t%s\t%s\n' "$result" "$THRURNDIS_PF_ENABLED" \
    "$THRURNDIS_PF_PORTS" "$THRURNDIS_PF_NFT_ELEMENTS"
'''

        cases = {
            "console=hvc0": "ok\t0",
            "thrurndis.tcp_port_forward=8080": "ok\t0",
            "thrurndis.port_forward": "error\t0",
            "thrurndis.port_forward thrurndis.port_forward=8080": "error\t0",
            "thrurndis.port_forward=5050,6550-6557":
                "ok\t1\t5050,6550-6557\t5050, 6550-6557",
            "thrurndis.port_forward=6550-6557,5050": "error\t0",
            "thrurndis.port_forward=5050,5051": "error\t0",
            "thrurndis.port_forward=5050-5050": "error\t0",
            "thrurndis.port_forward=05050": "error\t0",
            "thrurndis.port_forward=6557-6550": "error\t0",
            "thrurndis.port_forward=5050,,6550": "error\t0",
        }
        for command_line, expected in cases.items():
            with self.subTest(command_line=command_line):
                self.assertEqual(
                    run_module(probe, cmdline=command_line).stdout.strip(),
                    expected,
                )

    def test_rule_fragments_share_one_tcp_udp_interval_set(self) -> None:
        probe = r'''
thrurndis_pf_prepare_nft_rules || exit 1
printf '%s\n%s\n%s\n%s\n' "$THRURNDIS_PF_SET_DEFINITION" \
    "$THRURNDIS_PF_PREROUTING_RULES" "$THRURNDIS_PF_FORWARD_RULES" \
    "$THRURNDIS_PF_POSTROUTING_RULES"
'''
        result = run_module(
            probe,
            cmdline="thrurndis.port_forward=5050,6550-6557",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("type inet_service", result.stdout)
        self.assertIn("flags interval", result.stdout)
        self.assertIn("elements = { 5050, 6550-6557 }", result.stdout)
        for protocol in ("tcp", "udp"):
            self.assertGreaterEqual(
                result.stdout.count(
                    f"{protocol} dport @thrurndis_forwarded_ports"
                ),
                3,
            )
        self.assertNotIn("dnat to 192.168.100.2:", result.stdout)

    def test_rule_status_fails_when_udp_rules_are_missing(self) -> None:
        probe = r'''
thrurndis_pf_prepare_nft_rules || exit 1
nft() {
    case "$2" in
        set) printf '%s\n' "$THRURNDIS_PF_SET_DEFINITION" ;;
        chain)
            case "$5" in
                prerouting) printf '%s\n' "$THRURNDIS_PF_PREROUTING_RULES" ;;
                forward) printf '%s\n' "$THRURNDIS_PF_FORWARD_RULES" ;;
                postrouting) printf '%s\n' "$THRURNDIS_PF_POSTROUTING_RULES" ;;
            esac | "$BB" grep -v "udp dport"
            ;;
    esac
}
thrurndis_pf_rules_ready
'''
        result = run_module(
            probe,
            cmdline="thrurndis.port_forward=5050,6550-6557",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing udp", result.stdout)

    def test_inactive_rule_status_rejects_direct_forwarding_rules(self) -> None:
        probe = r'''
nft() {
    case "$2" in
        set) return 1 ;;
        chain)
            case "$MOCK_RULE_MUTATION:$5" in
                prerouting:prerouting)
                    printf '%s\n' 'iifname "usb0" tcp dport 8080 counter dnat to 192.168.100.2'
                    ;;
                forward:forward)
                    printf '%s\n' 'iifname "usb0" oifname "eth0" ip daddr 192.168.100.2 tcp dport 8080 ct state new,established counter accept'
                    ;;
                postrouting:postrouting)
                    printf '%s\n' 'iifname "usb0" oifname "eth0" ip daddr 192.168.100.2 tcp dport 8080 counter snat to 192.168.100.1'
                    ;;
            esac
            ;;
    esac
}
thrurndis_pf_rules_ready
'''
        expected_errors = {
            "prerouting": "unexpected port forwarding DNAT rule",
            "forward": "unexpected port forwarding allow rule",
            "postrouting": "unexpected port forwarding SNAT rule",
        }
        for rule_mutation, expected_error in expected_errors.items():
            with self.subTest(rule_mutation=rule_mutation):
                result = run_module(
                    probe,
                    cmdline="console=hvc0",
                    rule_mutation=rule_mutation,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stdout)

    def test_rule_status_rejects_wrong_rule_targets(self) -> None:
        probe = r'''
thrurndis_pf_prepare_nft_rules || exit 1
nft() {
    case "$2" in
        set) printf '%s\n' "$THRURNDIS_PF_SET_DEFINITION" ;;
        chain)
            case "$5" in
                prerouting)
                    case "$MOCK_RULE_MUTATION" in
                        prerouting-address)
                            printf '%s\n' "$THRURNDIS_PF_PREROUTING_RULES" |
                                "$BB" sed 's/192\.168\.100\.2/192.168.100.20/g'
                            ;;
                        prerouting-port)
                            printf '%s\n' "$THRURNDIS_PF_PREROUTING_RULES" |
                                "$BB" sed 's/dnat to 192\.168\.100\.2/dnat to 192.168.100.2:5050/g'
                            ;;
                        *) printf '%s\n' "$THRURNDIS_PF_PREROUTING_RULES" ;;
                    esac
                    ;;
                forward)
                    if [ "$MOCK_RULE_MUTATION" = forward-address ]; then
                        printf '%s\n' "$THRURNDIS_PF_FORWARD_RULES" |
                            "$BB" sed 's/192\.168\.100\.2/192.168.100.20/g'
                    else
                        printf '%s\n' "$THRURNDIS_PF_FORWARD_RULES"
                    fi
                    ;;
                postrouting)
                    if [ "$MOCK_RULE_MUTATION" = postrouting-address ]; then
                        printf '%s\n' "$THRURNDIS_PF_POSTROUTING_RULES" |
                            "$BB" sed 's/192\.168\.100\.1/192.168.100.10/g'
                    else
                        printf '%s\n' "$THRURNDIS_PF_POSTROUTING_RULES"
                    fi
                    ;;
            esac
            ;;
    esac
}
thrurndis_pf_rules_ready
'''
        expected_errors = {
            "prerouting-address": "without port translation",
            "prerouting-port": "without port translation",
            "forward-address": "missing tcp forward allow",
            "postrouting-address": "missing tcp SNAT",
        }
        for rule_mutation, expected_error in expected_errors.items():
            with self.subTest(rule_mutation=rule_mutation):
                result = run_module(
                    probe,
                    cmdline="thrurndis.port_forward=5050,6550-6557",
                    rule_mutation=rule_mutation,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(expected_error, result.stdout)

    def test_rule_status_requires_exact_connection_states(self) -> None:
        probe = r'''
thrurndis_pf_prepare_nft_rules || exit 1
nft() {
    case "$2" in
        set) printf '%s\n' "$THRURNDIS_PF_SET_DEFINITION" ;;
        chain)
            case "${5:-}" in
                prerouting) printf '%s\n' "$THRURNDIS_PF_PREROUTING_RULES" ;;
                forward) printf '%s\n' "$THRURNDIS_PF_FORWARD_RULES" |
                    "$BB" sed "s/ct state new,established/ct state $MOCK_CT_STATES/g" ;;
                postrouting) printf '%s\n' "$THRURNDIS_PF_POSTROUTING_RULES" ;;
            esac
            ;;
    esac
}
thrurndis_pf_rules_ready
'''
        command_line = "thrurndis.port_forward=5050,6550-6557"
        cases = {
            "established": False,
            "new,established,related": False,
            "new,established": True,
            "established,new": True,
        }
        for states, expected in cases.items():
            with self.subTest(states=states):
                result = run_module(
                    probe,
                    cmdline=command_line,
                    states=states,
                )
                self.assertEqual(result.returncode == 0, expected, result.stdout)
