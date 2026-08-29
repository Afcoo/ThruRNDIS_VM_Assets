# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "script/initramfs/eth0-usb0-gateway"


def gateway_dns_functions() -> str:
    source = GATEWAY.read_text()
    return source[
        source.index("interface_ipv4_cidr() {"):
        source.index("configure_rndis_ipv4() {")
    ]


SHELL_HARNESS = r'''
bb() {
    if [ "$1" = cat ] && [ "$2" = /sys/class/net/usb0/carrier ]; then
        [ "$MOCK_RNDIS_CARRIER_OK" = 1 ] || return 1
        printf '%s\n' "$MOCK_RNDIS_CARRIER"
        return 0
    fi
    command "$@"
}
BB=bb
RNDIS_IFACE=usb0
RNDIS_RESOLV_CONF=$1

ip() {
    if [ "$1" = -4 ] && [ "$2" = -o ]; then
        printf '2: usb0 inet %s/24 scope global usb0\n' "$MOCK_RNDIS_SOURCE"
        return 0
    fi
    if [ "$1" = -4 ] && [ "$2" = route ] && [ "$3" = get ]; then
        case " $* " in
            *" from $MOCK_RNDIS_SOURCE oif $RNDIS_IFACE "*)
                [ "$MOCK_RNDIS_ROUTE_OK" = 1 ] || return 1
                printf '%s\n' "$MOCK_RNDIS_ROUTE"
                ;;
            *" oif "*) return 1 ;;
            *)
                [ "$MOCK_MAIN_ROUTE_OK" = 1 ] || return 1
                printf '%s\n' "$MOCK_MAIN_ROUTE"
                ;;
        esac
        return 0
    fi
    return 1
}
'''

SHELL_PROBE = r'''
if server=$(rndis_dns_server); then
    printf 'ok:%s\n' "$server"
else
    echo error
fi
'''


def run_dns_server(
    resolv_conf: str,
    *,
    main_route: str,
    rndis_route: str,
    main_route_ok: bool = True,
    rndis_route_ok: bool = True,
    rndis_carrier: str = "1",
    rndis_carrier_ok: bool = True,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        resolv_path = Path(temporary) / "resolv.conf"
        resolv_path.write_text(resolv_conf)
        return subprocess.run(
            [
                "/bin/sh",
                "-c",
                SHELL_HARNESS + gateway_dns_functions() + SHELL_PROBE,
                "sh",
                str(resolv_path),
            ],
            check=False,
            text=True,
            capture_output=True,
            env={
                **os.environ,
                "MOCK_RNDIS_SOURCE": "192.168.42.2",
                "MOCK_MAIN_ROUTE": main_route,
                "MOCK_RNDIS_ROUTE": rndis_route,
                "MOCK_MAIN_ROUTE_OK": "1" if main_route_ok else "0",
                "MOCK_RNDIS_ROUTE_OK": "1" if rndis_route_ok else "0",
                "MOCK_RNDIS_CARRIER": rndis_carrier,
                "MOCK_RNDIS_CARRIER_OK": "1" if rndis_carrier_ok else "0",
            },
        )


class GatewayDnsTests(unittest.TestCase):
    def test_rejects_non_unicast_and_noncanonical_servers(self) -> None:
        servers = (
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.255.254",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "01.2.3.4",
            "127.1",
            "localhost",
            "::1",
            "192.168.42.1/24",
            r"\06192.168.42.1",
        )
        for server in servers:
            with self.subTest(server=server):
                result = run_dns_server(
                    f"nameserver {server}\n",
                    main_route=f"{server} dev usb0 src 192.168.42.2",
                    rndis_route=f"{server} dev usb0 src 192.168.42.2",
                )
                self.assertEqual(result.stdout.strip(), "error", result.stderr)

    def test_rejects_local_broadcast_and_non_rndis_routes(self) -> None:
        cases = (
            (
                "192.168.42.2",
                "local 192.168.42.2 dev lo src 192.168.42.2",
                "192.168.42.2 dev usb0 src 192.168.42.2",
            ),
            (
                "192.168.42.255",
                "broadcast 192.168.42.255 dev usb0 src 192.168.42.2",
                "192.168.42.255 dev usb0 src 192.168.42.2",
            ),
            (
                "192.168.42.53",
                "192.168.42.53 via 192.168.64.1 dev eth0",
                "192.168.42.53 via 192.168.64.1 dev eth0",
            ),
        )
        for server, main_route, rndis_route in cases:
            with self.subTest(server=server):
                result = run_dns_server(
                    f"nameserver {server}\n",
                    main_route=main_route,
                    rndis_route=rndis_route,
                )
                self.assertEqual(result.stdout.strip(), "error", result.stderr)

        result = run_dns_server(
            "nameserver 192.168.42.53\n",
            main_route="192.168.42.53 via 192.168.64.1 dev eth0",
            rndis_route="",
            rndis_route_ok=False,
        )
        self.assertEqual(result.stdout.strip(), "error", result.stderr)

    def test_rejects_carrier_down_and_linkdown_routes(self) -> None:
        server = "192.168.42.1"
        route = f"{server} dev usb0 src 192.168.42.2"
        carrier_down = run_dns_server(
            f"nameserver {server}\n",
            main_route=route,
            rndis_route=route,
            rndis_carrier="0",
        )
        self.assertEqual(carrier_down.stdout.strip(), "error", carrier_down.stderr)

        linkdown_route = f"{route} linkdown"
        linkdown = run_dns_server(
            f"nameserver {server}\n",
            main_route=linkdown_route,
            rndis_route=linkdown_route,
        )
        self.assertEqual(linkdown.stdout.strip(), "error", linkdown.stderr)

    def test_selects_first_usable_server_through_rndis(self) -> None:
        server = "192.168.42.1"
        result = run_dns_server(
            f"nameserver 0.0.0.0\nnameserver {server}\nnameserver 100.64.0.53\n",
            main_route=f"{server} via 192.168.64.1 dev eth0",
            rndis_route=f"{server} dev usb0 src 192.168.42.2",
        )
        self.assertEqual(result.stdout.strip(), f"ok:{server}", result.stderr)

    def test_preserves_unicast_servers_reachable_on_rndis(self) -> None:
        cases = (
            (
                "100.64.0.53",
                "100.64.0.53 via 192.168.64.1 dev eth0",
                "100.64.0.53 via 192.168.42.1 dev usb0 src 192.168.42.2",
            ),
            (
                "169.254.10.1",
                "169.254.10.1 dev usb0 scope link src 192.168.42.2",
                "169.254.10.1 dev usb0 scope link src 192.168.42.2",
            ),
        )
        for server, main_route, rndis_route in cases:
            with self.subTest(server=server):
                result = run_dns_server(
                    f"nameserver {server}\n",
                    main_route=main_route,
                    rndis_route=rndis_route,
                )
                self.assertEqual(result.stdout.strip(), f"ok:{server}", result.stderr)


if __name__ == "__main__":
    unittest.main()
