# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "script/initramfs/mdns-advertising"
CONFIG = ROOT / "script/avahi-daemon.conf"
SERVICE = ROOT / "script/thrurndis.service"
INIT_MDNS = ROOT / "script/initramfs/init-mdns"
GATEWAY = ROOT / "script/initramfs/eth0-usb0-gateway"
sys.path.insert(0, str(ROOT / "script/lib"))
sys.path.insert(0, str(ROOT / "compliance"))

import build_assets  # noqa: E402
from common import CpioEntry, ComplianceError, read_newc  # noqa: E402
from verify_compliance import verify_mdns_payload  # noqa: E402


SHELL_HARNESS = r'''
bb() {
    if [ "$1" = sha256sum ] && ! command -v sha256sum >/dev/null 2>&1; then
        shift
        shasum -a 256 "$@"
    else
        command "$@"
    fi
}
BB=bb
RNDIS_IFACE=usb0
log_console() { printf 'log:%s\n' "$*" >&2; }
interface_ipv4_address() { printf '%s' "$MOCK_RNDIS_IPV4"; }
. "$1"
'''


FAKE_AVAHI = r'''#!/bin/sh
set -eu
printf '%s\n' "$1" >>"$MOCK_AVAHI_CALLS"
case "$1" in
    --check)
        test -s "$THRURNDIS_MDNS_PID_FILE"
        ;;
    *) exit 2 ;;
esac
'''


def run_module(
    probe: str,
    *,
    interface_ipv4: str = "192.168.42.2",
    title: str = "avahi-daemon: running [thrurndis.local]",
    membership: bool = True,
    uid: int = 86,
    ppid: int = 1,
) -> tuple[subprocess.CompletedProcess[str], Path, tempfile.TemporaryDirectory[str]]:
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    daemon = root / "avahi-daemon"
    daemon.write_text(FAKE_AVAHI)
    daemon.chmod(0o755)
    runtime = root / "run"
    proc = root / "proc"
    calls = root / "calls"
    service = root / "thrurndis.service"
    service.write_bytes(SERVICE.read_bytes())
    service_hash = root / "mdns-service.sha256"
    service_hash.write_text(hashlib.sha256(service.read_bytes()).hexdigest() + "\n")
    pid = "4242"
    pid_dir = proc / pid
    (runtime / "avahi-daemon").mkdir(parents=True)
    (pid_dir / "net").mkdir(parents=True)
    (runtime / "avahi-daemon/pid").write_text(f"{pid}\n")
    (pid_dir / "exe").symlink_to(daemon)
    (pid_dir / "cmdline").write_bytes(title.encode() + b"\0")
    (pid_dir / "status").write_text(
        "Name:\tavahi-daemon\n"
        f"PPid:\t{ppid}\n"
        f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        "Gid:\t86\t86\t86\t86\n"
    )
    group = "FB0000E0" if membership else "010000E0"
    (pid_dir / "net/igmp").write_text(
        "Idx Device    : Count Querier\n"
        "2 usb0       :     1      V3\n"
        f"                {group}     1 0:00000000 0\n"
    )
    result = subprocess.run(
        ["/bin/sh", "-c", SHELL_HARNESS + probe, "sh", str(MODULE)],
        check=False,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "MOCK_RNDIS_IPV4": interface_ipv4,
            "MOCK_AVAHI_CALLS": str(calls),
            "THRURNDIS_MDNS_AVAHI_DAEMON": str(daemon),
            "THRURNDIS_MDNS_CONFIG": str(CONFIG),
            "THRURNDIS_MDNS_SERVICE_FILE": str(service),
            "THRURNDIS_MDNS_SERVICE_HASH": str(service_hash),
            "THRURNDIS_MDNS_PID_FILE": str(runtime / "avahi-daemon/pid"),
            "THRURNDIS_MDNS_PROC_ROOT": str(proc),
            "THRURNDIS_MDNS_READY_ATTEMPTS": "1",
            "THRURNDIS_MDNS_READY_INTERVAL_SECONDS": "0",
        },
    )
    return result, root, temporary


class MdnsAdvertisingTests(unittest.TestCase):
    def test_current_lock_contains_avahi_root(self) -> None:
        lock = json.loads((ROOT / "config/packages.lock.json").read_text())
        env = build_assets.read_env(ROOT / "config/alpine.env")
        build_assets.validate_lock(env, lock)

        self.assertIn("avahi", lock["rootPackages"])
        packages = {package["name"]: package for package in lock["packages"]}
        self.assertIn("avahi", packages)
        self.assertEqual(packages["avahi"]["role"], "runtime")
        self.assertEqual(packages["avahi"]["origin"], "avahi")

    def test_module_config_and_avahi_identity_are_packaged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            example_services = root / "etc/avahi/services"
            example_services.mkdir(parents=True)
            (example_services / "ssh.service").write_text("must be removed")
            (root / "var/run").mkdir(parents=True)
            owners: dict[str, str] = {}

            build_assets.install_project_files(root, owners)

            installed_module = root / "usr/local/libexec/thrurndis/mdns-advertising"
            installed_init = root / "usr/local/sbin/init-mdns"
            installed_config = root / "etc/avahi/avahi-daemon.conf"
            installed_service = example_services / "thrurndis.service"
            installed_hash = root / "usr/local/libexec/thrurndis/mdns-service.sha256"
            self.assertEqual(installed_module.read_bytes(), MODULE.read_bytes())
            self.assertEqual(stat.S_IMODE(installed_module.stat().st_mode), 0o644)
            self.assertEqual(installed_init.read_bytes(), INIT_MDNS.read_bytes())
            self.assertEqual(stat.S_IMODE(installed_init.stat().st_mode), 0o755)
            self.assertEqual(installed_config.read_bytes(), CONFIG.read_bytes())
            self.assertEqual(list(example_services.iterdir()), [installed_service])
            self.assertEqual(installed_service.read_bytes(), SERVICE.read_bytes())
            self.assertEqual(stat.S_IMODE(installed_service.stat().st_mode), 0o644)
            self.assertEqual(
                installed_hash.read_text().strip(),
                hashlib.sha256(installed_service.read_bytes()).hexdigest(),
            )
            self.assertEqual((root / "var/run").readlink(), Path("/run"))
            self.assertIn(
                "avahi:x:86:86:Avahi System User:/dev/null:/sbin/nologin",
                (root / "etc/passwd").read_text(),
            )
            self.assertIn("avahi:x:86:", (root / "etc/group").read_text())
            for installed in (
                installed_module, installed_init, installed_config,
                installed_service, installed_hash,
            ):
                self.assertEqual(
                    owners[str(installed.relative_to(root))],
                    "project",
                )

        builder = (ROOT / "script/lib/build_assets.py").read_text()
        self.assertIn('"usr/sbin/avahi-daemon"', builder)

        inittab = build_assets.write_inittab
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owners: dict[str, str] = {}
            inittab(root, owners)
            text = (root / "etc/inittab").read_text()
        mdns_action = "::respawn:/usr/local/sbin/init-mdns"
        watcher_action = "::respawn:/usr/local/sbin/usb0-watcher"
        self.assertIn(mdns_action, text)
        self.assertLess(text.index(mdns_action), text.index(watcher_action))

        init_text = INIT_MDNS.read_text()
        self.assertEqual(stat.S_IMODE(INIT_MDNS.stat().st_mode), 0o755)
        self.assertIn('exec "$AVAHI_DAEMON" --file="$AVAHI_CONFIG"', init_text)
        self.assertNotIn("--daemonize", init_text)
        self.assertNotIn(" &", init_text)

    def test_service_has_complete_ipv4_discovery_records(self) -> None:
        group = ET.fromstring(SERVICE.read_bytes())
        self.assertEqual(group.tag, "service-group")
        self.assertEqual([child.tag for child in group], ["name", "service"])
        self.assertEqual(group.findtext("name"), "ThruRNDIS")
        service = group.find("service")
        self.assertEqual(service.attrib, {"protocol": "ipv4"})
        self.assertEqual(service.findtext("type"), "_thrurndis._tcp")
        self.assertEqual(service.findtext("domain-name"), "local")
        self.assertEqual(service.findtext("host-name"), "thrurndis.local")
        self.assertEqual(service.findtext("port"), "0")
        self.assertEqual(
            [element.text for element in service.findall("txt-record")],
            ["txtvers=1", "hostname=thrurndis.local", "discovery-only=1"],
        )

    def test_final_initramfs_enforces_service_allowlist_and_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            build_assets.install_project_files(root, {})
            archive = Path(temporary) / "initramfs.gz"
            build_assets.write_initramfs(root, archive)
            entries = read_newc(archive)
        verify_mdns_payload(entries, ROOT)
        service_path = "etc/avahi/services/thrurndis.service"
        for mutation in (
            [entry for entry in entries if entry.path != service_path],
            entries + [CpioEntry("etc/avahi/services/ssh.service", stat.S_IFREG | 0o644, b"example")],
            [CpioEntry(entry.path, entry.mode, b"modified")
             if entry.path == service_path else entry for entry in entries],
            [CpioEntry(entry.path, stat.S_IFLNK | 0o777, b"/other.service")
             if entry.path == service_path else entry for entry in entries],
            [CpioEntry(entry.path, entry.mode, b"0" * 64 + b"\n")
             if entry.path.endswith("mdns-service.sha256") else entry for entry in entries],
            [CpioEntry(entry.path, entry.mode, entry.data.replace(b"allow-interfaces=usb0", b"allow-interfaces=eth0"))
             if entry.path.endswith("avahi-daemon.conf") else entry for entry in entries],
        ):
            with self.subTest(mutation=mutation[-1].path), self.assertRaises(ComplianceError):
                verify_mdns_payload(mutation, ROOT)

    def test_missing_or_modified_service_fails_closed(self) -> None:
        for mutation in (
            'rm "$THRURNDIS_MDNS_SERVICE_FILE"',
            'printf "<invalid/>\\n" >"$THRURNDIS_MDNS_SERVICE_FILE"',
            'rm "$THRURNDIS_MDNS_SERVICE_HASH"',
            'printf "invalid\\n" >"$THRURNDIS_MDNS_SERVICE_HASH"',
        ):
            with self.subTest(mutation=mutation):
                result, _root, temporary = run_module(
                    mutation + '\nif thrurndis_mdns_status 192.168.42.2; then exit 10; fi\n'
                )
                try:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("DNS-SD service is missing or differs", result.stdout)
                finally:
                    temporary.cleanup()

    def test_configuration_publishes_only_usb0_ipv4(self) -> None:
        text = CONFIG.read_text()
        for line in (
            "host-name=thrurndis",
            "domain-name=local",
            "use-ipv4=yes",
            "use-ipv6=no",
            "allow-interfaces=usb0",
            "use-iff-running=no",
            "enable-dbus=no",
            "publish-addresses=yes",
            "publish-workstation=no",
            "publish-resolv-conf-dns-servers=no",
            "enable-reflector=no",
        ):
            self.assertIn(f"{line}\n", text)

    def test_forwarding_gateway_checks_init_supervised_exact_name(self) -> None:
        probe = r'''
THRURNDIS_PF_ENABLED=1
thrurndis_mdns_status 192.168.42.2 || exit 10
thrurndis_mdns_wait_ready 192.168.42.2 || exit 11
printf 'ok\n'
'''
        result, root, temporary = run_module(probe)
        try:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "ok")
            calls = (root / "calls").read_text().splitlines()
            self.assertEqual(calls, ["--check", "--check"])
        finally:
            temporary.cleanup()

    def test_inactive_forwarding_still_advertises(self) -> None:
        self.assertNotIn("THRURNDIS_PF_ENABLED", MODULE.read_text())
        probe = r'''
THRURNDIS_PF_ENABLED=0
thrurndis_mdns_status 192.168.42.2 || exit 10
thrurndis_mdns_wait_ready 192.168.42.2 || exit 11
printf 'ok\n'
'''
        result, root, temporary = run_module(probe)
        try:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "ok")
            calls = (root / "calls").read_text().splitlines()
            self.assertEqual(calls, ["--check", "--check"])
        finally:
            temporary.cleanup()

    def test_name_collision_fails_closed(self) -> None:
        probe = r'''
if thrurndis_mdns_status 192.168.42.2; then exit 10; fi
printf 'rejected\n'
'''
        result, _root, temporary = run_module(
            probe,
            title="avahi-daemon: running [thrurndis-2.local]",
        )
        try:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("has not claimed the exact host name", result.stdout)
            self.assertEqual(result.stdout.splitlines()[-1], "rejected")
        finally:
            temporary.cleanup()

    def test_missing_usb0_multicast_membership_fails_closed(self) -> None:
        probe = r'''
if thrurndis_mdns_status 192.168.42.2; then exit 10; fi
printf 'membership-rejected\n'
'''
        result, _root, temporary = run_module(probe, membership=False)
        try:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("has not joined 224.0.0.251", result.stdout)
            self.assertEqual(result.stdout.splitlines()[-1], "membership-rejected")
        finally:
            temporary.cleanup()

    def test_privileged_avahi_process_fails_closed(self) -> None:
        probe = r'''
if thrurndis_mdns_status 192.168.42.2; then exit 10; fi
printf 'privileged-rejected\n'
'''
        result, _root, temporary = run_module(probe, uid=0)
        try:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("is not an init-supervised UID/GID 86 process", result.stdout)
            self.assertEqual(result.stdout.splitlines()[-1], "privileged-rejected")
        finally:
            temporary.cleanup()

    def test_non_init_parent_fails_closed(self) -> None:
        probe = r'''
if thrurndis_mdns_status 192.168.42.2; then exit 10; fi
printf 'parent-rejected\n'
'''
        result, _root, temporary = run_module(probe, ppid=99)
        try:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("is not an init-supervised UID/GID 86 process", result.stdout)
            self.assertEqual(result.stdout.splitlines()[-1], "parent-rejected")
        finally:
            temporary.cleanup()

    def test_changed_usb0_address_invalidates_advertisement(self) -> None:
        probe = r'''
MOCK_RNDIS_IPV4=192.168.42.9
if thrurndis_mdns_status 192.168.42.2; then exit 10; fi
printf 'stale-rejected\n'
'''
        result, _root, temporary = run_module(probe)
        try:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "usb0 IPv4 changed while advertising thrurndis.local",
                result.stdout,
            )
            self.assertEqual(result.stdout.splitlines()[-1], "stale-rejected")
        finally:
            temporary.cleanup()

    def test_gateway_only_waits_for_init_supervised_avahi(self) -> None:
        gateway = GATEWAY.read_text()
        self.assertIn('. "$MDNS_ADVERTISING_MODULE"', gateway)
        clear = gateway[gateway.index("clear_gateway_state() {"):gateway.index("gateway_up() {")]
        up = gateway[gateway.index("gateway_up() {"):gateway.index("gateway_down() {")]
        status = gateway[gateway.index("gateway_status() {"):gateway.index('case "${1:-up}"')]
        self.assertNotIn("thrurndis_mdns", clear)
        self.assertLess(
            up.index('thrurndis_mdns_wait_ready "$rndis_ipv4"'),
            up.index("if ! gateway_status"),
        )
        self.assertLess(
            up.index('thrurndis_mdns_wait_ready "$rndis_ipv4"'),
            up.index("announce_route_ready 1"),
        )
        self.assertIn('thrurndis_mdns_status "$ipv4"', status)

        module = MODULE.read_text()
        for mutation in ("--daemonize", "--kill", "kill -9", "thrurndis_mdns_start", "thrurndis_mdns_stop"):
            self.assertNotIn(mutation, module)


if __name__ == "__main__":
    unittest.main()
