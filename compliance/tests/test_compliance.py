# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from types import SimpleNamespace

COMPLIANCE_DIR = Path(__file__).resolve().parents[1]
ROOT = COMPLIANCE_DIR.parent
sys.path.insert(0, str(COMPLIANCE_DIR))

import build_compliance  # noqa: E402
import verify_compliance  # noqa: E402
from common import (  # noqa: E402
    CpioEntry,
    ComplianceError,
    check_initramfs_content,
    load_policy,
    load_vm_asset_config,
    normalize_license,
    sha256_file,
    write_json,
)
from source_bundle import (  # noqa: E402
    ensure_commits,
    extract_licenses_from_tar,
    recipe_checksums,
    source_inventory,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_newc(entries: dict[str, tuple[int, bytes]]) -> bytes:
    result = bytearray()
    inode = 1

    def pad() -> None:
        result.extend(b"\0" * ((-len(result)) % 4))

    def add(name: str, mode: int, data: bytes) -> None:
        nonlocal inode
        encoded = name.encode()
        fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded) + 1, 0)
        inode += 1
        result.extend(("070701" + "".join(f"{value:08x}" for value in fields)).encode())
        result.extend(encoded + b"\0")
        pad()
        result.extend(data)
        pad()

    for name, (mode, data) in entries.items():
        add(name, mode, data)
    add("TRAILER!!!", 0, b"")
    return gzip.compress(bytes(result), compresslevel=9, mtime=0)


class ComplianceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_path = ROOT / "compliance/license-policy.toml"

    def test_current_lock_uses_only_reviewed_spdx_expressions(self) -> None:
        lock = json.loads((ROOT / "config/packages.lock.json").read_text())
        policy = load_policy(self.policy_path)
        for package in lock["packages"]:
            normalize_license(package["license"], policy)

    def test_current_asset_version_is_positive(self) -> None:
        config = load_vm_asset_config(ROOT / "config/vm-assets.json")
        self.assertEqual(config["assetVersion"], 1)

    def test_asset_version_rejects_non_positive_integers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "vm-assets.json"
            for value in (None, True, 0, -1, "1"):
                path.write_text(json.dumps({"schemaVersion": 1, "assetVersion": value}))
                with self.subTest(value=value), self.assertRaisesRegex(
                    ComplianceError, "assetVersion must be a positive integer"
                ):
                    load_vm_asset_config(path)

    def test_current_inputs_exclude_legacy_wireguard_payloads(self) -> None:
        lock = json.loads((ROOT / "config/packages.lock.json").read_text())
        names = {package["name"] for package in lock["packages"]}
        self.assertFalse(any(name.startswith("wireguard") for name in names))
        self.assertNotIn("wireguard-tools-wg-quick", lock["rootPackages"])

        alpine_env = (ROOT / "config/alpine.env").read_text().lower()
        self.assertNotIn("wireguard", alpine_env)
        self.assertNotIn("virtiofs", alpine_env)

        scripts = ROOT / "script/initramfs"
        self.assertFalse((scripts / "init-virtiofs-wgconf").exists())
        self.assertFalse((scripts / "wg0-usb0-gateway").exists())

    def test_guest_vznat_and_fixed_host_link_contract(self) -> None:
        scripts = ROOT / "script/initramfs"
        init_network = (scripts / "init-network").read_text()
        gateway = (scripts / "eth0-usb0-gateway").read_text()
        for marker in (
            "THRURNDIS_VZNAT_IPV4=",
            "THRURNDIS_VZNAT_CIDR=",
            "THRURNDIS_VZNAT_GATEWAY=",
        ):
            self.assertIn(marker, init_network)
        self.assertIn("HOST_LINK_GUEST_CIDR=192.168.100.1/24", init_network)
        self.assertIn(
            'ip -4 address replace "$HOST_LINK_GUEST_CIDR" dev "$iface"',
            init_network,
        )

        self.assertIn("HOST_LINK_GUEST_IPV4=192.168.100.1", gateway)
        self.assertIn("HOST_LINK_GUEST_CIDR=192.168.100.1/24", gateway)
        self.assertIn("HOST_LINK_HOST_IPV4=192.168.100.2", gateway)
        self.assertIn("HOST_LINK_HOST_CIDR=192.168.100.2/32", gateway)
        self.assertIn('THRURNDIS_RNDIS_IPV4=${1:-}', gateway)
        self.assertIn('THRURNDIS_RNDIS_ROUTE_READY=$1', gateway)
        gateway_up = gateway[gateway.index("gateway_up() {"):gateway.index("gateway_down() {")]
        gateway_down = gateway[gateway.index("gateway_down() {"):gateway.index("gateway_status() {")]
        self.assertLess(
            gateway_up.index("announce_route_ready 0"),
            gateway_up.index('announce_rndis_ipv4 ""'),
        )
        self.assertLess(
            gateway_up.index("if ! gateway_status"),
            gateway_up.index('announce_rndis_ipv4 "$rndis_ipv4"'),
        )
        self.assertLess(
            gateway_up.index('announce_rndis_ipv4 "$rndis_ipv4"'),
            gateway_up.index("announce_route_ready 1"),
        )
        self.assertLess(
            gateway_down.index("announce_route_ready 0"),
            gateway_down.index('announce_rndis_ipv4 ""'),
        )
        self.assertIn('from "$HOST_LINK_HOST_CIDR"', gateway)
        self.assertIn('iif "$INGRESS_IFACE" table "$TABLE_ID"', gateway)
        self.assertIn('ip saddr $HOST_LINK_HOST_CIDR', gateway)
        self.assertIn('ip daddr $HOST_LINK_HOST_CIDR', gateway)
        self.assertIn('ip daddr $HOST_LINK_GUEST_IPV4', gateway)
        self.assertIn('iifname "$INGRESS_IFACE" oifname "$RNDIS_IFACE"', gateway)
        self.assertIn('udp dport 53 dnat to $rndis_dns', gateway)
        self.assertIn('tcp dport 53 dnat to $rndis_dns', gateway)
        self.assertIn('THRURNDIS_RNDIS_RESOLV_CONF', gateway)
        self.assertIn('$1 == "nameserver"', gateway)
        self.assertNotIn(
            'ingress_source=$(interface_default_gateway "$INGRESS_IFACE")',
            gateway,
        )
        self.assertNotIn("ingress_destination=", gateway)

    def test_legacy_wireguard_payload_fails_closed(self) -> None:
        entry = CpioEntry(
            "lib/modules/6.0-0-lts/kernel/drivers/net/wireguard/wireguard.ko.gz",
            stat.S_IFREG | 0o644,
            b"legacy module",
        )
        with self.assertRaisesRegex(ComplianceError, "runtime configuration leaked"):
            check_initramfs_content([entry])

    def test_unknown_license_fails_closed(self) -> None:
        with self.assertRaisesRegex(ComplianceError, "unreviewed SPDX license"):
            normalize_license("License-That-Was-Not-Reviewed", load_policy(self.policy_path))

    def test_literal_apkbuild_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            apkbuild = Path(temporary) / "APKBUILD"
            apkbuild.write_text(
                'pkgname=example\nsha512sums="\n'
                + "a" * 128
                + "  source.tar.xz\n"
                + "b" * 128
                + '  local.patch\n"\n'
            )
            algorithm, rows = recipe_checksums(apkbuild)
            self.assertEqual(algorithm, "sha512")
            self.assertEqual(rows, {"source.tar.xz": "a" * 128, "local.patch": "b" * 128})

    def test_source_inventory_records_safe_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target").write_text("target")
            (root / "link").symlink_to("target")
            rows = source_inventory(root)
            self.assertIn({"path": "link", "type": "symlink", "target": "target"}, rows)
            (root / "escape").symlink_to("../outside")
            with self.assertRaisesRegex(ComplianceError, "escapes root"):
                source_inventory(root)

    def test_license_extraction_ignores_empty_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "build").mkdir(parents=True)
            (source / "build/LICENSE").write_bytes(b"")
            (source / "LICENSE").write_text("Copyright 2026 Example\nMIT License\n")
            archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                handle.add(source, arcname="example")

            destination = root / "licenses"
            budget = [0, 0]
            self.assertTrue(
                extract_licenses_from_tar(archive, destination, ["LICENSE*"], [], budget)
            )
            self.assertFalse(
                (destination / "from-source.tar.gz/example/build/LICENSE").exists()
            )
            self.assertEqual(
                (destination / "from-source.tar.gz/example/LICENSE").read_text(),
                "Copyright 2026 Example\nMIT License\n",
            )
            self.assertEqual(budget, [35, 1])

    def test_ensure_commits_materializes_generator_once(self) -> None:
        commits = ("1" * 40, "2" * 40)
        with mock.patch(
            "source_bundle.subprocess.run", return_value=SimpleNamespace(returncode=0)
        ), mock.patch(
            "source_bundle.run_checked",
            side_effect=lambda command, **_kwargs: command[-1].removesuffix("^{commit}") + "\n",
        ) as checked:
            ensure_commits(Path("/unused"), (commit for commit in commits), offline=True)
        self.assertEqual(checked.call_count, 2)

    def test_binary_compliance_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            repo = temp / "repo"
            build = temp / "build"
            assets = build / "assets"
            provenance = build / "provenance"
            apk_dir = build / "cache/apks"
            iso_dir = build / "cache/iso"
            license_dir = build / "source-bundle/licenses"
            for path in (assets, provenance / "packages", apk_dir, iso_dir):
                path.mkdir(parents=True)

            runtime_apk = b"locked fake APK"
            modloop = b"locked fake modloop"
            iso = b"locked fake Alpine ISO"
            runtime_commit = "1" * 40
            kernel_commit = "2" * 40
            datahash = "3" * 64
            runtime = {
                "name": "busybox",
                "version": "1.0-r0",
                "file": "busybox-1.0-r0.apk",
                "repository": "https://example.invalid/v3.24/main/aarch64",
                "url": "https://example.invalid/busybox.apk",
                "sha256": sha256(runtime_apk),
                "origin": "busybox",
                "license": "GPL-2.0-only",
                "aportsCommit": runtime_commit,
                "datahash": datahash,
                "dependencies": [],
                "role": "runtime",
            }
            kernel = {
                "name": "linux-lts",
                "version": "6.0-r0",
                "file": "boot/modloop-lts",
                "repository": "https://example.invalid/alpine.iso",
                "url": "https://example.invalid/alpine.iso#boot/modloop-lts",
                "sha256": sha256(modloop),
                "origin": "linux-lts",
                "license": "GPL-2.0-only",
                "aportsCommit": kernel_commit,
                "datahash": f"sha256:{sha256(modloop)}",
                "dependencies": [],
                "role": "kernel",
            }
            lock = {
                "schemaVersion": 1,
                "alpine": {
                    "version": "3.24.1",
                    "branch": "v3.24",
                    "arch": "aarch64",
                    "flavor": "standard",
                    "isoUrl": "https://example.invalid/alpine-standard.iso",
                    "isoSha256": sha256(iso),
                },
                "packages": [runtime, kernel],
            }
            lock_path = temp / "packages.lock.json"
            lock_path.write_text(json.dumps(lock))
            (apk_dir / runtime["file"]).write_bytes(runtime_apk)
            (iso_dir / "alpine-standard.iso").write_bytes(iso)
            pkginfo_path = provenance / "packages/busybox-1.0-r0.PKGINFO"
            pkginfo_path.write_text(
                "\n".join(
                    (
                        "pkgname = busybox",
                        "pkgver = 1.0-r0",
                        "origin = busybox",
                        "license = GPL-2.0-only",
                        f"commit = {runtime_commit}",
                        f"datahash = {datahash}",
                        "",
                    )
                )
            )

            module_path = "lib/modules/6.0-0-lts/kernel/drivers/net/usb/rndis_host.ko.gz"
            init_files = {
                "bin/busybox": (stat.S_IFREG | 0o755, b"busybox"),
                "etc/init.d/rcS": (stat.S_IFREG | 0o755, b"#!/bin/sh\n"),
                module_path: (stat.S_IFREG | 0o644, b"kernel module"),
            }
            (repo / "script").mkdir(parents=True)
            for source_name, installed_path in (
                ("avahi-daemon.conf", "etc/avahi/avahi-daemon.conf"),
                ("thrurndis.service", "etc/avahi/services/thrurndis.service"),
            ):
                content = (ROOT / "script" / source_name).read_bytes()
                (repo / "script" / source_name).write_bytes(content)
                init_files[installed_path] = (stat.S_IFREG | 0o644, content)
            service_hash = sha256((repo / "script/thrurndis.service").read_bytes())
            init_files["usr/local/libexec/thrurndis/mdns-service.sha256"] = (
                stat.S_IFREG | 0o644, (service_hash + "\n").encode(),
            )
            initramfs = assets / "initramfs-thrurndis-lts"
            initramfs.write_bytes(make_newc(init_files))
            image = assets / "Image-lts"
            image.write_bytes(b"Linux Image")
            file_map = {
                path: {
                    "owner": "kernel" if path == module_path else ("busybox" if path == "bin/busybox" else "project"),
                    "sha256": sha256(data),
                }
                for path, (_, data) in init_files.items()
            }
            (provenance / "file-map.json").write_text(json.dumps(file_map))
            (provenance / "packages.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "lockPath": os.path.relpath(lock_path, build),
                        "packages": [
                            {
                                "name": runtime["name"],
                                "version": runtime["version"],
                                "origin": runtime["origin"],
                                "license": runtime["license"],
                                "apkSha256": runtime["sha256"],
                                "pkginfoPath": "provenance/packages/busybox-1.0-r0.PKGINFO",
                                "pkginfoSha256": sha256_file(pkginfo_path),
                            }
                        ],
                    }
                )
            )
            (provenance / "kernel.json").write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "kernelFlavor": "lts",
                        "kernelRelease": "6.0-0-lts",
                        "packageName": "linux-lts",
                        "packageVersion": "6.0-r0",
                        "aportsCommit": kernel_commit,
                        "isoUrl": lock["alpine"]["isoUrl"],
                        "isoSha256": sha256(iso),
                        "modloopPath": "boot/modloop-lts",
                        "modloopSha256": sha256(modloop),
                        "imagePath": "assets/Image-lts",
                        "imageSha256": sha256_file(image),
                        "modules": [{"path": module_path, "sha256": sha256(b"kernel module")}],
                        "modulePaths": [module_path],
                    }
                )
            )

            for origin in ("busybox", "linux-lts"):
                target = license_dir / origin
                target.mkdir(parents=True)
                (target / "COPYING").write_text(f"license text for {origin}\n")

            (repo / "LICENSES").mkdir(parents=True)
            shutil.copyfile(ROOT / "LICENSES/GPL-2.0-or-later.txt", repo / "LICENSES/GPL-2.0-or-later.txt")
            (repo / "config").mkdir()
            (repo / "config/packages.lock.json").write_text(json.dumps(lock))
            asset_config = {"schemaVersion": 1, "assetVersion": 1}
            (repo / "config/vm-assets.json").write_text(json.dumps(asset_config))
            subprocess.run(["git", "init", "-q", repo], check=True)
            subprocess.run(["git", "-C", repo, "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", repo, "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", repo, "add", "."], check=True)
            subprocess.run(["git", "-C", repo, "commit", "-qm", "test fixture"], check=True)

            build_compliance.run(
                SimpleNamespace(
                    lock=lock_path,
                    policy=self.policy_path,
                    build_dir=build,
                    asset_dir=assets,
                    license_dir=license_dir,
                    archive=build / "release/vm_assets.zip",
                    no_archive=False,
                    repo=repo,
                )
            )
            verify_compliance.run(
                SimpleNamespace(
                    lock=lock_path,
                    policy=self.policy_path,
                    build_dir=build,
                    asset_dir=assets,
                    archive=build / "release/vm_assets.zip",
                    source_bundle=None,
                    repo=repo,
                )
            )
            manifest = json.loads((assets / "manifest.json").read_text())
            self.assertEqual(manifest["assetVersion"], 1)
            self.assertTrue((assets / "compliance/sbom.spdx.json").is_file())
            self.assertTrue((build / "release/vm_assets.zip").is_file())

            manifest_path = assets / "manifest.json"
            original_manifest = manifest_path.read_text()
            manifest["assetVersion"] = 2
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ComplianceError, "assetVersion differs from config"):
                verify_compliance.run(
                    SimpleNamespace(
                        lock=lock_path,
                        policy=self.policy_path,
                        build_dir=build,
                        asset_dir=assets,
                        archive=build / "release/vm_assets.zip",
                        source_bundle=None,
                        repo=repo,
                    )
                )
            manifest_path.write_text(original_manifest)

            if shutil.which("zstd") is None:
                return
            source_root = temp / "source-staging"
            (source_root / "builder/LICENSES").mkdir(parents=True)
            (source_root / "builder/config").mkdir(parents=True)
            shutil.copyfile(repo / "LICENSES/GPL-2.0-or-later.txt", source_root / "builder/LICENSES/GPL-2.0-or-later.txt")
            shutil.copyfile(repo / "config/packages.lock.json", source_root / "builder/config/packages.lock.json")
            shutil.copyfile(repo / "config/vm-assets.json", source_root / "builder/config/vm-assets.json")
            (source_root / "packages").mkdir()
            shutil.copyfile(
                provenance / "packages/busybox-1.0-r0.PKGINFO",
                source_root / f"packages/{runtime['file']}.PKGINFO",
            )
            (source_root / f"packages/{runtime['file']}.sha256").write_text(
                f"{runtime['sha256']}  {runtime['file']}\n"
            )
            source_rows = []
            for package in (runtime, kernel):
                origin = package["origin"]
                commit = package["aportsCommit"]
                recipe = source_root / "aports" / commit / "main" / origin
                recipe.mkdir(parents=True)
                distfile_data = f"source for {origin}\n".encode()
                digest = sha256(distfile_data)
                filename = f"{origin}.tar"
                (recipe / "APKBUILD").write_text(f'sha256sums="\n{digest}  {filename}\n"\n')
                distfile = source_root / "distfiles" / origin / filename
                distfile.parent.mkdir(parents=True)
                distfile.write_bytes(distfile_data)
                license_file = source_root / "licenses" / origin / "COPYING"
                license_file.parent.mkdir(parents=True)
                license_file.write_text(f"license for {origin}\n")
                source_rows.append(
                    {
                        "origin": origin,
                        "packages": [package["name"]],
                        "aportsCommit": commit,
                        "repository": "main",
                        "distfiles": [
                            {
                                "name": filename,
                                "kind": "upstream-distfile",
                                "sha256": digest,
                            }
                        ],
                        "licenseFiles": [f"licenses/{origin}/COPYING"],
                    }
                )
            commit = subprocess.run(
                ["git", "-C", repo, "rev-parse", "HEAD"], check=True, text=True, capture_output=True
            ).stdout.strip()
            (source_root / "BUILDING.md").write_text("fixture build instructions\n")
            write_json(
                source_root / "SOURCES.json",
                {"schemaVersion": 1, "builderCommit": commit, "sources": source_rows},
            )
            write_json(
                source_root / "SOURCE_MANIFEST.json",
                {
                    "schemaVersion": 1,
                    "assetVersion": 1,
                    "created": "1970-01-01T00:00:00Z",
                    "builderCommit": commit,
                    "alpine": lock["alpine"],
                    "files": source_inventory(source_root),
                },
            )
            tar_path = temp / "source.tar"
            with tarfile.open(tar_path, "w") as archive_handle:
                archive_handle.add(source_root, arcname="vm_assets-sources")
            source_bundle = build / "release/vm_assets-sources.tar.zst"
            subprocess.run(["zstd", "-q", "-f", str(tar_path), "-o", str(source_bundle)], check=True)
            verify_compliance.run(
                SimpleNamespace(
                    lock=lock_path,
                    policy=self.policy_path,
                    build_dir=build,
                    asset_dir=assets,
                    archive=build / "release/vm_assets.zip",
                    source_bundle=source_bundle,
                    repo=repo,
                )
            )


if __name__ == "__main__":
    unittest.main()
