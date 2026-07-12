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
from common import ComplianceError, load_policy, normalize_license, sha256_file, write_json  # noqa: E402
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

            module_path = "lib/modules/6.0-0-lts/kernel/wireguard.ko.gz"
            init_files = {
                "bin/busybox": (stat.S_IFREG | 0o755, b"busybox"),
                "etc/init.d/rcS": (stat.S_IFREG | 0o755, b"#!/bin/sh\n"),
                module_path: (stat.S_IFREG | 0o644, b"kernel module"),
            }
            initramfs = assets / "initramfs-rtpvm-lts"
            initramfs.write_bytes(make_newc(init_files))
            image = assets / "Image-lts"
            image.write_bytes(b"Linux Image")
            file_map = {
                path: {
                    "owner": "kernel" if path == module_path else ("project" if path.startswith("etc/") else "busybox"),
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
                )
            )
            self.assertTrue((assets / "compliance/sbom.spdx.json").is_file())
            self.assertTrue((build / "release/vm_assets.zip").is_file())

            if shutil.which("zstd") is None:
                return
            source_root = temp / "source-staging"
            (source_root / "builder/LICENSES").mkdir(parents=True)
            (source_root / "builder/config").mkdir(parents=True)
            shutil.copyfile(repo / "LICENSES/GPL-2.0-or-later.txt", source_root / "builder/LICENSES/GPL-2.0-or-later.txt")
            shutil.copyfile(repo / "config/packages.lock.json", source_root / "builder/config/packages.lock.json")
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
                )
            )


if __name__ == "__main__":
    unittest.main()
