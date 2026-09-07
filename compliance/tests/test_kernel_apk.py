# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "script"))
sys.path.insert(0, str(ROOT / "script/lib"))

from apk_fixture import make_apk, tar_bytes  # noqa: E402
from apk_payload import verified_pkginfo  # noqa: E402
import build_assets  # noqa: E402
import update_dependencies as updater  # noqa: E402


class KernelApkTests(unittest.TestCase):
    def test_kernel_updates_without_iso_change_or_installer_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "alpine.env"
            lock = root / "packages.lock.json"
            env = updater.read_env(ROOT / "config/alpine.env")
            env["GUEST_ROOT_PACKAGES"] = "busybox"
            updater.write_env(config, env)
            snapshots = []
            for version in ("6.18.48-r0", "6.18.49-r0", "6.18.49-r0"):
                payloads = {}
                index_rows = []
                for name, package_version, commit, dependencies in (
                    ("busybox", "1.0-r0", "a" * 40, ""),
                    ("linux-lts", version, "b" * 40, "initramfs-generator linux-firmware-any"),
                ):
                    payload, _, checksum = make_apk({"example": b"payload"}, name, package_version, commit)
                    filename = f"{name}-{package_version}.apk"
                    payloads[filename] = payload
                    index_rows.append("\n".join((f"P:{name}", f"V:{package_version}", "A:aarch64",
                                                  "L:GPL-2.0-only", f"o:{name}", f"c:{commit}",
                                                  f"C:{checksum}", f"D:{dependencies}")))
                index = gzip.compress(tar_bytes({"APKINDEX": "\n\n".join(index_rows).encode()}), mtime=0)
                empty_index = gzip.compress(tar_bytes({"APKINDEX": b""}), mtime=0)
                release = (
                    f"- title: Standard\n  branch: {env['ALPINE_BRANCH']}\n  arch: aarch64\n"
                    f"  version: {env['ALPINE_VERSION']}\n  flavor: alpine-standard\n"
                    f"  sha256: {env['ALPINE_ISO_SHA256']}\n"
                ).encode()

                def fetch(url, destination=None):
                    if url.endswith("latest-releases.yaml"):
                        return release
                    if url.endswith("/main/aarch64/APKINDEX.tar.gz"):
                        return index
                    if url.endswith("/community/aarch64/APKINDEX.tar.gz"):
                        return empty_index
                    # Any ISO, APKBUILD, firmware, or installer fetch fails here.
                    data = payloads[url.rsplit("/", 1)[-1]]
                    destination.write_bytes(data)
                    return b""

                with mock.patch.object(updater, "fetch", side_effect=fetch), \
                     mock.patch.object(updater, "resolve_aports_tag", return_value="c" * 40), \
                     mock.patch.object(sys, "argv", ["update_dependencies.py", "--latest",
                                      "--config", str(config), "--lock", str(lock),
                                      "--cache-dir", str(root / "cache")]):
                    self.assertEqual(updater.main(), 0)
                snapshots.append(json.loads(lock.read_text()))

            before, after, unchanged = snapshots
            self.assertEqual(after, unchanged)
            for key in ("version", "isoUrl", "isoSha256", "aportsCommit"):
                self.assertEqual(before["alpine"][key], after["alpine"][key])
            self.assertEqual({p["name"] for p in after["packages"]}, {"busybox", "linux-lts"})
            self.assertEqual(before["packages"][0], after["packages"][0])
            kernel = next(p for p in after["packages"] if p["role"] == "kernel")
            self.assertEqual(kernel["version"], "6.18.49-r0")
            self.assertEqual(kernel["repositoryName"], "main")
            self.assertEqual(kernel["aportsCommit"], "b" * 40)
            self.assertNotEqual(kernel["aportsCommit"], after["alpine"]["aportsCommit"])
            self.assertEqual(after["rootPackages"], ["busybox"])

    def test_missing_or_ambiguous_kernel_fails_closed(self) -> None:
        candidate = {"name": "linux-lts", "repositoryName": "main"}
        for catalog in ([], [candidate, candidate], [{**candidate, "repositoryName": "community"}]):
            with self.subTest(catalog=catalog), self.assertRaises(SystemExit):
                updater.select_kernel(catalog)

    def test_apk_control_and_data_checksums(self) -> None:
        payload, pkginfo, checksum = make_apk({"boot/vmlinuz-lts": b"kernel"})
        with tempfile.TemporaryDirectory() as temporary:
            apk = Path(temporary) / "kernel.apk"
            apk.write_bytes(payload)
            self.assertEqual(verified_pkginfo(apk, checksum), pkginfo)
            wrong_checksum = "Q1" + "A" * 27 + "="
            with self.assertRaisesRegex(ValueError, "control checksum mismatch"):
                verified_pkginfo(apk, wrong_checksum)
            apk.write_bytes(payload[:-1] + bytes([payload[-1] ^ 1]))
            with self.assertRaisesRegex(ValueError, "data checksum mismatch"):
                verified_pkginfo(apk, checksum)

    def test_gzip_module_normalization_preserves_source_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            data = b"module ELF contents"
            compressed = gzip.compress(data, mtime=0)
            (source / "rndis_host.ko.gz").write_bytes(compressed)
            (source / "modules.dep").write_text("rndis_host.ko.gz:\n")
            (source / "modules.builtin").write_text("")
            guest = root / "guest"
            guest.mkdir()
            with mock.patch.object(build_assets, "run", return_value=mock.Mock(stdout="")) as run:
                rows, builtins = build_assets.copy_module_closure(source, guest, "6.18.49-0-lts", ["rndis_host"], {})
            self.assertFalse(builtins)
            self.assertEqual((guest / rows[0]["path"]).read_bytes(), data)
            self.assertTrue(rows[0]["sourcePath"].endswith("rndis_host.ko.gz"))
            self.assertEqual(rows[0]["sourceSha256"], hashlib.sha256(compressed).hexdigest())
            modinfo_path = run.call_args_list[0].args[0][-1]
            self.assertTrue(modinfo_path.endswith("rndis_host.ko"))

    def test_kernel_architecture_must_match_guest(self) -> None:
        payload, _, checksum = make_apk({}, arch="x86_64")
        package = {"name": "linux-lts", "version": "6.18.49-r0", "origin": "linux-lts",
                   "file": "linux-lts-6.18.49-r0.apk", "url": "https://example.invalid/kernel.apk",
                   "license": "GPL-2.0-only", "aportsCommit": "2" * 40, "apkIndexChecksum": checksum}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(updater, "fetch", side_effect=lambda url, destination: destination.write_bytes(payload)), \
             self.assertRaisesRegex(SystemExit, "architecture"):
            updater.lock_apk(package, "kernel", Path(temporary), "aarch64")

    @unittest.skipUnless(shutil.which("bsdtar"), "requires libarchive")
    def test_extract_kernel_without_running_installer_or_overlaying_guest(self) -> None:
        version = "6.18.49-r0"
        release = "6.18.49-0-lts"
        payload, pkginfo, checksum = make_apk({
            "boot/vmlinuz-lts": gzip.compress(b"image"),
            f"lib/modules/{release}/modules.builtin": b"",
            f"lib/modules/{release}/modules.dep": b"kernel/rndis_host.ko:\n",
            f"lib/modules/{release}/kernel/rndis_host.ko": b"module",
        })
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            cache = build / "cache"
            staging = build / "staging"
            provenance = build / "provenance"
            (cache / "apks").mkdir(parents=True)
            (provenance / "packages").mkdir(parents=True)
            apk = cache / "apks" / f"linux-lts-{version}.apk"
            apk.write_bytes(payload)
            fields = updater.pkginfo_fields(pkginfo)
            package = {"name": "linux-lts", "version": version, "origin": "linux-lts", "role": "kernel",
                       "file": apk.name, "url": "https://example.invalid/kernel.apk", "license": "GPL-2.0-only",
                       "aportsCommit": "2" * 40, "datahash": fields["datahash"][0],
                       "sha256": hashlib.sha256(payload).hexdigest(), "apkIndexChecksum": checksum}
            package_root, record = build_assets.prepare_apk(package, cache, staging, provenance, True)
            self.assertEqual((build / record["pkginfoPath"]).read_text(), pkginfo)
            self.assertFalse((package_root / ".post-install").exists())
            self.assertFalse((staging / "initramfs-root").exists())
            with mock.patch.object(build_assets, "run") as run:
                image, modules = build_assets.kernel_apk_paths(package_root, version)
                self.assertEqual(image.name, "vmlinuz-lts")
                self.assertEqual(modules.name, release)
                run.assert_not_called()
                with self.assertRaisesRegex(SystemExit, "does not match"):
                    build_assets.kernel_apk_paths(package_root, "6.18.48-r0")


if __name__ == "__main__":
    unittest.main()
