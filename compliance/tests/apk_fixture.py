# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

"""Small APK v2 archives for checksum and extraction regression tests."""

import base64
import gzip
import hashlib
import io
import tarfile


def tar_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(data))
    # APK's signature/control streams omit tar end markers; libarchive must
    # continue into the next gzip stream rather than stopping after signatures.
    length = sum(512 + ((len(data) + 511) // 512) * 512 for data in files.values())
    return output.getvalue()[:length]


def make_apk(files: dict[str, bytes], name: str = "linux-lts", version: str = "6.18.49-r0",
             commit: str = "2" * 40, arch: str = "aarch64") -> tuple[bytes, str, str]:
    data = gzip.compress(tar_bytes(files), mtime=0)
    pkginfo = "\n".join((f"pkgname = {name}", f"pkgver = {version}", f"origin = {name}",
                         "license = GPL-2.0-only", f"arch = {arch}", f"commit = {commit}",
                         f"datahash = {hashlib.sha256(data).hexdigest()}", ""))
    control = gzip.compress(tar_bytes({".PKGINFO": pkginfo.encode(),
                                      ".post-install": b"#!/bin/sh\nexit 99\n"}), mtime=0)
    signature = gzip.compress(tar_bytes({".SIGN.RSA.test": b"test signature"}), mtime=0)
    checksum = "Q1" + base64.b64encode(hashlib.sha1(control).digest()).decode()
    return signature + control + data, pkginfo, checksum
