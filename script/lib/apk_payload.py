# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

"""Verify APK v2 control/data digests without executing package scripts."""

from __future__ import annotations

import base64
import hashlib
import io
from pathlib import Path
import tarfile
import zlib


def verified_pkginfo(path: Path, index_checksum: str) -> str:
    """Bind .PKGINFO and the data stream to the APKINDEX control checksum."""
    if not index_checksum.startswith("Q1"):
        raise ValueError("unsupported APKINDEX checksum (expected Q1)")
    expected = base64.b64decode(index_checksum[2:], validate=True)
    if len(expected) != 20:
        raise ValueError("invalid APKINDEX SHA-1 length")
    with path.open("rb") as archive:
        # Signed APKs have a signature stream before the control stream.
        for _ in range(2):
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            digest = hashlib.sha1()
            control = bytearray()
            while not decoder.eof:
                chunk = archive.read(65536)
                if not chunk:
                    raise ValueError("truncated APK control stream")
                control.extend(decoder.decompress(chunk, 8 * 1024 * 1024 + 1 - len(control)))
                if len(control) > 8 * 1024 * 1024:
                    raise ValueError("APK control stream exceeds 8 MiB")
                consumed = len(chunk) - len(decoder.unused_data)
                digest.update(chunk[:consumed])
                if decoder.unused_data:
                    archive.seek(-len(decoder.unused_data), 1)
            with tarfile.open(fileobj=io.BytesIO(control), mode="r:") as metadata:
                members = [member for member in metadata if member.name == ".PKGINFO"]
                if not members:
                    continue
                if len(members) != 1 or not members[0].isfile():
                    raise ValueError("APK must contain one regular .PKGINFO")
                content = metadata.extractfile(members[0])
                assert content is not None
                text = content.read().decode()
            if digest.digest() != expected:
                raise ValueError("APKINDEX control checksum mismatch")
            datahashes = [line.removeprefix("datahash = ") for line in text.splitlines()
                          if line.startswith("datahash = ")]
            data_digest = hashlib.sha256()
            for chunk in iter(lambda: archive.read(1024 * 1024), b""):
                data_digest.update(chunk)
            if datahashes != [data_digest.hexdigest()]:
                raise ValueError("APK data checksum mismatch")
            return text
    raise ValueError("APK control metadata is missing")
