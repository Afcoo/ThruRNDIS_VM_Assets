#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

"""Resolve and pin Alpine APK dependencies.

This is deliberately separate from the normal builder.  It is the only tool
that reads APKINDEX and changes the dependency closure.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config/alpine.env"
DEFAULT_LOCK = ROOT / "config/packages.lock.json"
sys.path.insert(0, str(ROOT / "script/lib"))

from apk_payload import verified_pkginfo  # noqa: E402


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def read_env(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"{path}:{number}: expected KEY=value")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            fail(f"{path}:{number}: invalid key {key!r}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def write_env(path: pathlib.Path, values: dict[str, str]) -> None:
    roots = values["GUEST_ROOT_PACKAGES"]
    modules = values["KERNEL_MODULES"]
    text = f"""# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

# This file is updated only by script/update_dependencies.py.  The normal
# builder consumes these pinned values and config/packages.lock.json.
ALPINE_VERSION={values['ALPINE_VERSION']}
ALPINE_BRANCH={values['ALPINE_BRANCH']}
ALPINE_ARCH={values['ALPINE_ARCH']}
ALPINE_FLAVOR={values['ALPINE_FLAVOR']}
ALPINE_MIRROR={values['ALPINE_MIRROR']}
ALPINE_ISO_SHA256={values['ALPINE_ISO_SHA256']}
ALPINE_APORTS_COMMIT={values['ALPINE_APORTS_COMMIT']}

# Packages copied into the initramfs.  Their complete runtime dependency
# closure is recorded in packages.lock.json.
GUEST_ROOT_PACKAGES=\"{roots}\"

# Kernel modules copied from the locked linux-lts APK.  A module built into
# the kernel satisfies a seed; otherwise its modules.dep closure is copied.
KERNEL_MODULES=\"{modules}\"
"""
    atomic_write(path, text.encode())


def atomic_write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(data)
        temp = pathlib.Path(handle.name)
    os.replace(temp, path)


def fetch(url: str, destination: pathlib.Path | None = None) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "ThruRNDIS-VM-Assets/1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        if destination is None:
            return response.read()
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
            shutil.copyfileobj(response, handle)
            temp = pathlib.Path(handle.name)
        os.replace(temp, destination)
        return b""


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_kernel(catalog: list[dict[str, object]]) -> dict[str, object]:
    # This APK supplies build inputs only. Its installer dependencies (including
    # firmware and initramfs-generator) must not enter the guest runtime closure.
    candidates = [package for package in catalog
                  if package["name"] == "linux-lts" and package["repositoryName"] == "main"]
    if len(candidates) != 1:
        fail(f"Expected one linux-lts APK in main, found {len(candidates)}")
    return candidates[0]


def lock_apk(package: dict[str, object], role: str, cache: pathlib.Path, arch: str) -> dict[str, object]:
    package = dict(package)
    if not package["license"] or not package["aportsCommit"] or not package["apkIndexChecksum"]:
        fail(f"Incomplete provenance in APKINDEX for {package['name']}")
    apk = cache / str(package["file"])
    fetch(str(package["url"]), apk)
    try:
        fields = pkginfo_fields(verified_pkginfo(apk, str(package["apkIndexChecksum"])))
    except ValueError as error:
        fail(f"Invalid APK {package['file']}: {error}")
    expected = (str(package["name"]), str(package["version"]), str(package["origin"]), str(package["license"]))
    actual = tuple((fields.get(key) or [""])[0] for key in ("pkgname", "pkgver", "origin", "license"))
    if expected != actual:
        fail(f"APKINDEX/.PKGINFO mismatch for {package['file']}: expected {expected}, got {actual}")
    commit = (fields.get("commit") or [""])[0]
    datahash = (fields.get("datahash") or [""])[0]
    package_arch = (fields.get("arch") or [""])[0]
    if package_arch not in ({arch} if role == "kernel" else {arch, "noarch"}):
        fail(f"Unexpected APK architecture for {package['file']}: {package_arch}")
    if commit != package["aportsCommit"] or not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail(f"Invalid .PKGINFO source commit for {package['file']}")
    if not re.fullmatch(r"[0-9a-f]{64}", datahash):
        fail(f"Invalid .PKGINFO datahash for {package['file']}")
    package.update(sha256=sha256(apk), datahash=datahash, role=role)
    package.pop("provides", None)
    package.pop("providerPriority", None)
    return package


def parse_latest_releases(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped == "-" or stripped.startswith("- "):
            if current:
                records.append(current)
            current = {}
            inline = stripped[1:].strip()
            if inline and ":" in inline:
                key, value = inline.split(":", 1)
                current[key.strip()] = value.strip().strip('"')
            continue
        match = re.match(r"^  ([a-z0-9_]+):\s*(.*)$", raw)
        if match:
            value = match.group(2).strip().strip('"')
            current[match.group(1)] = value
    if current:
        records.append(current)
    return records


def self_test() -> None:
    fixtures = (
        """---
- title: \"Standard\"
  branch: v3.24
  arch: aarch64
  version: 3.24.1
  flavor: alpine-standard
  sha256: abcdef
""",
        """---
-
  title: \"Standard\"
  branch: v3.24
  arch: aarch64
  version: 3.24.1
  flavor: alpine-standard
  sha256: abcdef
""",
    )
    for fixture in fixtures:
        records = parse_latest_releases(fixture)
        assert records == [{
            "title": "Standard", "branch": "v3.24", "arch": "aarch64",
            "version": "3.24.1", "flavor": "alpine-standard", "sha256": "abcdef",
        }]
    print("update_dependencies self-test passed")


def latest_standard(env: dict[str, str]) -> dict[str, str]:
    url = f"{env['ALPINE_MIRROR']}/latest-stable/releases/{env['ALPINE_ARCH']}/latest-releases.yaml"
    records = parse_latest_releases(fetch(url).decode())
    flavor = f"alpine-{env['ALPINE_FLAVOR']}"
    for record in records:
        if record.get("arch") == env["ALPINE_ARCH"] and record.get("flavor") == flavor:
            return record
    fail(f"No {flavor}/{env['ALPINE_ARCH']} record in {url}")


def resolve_aports_tag(version: str) -> str:
    command = [
        "git", "ls-remote", "--tags",
        "https://github.com/alpinelinux/aports.git",
        f"refs/tags/v{version}^{{}}",
    ]
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    lines = [line for line in result.stdout.splitlines() if line]
    if len(lines) != 1 or not re.fullmatch(r"[0-9a-f]{40}\s+.+", lines[0]):
        fail(f"Unable to resolve aports tag v{version}")
    return lines[0].split()[0]


def parse_index(archive: bytes, repository: str, repository_url: str) -> list[dict[str, object]]:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        extracted = bundle.extractfile("APKINDEX")
        if extracted is None:
            fail(f"APKINDEX missing from {repository}")
        text = extracted.read().decode()
    packages: list[dict[str, object]] = []
    for paragraph in text.strip().split("\n\n"):
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            if len(line) > 2 and line[1] == ":":
                fields[line[0]] = line[2:]
        if "P" not in fields or "V" not in fields:
            continue
        packages.append({
            "name": fields["P"],
            "version": fields["V"],
            "file": f"{fields['P']}-{fields['V']}.apk",
            "repositoryName": repository,
            "repository": repository_url,
            "url": f"{repository_url}/{fields['P']}-{fields['V']}.apk",
            "origin": fields.get("o", fields["P"]),
            "license": fields.get("L", ""),
            "aportsCommit": fields.get("c", ""),
            "apkIndexChecksum": fields.get("C", ""),
            "dependencies": fields.get("D", "").split(),
            "provides": fields.get("p", "").split(),
            "providerPriority": int(fields.get("k", "0")),
        })
    return packages


def dependency_name(token: str) -> str | None:
    if not token or token.startswith("!"):
        return None
    return re.split(r"[<>=~]", token.split("@", 1)[0], maxsplit=1)[0]


def resolve_closure(catalog: list[dict[str, object]], roots: list[str]) -> list[dict[str, object]]:
    by_name: dict[str, dict[str, object]] = {}
    providers: dict[str, list[dict[str, object]]] = {}
    for package in catalog:
        name = str(package["name"])
        by_name.setdefault(name, package)
        for provided in package["provides"]:
            key = dependency_name(str(provided))
            if key:
                providers.setdefault(key, []).append(package)
    pending = list(roots)
    selected: dict[str, dict[str, object]] = {}
    while pending:
        token = pending.pop(0)
        key = dependency_name(token)
        if key is None:
            continue
        package = by_name.get(key)
        if package is None:
            choices = providers.get(key, [])
            if not choices:
                fail(f"Unable to resolve Alpine runtime dependency: {token}")
            # apk-tools selects the highest provider_priority (APKINDEX `k`).
            # Preserve that rule and refuse an unresolved tie rather than
            # silently changing providers later.
            highest = max(int(choice["providerPriority"]) for choice in choices)
            preferred = [choice for choice in choices if int(choice["providerPriority"]) == highest]
            unique = {str(choice["name"]): choice for choice in preferred}
            if len(unique) != 1:
                fail(f"Ambiguous Alpine provider for {token}: {', '.join(sorted(unique))}")
            package = next(iter(unique.values()))
        name = str(package["name"])
        if name in selected:
            continue
        selected[name] = package
        pending.extend(str(item) for item in package["dependencies"])
    return [selected[name] for name in sorted(selected)]


def pkginfo_fields(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for raw in text.splitlines():
        if " = " in raw:
            key, value = raw.split(" = ", 1)
            fields.setdefault(key, []).append(value)
    return fields


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONFIG)
    parser.add_argument("--lock", type=pathlib.Path, default=DEFAULT_LOCK)
    parser.add_argument("--cache-dir", type=pathlib.Path, default=ROOT / "build/cache")
    parser.add_argument("--latest", action="store_true", help="bump to latest stable Alpine standard ISO")
    parser.add_argument("--self-test", action="store_true", help="run parser tests without network access")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    env = read_env(args.config)
    required = {
        "ALPINE_VERSION", "ALPINE_BRANCH", "ALPINE_ARCH", "ALPINE_FLAVOR",
        "ALPINE_MIRROR", "GUEST_ROOT_PACKAGES", "KERNEL_MODULES",
    }
    missing = sorted(required - env.keys())
    if missing:
        fail(f"Missing config keys: {', '.join(missing)}")

    if args.latest:
        release = latest_standard(env)
        env["ALPINE_VERSION"] = release["version"]
        env["ALPINE_BRANCH"] = release["branch"]
        env["ALPINE_ISO_SHA256"] = release["sha256"]
    else:
        iso_name = f"alpine-{env['ALPINE_FLAVOR']}-{env['ALPINE_VERSION']}-{env['ALPINE_ARCH']}.iso"
        checksum_url = f"{env['ALPINE_MIRROR']}/{env['ALPINE_BRANCH']}/releases/{env['ALPINE_ARCH']}/{iso_name}.sha256"
        checksum = fetch(checksum_url).decode().split()[0]
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            fail(f"Invalid ISO checksum from {checksum_url}")
        env["ALPINE_ISO_SHA256"] = checksum
    env["ALPINE_APORTS_COMMIT"] = resolve_aports_tag(env["ALPINE_VERSION"])

    iso_name = f"alpine-{env['ALPINE_FLAVOR']}-{env['ALPINE_VERSION']}-{env['ALPINE_ARCH']}.iso"
    iso_url = f"{env['ALPINE_MIRROR']}/{env['ALPINE_BRANCH']}/releases/{env['ALPINE_ARCH']}/{iso_name}"
    catalog: list[dict[str, object]] = []
    index_hashes: dict[str, str] = {}
    for repository in ("main", "community"):
        repository_url = f"{env['ALPINE_MIRROR']}/{env['ALPINE_BRANCH']}/{repository}/{env['ALPINE_ARCH']}"
        archive = fetch(f"{repository_url}/APKINDEX.tar.gz")
        index_hashes[repository] = hashlib.sha256(archive).hexdigest()
        catalog.extend(parse_index(archive, repository, repository_url))

    runtime = resolve_closure(catalog, env["GUEST_ROOT_PACKAGES"].split())
    if any(package["name"] == "linux-lts" for package in runtime):
        fail("linux-lts must be a kernel input, not a guest runtime package")
    kernel = select_kernel(catalog)
    apk_cache = args.cache_dir / "apks"
    apk_cache.mkdir(parents=True, exist_ok=True)
    packages = [lock_apk(package, "runtime", apk_cache, env["ALPINE_ARCH"]) for package in runtime]
    packages.append(lock_apk(kernel, "kernel", apk_cache, env["ALPINE_ARCH"]))
    packages.sort(key=lambda package: (str(package["name"]), str(package["role"])))

    lock = {
        "schemaVersion": 1,
        "spdxFileCopyrightText": "2026 Afcoo",
        "spdxLicenseIdentifier": "GPL-2.0-or-later",
        "alpine": {
            "version": env["ALPINE_VERSION"],
            "branch": env["ALPINE_BRANCH"],
            "arch": env["ALPINE_ARCH"],
            "flavor": env["ALPINE_FLAVOR"],
            "isoUrl": iso_url,
            "isoSha256": env["ALPINE_ISO_SHA256"],
            "aportsCommit": env["ALPINE_APORTS_COMMIT"],
            "apkIndexSha256": index_hashes,
        },
        "rootPackages": env["GUEST_ROOT_PACKAGES"].split(),
        "packages": packages,
    }
    write_env(args.config, env)
    atomic_write(args.lock, (json.dumps(lock, indent=2, sort_keys=True) + "\n").encode())
    print(f"Locked Alpine {env['ALPINE_VERSION']} ({env['ALPINE_ARCH']})")
    runtime_count = sum(package["role"] == "runtime" for package in packages)
    print(f"Locked {runtime_count} runtime APKs and linux-lts {kernel['version']} APK in {args.lock}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
