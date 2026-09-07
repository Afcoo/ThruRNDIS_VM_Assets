#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later

"""Build a minimal aarch64 Alpine initramfs from pinned inputs only."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zlib

from apk_payload import verified_pkginfo

SCRIPT_DIR = pathlib.Path(__file__).resolve().parents[1]
ROOT = SCRIPT_DIR.parent
DEFAULT_CONFIG = ROOT / "config/alpine.env"
DEFAULT_LOCK = ROOT / "config/packages.lock.json"
INITRAMFS_SCRIPTS = (
    "rcS", "init-console", "init-rndis", "init-network", "usb0-watcher",
    "eth0-usb0-gateway",
)
INITRAMFS_SOURCED_MODULES = ("port-forwarding",)


class GuestPathError(ValueError):
    """A guest path escaped its root or traversed a symlink cycle."""


class KernelMetadataError(ValueError):
    """Selected built-in kernel metadata is missing, unsafe, or malformed."""


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


def hash_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_download(url: str, destination: pathlib.Path, expected: str, offline: bool) -> None:
    if destination.is_file() and hash_file(destination) == expected:
        print(f"Using cached {destination.name}")
        return
    if destination.exists():
        destination.unlink()
    if offline:
        fail(f"Offline cache miss: {destination} ({expected})")
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "ThruRNDIS-VM-Assets/1"})
    print(f"Downloading {url}")
    with urllib.request.urlopen(request, timeout=180) as response:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
            shutil.copyfileobj(response, handle)
            temp = pathlib.Path(handle.name)
    actual = hash_file(temp)
    if actual != expected:
        temp.unlink()
        fail(f"SHA-256 mismatch for {url}: expected {expected}, got {actual}")
    os.replace(temp, destination)


def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, check=True, **kwargs)
    except subprocess.CalledProcessError as error:
        fail(f"Command failed ({error.returncode}): {' '.join(command)}")


def extract_member(archive: pathlib.Path, member: str, destination: pathlib.Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as handle:
        run(["bsdtar", "-xOf", str(archive), member], stdout=handle)
    if not destination.is_file() or destination.stat().st_size == 0:
        fail(f"Missing or empty {member} in {archive}")


def extract_linux_image(vmlinuz: pathlib.Path, destination: pathlib.Path) -> None:
    data = vmlinuz.read_bytes()
    offset = data.find(b"\x1f\x8b\x08")
    if offset < 0:
        fail(f"gzip Linux Image payload not found in {vmlinuz}")
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    image = decompressor.decompress(data[offset:]) + decompressor.flush()
    if len(image) < 1024 * 1024:
        fail(f"Implausibly small Linux Image extracted from {vmlinuz}")
    destination.write_bytes(image)
    destination.chmod(0o644)


def pkginfo_fields(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for raw in text.splitlines():
        if " = " in raw:
            key, value = raw.split(" = ", 1)
            fields.setdefault(key, []).append(value)
    return fields


def prepare_apk(package: dict[str, object], cache: pathlib.Path, staging: pathlib.Path,
                provenance: pathlib.Path, offline: bool) -> tuple[pathlib.Path, dict[str, object]]:
    name = str(package["name"])
    apk = cache / "apks" / str(package["file"])
    atomic_download(str(package["url"]), apk, str(package["sha256"]), offline)
    try:
        pkginfo = verified_pkginfo(apk, str(package["apkIndexChecksum"]))
    except ValueError as error:
        fail(f"Invalid APK {apk.name}: {error}")
    fields = pkginfo_fields(pkginfo)
    for field, key in (("pkgname", "name"), ("pkgver", "version"), ("origin", "origin"),
                       ("license", "license"), ("commit", "aportsCommit"), ("datahash", "datahash")):
        if fields.get(field) != [str(package[key])]:
            fail(f"Locked metadata mismatch for {apk.name}: {field}")
    if package.get("role") == "kernel" and fields.get("arch") != ["aarch64"]:
        fail("Kernel APK must target aarch64")
    metadata_path = provenance / "packages" / f"{name}-{package['version']}.PKGINFO"
    metadata_path.write_text(pkginfo)
    package_root = staging / "packages" / name
    package_root.mkdir(parents=True)
    run(["bsdtar", "-xf", str(apk), "-C", str(package_root)])
    clean_control_files(package_root)
    return package_root, {
        "name": name, "version": package["version"], "origin": package["origin"],
        "license": package["license"], "apkSha256": package["sha256"],
        "pkginfoPath": metadata_path.relative_to(provenance.parent).as_posix(),
        "pkginfoSha256": hash_file(metadata_path),
    }


def kernel_apk_paths(package_root: pathlib.Path, version: str) -> tuple[pathlib.Path, pathlib.Path]:
    match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)-r([0-9]+)", version)
    if match is None:
        fail(f"Unexpected linux-lts package version: {version}")
    release = f"{match.group(1)}-{match.group(2)}-lts"
    image = resolve_guest_path(package_root, "boot/vmlinuz-lts")
    modules = resolve_guest_path(package_root, "lib/modules")
    if image is None or not image.is_file() or modules is None or not modules.is_dir():
        fail("Kernel APK lacks boot/vmlinuz-lts or lib/modules")
    module_dirs = sorted(modules.iterdir())
    if len(module_dirs) != 1 or module_dirs[0].name != release or not module_dirs[0].is_dir() or module_dirs[0].is_symlink():
        fail(f"Kernel APK module directory does not match locked release {release}")
    # Use the dependency map shipped in this exact APK. Host kmod may not
    # support its compressed modules; only the selected closure is normalized.
    if not (module_dirs[0] / "modules.dep").is_file():
        fail("Kernel APK lacks modules.dep")
    return image, module_dirs[0]


def clean_control_files(root: pathlib.Path) -> None:
    for path in list(root.iterdir()):
        if path.name.startswith("."):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()


def overlay(source: pathlib.Path, destination: pathlib.Path, owner: str, owners: dict[str, str]) -> None:
    for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(source)
        target = destination / relative
        key = relative.as_posix()
        if path.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            target.symlink_to(os.readlink(path))
            owners[key] = owner
        elif path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(stat.S_IMODE(path.stat().st_mode))
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                target.unlink()
            shutil.copy2(path, target)
            owners[key] = owner
        else:
            fail(f"Unsupported special file in package {owner}: {relative}")


def add_symlink(root: pathlib.Path, relative: str, target: str, owner: str, owners: dict[str, str]) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    path.symlink_to(target)
    owners[relative] = owner


def add_file(root: pathlib.Path, relative: str, data: str | bytes, mode: int, owner: str, owners: dict[str, str]) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        path.unlink()
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(mode)
    owners[relative] = owner


def resolve_guest_path(root: pathlib.Path, relative: str) -> pathlib.Path | None:
    """Resolve a guest pathname without interpreting it against the host root.

    Absolute symlink targets restart at ``root``. Relative targets restart at
    the symlink's guest parent. Attempts to traverse above the guest root and
    symlink cycles are rejected.
    """

    if not relative or relative.startswith("/"):
        raise GuestPathError(f"guest path must be non-empty and relative: {relative!r}")
    pending = relative.split("/")
    resolved: list[str] = []
    visited: set[tuple[str, ...]] = set()
    traversals = 0

    while pending:
        component = pending.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            if not resolved:
                raise GuestPathError(f"guest path escapes root: {relative!r}")
            resolved.pop()
            continue

        resolved.append(component)
        candidate = root.joinpath(*resolved)
        try:
            candidate.lstat()
        except FileNotFoundError:
            return None
        if not candidate.is_symlink():
            continue

        guest_symlink = tuple(resolved)
        if guest_symlink in visited:
            raise GuestPathError(f"guest symlink cycle at /{'/'.join(resolved)}")
        visited.add(guest_symlink)
        traversals += 1
        if traversals > 40:
            raise GuestPathError(f"too many guest symlinks while resolving {relative!r}")

        target = os.readlink(candidate)
        resolved.pop()
        if target.startswith("/"):
            resolved = []
        pending = target.split("/") + pending

    return root.joinpath(*resolved)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = pathlib.Path(temp)
        (root / "bin").mkdir()
        (root / "usr/bin").mkdir(parents=True)
        (root / "usr/local").mkdir(parents=True)
        busybox = root / "bin/busybox"
        busybox.write_bytes(b"busybox")
        busybox.chmod(0o755)
        (root / "bin/sh").symlink_to("/bin/busybox")
        (root / "usr/bin/busybox").symlink_to("/bin/busybox")
        (root / "usr/local/bin").symlink_to("../../bin")

        assert resolve_guest_path(root, "bin/sh") == busybox
        assert resolve_guest_path(root, "usr/bin/busybox") == busybox
        assert resolve_guest_path(root, "usr/local/bin/busybox") == busybox
        assert resolve_guest_path(root, "bin/missing") is None

        (root / "escape").symlink_to("../../host")
        try:
            resolve_guest_path(root, "escape")
        except GuestPathError:
            pass
        else:
            raise AssertionError("guest-root escape was not rejected")

        (root / "cycle-a").symlink_to("cycle-b")
        (root / "cycle-b").symlink_to("cycle-a")
        try:
            resolve_guest_path(root, "cycle-a")
        except GuestPathError:
            pass
        else:
            raise AssertionError("guest symlink cycle was not rejected")

    with tempfile.TemporaryDirectory() as temp:
        module_dir = pathlib.Path(temp)
        (module_dir / "modules.builtin").write_text(
            "kernel/drivers/example/safe_builtin.ko\n"
            "kernel/drivers/example/firmware_builtin.ko\n"
        )
        metadata = module_dir / "modules.builtin.modinfo"
        metadata.write_bytes(
            b"safe_builtin.file=drivers/example/safe_builtin\0"
            b"safe_builtin.license=GPL\0"
            b"firmware_builtin.file=drivers/example/firmware_builtin\0"
            b"firmware_builtin.firmware=vendor/required.bin\0"
        )
        validate_builtin_module_firmware(module_dir, ["safe_builtin"])
        try:
            validate_builtin_module_firmware(module_dir, ["firmware_builtin"])
        except KernelMetadataError:
            pass
        else:
            raise AssertionError("built-in module firmware metadata was not rejected")

        metadata.write_bytes(b"safe_builtin.file=drivers/example/safe_builtin\0malformed\0")
        try:
            validate_builtin_module_firmware(module_dir, ["safe_builtin"])
        except KernelMetadataError:
            pass
        else:
            raise AssertionError("malformed built-in module metadata was not rejected")
    print("build_assets self-test passed")


def install_busybox_applets(root: pathlib.Path, owners: dict[str, str]) -> None:
    busybox = root / "bin/busybox"
    paths = root / "etc/busybox-paths.d/busybox"
    if not busybox.is_file() or not paths.is_file():
        fail("Pinned busybox package is missing bin/busybox or its applet path manifest")
    for raw in paths.read_text().splitlines():
        relative = raw.strip().lstrip("/")
        if not relative or relative == "bin/busybox":
            continue
        target = root / relative
        # Do not replace a real executable shipped by another locked package.
        if target.exists() and not target.is_symlink():
            continue
        add_symlink(root, relative, "/bin/busybox", "busybox", owners)
    add_symlink(root, "usr/bin/busybox", "/bin/busybox", "project", owners)
    add_symlink(root, "usr/bin/sh", "/bin/busybox", "project", owners)
    add_symlink(root, "bin/ip", "/sbin/ip", "project", owners)


def normalize_module(name: str) -> str:
    return name.replace("-", "_")


def module_stem(path: str) -> str:
    name = pathlib.PurePosixPath(path).name
    return normalize_module(re.sub(r"\.ko(?:\.(?:gz|xz|zst))?$", "", name))


def read_module_paths(module_dir: pathlib.Path) -> tuple[dict[str, str], dict[str, list[str]]]:
    modules: dict[str, str] = {}
    dependencies: dict[str, list[str]] = {}
    dep_file = module_dir / "modules.dep"
    if not dep_file.is_file():
        fail(f"modules.dep missing from modloop: {dep_file}")
    for raw in dep_file.read_text().splitlines():
        if ":" not in raw:
            continue
        path, dep_text = raw.split(":", 1)
        modules[module_stem(path)] = path
        dependencies[path] = dep_text.split()
    return modules, dependencies


def builtin_module_names(module_dir: pathlib.Path) -> set[str]:
    result: set[str] = set()
    builtin = module_dir / "modules.builtin"
    if builtin.is_file():
        for raw in builtin.read_text().splitlines():
            if raw.strip():
                result.add(module_stem(raw.strip()))
    return result


def validate_builtin_module_firmware(module_dir: pathlib.Path, selected: list[str]) -> None:
    """Fail closed if selected built-in modules declare firmware.

    The kernel emits ``modules.builtin.modinfo`` as NUL-delimited
    ``module.field=value`` records. Every built-in module has a ``file``
    record, which lets this function also reject incomplete metadata.
    """

    if not selected:
        return
    metadata_path = module_dir / "modules.builtin.modinfo"
    if not metadata_path.is_file():
        raise KernelMetadataError(f"missing {metadata_path}")
    raw = metadata_path.read_bytes()
    if not raw:
        raise KernelMetadataError(f"empty {metadata_path}")

    # Upstream emits NUL-delimited data. Accept newline-delimited fixtures or
    # distro-normalized copies as long as every record has the same grammar.
    records = raw.split(b"\0") if b"\0" in raw else raw.splitlines()
    fields: dict[str, list[tuple[str, str]]] = {}
    for number, encoded in enumerate(records, 1):
        if not encoded:
            continue
        try:
            record = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise KernelMetadataError(
                f"non-UTF-8 record {number} in {metadata_path}"
            ) from error
        match = re.fullmatch(r"([A-Za-z0-9_:_-]+)\.([A-Za-z0-9_]+)=(.*)", record)
        if not match:
            raise KernelMetadataError(
                f"unrecognized record {number} in {metadata_path}: {record!r}"
            )
        module = normalize_module(match.group(1))
        fields.setdefault(module, []).append((match.group(2), match.group(3)))

    for seed in selected:
        module = normalize_module(seed)
        module_fields = fields.get(module)
        if not module_fields:
            raise KernelMetadataError(
                f"selected built-in module {seed} has no evaluable metadata in {metadata_path}"
            )
        if not any(field == "file" and value for field, value in module_fields):
            raise KernelMetadataError(
                f"selected built-in module {seed} has no file record in {metadata_path}"
            )
        firmware = [value for field, value in module_fields if field == "firmware"]
        if firmware:
            rendered = ", ".join(value or "<empty>" for value in firmware)
            raise KernelMetadataError(
                f"selected built-in module {seed} declares forbidden firmware: {rendered}"
            )


def copy_module_closure(
    source_dir: pathlib.Path,
    root: pathlib.Path,
    release: str,
    seeds: list[str],
    owners: dict[str, str],
) -> tuple[list[dict[str, str]], list[str]]:
    by_name, dependencies = read_module_paths(source_dir)
    builtins = builtin_module_names(source_dir)
    pending: list[str] = []
    builtin_seeds: list[str] = []
    for seed in seeds:
        normalized = normalize_module(seed)
        if normalized in by_name:
            pending.append(by_name[normalized])
        elif normalized in builtins:
            builtin_seeds.append(seed)
        else:
            fail(f"Kernel module seed is neither loadable nor built in: {seed}")
    selected: list[str] = []
    seen: set[str] = set()
    while pending:
        module = pending.pop(0)
        if module in seen:
            continue
        if module not in dependencies:
            fail(f"Module dependency missing from modules.dep: {module}")
        seen.add(module)
        selected.append(module)
        pending.extend(dependencies[module])

    try:
        validate_builtin_module_firmware(source_dir, builtin_seeds)
    except KernelMetadataError as error:
        fail(f"Cannot prove built-in module firmware policy: {error}")

    destination_dir = root / "lib/modules" / release
    copied: list[dict[str, str]] = []
    for relative in sorted(selected):
        source = source_dir / relative
        if not source.is_file():
            fail(f"Selected kernel module missing from kernel input: {relative}")
        target_relative = relative.removesuffix(".gz") if relative.endswith(".ko.gz") else relative
        target = destination_dir / target_relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if relative.endswith(".ko.gz"):
            with gzip.open(source, "rb") as compressed, target.open("wb") as output:
                shutil.copyfileobj(compressed, output)
            target.chmod(0o644)
        else:
            shutil.copy2(source, target)
        result = run(["modinfo", "-F", "firmware", str(target)], capture_output=True, text=True)
        firmware = [line for line in result.stdout.splitlines() if line.strip()]
        if firmware:
            fail(f"Selected module requires forbidden firmware ({relative}): {', '.join(firmware)}")
        archive_path = f"lib/modules/{release}/{target_relative}"
        owners[archive_path] = "kernel"
        record = {"path": archive_path, "sha256": hash_file(target)}
        if target_relative != relative:
            record.update(sourcePath=f"lib/modules/{release}/{relative}", sourceSha256=hash_file(source))
        copied.append(record)

    # depmod generates metadata exclusively for the copied closure.  No stock
    # module or firmware directory is carried over from the kernel input.
    run(["depmod", "-b", str(root), release])
    for metadata in sorted(destination_dir.glob("modules.*")):
        if metadata.is_file():
            owners[metadata.relative_to(root).as_posix()] = "kernel"
    return copied, sorted(builtin_seeds)


def write_inittab(root: pathlib.Path, owners: dict[str, str]) -> None:
    add_file(root, "etc/inittab", """::sysinit:/etc/init.d/rcS
::wait:/usr/local/sbin/init-rndis
::wait:/usr/local/sbin/init-network
::respawn:/usr/local/sbin/usb0-watcher
hvc0::respawn:/usr/local/sbin/init-console
::restart:/sbin/init
::ctrlaltdel:/bin/umount -a -r
""", 0o644, "project", owners)


def install_project_files(root: pathlib.Path, owners: dict[str, str]) -> None:
    for directory, mode in (
        ("bin", 0o755), ("sbin", 0o755), ("dev", 0o755),
        ("etc/init.d", 0o755), ("root", 0o700), ("run", 0o755),
        ("tmp", 0o1777), ("usr/local/libexec/thrurndis", 0o755),
        ("usr/local/sbin", 0o755), ("var/log", 0o755),
    ):
        path = root / directory
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)
    add_symlink(root, "init", "/sbin/init", "project", owners)
    write_inittab(root, owners)
    for name in INITRAMFS_SCRIPTS:
        source = SCRIPT_DIR / "initramfs" / name
        if not source.is_file():
            fail(f"Missing project initramfs script: {source}")
        destination = "etc/init.d/rcS" if name == "rcS" else f"usr/local/sbin/{name}"
        add_file(root, destination, source.read_bytes(), 0o755, "project", owners)
    for name in INITRAMFS_SOURCED_MODULES:
        source = SCRIPT_DIR / "initramfs" / name
        if not source.is_file():
            fail(f"Missing project initramfs module: {source}")
        destination = f"usr/local/libexec/thrurndis/{name}"
        add_file(root, destination, source.read_bytes(), 0o644, "project", owners)
    add_file(root, "etc/resolv.conf", b"", 0o644, "project", owners)


def cpio_header(
    inode: int, name: bytes, mode: int, size: int, nlink: int = 1,
    rdevmajor: int = 0, rdevminor: int = 0,
) -> bytes:
    fields = (inode, mode, 0, 0, nlink, 0, size, 0, 0, rdevmajor, rdevminor, len(name) + 1, 0)
    return ("070701" + "".join(f"{field:08x}" for field in fields)).encode()


def write_padding(handle, size: int) -> None:
    padding = (-size) % 4
    if padding:
        handle.write(b"\0" * padding)


def write_initramfs(root: pathlib.Path, destination: pathlib.Path) -> None:
    with tempfile.NamedTemporaryFile(delete=False) as raw_handle:
        raw_path = pathlib.Path(raw_handle.name)
        inode = 1
        entries = [pathlib.Path(".")]
        entries.extend(sorted((path.relative_to(root) for path in root.rglob("*")), key=lambda path: path.as_posix()))
        for relative in entries:
            path = root if relative == pathlib.Path(".") else root / relative
            name = relative.as_posix().encode()
            info = path.lstat()
            if path.is_symlink():
                data = os.readlink(path).encode()
                mode = stat.S_IFLNK | 0o777
                nlink = 1
            elif path.is_dir():
                data = b""
                mode = stat.S_IFDIR | stat.S_IMODE(info.st_mode)
                nlink = 2
            elif path.is_file():
                data = path.read_bytes()
                mode = stat.S_IFREG | stat.S_IMODE(info.st_mode)
                nlink = 1
            else:
                fail(f"Unsupported file in initramfs root: {relative}")
            header = cpio_header(inode, name, mode, len(data), nlink)
            inode += 1
            raw_handle.write(header)
            raw_handle.write(name + b"\0")
            write_padding(raw_handle, len(header) + len(name) + 1)
            raw_handle.write(data)
            write_padding(raw_handle, len(data))
        for name, major, minor, mode in (
            (b"dev/console", 5, 1, 0o600),
            (b"dev/null", 1, 3, 0o666),
            (b"dev/kmsg", 1, 11, 0o600),
        ):
            header = cpio_header(inode, name, stat.S_IFCHR | mode, 0, 1, major, minor)
            inode += 1
            raw_handle.write(header)
            raw_handle.write(name + b"\0")
            write_padding(raw_handle, len(header) + len(name) + 1)
        trailer = b"TRAILER!!!"
        header = cpio_header(inode, trailer, 0, 0)
        raw_handle.write(header)
        raw_handle.write(trailer + b"\0")
        write_padding(raw_handle, len(header) + len(trailer) + 1)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with raw_path.open("rb") as source, destination.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, compresslevel=9, mtime=0) as compressed:
            shutil.copyfileobj(source, compressed)
    raw_path.unlink()
    destination.chmod(0o644)


def write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def validate_lock(env: dict[str, str], lock: dict[str, object]) -> None:
    if lock.get("schemaVersion") != 1:
        fail("Unsupported packages lock schema")
    alpine = lock.get("alpine")
    if not isinstance(alpine, dict):
        fail("Lock is missing alpine metadata")
    pairs = {
        "version": "ALPINE_VERSION", "branch": "ALPINE_BRANCH", "arch": "ALPINE_ARCH",
        "flavor": "ALPINE_FLAVOR", "isoSha256": "ALPINE_ISO_SHA256",
        "aportsCommit": "ALPINE_APORTS_COMMIT",
    }
    for lock_key, env_key in pairs.items():
        if alpine.get(lock_key) != env.get(env_key):
            fail(f"Config/lock mismatch for {env_key}; run script/update_dependencies.py")
    configured_roots = env.get("GUEST_ROOT_PACKAGES", "").split()
    if lock.get("rootPackages") != configured_roots:
        fail("Config/lock mismatch for GUEST_ROOT_PACKAGES; run script/update_dependencies.py")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONFIG)
    parser.add_argument("--lock", type=pathlib.Path, default=DEFAULT_LOCK)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "build", help="build root")
    parser.add_argument("--cache-dir", type=pathlib.Path, help="verified input cache (default: OUTPUT/cache)")
    parser.add_argument("--offline", action="store_true", help="forbid downloads and require a complete verified cache")
    parser.add_argument("--self-test", action="store_true", help="run guest path regression tests without building")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0
    if sys.platform != "linux":
        fail("This builder is Linux-only")
    for command in ("bsdtar", "unsquashfs", "depmod", "modinfo"):
        if shutil.which(command) is None:
            fail(f"Required host command not found: {command}")

    env = read_env(args.config)
    lock = json.loads(args.lock.read_text())
    validate_lock(env, lock)
    output = args.output.resolve()
    cache = (args.cache_dir or (output / "cache")).resolve()
    assets = output / "assets"
    provenance = output / "provenance"
    staging = output / "staging"
    for path in (assets, provenance, staging):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)
    (provenance / "packages").mkdir()

    alpine = lock["alpine"]
    iso_url = str(alpine["isoUrl"])
    iso = cache / "iso" / pathlib.PurePosixPath(iso_url).name
    atomic_download(iso_url, iso, str(alpine["isoSha256"]), args.offline)

    packages = lock.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("Lock contains no packages")
    runtime_packages = [package for package in packages if package.get("role", "runtime") == "runtime"]
    kernel_packages = [package for package in packages if package.get("role") == "kernel"]
    if len(kernel_packages) != 1:
        fail("Lock must contain exactly one role=kernel package")
    package_names = {str(package["name"]) for package in runtime_packages}
    missing_roots = sorted(set(lock.get("rootPackages", [])) - package_names)
    if missing_roots:
        fail(f"Lock is missing root packages: {', '.join(missing_roots)}")

    root = staging / "initramfs-root"
    root.mkdir()
    owners: dict[str, str] = {}
    package_records: list[dict[str, object]] = []
    for package in runtime_packages:
        package_root, record = prepare_apk(package, cache, staging, provenance, args.offline)
        overlay(package_root, root, str(package["name"]), owners)
        package_records.append(record)

    install_busybox_applets(root, owners)
    install_project_files(root, owners)
    for forbidden_firmware in (root / "lib/firmware", root / "usr/lib/firmware"):
        if forbidden_firmware.exists():
            fail(f"Firmware payloads are forbidden in the initramfs: {forbidden_firmware}")
    required_commands = (
        "bin/sh", "usr/bin/busybox", "sbin/ip", "usr/sbin/nft",
        "usr/bin/tcpdump",
    )
    for relative in required_commands:
        try:
            resolved_command = resolve_guest_path(root, relative)
        except GuestPathError as error:
            fail(f"Unsafe required guest command path {relative}: {error}")
        if resolved_command is None or not resolved_command.is_file():
            fail(f"Required guest command missing after locked APK extraction: {relative}")
        if not stat.S_IMODE(resolved_command.stat().st_mode) & 0o111:
            fail(f"Required guest command is not executable: {relative}")

    kernel_flavor = "lts"
    kernel_package = kernel_packages[0]
    if str(kernel_package["file"]).endswith(".apk"):
        package_root, record = prepare_apk(kernel_package, cache, staging, provenance, args.offline)
        package_records.append(record)
        vmlinuz, module_dir = kernel_apk_paths(package_root, str(kernel_package["version"]))
        kernel_input = {
            "schemaVersion": 2, "sourceType": "apk",
            "apkUrl": kernel_package["url"], "apkSha256": kernel_package["sha256"],
            "vmlinuzPath": "boot/vmlinuz-lts", "vmlinuzSha256": hash_file(vmlinuz),
        }
    else:
        # Keep the checked-in ISO lock buildable until the manual updater creates
        # and validates the first APK-based kernel lock.
        vmlinuz = staging / "vmlinuz-lts"
        modloop = staging / "modloop-lts"
        extract_member(iso, "boot/vmlinuz-lts", vmlinuz)
        extract_member(iso, "boot/modloop-lts", modloop)
        if hash_file(modloop) != kernel_package["sha256"]:
            fail("ISO modloop hash does not match the locked kernel provenance entry")
        modloop_root = staging / "modloop"
        run(["unsquashfs", "-no-progress", "-d", str(modloop_root), str(modloop)], stdout=subprocess.DEVNULL)
        dep_files = sorted(modloop_root.rglob("modules.dep"))
        if len(dep_files) != 1:
            fail(f"Expected one modules.dep in modloop, found {len(dep_files)}")
        module_dir = dep_files[0].parent
        kernel_input = {
            "schemaVersion": 1, "isoUrl": iso_url, "isoSha256": alpine["isoSha256"],
            "modloopPath": "boot/modloop-lts", "modloopSha256": hash_file(modloop),
        }
    image = assets / "Image-lts"
    extract_linux_image(vmlinuz, image)
    kernel_release = module_dir.name
    match = re.fullmatch(r"(.+)-(\d+)-lts", kernel_release)
    if not match:
        fail(f"Unexpected Alpine lts kernel release: {kernel_release}")
    package_version = f"{match.group(1)}-r{match.group(2)}"
    if package_version != kernel_package["version"]:
        fail(f"Kernel release {kernel_release} does not match locked {kernel_package['name']} {kernel_package['version']}")
    copied_modules, builtin_seeds = copy_module_closure(
        module_dir, root, kernel_release, env["KERNEL_MODULES"].split(), owners,
    )
    initramfs = assets / f"initramfs-thrurndis-{kernel_flavor}"
    write_initramfs(root, initramfs)

    # Restrict the map to final archive paths so overwritten package files do
    # not leave stale provenance records.
    final_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    missing_owners = sorted(final_paths - owners.keys())
    if missing_owners:
        fail(f"File provenance missing for: {', '.join(missing_owners[:10])}")
    file_map = {
        path: {"owner": owners[path], "sha256": hash_file(root / path)}
        for path in sorted(final_paths)
    }

    kernel_json = {
        **kernel_input,
        "kernelFlavor": kernel_flavor,
        "kernelRelease": kernel_release,
        "packageName": kernel_package["name"],
        "packageVersion": kernel_package["version"],
        "aportsCommit": kernel_package["aportsCommit"],
        "imagePath": image.relative_to(output).as_posix(),
        "imageSha256": hash_file(image),
        "modules": copied_modules,
        "modulePaths": [entry["path"] for entry in copied_modules],
        "builtInSeeds": builtin_seeds,
    }
    packages_json = {
        "schemaVersion": 1,
        "lockPath": os.path.relpath(args.lock.resolve(), output),
        "packages": package_records,
    }
    write_json(provenance / "packages.json", packages_json)
    write_json(provenance / "kernel.json", kernel_json)
    write_json(provenance / "file-map.json", file_map)

    print("Prepared locked Alpine ThruRNDIS assets:")
    print(f"  Kernel:          {image}")
    print(f"  Initramfs:       {initramfs}")
    print(f"  Kernel release:  {kernel_release}")
    print(f"  Runtime APKs:    {len(runtime_packages)}")
    print(f"  Kernel modules:  {len(copied_modules)} copied, {len(builtin_seeds)} built in")
    print(f"  Provenance:      {provenance}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
