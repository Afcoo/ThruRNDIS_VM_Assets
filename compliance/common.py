# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared, dependency-free helpers for the VM asset compliance tools."""

from __future__ import annotations

import ast
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 and earlier on non-CI developer hosts.
    tomllib = None  # type: ignore[assignment]
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


class ComplianceError(RuntimeError):
    """A fail-closed compliance or provenance error."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_text(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    temporary.chmod(mode)
    temporary.replace(path)


def write_json(path: Path, value: Any) -> None:
    write_text(path, canonical_json(value))


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ComplianceError(f"cannot read JSON {path}: {error}") from error


def require_relative_path(raw_path: str, label: str = "path") -> PurePosixPath:
    normalized = raw_path.removeprefix("./")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise ComplianceError(f"unsafe {label}: {raw_path!r}")
    return path


def source_date_epoch(repo: Path | None = None) -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH")
    if value:
        try:
            parsed = int(value)
        except ValueError as error:
            raise ComplianceError("SOURCE_DATE_EPOCH must be an integer") from error
        if parsed < 0:
            raise ComplianceError("SOURCE_DATE_EPOCH must not be negative")
        return parsed
    if repo is not None:
        result = subprocess.run(
            ["git", "-C", str(repo), "show", "-s", "--format=%ct", "HEAD"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip())
    return 0


def iso_timestamp(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    filename: str
    repository: str
    url: str
    sha256: str
    origin: str
    license_expression: str
    aports_commit: str
    datahash: str
    role: str
    dependencies: tuple[str, ...]

    @property
    def spdx_id(self) -> str:
        token = re.sub(r"[^A-Za-z0-9.-]+", "-", f"{self.name}-{self.version}")
        return f"SPDXRef-Package-{token}"


def _pick(mapping: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return default


def load_lock(path: Path) -> tuple[dict[str, Any], list[Package]]:
    raw = load_json(path)
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise ComplianceError(f"{path}: schemaVersion must be 1")
    alpine = raw.get("alpine")
    if not isinstance(alpine, dict):
        raise ComplianceError(f"{path}: alpine must be an object")
    for field in ("version", "branch", "arch", "flavor", "isoUrl", "isoSha256"):
        value = alpine.get(field)
        if not isinstance(value, str) or not value:
            raise ComplianceError(f"{path}: alpine.{field} is required")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", alpine["version"]):
        raise ComplianceError(f"{path}: alpine.version must be major.minor.patch")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+", alpine["branch"]):
        raise ComplianceError(f"{path}: alpine.branch must be v<major>.<minor>")
    if alpine["arch"] != "aarch64" or alpine["flavor"] != "standard":
        raise ComplianceError(f"{path}: only Alpine standard/aarch64 is supported")
    if not alpine["isoUrl"].startswith("https://"):
        raise ComplianceError(f"{path}: alpine.isoUrl must use HTTPS")
    if not re.fullmatch(r"[0-9a-f]{64}", alpine["isoSha256"]):
        raise ComplianceError(f"{path}: alpine.isoSha256 is not lowercase SHA-256")

    rows = raw.get("packages")
    if not isinstance(rows, list) or not rows:
        raise ComplianceError(f"{path}: packages must be a non-empty array")
    packages: list[Package] = []
    names: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ComplianceError(f"{path}: packages[{index}] must be an object")
        values = {
            "name": _pick(row, "name"),
            "version": _pick(row, "version"),
            "filename": _pick(row, "file", "filename"),
            "repository": _pick(row, "repository"),
            "url": _pick(row, "url"),
            "sha256": _pick(row, "sha256"),
            "origin": _pick(row, "origin"),
            "license_expression": _pick(row, "license", "licenseExpression"),
            "aports_commit": _pick(row, "aportsCommit", "aports_commit", "commit"),
            "datahash": _pick(row, "datahash", "dataHash", default=""),
            "role": _pick(row, "role", default="runtime"),
        }
        missing = [name for name, value in values.items() if name != "datahash" and not isinstance(value, str)]
        if missing:
            raise ComplianceError(f"{path}: packages[{index}] missing {', '.join(missing)}")
        if any(not value for name, value in values.items() if name != "datahash"):
            raise ComplianceError(f"{path}: packages[{index}] contains an empty required value")
        if values["name"] in names:
            raise ComplianceError(f"{path}: duplicate package {values['name']}")
        names.add(values["name"])
        if not re.fullmatch(r"[0-9a-f]{64}", values["sha256"]):
            raise ComplianceError(f"{path}: {values['name']} has an invalid SHA-256")
        if not re.fullmatch(r"[0-9a-f]{40}", values["aports_commit"]):
            raise ComplianceError(f"{path}: {values['name']} has an invalid aports commit")
        if values["role"] not in {"runtime", "kernel"}:
            raise ComplianceError(f"{path}: {values['name']} has unsupported role {values['role']!r}")
        for field in ("name", "origin"):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]*", values[field]):
                raise ComplianceError(f"{path}: {values['name']} has unsafe {field} {values[field]!r}")
        require_relative_path(values["filename"], f"{values['name']} package file")
        if values["role"] == "runtime" and "/" in values["filename"]:
            raise ComplianceError(f"{path}: runtime package file must be a basename: {values['filename']!r}")
        if not values["url"].startswith("https://") or not values["repository"].startswith("https://"):
            raise ComplianceError(f"{path}: {values['name']} package URLs must use HTTPS")
        dependencies = _pick(row, "dependencies", default=[])
        if not isinstance(dependencies, list) or not all(isinstance(item, str) for item in dependencies):
            raise ComplianceError(f"{path}: {values['name']}.dependencies must be strings")
        packages.append(Package(**values, dependencies=tuple(dependencies)))
    return raw, packages


def load_policy(path: Path) -> dict[str, Any]:
    try:
        if tomllib is not None:
            with path.open("rb") as handle:
                policy = tomllib.load(handle)
        else:
            policy = _load_simple_policy_toml(path)
    except (OSError, ValueError) as error:
        raise ComplianceError(f"cannot read policy {path}: {error}") from error
    if policy.get("version") != 1:
        raise ComplianceError(f"{path}: policy version must be 1")
    return policy


def _load_simple_policy_toml(path: Path) -> dict[str, Any]:
    """Parse the deliberately small policy grammar on Python before 3.11.

    This is not a general TOML implementation. It accepts only the root scalar
    and string-array assignments plus one-level tables used by the checked-in
    policy, and rejects every other construct.
    """

    lines = path.read_text(encoding="utf-8").splitlines()
    result: dict[str, Any] = {}
    table = result
    index = 0
    while index < len(lines):
        raw = lines[index].strip()
        index += 1
        if not raw or raw.startswith("#"):
            continue
        if raw.startswith("["):
            match = re.fullmatch(r"\[([A-Za-z0-9_-]+)\]", raw)
            if not match:
                raise ValueError(f"unsupported TOML table syntax at line {index}")
            name = match.group(1)
            if name in result:
                raise ValueError(f"duplicate TOML table {name}")
            table = {}
            result[name] = table
            continue
        if "=" not in raw:
            raise ValueError(f"invalid TOML assignment at line {index}")
        key, value_text = (part.strip() for part in raw.split("=", 1))
        if not re.fullmatch(r'(?:[A-Za-z_][A-Za-z0-9_-]*|"[^"\\]+")', key):
            raise ValueError(f"unsupported TOML key at line {index}: {key!r}")
        key = ast.literal_eval(key) if key.startswith('"') else key
        if value_text.startswith("["):
            while "]" not in value_text:
                if index >= len(lines):
                    raise ValueError(f"unterminated TOML array for {key}")
                next_line = lines[index].strip()
                index += 1
                if next_line and not next_line.startswith("#"):
                    value_text += "\n" + next_line
        try:
            value = ast.literal_eval(value_text)
        except (SyntaxError, ValueError) as error:
            raise ValueError(f"unsupported TOML value for {key}: {value_text!r}") from error
        if not isinstance(value, (str, int, list)):
            raise ValueError(f"unsupported TOML value type for {key}")
        if isinstance(value, list) and not all(isinstance(item, str) for item in value):
            raise ValueError(f"TOML array for {key} must contain only strings")
        if key in table:
            raise ValueError(f"duplicate TOML key {key}")
        table[key] = value
    return result


_LICENSE_TOKEN = re.compile(r"LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.+-]*|\(|\)")


def normalize_license(expression: str, policy: Mapping[str, Any]) -> str:
    aliases = policy.get("license_aliases", {})
    if not isinstance(aliases, dict):
        raise ComplianceError("license_aliases policy entry must be a table")
    for old, new in sorted(aliases.items(), key=lambda pair: len(pair[0]), reverse=True):
        expression = re.sub(rf"(?<![A-Za-z0-9.+-]){re.escape(old)}(?![A-Za-z0-9.+-])", new, expression)
    tokens = _LICENSE_TOKEN.findall(expression)
    compact = re.sub(r"\s+", "", expression)
    if "".join(tokens) != compact:
        raise ComplianceError(f"invalid SPDX expression syntax: {expression!r}")
    if not tokens:
        raise ComplianceError("empty license expression")

    allowed = set(policy.get("allowed_licenses", []))
    exceptions = set(policy.get("allowed_exceptions", []))
    forbidden = tuple(policy.get("forbidden_license_tokens", []))
    expect_license = True
    depth = 0
    normalized: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if any(marker in token for marker in forbidden):
            raise ComplianceError(f"forbidden license token {token!r}")
        upper = token.upper()
        if token == "(":
            if not expect_license:
                raise ComplianceError(f"invalid SPDX expression: {expression!r}")
            depth += 1
            normalized.append(token)
        elif token == ")":
            if expect_license or depth == 0:
                raise ComplianceError(f"invalid SPDX expression: {expression!r}")
            depth -= 1
            normalized.append(token)
            expect_license = False
        elif upper in {"AND", "OR"}:
            if expect_license:
                raise ComplianceError(f"invalid SPDX expression: {expression!r}")
            normalized.append(upper)
            expect_license = True
        elif upper == "WITH":
            if expect_license or index + 1 >= len(tokens):
                raise ComplianceError(f"invalid SPDX WITH expression: {expression!r}")
            exception = tokens[index + 1]
            if exception not in exceptions:
                raise ComplianceError(f"unreviewed SPDX exception {exception!r}")
            normalized.extend(("WITH", exception))
            index += 1
            expect_license = False
        else:
            if not expect_license or token not in allowed:
                if token not in allowed:
                    raise ComplianceError(f"unreviewed SPDX license {token!r}")
                raise ComplianceError(f"invalid SPDX expression: {expression!r}")
            normalized.append(token)
            expect_license = False
        index += 1
    if expect_license or depth:
        raise ComplianceError(f"incomplete SPDX expression: {expression!r}")
    return " ".join(normalized).replace("( ", "(").replace(" )", ")")


def parse_pkginfo(path: Path) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ComplianceError(f"cannot read package metadata {path}: {error}") from error
    for raw in lines:
        if not raw or raw.startswith("#"):
            continue
        if " = " in raw:
            key, value = raw.split(" = ", 1)
        elif len(raw) > 2 and raw[1] == ":":
            key, value = raw[0], raw[2:]
            key = {
                "P": "pkgname",
                "V": "pkgver",
                "L": "license",
                "o": "origin",
                "c": "commit",
                "D": "depend",
            }.get(key, key)
        else:
            continue
        if key in fields:
            current = fields[key]
            if not isinstance(current, list):
                current = [current]
            current.append(value)
            fields[key] = current
        else:
            fields[key] = value
    return fields


def pkginfo_index(directory: Path) -> dict[str, tuple[Path, dict[str, Any]]]:
    if not directory.is_dir():
        raise ComplianceError(f"missing package metadata directory: {directory}")
    result: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(directory.glob("*.PKGINFO")):
        fields = parse_pkginfo(path)
        name = fields.get("pkgname")
        if not isinstance(name, str) or not name:
            raise ComplianceError(f"{path}: missing pkgname")
        if name in result:
            raise ComplianceError(f"duplicate .PKGINFO for {name}")
        result[name] = (path, fields)
    return result


def validate_package_evidence(packages: Sequence[Package], metadata_dir: Path, apk_dir: Path) -> dict[str, Path]:
    packages = [package for package in packages if package.role == "runtime"]
    metadata = pkginfo_index(metadata_dir)
    archives: dict[str, Path] = {}
    expected_names = {package.name for package in packages}
    if set(metadata) != expected_names:
        missing = sorted(expected_names - set(metadata))
        extra = sorted(set(metadata) - expected_names)
        raise ComplianceError(f".PKGINFO set differs from lock; missing={missing}, extra={extra}")
    for package in packages:
        path, fields = metadata[package.name]
        comparisons = {
            "pkgver": package.version,
            "origin": package.origin,
            "license": package.license_expression,
            "commit": package.aports_commit,
        }
        for field, expected in comparisons.items():
            actual = fields.get(field)
            if actual != expected:
                raise ComplianceError(
                    f"{path}: {field} differs from lock for {package.name}: {actual!r} != {expected!r}"
                )
        if package.datahash and fields.get("datahash") != package.datahash:
            raise ComplianceError(f"{path}: datahash differs from lock for {package.name}")
        archive = apk_dir / package.filename
        if not archive.is_file():
            raise ComplianceError(f"missing locked APK: {archive}")
        actual_hash = sha256_file(archive)
        if actual_hash != package.sha256:
            raise ComplianceError(f"APK SHA-256 mismatch for {package.name}: {actual_hash} != {package.sha256}")
        archives[package.name] = archive
    return archives


@dataclass(frozen=True)
class CpioEntry:
    path: str
    mode: int
    data: bytes

    @property
    def kind(self) -> str:
        if stat.S_ISREG(self.mode):
            return "file"
        if stat.S_ISLNK(self.mode):
            return "symlink"
        if stat.S_ISDIR(self.mode):
            return "directory"
        if stat.S_ISCHR(self.mode):
            return "character-device"
        return "other"


def read_newc(path: Path) -> list[CpioEntry]:
    try:
        with gzip.open(path, "rb") as handle:
            blob = handle.read()
    except (OSError, gzip.BadGzipFile) as error:
        raise ComplianceError(f"cannot decompress initramfs {path}: {error}") from error
    offset = 0
    entries: list[CpioEntry] = []
    seen_paths: set[str] = set()

    def aligned(value: int) -> int:
        return (value + 3) & ~3

    while offset + 110 <= len(blob):
        header = blob[offset : offset + 110]
        if header[:6] not in {b"070701", b"070702"}:
            raise ComplianceError(f"invalid newc header in {path} at byte {offset}")
        try:
            fields = [int(header[6 + index * 8 : 14 + index * 8], 16) for index in range(13)]
        except ValueError as error:
            raise ComplianceError(f"invalid newc numeric field in {path}") from error
        mode = fields[1]
        size = fields[6]
        name_size = fields[11]
        if name_size < 1:
            raise ComplianceError(f"invalid newc pathname length in {path}")
        name_start = offset + 110
        name_end = name_start + name_size
        if name_end > len(blob) or blob[name_end - 1] != 0:
            raise ComplianceError(f"truncated newc pathname in {path}")
        try:
            name = blob[name_start : name_end - 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ComplianceError(f"non-UTF-8 newc pathname in {path}") from error
        data_start = aligned(name_end)
        data_end = data_start + size
        if data_end > len(blob):
            raise ComplianceError(f"truncated newc entry {name!r} in {path}")
        offset = aligned(data_end)
        if name == "TRAILER!!!":
            if any(blob[offset:]):
                raise ComplianceError(f"non-zero data follows newc trailer in {path}")
            return entries
        clean = str(require_relative_path(name, "initramfs path"))
        if clean != ".":
            if clean in seen_paths:
                raise ComplianceError(f"duplicate newc pathname in {path}: {clean}")
            seen_paths.add(clean)
            entries.append(CpioEntry(clean, mode, blob[data_start:data_end]))
    raise ComplianceError(f"missing newc trailer in {path}")


def load_file_map(path: Path) -> dict[str, dict[str, str]]:
    raw = load_json(path)
    if isinstance(raw, dict) and "files" in raw:
        raw = raw["files"]
    result: dict[str, dict[str, str]] = {}
    if isinstance(raw, dict):
        iterator = raw.items()
    elif isinstance(raw, list):
        iterator = ((row.get("path"), row) for row in raw if isinstance(row, dict))
    else:
        raise ComplianceError(f"{path}: file map must be an object or files array")
    for raw_name, raw_value in iterator:
        if not isinstance(raw_name, str):
            raise ComplianceError(f"{path}: file map path must be a string")
        name = str(require_relative_path(raw_name, "file-map path"))
        if isinstance(raw_value, str):
            record = {"owner": raw_value}
        elif isinstance(raw_value, dict):
            owner = _pick(raw_value, "owner", "package", "source")
            if not isinstance(owner, str):
                raise ComplianceError(f"{path}: {name} has no owner")
            record = {str(key): str(value) for key, value in raw_value.items() if value is not None}
            record["owner"] = owner
        else:
            raise ComplianceError(f"{path}: invalid mapping for {name}")
        if name in result:
            raise ComplianceError(f"{path}: duplicate mapping for {name}")
        result[name] = record
    return result


def verify_file_map(entries: Sequence[CpioEntry], file_map: Mapping[str, Mapping[str, str]], packages: Sequence[Package]) -> None:
    package_names = {package.name for package in packages if package.role == "runtime"}
    allowed_owners = package_names | {"project", "kernel"}
    # Symlinks carry no independent program data. Their target regular files
    # are mapped; every regular executable, library, and module is therefore
    # still required to have one concrete owner.
    relevant = {entry.path: entry for entry in entries if entry.kind == "file"}
    missing = sorted(set(relevant) - set(file_map))
    extra = sorted(set(file_map) - set(relevant))
    if missing or extra:
        raise ComplianceError(f"file-map differs from initramfs; missing={missing[:20]}, extra={extra[:20]}")
    for path, entry in relevant.items():
        record = file_map[path]
        owner = record.get("owner")
        if owner not in allowed_owners:
            raise ComplianceError(f"{path}: unknown provenance owner {owner!r}")
        expected_hash = record.get("sha256")
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise ComplianceError(f"{path}: file-map is missing a lowercase SHA-256")
        if expected_hash != hashlib.sha256(entry.data).hexdigest():
            raise ComplianceError(f"{path}: file-map SHA-256 differs from initramfs")


def check_initramfs_content(entries: Sequence[CpioEntry]) -> None:
    forbidden_parts = {".PKGINFO", ".cache"}
    forbidden_exact = {
        "wg0.conf", "wg", "wg-quick", "init-virtiofs-wgconf",
        "wg0-usb0-gateway",
    }
    for entry in entries:
        parts = PurePosixPath(entry.path).parts
        lower_name = PurePosixPath(entry.path).name.lower()
        if forbidden_parts.intersection(parts) or any(part.startswith(".SIGN") for part in parts):
            raise ComplianceError(f"staging metadata leaked into initramfs: {entry.path}")
        if parts[:2] == ("lib", "firmware") or parts[:3] == ("usr", "lib", "firmware"):
            raise ComplianceError(f"firmware is forbidden without explicit provenance: {entry.path}")
        if (
            lower_name in forbidden_exact
            or lower_name.startswith("wireguard.ko")
            or lower_name.endswith((".key", ".pem", ".p12", ".pfx"))
        ):
            raise ComplianceError(f"secret or runtime configuration leaked into initramfs: {entry.path}")


def git_commit(repo: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}\n?", result.stdout):
        raise ComplianceError(f"cannot determine builder commit in {repo}: {result.stderr.strip()}")
    return result.stdout.strip()


def deterministic_zip(source: Path, destination: Path, root_name: str, epoch: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    if temporary.exists():
        temporary.unlink()
    # ZIP cannot represent timestamps before 1980.
    date_time = datetime.fromtimestamp(max(epoch, 315532800), timezone.utc).timetuple()[:6]
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(source.rglob("*")):
            relative = path.relative_to(source).as_posix()
            archive_name = f"{root_name}/{relative}"
            if path.is_dir():
                info = zipfile.ZipInfo(archive_name + "/", date_time)
                info.create_system = 3
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
                archive.writestr(info, b"")
                continue
            if path.is_symlink():
                raise ComplianceError(f"asset archive must not contain symlinks: {path}")
            info = zipfile.ZipInfo(archive_name, date_time)
            info.create_system = 3
            executable = os.access(path, os.X_OK)
            info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    temporary.replace(destination)


def checksum_manifest(root: Path, exclude: Iterable[str] = ()) -> list[tuple[str, str]]:
    excluded = set(exclude)
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            relative = path.relative_to(root).as_posix()
            if relative not in excluded:
                rows.append((sha256_file(path), relative))
    return rows


def copy_tree_files(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ComplianceError(f"missing directory: {source}")
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_symlink():
            raise ComplianceError(f"symlink is not allowed in compliance evidence: {path}")
        if path.is_dir():
            (destination / relative).mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            target.chmod(0o644)
