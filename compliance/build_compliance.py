#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Afcoo
# SPDX-License-Identifier: GPL-2.0-or-later
"""Create the license, provenance, manifest, SPDX, and binary archive payload."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

from common import (
    ComplianceError,
    Package,
    canonical_json,
    check_initramfs_content,
    checksum_manifest,
    copy_tree_files,
    deterministic_zip,
    git_commit,
    iso_timestamp,
    load_file_map,
    load_json,
    load_lock,
    load_policy,
    load_vm_asset_config,
    normalize_license,
    read_newc,
    sha256_file,
    source_date_epoch,
    validate_package_evidence,
    verify_file_map,
    write_json,
    write_text,
)


REPOSITORY_URL = "https://github.com/Afcoo/ThruRNDIS_VM_Assets"


def parse_arguments() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=root / "config/packages.lock.json")
    parser.add_argument("--policy", type=Path, default=root / "compliance/license-policy.toml")
    parser.add_argument("--build-dir", type=Path, default=root / "build")
    parser.add_argument("--asset-dir", type=Path)
    parser.add_argument("--license-dir", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--no-archive", action="store_true")
    parser.add_argument("--repo", type=Path, default=root)
    return parser.parse_args()


def unique_asset(asset_dir: Path, pattern: str, label: str) -> Path:
    matches = sorted(path for path in asset_dir.glob(pattern) if path.is_file())
    if len(matches) != 1:
        raise ComplianceError(f"expected exactly one {label} matching {asset_dir / pattern}; found {matches}")
    if matches[0].stat().st_size == 0:
        raise ComplianceError(f"empty {label}: {matches[0]}")
    return matches[0]


def validate_asset_allowlist(asset_dir: Path, kernel_image: Path, initramfs: Path) -> None:
    allowed = {
        kernel_image.name,
        initramfs.name,
        "manifest.json",
        "SHA256SUMS",
        "compliance",
    }
    actual = {path.name for path in asset_dir.iterdir()}
    unexpected = sorted(actual - allowed)
    if unexpected:
        raise ComplianceError(f"asset directory contains files outside the distribution allowlist: {unexpected}")
    for path in asset_dir.rglob("*"):
        if path.is_symlink():
            raise ComplianceError(f"asset distribution must not contain symlinks: {path}")


def find_iso(build_dir: Path, iso_url: str) -> Path:
    basename = iso_url.rsplit("/", 1)[-1]
    candidates = [build_dir / "cache/iso" / basename, build_dir / "cache" / basename]
    matches = [path for path in candidates if path.is_file()]
    if len(matches) != 1:
        raise ComplianceError(f"cannot find exactly one cached locked ISO {basename}: {matches}")
    return matches[0]


def normalized_licenses(packages: Sequence[Package], policy: dict[str, Any]) -> dict[str, str]:
    result = {}
    for package in packages:
        try:
            result[package.name] = normalize_license(package.license_expression, policy)
        except ComplianceError as error:
            raise ComplianceError(f"{package.name}: {error}") from error
    project_license = str(policy.get("project_license", ""))
    normalize_license(project_license, policy)
    return result


def validate_kernel_provenance(
    path: Path,
    packages: Sequence[Package],
    iso_hash: str,
    iso_url: str,
    kernel_image: Path,
    initramfs_entries: Sequence[Any],
    file_map: dict[str, dict[str, str]],
) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise ComplianceError(f"{path}: kernel provenance must be an object")
    kernel_packages = [package for package in packages if package.role == "kernel"]
    if len(kernel_packages) != 1:
        raise ComplianceError("lock must contain exactly one packages[] entry with role=kernel")
    kernel = kernel_packages[0]
    exact = {
        "packageName": kernel.name,
        "packageVersion": kernel.version,
        "aportsCommit": kernel.aports_commit,
        "modloopSha256": kernel.sha256,
        "isoUrl": iso_url,
    }
    for field, expected in exact.items():
        if value.get(field) != expected:
            raise ComplianceError(f"{path}: {field} differs from the locked kernel provenance")
    if value.get("imageSha256") != sha256_file(kernel_image):
        raise ComplianceError(f"{path}: imageSha256 differs from {kernel_image.name}")
    if value.get("schemaVersion") != 1 or value.get("kernelFlavor") != "lts":
        raise ComplianceError(f"{path}: unsupported kernel provenance schema/flavor")
    kernel_release = value.get("kernelRelease")
    match = re.fullmatch(r"(.+)-(\d+)-lts", str(kernel_release))
    if match is None or f"{match.group(1)}-r{match.group(2)}" != kernel.version:
        raise ComplianceError(f"{path}: kernelRelease does not map to the locked package version")
    if value.get("modloopPath") != "boot/modloop-lts" or value.get("imagePath") != "assets/Image-lts":
        raise ComplianceError(f"{path}: kernel input/output paths differ from the distribution contract")
    provenance_iso_hash = value.get("isoSha256")
    if provenance_iso_hash != iso_hash:
        raise ComplianceError(f"{path}: ISO SHA-256 differs from the locked ISO")
    modules = value.get("modules") or value.get("copiedModules")
    if not isinstance(modules, list) or not modules:
        raise ComplianceError(f"{path}: copied module provenance is missing")
    for module in modules:
        if (
            not isinstance(module, dict)
            or not isinstance(module.get("path"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(module.get("sha256", "")))
        ):
            raise ComplianceError(f"{path}: malformed copied module provenance")
    declared_modules = {module["path"]: module["sha256"] for module in modules}
    if len(declared_modules) != len(modules):
        raise ComplianceError(f"{path}: duplicate copied module path")
    if value.get("modulePaths") != [module["path"] for module in modules]:
        raise ComplianceError(f"{path}: modulePaths differs from copied module provenance")
    entry_hashes = {
        entry.path: hashlib.sha256(entry.data).hexdigest()
        for entry in initramfs_entries
        if entry.kind == "file"
    }
    kernel_module_paths = {
        name
        for name, record in file_map.items()
        if record.get("owner") == "kernel" and re.search(r"\.ko(?:\.(?:gz|xz|zst))?$", name)
    }
    if set(declared_modules) != kernel_module_paths:
        raise ComplianceError(
            f"{path}: module inventory differs from kernel-owned initramfs modules; "
            f"missing={sorted(kernel_module_paths - set(declared_modules))}, "
            f"extra={sorted(set(declared_modules) - kernel_module_paths)}"
        )
    for module_path, expected_hash in declared_modules.items():
        if entry_hashes.get(module_path) != expected_hash:
            raise ComplianceError(f"{path}: copied module hash differs for {module_path}")
    return value


def validate_packages_provenance(
    path: Path,
    build_dir: Path,
    lock_path: Path,
    packages: Sequence[Package],
) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise ComplianceError(f"{path}: unsupported package provenance schema")
    raw_lock_path = value.get("lockPath")
    if not isinstance(raw_lock_path, str) or (build_dir / raw_lock_path).resolve() != lock_path.resolve():
        raise ComplianceError(f"{path}: lockPath does not resolve to the active dependency lock")
    rows = value.get("packages")
    if not isinstance(rows, list):
        raise ComplianceError(f"{path}: packages must be an array")
    by_name = {
        row.get("name"): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    runtime = [package for package in packages if package.role == "runtime"]
    if len(by_name) != len(rows) or set(by_name) != {package.name for package in runtime}:
        raise ComplianceError(f"{path}: runtime package set differs from lock")
    for package in runtime:
        row = by_name[package.name]
        expected = {
            "version": package.version,
            "origin": package.origin,
            "license": package.license_expression,
            "apkSha256": package.sha256,
        }
        for field, expected_value in expected.items():
            if row.get(field) != expected_value:
                raise ComplianceError(f"{path}: {package.name}.{field} differs from lock")
        raw_metadata = row.get("pkginfoPath")
        if not isinstance(raw_metadata, str):
            raise ComplianceError(f"{path}: {package.name}.pkginfoPath is missing")
        metadata_path = (build_dir / raw_metadata).resolve()
        expected_metadata = (build_dir / "provenance/packages" / f"{package.name}-{package.version}.PKGINFO").resolve()
        if metadata_path != expected_metadata or not metadata_path.is_file():
            raise ComplianceError(f"{path}: {package.name}.pkginfoPath is not the exact provenance record")
        if row.get("pkginfoSha256") != sha256_file(metadata_path):
            raise ComplianceError(f"{path}: {package.name}.pkginfoSha256 differs")
    return value


def copy_license_evidence(
    license_source: Path,
    destination: Path,
    packages: Sequence[Package],
    repo: Path,
) -> dict[str, list[str]]:
    origins = sorted({package.origin for package in packages})
    evidence: dict[str, list[str]] = {}
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for origin in origins:
        source = license_source / origin
        target = destination / origin
        if not source.is_dir():
            raise ComplianceError(f"missing upstream license evidence for {origin}: {source}")
        copy_tree_files(source, target)
        files = [path for path in sorted(target.rglob("*")) if path.is_file()]
        if not files or any(path.stat().st_size == 0 for path in files):
            raise ComplianceError(f"empty upstream license evidence for {origin}: {source}")
        evidence[origin] = [path.relative_to(destination).as_posix() for path in files]

    project_license = repo / "LICENSES/GPL-2.0-or-later.txt"
    if not project_license.is_file() or project_license.stat().st_size == 0:
        raise ComplianceError(f"missing project license text: {project_license}")
    project_target = destination / "project/GPL-2.0-or-later.txt"
    project_target.parent.mkdir(parents=True)
    shutil.copyfile(project_license, project_target)
    project_target.chmod(0o644)
    evidence["project"] = [project_target.relative_to(destination).as_posix()]
    return evidence


def make_notices(
    packages: Sequence[Package],
    licenses: dict[str, str],
    evidence: dict[str, list[str]],
    policy: dict[str, Any],
) -> str:
    rows = [
        "# Third-Party Notices",
        "",
        "`vm_assets` is a multi-license aggregate. Each contained component remains",
        "under its own upstream license; the aggregate is not relicensed as a whole.",
        "The project-authored builder and guest init scripts are licensed under",
        f"`{policy['project_license']}`.",
        "",
        "| Package | Version | Role | Origin | SPDX license | aports commit | Artifact SHA-256 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for package in sorted(packages, key=lambda item: item.name):
        rows.append(
            f"| `{package.name}` | `{package.version}` | `{package.role}` | `{package.origin}` | "
            f"`{licenses[package.name]}` | `{package.aports_commit}` | `{package.sha256}` |"
        )
    rows.extend(("", "## Copyright, license, and notice files", ""))
    for origin, paths in sorted(evidence.items()):
        rows.append(f"### {origin}")
        rows.append("")
        rows.extend(f"- `licenses/{path}`" for path in paths)
        rows.append("")
    rows.extend(
        (
            "The exact package recipes, patches, configuration files, upstream distfiles,",
            "and source manifest are supplied in the paired `vm_assets-sources.tar.zst`",
            "release asset. See `SOURCE.md` for the corresponding-source distribution details.",
            "",
        )
    )
    return "\n".join(rows)


def make_source_notice(packages: Sequence[Package]) -> str:
    commits = sorted({package.aports_commit for package in packages})
    return "\n".join(
        (
            "# Source for VM Assets",
            "",
            "The corresponding source for this exact binary distribution is the",
            "`vm_assets-sources.tar.zst` asset attached to the same GitHub Release.",
            "It contains the builder source, original APK metadata and hashes, exact",
            "aports recipes and local files, verified upstream distfiles, build",
            "configuration, license texts, and an independently verifiable manifest.",
            "GitHub's automatically generated source archives are not a substitute.",
            "",
            f"Repository: {REPOSITORY_URL}",
            f"Aports commits represented: {', '.join(commits)}",
            "",
            "This paired corresponding-source distribution must remain available for as long as this binary Release",
            "is published. See `BUILDING.md` in that source asset for reconstruction.",
            "",
        )
    )


def aggregate_license_expression(expressions: Iterable[str]) -> str:
    unique = sorted(set(expressions))
    if not unique:
        raise ComplianceError("cannot form aggregate SPDX expression from an empty set")
    return " AND ".join(f"({expression})" if " " in expression else expression for expression in unique)


def make_sbom(
    lock: dict[str, Any],
    packages: Sequence[Package],
    licenses: dict[str, str],
    builder_commit: str,
    epoch: int,
) -> dict[str, Any]:
    alpine = lock["alpine"]
    seed = hashlib.sha256(
        canonical_json({"commit": builder_commit, "alpine": alpine, "packages": [package.sha256 for package in packages]}).encode()
    ).hexdigest()
    project_expression = "GPL-2.0-or-later"
    aggregate = aggregate_license_expression([project_expression, *licenses.values()])
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"ThruRNDIS VM assets Alpine {alpine['version']}",
        "documentNamespace": f"{REPOSITORY_URL}/spdx/{seed}",
        "creationInfo": {
            "created": iso_timestamp(epoch),
            "creators": ["Tool: ThruRNDIS-compliance/1", "Organization: Afcoo"],
            "licenseListVersion": "3.25",
        },
        "documentDescribes": ["SPDXRef-Package-vm-assets"],
        "packages": [
            {
                "name": "vm_assets",
                "SPDXID": "SPDXRef-Package-vm-assets",
                "versionInfo": f"alpine-{alpine['version']}",
                "downloadLocation": REPOSITORY_URL,
                "filesAnalyzed": False,
                "licenseConcluded": aggregate,
                "licenseDeclared": aggregate,
                "copyrightText": "Copyright information is documented per contained package in compliance/licenses.",
                "supplier": "Organization: Afcoo",
                "primaryPackagePurpose": "OPERATING-SYSTEM",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:generic/ThruRNDIS_VM_Assets@{builder_commit}",
                    }
                ],
            }
        ],
        "relationships": [],
    }
    document["packages"].append(
        {
            "name": "ThruRNDIS VM asset builder",
            "SPDXID": "SPDXRef-Package-builder",
            "versionInfo": builder_commit,
            "downloadLocation": f"{REPOSITORY_URL}/tree/{builder_commit}",
            "filesAnalyzed": False,
            "licenseConcluded": project_expression,
            "licenseDeclared": project_expression,
            "copyrightText": "Copyright (C) 2026 Afcoo",
            "supplier": "Organization: Afcoo",
            "primaryPackagePurpose": "SOURCE",
        }
    )
    document["relationships"].append(
        {
            "spdxElementId": "SPDXRef-Package-vm-assets",
            "relationshipType": "GENERATED_FROM",
            "relatedSpdxElement": "SPDXRef-Package-builder",
        }
    )
    for package in sorted(packages, key=lambda item: item.name):
        purpose = "OPERATING-SYSTEM" if package.role == "kernel" else "LIBRARY"
        external_refs = [
            {
                "referenceCategory": "OTHER",
                "referenceType": "https://github.com/alpinelinux/aports/commit",
                "referenceLocator": package.aports_commit,
            }
        ]
        if package.role == "runtime":
            external_refs.insert(
                0,
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": (
                        f"pkg:apk/alpine/{package.name}@{package.version}"
                        f"?arch={alpine['arch']}&distro=alpine-{alpine['version']}"
                    ),
                },
            )
        document["packages"].append(
            {
                "name": package.name,
                "SPDXID": package.spdx_id,
                "versionInfo": package.version,
                "downloadLocation": package.url,
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": package.sha256}],
                "licenseConcluded": licenses[package.name],
                "licenseDeclared": licenses[package.name],
                "copyrightText": f"See compliance/licenses/{package.origin}/ and THIRD_PARTY_NOTICES.md.",
                "supplier": "Organization: Alpine Linux",
                "sourceInfo": f"origin={package.origin}; aportsCommit={package.aports_commit}; role={package.role}",
                "primaryPackagePurpose": purpose,
                "externalRefs": external_refs,
            }
        )
        document["relationships"].append(
            {
                "spdxElementId": "SPDXRef-Package-vm-assets",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": package.spdx_id,
            }
        )
    return document


def build_manifest(
    lock: dict[str, Any],
    packages: Sequence[Package],
    licenses: dict[str, str],
    asset_dir: Path,
    provenance_dir: Path,
    asset_version: int,
    builder_commit: str,
    epoch: int,
) -> dict[str, Any]:
    artifacts = []
    for digest, relative in checksum_manifest(asset_dir, exclude=("manifest.json", "SHA256SUMS")):
        path = asset_dir / relative
        artifacts.append({"path": relative, "sha256": digest, "size": path.stat().st_size})
    provenance = {}
    for filename in ("packages.json", "kernel.json", "file-map.json"):
        path = provenance_dir / filename
        provenance[filename] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    return {
        "schemaVersion": 1,
        "assetVersion": asset_version,
        "created": iso_timestamp(epoch),
        "builder": {"repository": REPOSITORY_URL, "commit": builder_commit},
        "alpine": lock["alpine"],
        "artifacts": artifacts,
        "packages": [
            {
                "name": package.name,
                "version": package.version,
                "origin": package.origin,
                "role": package.role,
                "license": licenses[package.name],
                "sha256": package.sha256,
                "aportsCommit": package.aports_commit,
            }
            for package in sorted(packages, key=lambda item: item.name)
        ],
        "provenance": provenance,
    }


def run(arguments: argparse.Namespace) -> None:
    build_dir = arguments.build_dir.resolve()
    asset_dir = (arguments.asset_dir or build_dir / "assets").resolve()
    license_dir = (arguments.license_dir or build_dir / "source-bundle/licenses").resolve()
    archive = (arguments.archive or build_dir / "release/vm_assets.zip").resolve()
    repo = arguments.repo.resolve()
    lock, packages = load_lock(arguments.lock.resolve())
    asset_config = load_vm_asset_config(repo / "config/vm-assets.json")
    policy = load_policy(arguments.policy.resolve())
    licenses = normalized_licenses(packages, policy)
    required_origins = set(policy.get("required_source_origins", []))
    actual_origins = {package.origin for package in packages}
    if not required_origins.issubset(actual_origins):
        raise ComplianceError(f"required source origins missing from lock: {sorted(required_origins - actual_origins)}")

    kernel_image = unique_asset(asset_dir, "Image-*", "kernel image")
    initramfs = unique_asset(asset_dir, "initramfs-*", "initramfs")
    validate_asset_allowlist(asset_dir, kernel_image, initramfs)
    provenance_dir = build_dir / "provenance"
    for filename in ("packages.json", "kernel.json", "file-map.json"):
        if not (provenance_dir / filename).is_file():
            raise ComplianceError(f"missing build provenance: {provenance_dir / filename}")
    apk_dir = build_dir / "cache/apks"
    validate_package_evidence(packages, provenance_dir / "packages", apk_dir)
    validate_packages_provenance(
        provenance_dir / "packages.json", build_dir, arguments.lock.resolve(), packages
    )
    iso = find_iso(build_dir, lock["alpine"]["isoUrl"])
    iso_hash = sha256_file(iso)
    if iso_hash != lock["alpine"]["isoSha256"]:
        raise ComplianceError(f"ISO SHA-256 mismatch: {iso_hash} != {lock['alpine']['isoSha256']}")
    entries = read_newc(initramfs)
    check_initramfs_content(entries)
    file_map = load_file_map(provenance_dir / "file-map.json")
    verify_file_map(entries, file_map, packages)
    validate_kernel_provenance(
        provenance_dir / "kernel.json",
        packages,
        iso_hash,
        lock["alpine"]["isoUrl"],
        kernel_image,
        entries,
        file_map,
    )

    compliance_dir = asset_dir / "compliance"
    if compliance_dir.exists():
        shutil.rmtree(compliance_dir)
    compliance_dir.mkdir(parents=True)
    evidence = copy_license_evidence(license_dir, compliance_dir / "licenses", packages, repo)
    write_text(compliance_dir / "THIRD_PARTY_NOTICES.md", make_notices(packages, licenses, evidence, policy))
    write_text(compliance_dir / "SOURCE.md", make_source_notice(packages))

    commit = git_commit(repo)
    epoch = source_date_epoch(repo)
    write_json(compliance_dir / "sbom.spdx.json", make_sbom(lock, packages, licenses, commit, epoch))
    manifest = build_manifest(
        lock,
        packages,
        licenses,
        asset_dir,
        provenance_dir,
        asset_config["assetVersion"],
        commit,
        epoch,
    )
    write_json(asset_dir / "manifest.json", manifest)
    checksums = checksum_manifest(asset_dir, exclude=("SHA256SUMS",))
    write_text(asset_dir / "SHA256SUMS", "".join(f"{digest}  {relative}\n" for digest, relative in checksums))

    if not arguments.no_archive:
        deterministic_zip(asset_dir, archive, "vm_assets", epoch)
        print(f"Wrote {archive} ({sha256_file(archive)})")
    print(f"Wrote compliance payload to {compliance_dir}")


def main() -> int:
    try:
        run(parse_arguments())
    except ComplianceError as error:
        print(f"compliance build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
