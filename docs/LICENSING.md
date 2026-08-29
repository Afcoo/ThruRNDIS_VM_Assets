<!--
SPDX-FileCopyrightText: 2026 Afcoo
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Licensing and distribution policy

This document separates the license of this repository's original work from
the licenses of material assembled into a VM asset distribution. It describes
the project's conservative compliance process; it is not legal advice.

## Repository-authored work

Unless a file says otherwise, the builder, compliance tools, GitHub Actions
workflows, documentation, and files under `script/initramfs/` are:

```text
SPDX-FileCopyrightText: 2026 Afcoo
SPDX-License-Identifier: GPL-2.0-or-later
```

The complete GPL version 2 text is in `LICENSE` and
`LICENSES/GPL-2.0-or-later.txt`. `GPL-2.0-or-later` means recipients may use
GPL version 2 or, at their option, a later version published by the Free
Software Foundation. Relicensing the initially copied files assumes Afcoo owns
the copyright in those files; third-party material is not covered by that
assumption.

## Generated distribution

`vm_assets.zip` is a multi-license aggregate. Each packaged component keeps
its upstream copyright notices, license terms, and source obligations. In
particular, placing the repository under GPL does not relicense the Linux
kernel, BusyBox, Alpine packages, permissively licensed libraries, or any
future firmware.

Every binary distribution contains:

- `compliance/THIRD_PARTY_NOTICES.md`, identifying packaged components and
  their declared licenses;
- `compliance/licenses/<origin>/...`, preserving the applicable license,
  copyright, and NOTICE texts;
- `compliance/sbom.spdx.json`, an SPDX 2.3 inventory with versions, hashes,
  source revisions, licenses, and `CONTAINS` relationships; and
- `compliance/SOURCE.md`, mapping the distribution to its corresponding-source
  archive and offline rebuild instructions.

An SBOM, package URL, Alpine ISO, or GitHub's automatic source archive is not a
substitute for corresponding source.

## Corresponding source

Each published `vm_assets.zip` is accompanied in the same GitHub Release by
`vm_assets-sources.tar.zst`. The source bundle includes the release revision of
this repository plus the exact material required to rebuild every packaged
copyleft component: original APK metadata, pinned aports recipes and patches,
upstream distfiles, Linux and BusyBox sources, build configurations, install
scripts, module-build material, and license/NOTICE texts. A manifest records
the digest and provenance of every included source file.

The project keeps that source bundle, notices, SBOM, and checksums available
for as long as the corresponding binary Release remains available. Release
assets are not deleted or replaced in place. A corrected distribution receives
a new release revision.

## Automated policy gates

A release is rejected when any of these conditions holds:

- a final executable, shared library, kernel module, or package cannot be
  traced to repository-authored source or pinned package metadata;
- a license expression is empty, unknown, `NOASSERTION`, or an unapproved
  `LicenseRef`;
- an ISO, APK, aports revision, distfile, binary, or source checksum differs
  from its lock or manifest;
- required GPL/LGPL sources, patches, configurations, or build/install scripts
  are absent;
- a required Apache, BSD, MIT, X11, Zlib, copyright, or NOTICE text is absent;
- a private key, obsolete WireGuard configuration or tools, APK staging file,
  cache, undeclared firmware, or other prohibited file enters the
  distribution; or
- the archive, notices, SBOM, lock, source manifest, and checksum manifest do
  not describe the same content.

Firmware is denied by default. A future firmware blob may be added only after
its upstream `WHENCE`, license, redistributability, exact source, and package
provenance are recorded and accepted by the policy.

## Release checklist

A valid Release publishes exactly these project-built assets together:

```text
vm_assets.zip
vm_assets-sources.tar.zst
sbom.spdx.json
THIRD_PARTY_NOTICES.md
SHA256SUMS
```

The release workflow first creates a draft, uploads the complete set, downloads
it into a clean directory, verifies the asset allowlist and `SHA256SUMS`, and
only then makes the Release public. If an asset is missing, inconsistent, or
larger than GitHub's 2 GiB per-file limit, the workflow fails and leaves the
Release as a draft.
