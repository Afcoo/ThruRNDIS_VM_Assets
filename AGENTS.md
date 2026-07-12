# AGENTS.md

This repository builds redistributable Linux VM assets. Treat license and
source-provenance checks as release-blocking requirements, not documentation
extras.

## Repository Scope

- Repository-authored code is licensed under `GPL-2.0-or-later`.
- `vm_assets.zip` is a multi-license aggregate. Never label the whole archive
  as GPL, MIT, or any other single license.
- Do not copy files from the RNDIS application repository after the initial
  import. This repository has an independent history and release process.
- Keep the build Linux-only. Do not add a macOS or Xcode job.
- Do not add scheduled workflows. Dependency updates and releases are manual.

## Build and Provenance Rules

- Normal builds and releases consume `config/packages.lock.json`; only the
  manual dependency-update workflow may resolve a fresh APKINDEX.
- Every executable, shared library, kernel image, and kernel module in the
  final archive must map to repository-authored source or an exact Alpine
  package/source record.
- Preserve APK SHA-256, `.PKGINFO`, origin, license expression, and aports
  commit outside the initramfs. Do not leave package metadata or maintainer
  scripts inside the initramfs.
- Do not extend Alpine's opaque stock initramfs. Construct the root from the
  explicit locked APK closure and the required module dependency closure.
- Do not include firmware unless a required module declares it and the exact
  firmware license, notice, and source/provenance have been approved.

## Release Rules

- Never publish a binary-only artifact or Release.
- A public Release must contain `vm_assets.zip`,
  `vm_assets-sources.tar.zst`, `sbom.spdx.json`,
  `THIRD_PARTY_NOTICES.md`, and `SHA256SUMS`.
- Create Releases as drafts. Publish only after the binary, corresponding
  source, notices, SBOM, and checksums have all passed readback verification.
- GitHub's automatically generated repository source archive is not a
  substitute for the third-party corresponding-source bundle.
- Do not delete or replace a source bundle while its matching binary Release
  remains published.

## Minimum Verification

- Run shell syntax checks, ShellCheck, and `reuse lint`.
- Run the full clean Linux build and compliance verifier.
- Confirm that every APKBUILD source checksum and every downloaded artifact
  checksum matches the recorded value.
- Inspect the final initramfs for staging files, private keys, WireGuard
  configuration, package metadata, untracked binaries, and firmware.
- Confirm that the SPDX SBOM, notices, package lock, file provenance map, and
  both release archives agree before publishing.
