<!--
SPDX-FileCopyrightText: 2026 Afcoo
SPDX-License-Identifier: GPL-2.0-or-later
-->

# ThruRNDIS VM Assets

This repository builds the minimal Alpine Linux `aarch64` kernel and initramfs
used by ThruRNDIS. The builder runs on Linux and records the exact Alpine ISO,
APK, kernel-module, source, and license provenance used for every distribution.
It does not build the macOS application and never creates WireGuard keys or
configuration files.

## License model

The repository-authored builder, compliance tooling, workflows, and guest init
scripts are licensed under `GPL-2.0-or-later`. Generated VM assets are a
multi-license aggregate: Linux, BusyBox, WireGuard tools, Alpine packages, and
other upstream components retain their respective licenses. The root `LICENSE`
therefore describes the repository-authored code; it must not be read as
relicensing third-party binaries. See [docs/LICENSING.md](docs/LICENSING.md)
for the distribution policy and corresponding-source distribution details.

## Build on Linux

The supported build environment is Ubuntu 24.04. Install the tools used by CI:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends \
  ca-certificates cpio curl file git jq kmod libarchive-tools pipx python3 \
  python3-venv qemu-system-arm qemu-system-data rsync shellcheck squashfs-tools \
  unzip xz-utils zip zstd
```

Creating the corresponding-source archive also requires a running Docker
Engine. GitHub-hosted Ubuntu runners provide Docker; local builders must install
and start it separately.

Build only from the checked-in Alpine and package lock:

```sh
./script/make_vm_assets \
  --config config/alpine.env \
  --lock config/packages.lock.json \
  --output build
./script/make_source_bundle \
  --lock config/packages.lock.json \
  --build-dir build \
  --output build/release/vm_assets-sources.tar.zst
python3 compliance/build_compliance.py \
  --lock config/packages.lock.json \
  --build-dir build \
  --asset-dir build/assets
python3 compliance/verify_compliance.py \
  --lock config/packages.lock.json \
  --build-dir build \
  --asset-dir build/assets \
  --source-bundle build/release/vm_assets-sources.tar.zst
```

A successful build writes `build/release/vm_assets.zip` with this public
layout:

```text
vm_assets/
├── Image-lts
├── initramfs-rtpvm-lts
├── manifest.json
├── SHA256SUMS
└── compliance/
    ├── THIRD_PARTY_NOTICES.md
    ├── SOURCE.md
    ├── sbom.spdx.json
    └── licenses/<origin>/...
```

The build is intentionally lock-driven. It does not silently select newer
packages. To propose an Alpine or APK refresh, run the **Update dependencies**
workflow manually; it verifies the candidate distribution and opens a pull
request instead of changing `main` directly.

## Verification and releases

Pushes and pull requests run shell linting, REUSE checks, a clean full build,
compliance validation, and a QEMU `aarch64` boot smoke test. The verification
workflow deliberately uploads no binary artifact.

Releases are also manual. Run the **Release VM assets** workflow with a tag in
the form `alpine-3.24.1-r1`. It creates a draft release, uploads and reads back
all five required assets, verifies their checksums, and publishes only after
every check passes:

- `vm_assets.zip`
- `vm_assets-sources.tar.zst`
- `sbom.spdx.json`
- `THIRD_PARTY_NOTICES.md`
- `SHA256SUMS`

GitHub's automatically generated repository archive is not corresponding
source for the third-party binaries. Keep the source bundle and notices
attached for as long as the binary release is available.
