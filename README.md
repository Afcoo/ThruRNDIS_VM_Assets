<!--
SPDX-FileCopyrightText: 2026 Afcoo
SPDX-License-Identifier: GPL-2.0-or-later
-->

# ThruRNDIS VM Assets

This repository builds the minimal Alpine Linux `aarch64` kernel and initramfs
used by [ThruRNDIS](https://github.com/Afcoo/ThruRNDIS). The builder runs on
Linux and records the exact Alpine ISO, APK, kernel-module, source, and license
provenance used for every distribution. It does not build the macOS application
and never creates WireGuard keys or configuration files.

## Role in ThruRNDIS

ThruRNDIS does not bundle or build these Linux assets. Users download
`vm_assets.zip` from this repository's Releases, verify it with the attached
`SHA256SUMS`, extract it, and select the resulting `vm_assets` folder in the
app. The app passes `Image-lts` to `VZLinuxBootLoader` as the guest kernel and
`initramfs-thrurndis-lts` as its initial RAM disk. The initramfs supplies the
entire RAM-backed guest userspace; an optional user-managed scratch disk is
separate and does not replace the initramfs root.

Inside ThruRNDIS, the guest built here is the forwarding boundary for this IPv4
data path:

```text
macOS WireGuard client
-> VZNAT guest endpoint
-> guest wg0
-> guest policy routing and nftables masquerade
-> USB RNDIS usb0
```

WireGuard keys and configuration are deliberately outside the release assets.
The macOS app creates `Shared/wg0.conf` and exposes only that file's directory
to the guest through the read-only `thrurndis-wireguard` VirtioFS share. This
keeps persistent secrets and user configuration under app ownership while the
initramfs owns guest boot, device preparation, and packet forwarding.

### Initramfs boot responsibilities

`script/lib/build_assets.py` embeds the files in `script/initramfs/` and writes
the BusyBox `inittab` that runs them. These are guest-side programs baked into
the initramfs; the macOS app does not execute them on the host.

| BusyBox init action | Script | Responsibility inside the guest |
| --- | --- | --- |
| `::sysinit` | `rcS` | Mount early filesystems, create device and console state, initialize `mdev`, load console and kernel-command-line modules, and prepare the RAM-backed shell environment. |
| `::wait` | `init-rndis` | Load the XHCI, USB networking, and RNDIS host modules, then rescan devices before later network stages. |
| `::wait` | `init-virtiofs-wgconf` | Load `virtiofs`, mount `thrurndis-wireguard` read-only at `/run/thrurndis-wireguard`, and require a nonempty `wg0.conf`. |
| `::once` | `init-network` | Configure the VZNAT NIC `eth0` with DHCP, report `THRURNDIS_WG_ENDPOINT=<guest-nat-ip>:<listen-port>`, and start `wg0` from the shared configuration. |
| `::respawn` | `usb0-watcher` | Watch the fixed RNDIS interface `usb0`, retry gateway setup when it appears or becomes incomplete, and clear stale state when it disappears. |
| watcher helper | `wg0-usb0-gateway` | Acquire `usb0` DHCP, derive the source prefix from the live `wg0` CIDR, install source policy routing through the RNDIS gateway, enable IPv4 forwarding, and maintain the scoped `wg0`-to-`usb0` nftables rules. |
| `hvc0::respawn` | `init-console` | Attach a login shell to the virtio console and restore it after the shell exits. |

The split is intentional: boot-time RNDIS module preparation must not depend on
`usb0` already existing, while the respawned watcher must tolerate USB devices
appearing late, disconnecting, or reconnecting during a VM session.

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
  python3-venv qemu-system-arm rsync shellcheck squashfs-tools unzip xz-utils zip zstd
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
├── initramfs-thrurndis-lts
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
