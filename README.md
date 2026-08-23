<!--
SPDX-FileCopyrightText: 2026 Afcoo
SPDX-License-Identifier: GPL-2.0-or-later
-->

# ThruRNDIS VM Assets

This repository builds the minimal Alpine Linux `aarch64` kernel and initramfs
used by [ThruRNDIS](https://github.com/Afcoo/ThruRNDIS). The builder runs on
Linux and records the exact Alpine ISO, APK, kernel-module, source, and license
provenance used for every distribution. It does not build the macOS application
or modify host routing; those responsibilities stay with the app's privileged
helper.

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
macOS IPv4 `/1` routes
-> VZNAT guest eth0
-> guest ingress policy routing and nftables masquerade
-> USB RNDIS usb0
```

The VZNAT guest address is discovered at every boot rather than fixed in the
assets. After DHCP, the guest reports the live address to the host over the
virtio console. Once `usb0` DHCP and DNS discovery, policy routing, forwarding,
NAT, and the DNS DNAT proxy are all ready, it reports a separate readiness
marker. The privileged helper may then install the two host IPv4 routes
(`0.0.0.0/1` and `128.0.0.0/1`) using the guest address as their next hop.

The guest accepts this transit path only when the packet arrives on `eth0` with
the source `/32` equal to `eth0`'s live default gateway, which is the macOS
host-side VZNAT address. Other VZNAT peers are not granted the RNDIS egress.

macOS points DNS at the guest VZNAT address. The guest captures IPv4 DNS
servers from the live `usb0` DHCP lease and DNATs host UDP/TCP port 53 traffic
from its `eth0` address to the first RNDIS DNS server. DNS therefore uses the
same ingress allowlist, policy route, conntrack return path, and masquerade as
other forwarded IPv4 traffic.

The machine-readable console contract is line-oriented:

```text
THRURNDIS_VZNAT_IPV4=<guest-ipv4>
THRURNDIS_VZNAT_CIDR=<guest-ipv4/prefix>
THRURNDIS_VZNAT_GATEWAY=<vznat-gateway-ipv4>
THRURNDIS_RNDIS_ROUTE_READY=1
```

`THRURNDIS_RNDIS_ROUTE_READY=0` is emitted before gateway state is rebuilt and
when `usb0` disappears. The host must withdraw its `/1` routes on that marker,
VM termination, or loss of the control channel. WireGuard, its userspace tools,
kernel module, and the former configuration VirtioFS share are not included.

### Initramfs boot responsibilities

`script/lib/build_assets.py` embeds the files in `script/initramfs/` and writes
the BusyBox `inittab` that runs them. These are guest-side programs baked into
the initramfs; the macOS app does not execute them on the host.

| BusyBox init action | Script | Responsibility inside the guest |
| --- | --- | --- |
| `::sysinit` | `rcS` | Mount early filesystems, create device and console state, initialize `mdev`, load console and kernel-command-line modules, and prepare the RAM-backed shell environment. |
| `::wait` | `init-rndis` | Load the XHCI, USB networking, and RNDIS host modules, then rescan devices before later network stages. |
| `::wait` | `init-network` | Configure the VZNAT NIC `eth0` with DHCP and report its runtime IPv4, CIDR, and gateway markers before the RNDIS watcher starts. |
| `::respawn` | `usb0-watcher` | Watch the fixed RNDIS interface `usb0`, retry gateway setup when it appears or becomes incomplete, and clear stale state when it disappears. |
| watcher helper | `eth0-usb0-gateway` | Clear stale VZNAT DNS, acquire `usb0` DHCP so BusyBox atomically writes RNDIS DNS, route only the live host-side VZNAT source `/32` arriving on `eth0` through the RNDIS gateway, enable IPv4 forwarding, proxy guest-address UDP/TCP DNS to RNDIS DNS, maintain scoped nftables rules, and publish readiness changes. |
| `hvc0::respawn` | `init-console` | Attach a login shell to the virtio console and restore it after the shell exits. |

The split is intentional: boot-time RNDIS module preparation must not depend on
`usb0` already existing, while the respawned watcher must tolerate USB devices
appearing late, disconnecting, or reconnecting during a VM session.

## License model

The repository-authored builder, compliance tooling, workflows, and guest init
scripts are licensed under `GPL-2.0-or-later`. Generated VM assets are a
multi-license aggregate: Linux, BusyBox, Alpine packages, and other upstream
components retain their respective licenses. The root `LICENSE`
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

Pushes, pull requests, and manual **Verify VM assets** runs perform shell
linting, REUSE checks, a clean full build, compliance validation, and a QEMU
`aarch64` boot smoke test. After every successful run, the workflow uploads a
seven-day Actions artifact named `vm-assets-<commit-sha>` containing the same
five-file set listed below. This temporary verification artifact is not a
GitHub Release and is not selected by the app's latest-release installer.

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
