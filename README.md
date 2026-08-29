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
macOS `192.168.100.2/24` IPv4 `/1` routes
-> feth and the VM-created VZNAT bridge
-> guest eth0 `192.168.100.1/24`
-> guest ingress policy routing and nftables masquerade
-> USB RNDIS usb0
```

The VZNAT DHCP lease remains dynamic. After DHCP, the guest reports its live
address, CIDR, and gateway to the host over the virtio console so the privileged
helper can identify the VM-created bridge. The guest then adds the separate
fixed host-link address `192.168.100.1/24` to `eth0`; the helper configures the
host side as `192.168.100.2/24` and uses `192.168.100.1` as the next hop for the
two IPv4 routes (`0.0.0.0/1` and `128.0.0.0/1`). The DHCP lease is bridge
discovery metadata, not the data-plane next hop.

The guest accepts this transit path only for source `192.168.100.2/32` arriving
on `eth0`. Other VZNAT peers are not granted RNDIS egress. macOS points DNS at
`192.168.100.1`; the guest captures IPv4 DNS servers from the live `usb0` DHCP
lease and DNATs host UDP/TCP traffic addressed to `192.168.100.1:53` to the
first RNDIS DNS server. DNS uses the same fixed source allowlist, policy route,
conntrack return path, and masquerade as other forwarded IPv4 traffic.

Before VM start, the app can optionally append
`thrurndis.port_forward=<ports>` to the kernel command line. The value uses
commas for individual entries and hyphens for inclusive ranges, for example
`5050,6550-6557`. The sourced `port-forwarding` module validates the
canonical expression and prepares one `inet_service` interval set plus paired
TCP and UDP DNAT, forward, and SNAT rule fragments. `eth0-usb0-gateway`
includes them in its single owned `thrurndis` nftables transaction. DNAT
changes only the destination address to `192.168.100.2`, preserving the
original destination port. The value is immutable for that VM boot.

The machine-readable console contract is line-oriented:

```text
THRURNDIS_VZNAT_IPV4=<guest-ipv4>
THRURNDIS_VZNAT_CIDR=<guest-ipv4/prefix>
THRURNDIS_VZNAT_GATEWAY=<vznat-gateway-ipv4>
THRURNDIS_RNDIS_IPV4=<canonical-rndis-ipv4>
THRURNDIS_RNDIS_ROUTE_READY=1
THRURNDIS_PORT_FORWARD_STATE=inactive
THRURNDIS_PORT_FORWARD_STATE=pending:<ports>
THRURNDIS_PORT_FORWARD_STATE=active:<ports>
```

`THRURNDIS_RNDIS_IPV4` contains the canonical IPv4 address assigned to `usb0`
and is emitted immediately before the ready marker after the complete gateway
status succeeds. An empty `THRURNDIS_RNDIS_IPV4=` is emitted while gateway
state is rebuilt and after teardown so the host can discard a stale address.
`THRURNDIS_RNDIS_ROUTE_READY=0` is emitted before gateway state is rebuilt and
when `usb0` disappears. The host must withdraw its `/1` routes on that marker,
VM termination, or loss of the control channel. It may install them through
`192.168.100.1` only after the marker becomes `1`. WireGuard, its userspace
tools, kernel module, and the former configuration VirtioFS share are not
included.

`THRURNDIS_PORT_FORWARD_STATE=error:<code>` reports an invalid boot value or
failed rule setup. Current codes are `invalid-state`, `nft-unavailable`,
`nft-install`, and `rule-status`. `pending` means the boot configuration is
valid but the RNDIS gateway is not ready; `active` is emitted only after the
matching rules pass the guest's exact status checks.

### Initramfs boot responsibilities

`script/lib/build_assets.py` embeds the files in `script/initramfs/` and writes
the BusyBox `inittab` that runs them. These are guest-side programs baked into
the initramfs; the macOS app does not execute them on the host.

| BusyBox init action | Script | Responsibility inside the guest |
| --- | --- | --- |
| `::sysinit` | `rcS` | Mount early filesystems, create device and console state, initialize `mdev`, load console and kernel-command-line modules, and prepare the RAM-backed shell environment. |
| `::wait` | `init-rndis` | Load the XHCI, USB networking, and RNDIS host modules, then rescan devices before later network stages. |
| `::wait` | `init-network` | Configure the VZNAT NIC `eth0` with DHCP, report its runtime IPv4, CIDR, and gateway markers for bridge discovery, and add the fixed secondary host-link address `192.168.100.1/24`. |
| `::respawn` | `usb0-watcher` | Watch the fixed RNDIS interface `usb0`, retry gateway setup when it appears or becomes incomplete, and clear stale state when it disappears. |
| sourced module | `port-forwarding` | Parse and validate the optional canonical port/range set from `/proc/cmdline`, prepare one shared TCP/UDP interval set plus rule fragments and marker state, and inspect exact installed state without mutating nftables. |
| watcher helper | `eth0-usb0-gateway` | Source the port-forwarding module, clear stale VZNAT DNS, acquire `usb0` DHCP so BusyBox atomically writes RNDIS DNS, route only `192.168.100.2/32` arriving on `eth0` through the RNDIS gateway, enable IPv4 forwarding, proxy `192.168.100.1:53` UDP/TCP DNS to RNDIS DNS, apply the complete owned nftables table in one transaction, and publish the canonical RNDIS IPv4 plus readiness changes. |
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

`manifest.json` contains an integer `assetVersion` sourced from
`config/vm-assets.json`. This is the consumer-visible compatibility version of
the VM asset layout and contract; it is separate from both the manifest's
`schemaVersion` and the Alpine version. Increment it only for incompatible
changes such as required file/layout changes or breaking host/guest boot and
control-contract changes. Alpine or APK refreshes, rebuilds, and additive
backward-compatible metadata do not increment it. Consumers must treat a
missing value as an unversioned legacy asset and accept only format versions
they explicitly support. Versioned Release tags use the matching
`V<assetVersion>-` namespace.

The build is intentionally lock-driven. It does not silently select newer
packages. To propose an Alpine or APK refresh, run the **Update dependencies**
workflow manually; it verifies the candidate distribution and opens a pull
request instead of changing `main` directly.

## Verification and releases

Pushes, pull requests, and manual **Verify VM assets** runs perform shell
linting, REUSE checks, a clean full build, compliance validation, and a QEMU
`aarch64` boot smoke test. After every successful run, the workflow uploads the
five files listed below as independently downloadable, seven-day Actions
artifacts from the same verified commit. It uploads `vm_assets.zip` only after
the four companion artifacts succeed, so selecting the binary does not require
downloading the much larger corresponding-source archive. This temporary
verification artifact set is not a GitHub Release and is not selected by the
app's versioned Release-list installer.

Releases are also manual. Run the **Release VM assets** workflow without any
inputs. It reads the VM asset and Alpine versions from the checked-in
configuration and selects the tag automatically. The first Release for a
version uses `r1`; later Releases use one more than the largest revision in
that version's namespace. A failed run's latest draft is reused only when its
tag and target both match the checked-out commit. Any malformed, orphaned, or
otherwise ambiguous matching tag/Release state stops the workflow. The
workflow creates a draft release, uploads and reads back all five required
assets, verifies their checksums, and publishes a formal, non-prerelease
Release only after every check passes:

- `vm_assets.zip`
- `vm_assets-sources.tar.zst`
- `sbom.spdx.json`
- `THIRD_PARTY_NOTICES.md`
- `SHA256SUMS`

Versioned VM asset Releases are published with `--latest=false`. The legacy
`alpine-3.24.1-r2` Release remains GitHub Latest so ThruRNDIS v0.3.0 continues
to resolve its unversioned assets through `/releases/latest`. New app versions
list Releases and select only tags in their supported namespace, beginning
with `V1-*`.

GitHub's automatically generated repository archive is not corresponding
source for the third-party binaries. Keep the source bundle and notices
attached for as long as the binary release is available.
