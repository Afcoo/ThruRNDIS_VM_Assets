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

## Role in ThruRNDIS

- This repository is the production and release owner for the Linux kernel,
  initramfs, guest userspace, kernel-module closure, and guest init scripts
  consumed by [Afcoo/ThruRNDIS](https://github.com/Afcoo/ThruRNDIS).
- The ThruRNDIS app does not bundle or build these assets. Its baseline user
  flow downloads `vm_assets.zip` from this repository's Releases, verifies the
  attached `SHA256SUMS`, extracts it, and selects the `vm_assets` folder. The
  app uses `Image-lts` as the `VZLinuxBootLoader` kernel and
  `initramfs-thrurndis-lts` as the initial RAM disk. A user-managed scratch disk
  is optional and separate from the RAM-backed initramfs root.
- The guest is the packet-forwarding boundary for `macOS 192.168.100.2/24 /1
  routes -> feth and the VM-created VZNAT bridge -> guest eth0
  192.168.100.1/24 -> ingress policy routing and nftables masquerade -> USB
  RNDIS usb0`. The app and privileged helper configure the host link and
  routes but do not forward packet payloads themselves.
- macOS uses fixed guest host-link address `192.168.100.1` as its DNS server.
  DNS packets from fixed host source `192.168.100.2/32` addressed to
  `192.168.100.1:53` are DNATed for both UDP and TCP to the first usable IPv4
  DNS server from the live `usb0` DHCP lease, then follow the same policy route
  and masquerade path as other host traffic.
- The VZNAT DHCP subnet and guest lease are runtime-assigned and exist to let
  the helper discover the VM-created bridge. Never embed a fixed VZNAT DHCP
  address or subnet in `vm_assets.zip`, the source bundle, manifests, examples,
  or build inputs. The separate fixed host-link subnet is `192.168.100.0/24`.
  WireGuard and its former VirtioFS configuration share are no longer part of
  the guest architecture; do not reintroduce keys, configuration, tools,
  modules, or legacy init scripts.

### Guest init contract

`script/lib/build_assets.py` installs `script/initramfs/*` into the initramfs
and writes the BusyBox `inittab`. These scripts execute inside the Linux guest;
they are not host-side setup scripts and are not run by the macOS app.

- `rcS` (`::sysinit`) mounts the early filesystems, creates device and console
  state, initializes `mdev`, loads console and kernel-command-line modules, and
  prepares the RAM-backed shell environment.
- `init-rndis` (`::wait`) loads the XHCI, USB networking, and RNDIS host modules
  and rescans devices. Keep this boot-time preparation separate from the
  watcher so it does not depend on `usb0` already existing.
- `init-network` (`::wait`) configures the VZNAT NIC `eth0` with DHCP, adds the
  fixed secondary host-link address `192.168.100.1/24`, and emits the
  machine-readable `THRURNDIS_VZNAT_IPV4`, `THRURNDIS_VZNAT_CIDR`, and
  `THRURNDIS_VZNAT_GATEWAY` console markers from the live lease. Those markers
  identify the VM-created bridge; they are not the data-plane address. The host
  must not install its `/1` routes through `192.168.100.1` until the
  gateway-ready marker is also `1`.
- `init-mdns` (`::respawn`) uses `exec` to run Avahi in the foreground. BusyBox
  init is the sole process supervisor and restart owner for Avahi; the gateway
  and its sourced modules must never daemonize, kill, or restart it. Avahi
  remains resident when `usb0` is absent and follows interface appearance,
  address changes, detach, and reconnect itself.
- `usb0-watcher` (`::respawn`) watches the fixed RNDIS interface `usb0`, retries
  gateway setup when the interface appears or its state becomes incomplete,
  and clears stale gateway state when the interface disappears. It must remain
  tolerant of late USB attachment, detach, and reconnect.
- `eth0-usb0-gateway` is the watcher's `up`, `down`, and `status` helper. It
  obtains `usb0` DHCP. Its policy route and nftables rules admit only fixed host
  source `192.168.100.2/32` arriving on `eth0`, then forward it through the
  RNDIS gateway. It enables IPv4 forwarding, owns the narrow
  `eth0`-to-`usb0` rules, and DNATs UDP/TCP DNS addressed to
  `192.168.100.1:53` to RNDIS DNS. It emits
  `THRURNDIS_RNDIS_IPV4=<canonical-ipv4>` immediately before readiness after
  the complete gateway status succeeds. It emits an empty
  `THRURNDIS_RNDIS_IPV4=` while rebuilding or after teardown so the host can
  discard stale device addresses. It emits
  `THRURNDIS_RNDIS_ROUTE_READY=1` only after all gateway state succeeds and
  emits `THRURNDIS_RNDIS_ROUTE_READY=0` before rebuild or after teardown.
- `port-forwarding` is a side-effect-free shell module sourced from the
  fixed path `/usr/local/libexec/thrurndis/port-forwarding` by
  `eth0-usb0-gateway`. It parses the optional immutable kernel argument
  `thrurndis.port_forward=<ports>`. The value is a canonical comma-separated
  list of individual ports and inclusive hyphenated ranges. It rejects empty,
  unsorted, overlapping, adjacent, duplicated, descending, leading-zero, and
  out-of-range entries, prepares one nftables interval set plus validated rule
  fragments, reports marker values, and inspects the exact installed state. It
  is not an init action or runtime control daemon.
- Optional TCP and UDP forwarding adds one owned `inet_service` interval set
  and fixed rules to the `thrurndis` nftables table for that VM boot. TCP and
  UDP packets whose destination port belongs to that set are DNATed to host
  `192.168.100.2` without port translation, admitted only on
  `usb0 -> eth0`, and SNATed to guest `192.168.100.1`. The guest emits
  `THRURNDIS_PORT_FORWARD_STATE=inactive`,
  `pending:<ports>`, `active:<ports>`, or
  `error:<code>` on the system console. Changing the mapping requires a new VM
  boot.
- Whenever `usb0` has its RNDIS DHCP address, independently of optional port
  forwarding, Avahi publishes that address as the fixed link-local mDNS name
  `thrurndis.local` on `usb0` only. The advertisement is IPv4-only, does not
  reflect mDNS between interfaces, and must not publish example SSH/SFTP
  services or DNS servers. Treat an Avahi failure, stale interface state,
  daemon exit, or fallback collision name such as
  `thrurndis-2.local` as incomplete gateway state; never report the gateway
  ready under a name other than exactly `thrurndis.local`.
- `mdns-advertising` is the gateway's side-effect-free Avahi status module. It
  waits for and validates the init-supervised, privilege-dropped foreground
  daemon, exact name, live address, and `usb0` multicast membership. It must
  not mutate Avahi process state. The nftables prerouting chain must exempt
  IPv4 mDNS multicast
  `224.0.0.251:5353` before the optional UDP forwarding rule so forwarding port
  5353 cannot capture name-resolution queries.
- `eth0-usb0-gateway` remains the sole owner and mutator of the complete
  `thrurndis` nftables table. The sourced module must never invoke `nft` for
  mutation or install its rules in a separate transaction.
- Before `usb0` DHCP, `eth0-usb0-gateway` clears `/etc/resolv.conf`; Alpine's
  BusyBox DHCP script then atomically writes the live RNDIS DNS from option 6.
  The gateway accepts only the first value routable as IPv4. Do not hard-code a
  public resolver or treat the earlier VZNAT DHCP resolver as RNDIS upstream.
- `init-console` (`hvc0::respawn`) attaches the interactive shell to the Virtio
  console and restores it when the shell exits.

Keep the inittab wiring and these responsibility boundaries synchronized with
the scripts. In particular, do not fold RNDIS module preparation into the
runtime watcher and do not make the VZNAT one-shot wait for `usb0`. Keep the
one-shot ahead of the watcher so `eth0` DHCP completes before `usb0` DHCP can
alter the guest's main routing table. Keep foreground Avahi under its own
`::respawn` action rather than making the watcher or gateway its supervisor.

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

- Never publish a binary-only Release or distribute `vm_assets.zip` as part of
  an incomplete verification artifact set. A `Verify VM assets` run that
  distributes `vm_assets.zip` must expose exactly five independently
  downloadable Actions artifacts from the same verified commit and with the
  same retention: `vm_assets.zip`,
  `vm_assets-sources.tar.zst`, `sbom.spdx.json`, `THIRD_PARTY_NOTICES.md`, and
  `SHA256SUMS`. Upload `vm_assets.zip` only after all four companion artifacts
  have uploaded successfully so a failed run cannot leave a binary-only set.
- A public Release must contain `vm_assets.zip`,
  `vm_assets-sources.tar.zst`, `sbom.spdx.json`,
  `THIRD_PARTY_NOTICES.md`, and `SHA256SUMS`.
- Create Releases as drafts. Publish only after the binary, corresponding
  source, notices, SBOM, and checksums have all passed readback verification.
- Versioned Release tags use
  `V<assetVersion>-alpine-<ALPINE_VERSION>-r<N>`, where both versions
  match the checked-in configuration. Legacy `alpine-*` and former
  `vm-assets-v*` tags are separate namespaces and never contribute to the
  versioned revision number.
- Publish versioned artifacts as formal, non-prerelease Releases with
  `--latest=false`. Keep the legacy `alpine-3.24.1-r2` Release as GitHub Latest
  for ThruRNDIS v0.3.0 clients that still request `/releases/latest`.
- GitHub's automatically generated repository source archive is not a
  substitute for the third-party corresponding-source bundle.
- Do not delete or replace a source bundle while its matching binary Release
  remains published.

## Agent-Driven Update-and-Release Runbook

### Authority boundary

- Perform this runbook's external writes only when the user explicitly asks
  for the complete dependency **update-and-release** operation. That request
  authorizes dispatching both workflows, reviewing and merging the one PR
  created by the updater, and publishing the resulting Release through the
  release workflow.
- A stage-specific request authorizes only that stage. In particular, an
  explicit dependency-update request authorizes dispatching
  `.github/workflows/update-dependencies.yml` and allowing it to create its
  validated PR, but not merging that PR or publishing a Release. An explicit
  release request authorizes `.github/workflows/release.yml` for the current
  validated default branch, but not a dependency update or PR merge. Requests
  only to inspect versions, check whether an update exists, or explain the
  process remain read-only.
- The full-operation authority does not permit bypassing branch protection,
  force-pushing, manually publishing an incomplete draft, deleting or
  replacing tags/Releases, or making unrelated code changes. Stop and report
  whenever one of those actions would be required.
- Never add or enable a schedule. `Update dependencies` and
  `Release VM assets` must remain `workflow_dispatch`-only workflows.

### Update and merge

1. Record the current default-branch commit and confirm no earlier update or
   release workflow is still running. Dispatch `Update dependencies` against
   the default branch and identify the newly created run unambiguously; do not
   attach to a pre-existing run merely because it has the same workflow name.
2. Wait for the run to finish and require `conclusion=success`. If its
   `Detect dependency changes` step reports `changed=false`, the operation is
   complete: no PR was created, so do not merge anything and do not create a
   Release for the unchanged lock.
3. When changes exist, obtain the PR URL created by that exact workflow run.
   Confirm that the PR targets the default branch, comes from its
   `automation/alpine-...` branch, and changes only `config/alpine.env` and
   `config/packages.lock.json`.
4. Review the generated dependency/license diff. Verify the Alpine version,
   ISO checksum, package versions, licenses, origins, aports commits, artifact
   checksums, runtime/kernel roles, and package additions/removals. Treat any
   unexplained license or provenance change as blocking.
5. Require both the completed `Update dependencies` run and every required PR
   check, including `Verify VM assets`, to succeed for the PR head commit.
   Never merge a pending, skipped, cancelled, stale, or failing validation.
6. Squash-merge the validated PR using its Angular-style subject and delete
   the automation branch. Do not use an administrator bypass. Record the new
   default-branch commit produced by the merge.
7. Wait for the push-triggered `Verify VM assets` run on that exact merged
   default-branch commit. Require `conclusion=success`; a successful PR run is
   not a substitute for this post-merge main verification.

### Select and publish the tag

1. Re-read `assetVersion` from `config/vm-assets.json` and `ALPINE_VERSION` from
   `config/alpine.env` at the verified merged commit. Require a positive integer
   asset version and `major.minor.patch` Alpine version. Immediately before
   release dispatch, confirm the default branch still points to that same
   verified commit; if it moved, stop and verify the new commit before
   recalculating.
2. List all GitHub Releases, including drafts, and repository tags matching
   `V<assetVersion>-alpine-<ALPINE_VERSION>-r<N>`. Reject duplicate
   revision numbers, a tag without its corresponding Release, a Release without
   its tag, or any malformed matching name. Separately require
   `/releases/latest` to resolve to the published, non-prerelease legacy
   `alpine-3.24.1-r2` Release.
3. Calculate the expected next tag deterministically for review of the
   workflow's automatic selection:
   - If no Release exists for this asset-version namespace and the merged
     `ALPINE_VERSION`, use
     `V<assetVersion>-alpine-<ALPINE_VERSION>-r1`, even when legacy
     tags or older Alpine versions have Releases.
   - If Releases already exist for the same Alpine version, use one greater
     than the largest revision in the same asset-version namespace:
     `max(r<N>) + 1`.
   - Exception for retrying this runbook: if its failed release attempt left a
     draft at the intended next tag and that draft targets the same verified
     commit, reuse that tag. Do not increment merely because the failed draft
     exists.
4. Dispatch `Release VM assets` against the default branch without inputs.
   Wait for the exact new run and require `conclusion=success`. Require its
   automatically selected tag to equal the expected tag from the previous
   step. The workflow must check out the previously verified commit; a moved
   target is blocking.
5. Confirm from the run that `Ensure draft Release at the checked-out commit`
   succeeded before any upload, and that `Upload, read back, and publish the
   draft` succeeded. This proves the workflow created/reused a draft, uploaded
   the assets, downloaded them again, checked `SHA256SUMS`, byte-compared the
   readback, and only then published it.
6. Independently read the final Release and require all of the following:
   - `targetCommitish` is the verified merged default-branch commit.
   - `isDraft` is `false`.
   - `isPrerelease` is `false`, and the Release is not GitHub Latest.
   - `/releases/latest` still resolves to `alpine-3.24.1-r2`.
   - The asset allowlist contains exactly five non-empty files and no others:
     `vm_assets.zip`, `vm_assets-sources.tar.zst`, `sbom.spdx.json`,
     `THIRD_PARTY_NOTICES.md`, and `SHA256SUMS`.
   - A fresh download of all five files passes `sha256sum --check SHA256SUMS`.
   Report the published tag, Release URL, target commit, and five asset names.

### Failure handling

- If the update workflow fails or is cancelled, do not create/merge a PR or
  start a Release. Report the first failing step and its relevant log.
- If the updater reports no change, stop successfully without releasing.
- If PR scope, provenance review, or any PR check fails, leave the PR unmerged
  and do not release. Never weaken a check or edit the generated lock by hand
  to force it through.
- If merge is blocked, stop rather than bypassing protection. If the merged
  default-branch verification fails, keep the merge but do not tag or release.
- A release failure may leave a draft and tag. Never manually publish that
  draft, delete it, replace it, or advance to another revision to conceal the
  failure. Inspect its `isDraft`, target commit, and assets. The same workflow
  and tag may be retried only when the draft still targets the verified commit
  and the failure was transient or has been corrected within the user's
  authorized scope. Otherwise stop and report the draft URL and exact failure.
- If a release is unexpectedly already published, targets another commit, has
  an unexpected asset, or has an ambiguous tag/draft state, make no mutation
  and stop for user direction.
- Treat timeouts and lost run identifiers as ambiguous state: read back the
  workflow, PR, tag, and Release state before deciding. Never infer success
  from a partially completed run and never dispatch duplicate runs blindly.

## Minimum Verification

- Run shell syntax checks, ShellCheck, and `reuse lint`.
- Run the full clean Linux build and compliance verifier.
- Confirm that every APKBUILD source checksum and every downloaded artifact
  checksum matches the recorded value.
- Inspect the final initramfs for staging files, private keys, legacy WireGuard
  or VirtioFS configuration artifacts, package metadata, untracked binaries,
  and firmware.
- Confirm that the SPDX SBOM, notices, package lock, file provenance map, and
  both release archives agree before publishing.
