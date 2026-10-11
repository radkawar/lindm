# Arch Linux

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Arch Linux                                                                                              |
| ----------------- | ------------------------------------------------------------------------------------------------------- |
| inventory         | implemented                                                                                             |
| lifecycle         | implemented                                                                                             |
| dispatch          | implemented                                                                                             |
| packages          | gated: not implemented for Arch Linux                                                                   |
| accounts          | gated: not implemented for Arch Linux                                                                   |
| sysctl            | gated: not implemented for Arch Linux                                                                   |
| definitions       | gated: not implemented for Arch Linux                                                                   |
| password          | gated: not implemented for Arch Linux                                                                   |
| firewall          | gated: not implemented for Arch Linux                                                                   |
| encryption        | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| wipe              | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| report-loss       | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| lock              | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| recovery-sanitize | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| self-update       | implemented                                                                                             |
| assistance        | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| advisories        | implemented                                                                                             |
| os-update         | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release |
| release-upgrade   | gated: release upgrade is not implemented                                                               |

<!-- END GENERATED platform-capabilities -->

Arch is a **snapshot-qualified rolling platform**, not a moving `latest` support
claim. The launch target is x86_64. The recorded input is official arch-boxes
`20261001.604814`, paired with Arch Linux Archive repository date `2026-10-02`.
Image state and subsequent repository state are separate pins
([`arch-20261001-x86_64.json`](../../lab/images/arch-20261001-x86_64.json):2-19).

[Verification](../verification.md#1-launch-platform-qualification) is authoritative:
on that cloud snapshot, x86_64 native inspection (184 packages), the full signed
pacman 0.7.0→0.7.1 automatic-trust lifecycle and connected dispatch passed on
local KVM (2026-10-10). No complete release cell is certified. Desktop,
encrypted install, physical hardware, whole-system upgrade/rollback and air-gap
results do not follow from these cloud records.

**Arch Linux ARM is a separate derivative**, not an aarch64 build of this
qualification row. The pinned official arch-boxes input has architecture x86_64;
there is no recorded official aarch64 image or native lane to substitute. The
architecture boundary and upstream policy reference are retained in
`docs/verification.md:296-304`. Cross-compiling an agent does not change it.

## Packaging, signing, repositories, paths and LSM

Arch agent packaging explicitly selects `FormatArch`; default builds remain
DEB/RPM. The deterministic `.pkg.tar.zst` contains `.PKGINFO`, `.MTREE`,
`.BUILDINFO` and fixed `.INSTALL` lifecycle callbacks. The build record describes
lindm's assembler, not a fictitious makepkg/chroot build. Detached package
signatures and a signed pacman sync database are implemented
([`internal/packaging/doc.go`](../../internal/packaging/doc.go):30-42).

The repository admits one version per product and one architecture. The generated
configuration requires `PackageRequired DatabaseRequired TrustedOnly`; importing
and locally trusting the exact pinned signer is a separate caller responsibility
([`arch_publish.go`](../../internal/packaging/arch_publish.go):26-68).
The lab uses an isolated pacman keyring, disables automatic key retrieval, and
requires a signed repository for each agent version
([`vm_arch_linux.go`](../../internal/vmlab/vm_arch_linux.go):38-80).
Neither AUR packages nor third-party repository compatibility is qualified by this
lindm-only repository.

The installed binary is `/usr/libexec/lindm/lindm-agent`; configuration is
`/etc/lindm/{agent,executor}.json`, state is `/var/lib/lindm/{agent,executor}`, and
the root-owned runtime socket is `/run/lindm/executor.sock`
([`layout.go`](../../internal/packaging/layout.go):15-46;
[`lindm-agent.service`](../../internal/packaging/assets/lindm-agent.service):9-17;
[`lindm-executor.service`](../../internal/packaging/assets/lindm-executor.service):9-15).
Fixed lifecycle code refuses unsafe state ownership/symlinks, resolves rather than
invents the `lindm` UID, and retains account/journal/spool on removal
([`lifecycle.sh`](../../internal/packaging/assets/lifecycle.sh):30-109,137-142).

Record actual kernel, CPU baseline and LSM mode, not an assumed Arch default
(`docs/verification.md:171-175`). Package signature success is not evidence of a
qualified AppArmor/SELinux policy. Trust domains remain separate as described in
the [shared guide](README.md#shared-implementation-boundaries).

## Agent services and sandbox

The root executor and unprivileged `lindm` network units retain their separate
state and identity roles. The network service has empty capability sets; both
units use private devices, strict system protection and `NoNewPrivileges`.
The executor's address family is AF_UNIX only
([`lindm-agent.service`](../../internal/packaging/assets/lindm-agent.service):18-50;
[`lindm-executor.service`](../../internal/packaging/assets/lindm-executor.service):17-61).

The 2026-10-10 lifecycle and dispatch passes ran these units from signed pacman
packages, through enrollment, publication, reboot, reinstall, revocation and
missing-journal hold. Storage access requires the explicit per-target action
drop-in, not removal of `PrivateDevices` or broad block-device access.

## Inventory and per-field quirks

- Genuine Arch may omit `VERSION_ID`; the collector preserves that field as
  unavailable while still selecting pacman. It does not synthesize a date/version
  from the manifest
  ([`inventory_linux.go`](../../internal/agent/inventory/inventory_linux.go):46-62;
  [`packages_linux.go`](../../internal/agent/inventory/packages_linux.go):51-64).
- Package inventory reads bounded `/var/lib/pacman/local/*/desc` data directly,
  not repository metadata or a shell. No-follow descriptors, directory/file
  stability checks and duplicate checks reject changed, malformed or partial
  observations ([`pacman_linux.go`](../../internal/agent/inventory/pacman_linux.go):21-140).
  Native epoch/pkgver/pkgrel and `any` versus machine architecture are retained;
  independent lab truth uses `pacman -Q` and `pacman -Qi`
  (`docs/verification.md:745-749`).
- Pacman packages have no RPM module field. Stock Arch need not expose `CPE_NAME`;
  DNF repository fields are not a substitute for pacman repository inventory
  ([`inventory_unavailable_linux.go`](../../internal/vmlab/inventory_unavailable_linux.go):21,28-32,62-70).
- CPU, memory, storage, network/default routes, firmware, TPM, sessions, users,
  power and application backends remain independently status-bearing categories
  ([`details_linux.go`](../../internal/agent/inventory/details_linux.go):135-165).
  In the recorded SeaBIOS/no-TPM cloud guest, unavailable Secure Boot/TPM-version
  fields must be interpreted against those measured capabilities, not reported as
  false successful security checks. Optional-field reasons are explicit
  ([`inventory_unavailable_linux.go`](../../internal/vmlab/inventory_unavailable_linux.go):20-26).

A matching collector/oracle failure is not a health pass; see the
[shared strict-health rule](README.md#shared-implementation-boundaries).

## Updates and snapshot boundaries

Before any vendor transaction, the maintained guest path writes an exact dated
Archive mirror, currently
[`2026/10/02`](https://archive.archlinux.org/repos/2026/10/02/).
The signed cloud image defines initial installed state; the Archive date defines
subsequent vendor content
([`vm_arch_linux.go`](../../internal/vmlab/vm_arch_linux.go):18-31).
The separate signed lindm repository does not admit a vendor partial upgrade.

The product contract is pacman/libalpm with a **whole-system compatible upgrade
plan**, not unsupported partial upgrades (`docs/architecture.md:1294-1320`).
Promoting a newer image/repository pair requires fresh qualification; installation,
whole-system upgrade, transaction interruption and rollback are separate gates
(`docs/verification.md:730-743`). Never repoint a qualified snapshot to a rolling
mirror while retaining its evidence label.

Agent self-update is narrower: pacman previews the local admitted package and
rejects any selection other than `lindm-agent`, then authorizes and runs the local
`-U` transaction
([`native_linux.go`](../../internal/agent/update/native_linux.go):466-480).
That code is not a successful native self-update qualification, an OS upgrade or
a filesystem rollback system. Signed release freshness/replay fences and native
recovery receipts are independent of repository signing
(`docs/architecture.md:949-978`). OS rollback must not imply rollback of user data,
Flatpak state or database migrations (`docs/architecture.md:1315-1320`).

## Encryption and recovery

The passing inventory guest had no TPM and no encrypted-install qualification.
Do not infer LUKS escrow, binding or destructive-action support from pacman or
systemd availability. The generic action provider requires a configured qualified
target/operation; rotation preserves an independent owner recovery slot and needs
free keyslot/token capacity
([`provider_linux.go`](../../internal/agent/actionprovider/provider_linux.go):209-258).

In-band recovery readiness currently requires a writable FAT ESP, sufficient
measured capacity, Secure Boot enabled with SetupMode disabled and the matching
running systemd-boot ESP
([`readiness_linux.go`](../../internal/agent/recoveryboot/readiness_linux.go):28-105).
The recorded SeaBIOS guest does not satisfy this. A separately installed bootloader
or encrypted volume needs its own evidence; do not alter the qualified kernel or
boot topology merely to satisfy a check.

## Device actions

There is no Arch-wide native lock, quarantine, escrow or sanitization claim in the
[resource matrix](../verification.md#resource-kind-coverage). Implemented shared
providers require root, explicit provisioning, exact target identity and applicable
session/hardware capabilities; storage operations outside the allowlist or
qualification report unsupported
([`provider_linux.go`](../../internal/agent/actionprovider/provider_linux.go):69-88,205-222).
Reboot acceptance is not proof of a subsequent observed boot, and an active service
is not proof of a signed action completing. The required managed-device and desktop
journey gates remain those in `docs/verification.md:718-728`.

## Advisory feeds

The implemented Arch feed requires exactly `arch/rolling/x86_64`; derivatives and
Arch Linux ARM are rejected. The official JSON lacks per-package architecture,
repository identity and publication dates; a separate published-ASA index supplies
matching dates. No source mapping or acquisition-time publication date is invented
([`arch.go`](../../internal/advisory/feed/arch.go):19-47,111-135).

The tracker can omit historical, AUR and third-party packages, so even an
HTTPS-authenticated feed remains **partial**, especially for archived system
snapshots. `Testing`/`Vulnerable` records do not promote a tentative fixed version
into an available stable fix
([`arch.go`](../../internal/advisory/feed/arch.go):49-51,76-102).
Version matching uses native libalpm epoch/pkgver/pkgrel semantics, including
missing-pkgrel behavior (`docs/architecture.md:1160-1178`). No findings does not
mean complete coverage or a secure snapshot; stale/offline feed rules remain
explicit (`docs/architecture.md:1189-1196`).

## Lab inputs and recorded evidence

The immutable upstream image is
[`Arch-Linux-x86_64-cloudimg-20261001.604814.qcow2`](https://geo.mirror.pkgbuild.com/images/v20261001.604814/Arch-Linux-x86_64-cloudimg-20261001.604814.qcow2).
The manifest records detached-checksum signing, size `578080256`, primary signer
`1B9A16984A4E8CB448712D2AE0B78BF4326C6F8F` and image SHA-256
`360f0fa49db6813bdc8e35bed230a2dc2ae3567b7b5ab74719c0a706e4e34e87`
([`arch-20261001-x86_64.json`](../../lab/images/arch-20261001-x86_64.json):8-19).

The successful recorded native inspection is
`~/.cache/lindm-arch-20261010/inspect-fixed.json`, SHA-256
`952222918ef4787b221d926887a4f6dea8ebd15fabcd592145bbf68f0539cf89`.
It matched 184 packages, with agent SHA-256
`ca18d860e9a7e5494c2caefe8a0e30f4d7e60e3c428df3461f64967a24ee7d8f`.
Runtime was QEMU 8.2.2/KVM, SeaBIOS, virtio-blk, no TPM, no desktop and explicit
user-mode egress (`docs/verification.md:751-754`). This is not air-gap or physical
validation, nor a new test run performed for this page.

Two earlier packaged lifecycles (the original handoff and the first 2026-10-10
run) ended with `bounded control-plane inventory wait ended … deadline_exceeded:
get device failed` after 18 minutes, with active units and no agent errors. Root
cause (lab, not product): the agent correctly publishes Arch's absent `VERSION_ID`
as `UNAVAILABLE`, and inspection accepted that, but the control-plane publication
comparison required `SUCCESS` for every host field, so no publication could ever
match. The wait also overwrote that mismatch with the query its own deadline cut
off. Both comparisons now share one host rule, and an expiring wait reports the
last observed mismatch (`TestPublishedHostComparisonMatchesInspection`,
`TestInventoryWaitKeepsMismatchAtDeadline`).

Passing records under `~/.cache/lindm-mutabledistros3-20261010/`, local KVM,
SeaBIOS 1.16.3, virtio-blk, no TPM/desktop, explicit user egress, isolated local
password/WebAuthn authority. Source `d303cec` plus the `8c30afa7…` lab delta and
the 2026-10-10 inventory/lab fixes (private diff
`254f4c223519c8739fa2a6ae82c30e735d739b30093022cb7ad6ee9171e6f82e`); lab
`04709855c7e5872f35778ec903f58b01018ef50f961617995e64c752e20e2650`, server
`7b38f7a5c46047ae130f5e9f7048074c511889a3bc4e01badc2f0fbd8b88b762`, signed
packages `2f03beaa…` (0.7.0) / `4aa2d295…` (0.7.1) in signed repositories:

| Lane      | Observed result                                                                                                                                                                  | Record / SHA-256                                                                                             |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Inspect   | 184 native pacman identities and independent detail comparison                                                                                                                   | `arch-x86_64-local-inspect-md4b.json` / `ee1f077485d4312db0c6784df20e88263261bb169f3d17aef5df8ce753be4c54`   |
| Lifecycle | Five 185-package publications (the agent package included), denied attempt 6 kept snapshot 5, epoch 1→3, lost issuance, purge identity, spool recovery, revocation, journal hold | `arch-x86_64-local-lifecycle-md4b.json` / `6b2d89456a907f971abb6921e8562f60484a4b3c9f8d32145a4fed739e0fa8fe` |
| Dispatch  | Nine native scenarios incl. real periodic recheck/remediation, ±90 s clocks and revoked denial; unstarted supersession integration-only                                          | `arch-x86_64-local-dispatch-md4b.json` / `e6ae926e7293f5d58ce9e3a6731096bc931e9fe48dafc066d6cb0f8f6ddb2029`  |

Keep raw account/network/journal diagnostics private.

## Known gaps

Whole-system upgrade, interruption/rollback, encryption, desktop consent and
air-gap/physical gates remain open for this exact image/Archive pair. Each future
rolling candidate needs its own evidence. Arch Linux ARM cannot close any official
Arch x86_64 cell. Use the
[verification ledger](../verification.md#1-launch-platform-qualification), not
package-builder availability or shared provider code, as the support authority.
