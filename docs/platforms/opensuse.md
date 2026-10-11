# openSUSE and SUSE boundaries

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | openSUSE Tumbleweed                                                                       | openSUSE Leap 16.0                            | SLES 15                                    | SLED 15                                         |
| ----------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------- | ------------------------------------------ | ----------------------------------------------- |
| inventory         | implemented                                                                               | implemented                                   | implemented                                | implemented                                     |
| lifecycle         | implemented                                                                               | implemented                                   | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| dispatch          | implemented                                                                               | implemented                                   | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| packages          | gated: not implemented for openSUSE Tumbleweed                                            | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| accounts          | gated: not implemented for openSUSE Tumbleweed                                            | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| sysctl            | gated: not implemented for openSUSE Tumbleweed                                            | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| definitions       | gated: not implemented for openSUSE Tumbleweed                                            | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| password          | gated: not implemented for openSUSE Tumbleweed                                            | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| firewall          | gated: not implemented for openSUSE Tumbleweed                                            | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| encryption        | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| wipe              | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| report-loss       | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| lock              | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| recovery-sanitize | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| self-update       | implemented                                                                               | implemented                                   | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| assistance        | gated: no maintained encrypted installer, native action prerequisites or graphical golden | gated: not implemented for openSUSE Leap 16.0 | gated: not implemented for SLES 15         | gated: not implemented for SLED 15              |
| advisories        | implemented                                                                               | implemented                                   | implemented                                | gated: SLED is not mapped by the SUSE CSAF feed |
| os-update         | gated: OS patch policy provider not landed                                                | gated: OS patch policy provider not landed    | gated: OS patch policy provider not landed | gated: OS patch policy provider not landed      |
| release-upgrade   | gated: release upgrade is not implemented                                                 | gated: release upgrade is not implemented     | gated: release upgrade is not implemented  | gated: release upgrade is not implemented       |

<!-- END GENERATED platform-capabilities -->

This page covers mutable **Leap 16.0** and **Tumbleweed pinned snapshots**, not
MicroOS, Aeon or another transactional derivative. The launch allocation is x86_64,
with Leap GNOME, KDE and headless installations qualified separately. SLES 15 SP7
and 16, and SLED 15 SP7, are separate enterprise product rows, not results inherited
from openSUSE. [Verification](../verification.md#1-launch-platform-qualification)
is authoritative; no complete release cell is certified (`docs/verification.md:155-175,770-815`).

| Input                                         | Recorded boundary                                                                                                                                                                               |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Leap 16.0 Minimal-VM Cloud Build18.75, x86_64 | After the ndb fix: native inspection (378 RPMs), full signed lifecycle (five 380-package publications) and nine-scenario connected dispatch passed locally under UEFI (records below).          |
| Tumbleweed Cloud Snapshot20261007, x86_64     | Authenticated acquisition and offline cache verification only; no native inspection/lifecycle pass.                                                                                             |
| Leap 16.0 Build18.75, aarch64                 | Native inspection (376 RPMs), full signed lifecycle and connected dispatch passed on dgx21 KVM after the ndb and disk fixes below; not an expansion of the x86_64 launch allocation.            |
| Tumbleweed Snapshot20261007 DVD, aarch64      | Installer-to-golden (signed DVD + AutoYaST, snapshot-bound cloud-init closure): native inspection (830 RPMs), full signed lifecycle and connected dispatch passed on dgx21 KVM (records below). |
| SLES/SLED                                     | Required independent vendor installation, entitlement and native lifecycle evidence; openSUSE results do not qualify them.                                                                      |

These boundaries are recorded in `docs/verification.md:177-220,267-304`.

## Packaging, signing, repositories, paths and LSM

The mutable lab selects **zypper**, with canonical **RPM** package identity, only
for explicit `opensuse-leap` and `opensuse-tumbleweed` IDs. It does not route
`ID_LIKE` or unknown/immutable distributions through DNF
([`vm_distribution_linux.go`](../../internal/vmlab/vm_distribution_linux.go):20-50).
The local agent transaction uses an isolated repository directory, `--no-remote`
and explicit uploaded RPMs; that is not qualification of a vendor repository or
whole-system update ([`vm_packages_linux.go`](../../internal/vmlab/vm_packages_linux.go):341-350).

RPM archives are signed and verified in a private RPM database. Repository
publication is a separate `createrepo_c` path, not synthesized when that tool is
missing ([`internal/packaging/doc.go`](../../internal/packaging/doc.go):14-24).
The qualification contract retains pinned imported keys, independent package
signature checks and signed `repomd.xml`; disabling signatures is not a workaround
(`docs/verification.md:177-185`). Keep vendor image, native repository, TUF release
and execution-authority trust separate; see the
[shared boundaries](README.md#shared-implementation-boundaries).

Installed mutable-agent paths are `/usr/libexec/lindm/lindm-agent`,
`/etc/lindm/{agent,executor}.json`, `/var/lib/lindm/{agent,executor}` and
`/run/lindm/executor.sock`; units live under `/usr/lib/systemd/system`
([`layout.go`](../../internal/packaging/layout.go):15-46;
[`lindm-agent.service`](../../internal/packaging/assets/lindm-agent.service):9-17;
[`lindm-executor.service`](../../internal/packaging/assets/lindm-executor.service):9-15).
Lifecycle configuration checks ownership/modes instead of repairing arbitrary
state and retains the account, journal and spool on removal
([`lifecycle.sh`](../../internal/packaging/assets/lifecycle.sh):61-109,137-142).

Record the actual kernel, CPU baseline and SELinux/AppArmor mode for each image.
Neither RPM format nor a SUSE product label proves an enforcing LSM or correct
policy. The matrix requires those observations (`docs/verification.md:171-175`);
there is no passing Leap/Tumbleweed native LSM qualification here.

## Agent services and sandbox

Use the shared root executor/unprivileged network split. Both installed units
retain `NoNewPrivileges`, strict system protection, private devices and protected
homes. The executor has only AF_UNIX; network capabilities are empty
([`lindm-executor.service`](../../internal/packaging/assets/lindm-executor.service):17-61;
[`lindm-agent.service`](../../internal/packaging/assets/lindm-agent.service):18-50).
These are implemented assets, not proof that each SUSE systemd/LSM combination
has completed its native service lane. A storage action requires an explicitly
provisioned per-target exception; never disable the persistent device sandbox.

## Inventory and per-field quirks

- RPM inventory uses native name, epoch, version, release, architecture and module
  fields. Supported database locations include `/usr/lib/sysimage/rpm` and
  `/var/lib/rpm`, in sqlite, BerkeleyDB and **ndb** form. Leap 16.0 defaults to
  rpm's ndb backend: the Build18.75 image ships only
  `Index.db`/`Packages.db`. Before that marker was recognised the agent reported
  package collection `UNAVAILABLE` and `lindm-agent inspect` exited 1 with exactly
  the earlier 63 stderr bytes (`lindm-agent: package collection: COLLECTION_STATUS_UNAVAILABLE`).
  zypper presence is a separate capability, not the package manager name stored on
  each package
  ([`packages_linux.go`](../../internal/agent/inventory/packages_linux.go):51-104;
  [`mutable_packages_linux_test.go`](../../internal/agent/inventory/mutable_packages_linux_test.go):15-41;
  [`vm_distribution_linux_test.go`](../../internal/vmlab/vm_distribution_linux_test.go):55-78).
- Native package warnings/failures invalidate a complete observation rather than
  publishing a successful partial list
  ([`packages_linux.go`](../../internal/agent/inventory/packages_linux.go):104-153).
- The DNF-specific repository observation may be inapplicable on a successfully
  identified zypper host. This does not claim zypp repository inventory is complete
  ([`inventory_unavailable_linux.go`](../../internal/vmlab/inventory_unavailable_linux.go):29-30,62-73).
- CPU, memory, interfaces/default routes, storage, firmware, TPM, power, sessions,
  users, Flatpak and Snap are independently collected categories; tool absence,
  permissions and invalid output must remain field statuses
  ([`details_linux.go`](../../internal/agent/inventory/details_linux.go):135-165).
  BIOS has no UEFI Secure Boot variable; no TPM means its version is unavailable;
  absent application backends require successful presence=false evidence
  ([`inventory_unavailable_linux.go`](../../internal/vmlab/inventory_unavailable_linux.go):20-26).

The Leap inspection failure is not permission to normalize an error into an empty
collection. Follow the [strict-health boundary](README.md#shared-implementation-boundaries).

## Updates and snapshot boundaries

Leap requires a release-specific zypper/libzypp transaction model. Tumbleweed
requires a **tested distribution snapshot and native distribution-upgrade
semantics**, not Leap patch rules. Snapshot-pinned installation content, compatible
whole-system plans, interruption/reboot and rollback evidence remain separate
requirements (`docs/architecture.md:1294-1320`). A dated QCOW2 image alone does not
pin every subsequent repository transaction.

The implemented agent self-update helper installs only the admitted local package
using zypper `--no-refresh --disable-repositories`, without recommendations or
vendor changes. Interrupted same-version work can force reinstallation
([`native_linux.go`](../../internal/agent/update/native_linux.go):457-465).
This is an agent-package path, not a Tumbleweed distribution upgrade or an atomic
OS updater. Signed metadata, immutable staging, authorization and observed native
recovery remain required (`docs/architecture.md:949-978`).

Do not promise that a filesystem/OS rollback also reverses application databases,
Flatpak state or user data (`docs/architecture.md:1315-1320`).

## Encryption and recovery

No Leap/Tumbleweed encrypted-install, recovery-escrow or TPM-binding pass is
recorded here. Generic LUKS code does not qualify a SUSE installer topology.
Storage effects require a qualified allowlisted target and operation; rotation
also requires an independent owner recovery slot and available keyslot/token
capacity ([`provider_linux.go`](../../internal/agent/actionprovider/provider_linux.go):209-258).

Current in-band recovery readiness requires a writable FAT ESP, measured capacity,
Secure Boot enabled outside SetupMode, the running systemd-boot loader and its
matching ESP identity
([`readiness_linux.go`](../../internal/agent/recoveryboot/readiness_linux.go):28-105).
UEFI alone, a vendor bootloader or a large-enough filesystem does not satisfy that
contract. Do not replace vendor boot assets or resize an ESP to manufacture a pass.

## Device actions

Lock, quarantine, power, escrow, binding and erasure must be evaluated per action,
actual session/topology and provisioned privilege, not advertised from inventory
success. The provider requires root, explicit configuration and bounded quarantine
settings; unallowlisted/unqualified storage operations return unsupported
([`provider_linux.go`](../../internal/agent/actionprovider/provider_linux.go):69-88,205-222).
The [resource matrix](../verification.md#resource-kind-coverage) does not record
SUSE-wide native action qualification. VM sanitize results from another platform
are not physical-media erasure evidence.

## Advisory feeds

SUSE CSAF applicability binds exact product CPEs and package relationships; Leap,
SLES service packs, SLED and extensions do not inherit one another's fixes.
GA-media notices are rejected because a shipped package's accumulated fixes are
not a first-fixed EVR boundary
([`suse.go`](../../internal/advisory/feed/suse.go):17-19,78-125).
Feed authentication requires the vendor exact-filename checksum and detached
signature with pinned keys. SUSE coverage remains partial: no finding is not a
clean bill of health, and offline byte-pinned imports do not become fresh complete
coverage (`docs/architecture.md:1160-1196`). Do not interpret Tumbleweed GA notices
as rolling-snapshot vulnerability boundaries.
RPM `gpg-pubkey` signing-key rows without an architecture are keyring entries:
they neither match records nor make architecture coverage UNKNOWN
([Fedora advisory feeds](fedora.md#advisory-feeds)).

## Lab inputs and recorded evidence

Image/version pins, sizes and signer fingerprints are in:

- [`opensuse-leap-16.0-x86_64.json`](../../lab/images/opensuse-leap-16.0-x86_64.json):2-18:
  Build18.75, image SHA-256 `71930479c898c4e83cb7a25215b648c991bd1265350449b021ea6c3e1f76cee0`.
- [`opensuse-tumbleweed-20261007-x86_64.json`](../../lab/images/opensuse-tumbleweed-20261007-x86_64.json):2-18:
  Snapshot20261007, image SHA-256 `ba2c573a5894fbd27e6d19916abae222e04daaadad7aa10e8ebface2ebaf0884`.
- [`opensuse-leap-16.0-aarch64.json`](../../lab/images/opensuse-leap-16.0-aarch64.json):2-18:
  Build18.75, image SHA-256 `bca1bd30a41622eb78727ba9375bff4d99ffaec1aed49bde1efa0ffc96ee58a8`.
- [`opensuse-tumbleweed-20261007-aarch64.json`](../../lab/images/opensuse-tumbleweed-20261007-aarch64.json):2-18:
  signed Snapshot20261007 **DVD** (edition `dvd`), ISO SHA-256
  `bc84067c9a14aee474d151559b67fc8718295d2508d66669cb75edec587cb261`, 4,270,606,336
  bytes, `.sha256` signed by the openSUSE key `AD485664…29B700A4`.

Recorded acquisition evidence, not new checks performed for this page:

| Record                                                                                        | SHA-256                                                            | Meaning                                            |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------- |
| `~/.cache/lindm-mutabledistros-20261010/opensuse-leap-16.0-x86_64-acquisition.json`           | `f4721a173bde4e05d13ed47a67546d1e99ac156c2ffcac8f42464bcd1981260f` | Authenticated image acquisition/cache evidence.    |
| `~/.cache/lindm-mutabledistros-20261010/opensuse-tumbleweed-20261007-x86_64-acquisition.json` | `124c4f17194727099c0f9458ec73d3287672ed7960041025510cd0b11cce53bb` | Authenticated image acquisition/cache evidence.    |
| `~/.cache/lindm-mutabledistros3-20261010/arm64-acquisition.json`                              | `1c7b1bfe9711e92d513c768a72cfddc430bdc3dc3dac601e52c2885651d0d5fb` | Eight ARM inputs including Leap; acquisition only. |

The first two hashes are recorded in the retained `evidence-index.json`; the ARM
record is also cited in `docs/verification.md`. Leap x86_64 BIOS exited; UEFI
reached inspection after lab boot-time/SSH fixes, then the agent exited 1 with 63
stderr bytes. The ARM diagnostic below captured those bytes: package collection
was `UNAVAILABLE` because the ndb `Packages.db` marker was not recognised. Raw
diagnostics remain private.

### Leap 16.0 aarch64 native records (2026-10-10)

Two Leap-specific defects were fixed with regressions before the passes:

- **ndb rpmdb** (agent): `Packages.db` added to the RPM database markers;
  `TestMutableDistributionPackageManagerIdentity/opensuse-leap-16.0`.
- **1.5 GiB vendor disk** (lab): the Minimal-VM image's root had ~8 MB free and the
  first signed RPM install failed (`needs 27MB more space on the / filesystem`,
  zypper exit 8). Disposable lab overlays now get at least 10 GiB; kiwi-repart
  grows Leap's root on first boot as on any resized cloud disk
  ([`vm_linux.go`](../../internal/vmlab/vm_linux.go):33-60;
  `TestGuestOverlayDiskFloor`).

Records are under `~/.cache/lindm-mutabledistros3-20261010/`, host `dgx21`,
native aarch64 KVM/QEMU 8.2.2, AAVMF `2024.02-2ubuntu0.10` (Secure Boot disabled,
SetupMode), virtio-blk, no TPM/desktop, explicit user egress. Source is `d303cec`
plus the `8c30afa7…` lab delta, the ndb fix and the disk floor; the lane-recorded
source diff SHA-256 is `5e45a68b40197dea0ee85e0fd6a932e67572b608cff94dad1d04b7ff4ee8fdf7`.
Signed 0.7.0/0.7.1 RPMs (`491aca49…`/`f679b398…`) carry only the ndb product fix.

| Lane      | Observed result                                                                                                                                                                                   | Record / SHA-256                                                                                                 |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Inspect   | 376 native RPM identities and independent detail comparison                                                                                                                                       | `leap16-arm64-dgx21-inspect-diskfix.json` / `69b00b31f66d1255af30af2f2ffa3f584de1747ecc72d9c1366d64b2197fee9b`   |
| Lifecycle | Signed zypper 0.7.0→0.7.1 automatic-trust lifecycle: five 378-package publications, denied attempt 6 kept snapshot 5, epoch 1→3, purge identity, spool recovery, revocation, missing-journal hold | `leap16-arm64-dgx21-lifecycle-diskfix.json` / `8f5056bf5a095b46eead2a4cb89d6988008de18437cd5aa8f62a71c52e0ba87d` |
| Dispatch  | Nine native scenarios incl. real periodic recheck/remediation, ±90 s clocks and revoked denial; unstarted supersession integration-only. The lane records SELinux as `not applicable`             | `leap16-arm64-dgx21-dispatch-diskfix.json` / `29d037b83bcb7ca9c51c647a5175c4072542a7633e830c67e5d52274192a4b57`  |

The first post-fix inspection, before the disk floor, also passed
(`leap16-arm64-dgx21-inspect-ndbfix.json`,
`720a662f58912499b01d499cd7022874a13ebc8f9b0b183c7364348d83690c89`).

### Leap 16.0 x86_64 native records (2026-10-10)

The x86_64 cell, which had failed at inspection with the ndb cause, passed locally
(KVM, OVMF `2024.02-2ubuntu0.10` with Secure Boot disabled, virtio-blk, no
TPM/desktop, user egress, isolated local password/WebAuthn authority). Source is
`4d74dcf` plus the MutableDistros5 lab delta (installer goldens only; no agent
change). The signed 0.7.0/0.7.1 x86_64 RPMs are `ebafbefb…`/`f2c8da50…`. Records are
under `~/.cache/lindm-mutabledistros5-20261010/`:

| Lane      | Observed result                                                                                                                                 | Record / SHA-256                                                                                            |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Inspect   | 378 native RPM identities and independent detail comparison, UEFI                                                                               | `leap16-x86_64-local-inspect.json` / `dadb6bc9d37fd93dcaa6eecefc31913c37467738c1c68523904e2f567b2ea2cc`     |
| Lifecycle | Signed zypper 0.7.0→0.7.1 automatic trust: five 380-package publications, denied attempt 6 kept snapshot 5, epoch 1→3, revocation and hold      | `leap16-x86_64-local-lifecycle.json` / `06c36ca389fc455a92f09f8fd87f2010252e508303061d1c0dd7570d2ef8e752`   |
| Dispatch  | Nine native scenarios with real periodic intervals and revoked denial; SELinux Enforcing (kernel-observed rerun); supersession integration-only | `leap16-x86_64-local-dispatch-v3.json` / `d30cd1220e1573cbc0a5437ee76d5ea1a1c470309323a0c261fe71d2db3ebb55` |

The first x86_64 dispatch (`leap16-x86_64-local-dispatch.json`,
`4c0b3341432f59e0e4ab110579f0a37c0873c7ca635395948b1bdb91a320599b`) also passed,
but its `not applicable` label predates the SELinux observation. A Leap 16.0 aarch64
dispatch rerun likewise recorded **SELinux Enforcing** on `dgx20`
(`leap16-arm64-dgx20-dispatch-v3.json`,
`17289eba4f96fdb1605c590578c572ad3cd037cbceaa3b925e7867fa2be9ba43`, same directory).

### Tumbleweed Snapshot20261007 aarch64 installer-to-golden records (2026-10-10)

No official Tumbleweed ARM cloud/KVM image exists, so the lab installs one from the
signed Snapshot20261007 DVD with AutoYaST
([`tumbleweed_installer_linux.go`](../../internal/vmlab/tumbleweed_installer_linux.go);
workflow in `docs/engineering.md`). The base system (830 packages, Btrfs root with
snapper, SELinux enforcing, GRUB on the removable path) comes only from the
authenticated DVD. The DVD lacks cloud-init, so the lab takes `cloud-init` and
`cloud-init-config-suse` with their closure from the official ports OSS repository at
a lower priority. That repository's signed `repomd.xml` had to name snapshot
`20261007` both before and after installation. The golden disk's integrity pin is
`06442620b7e94fd5555a9b8cd54d7fd762e9a6d31ac13612a5e0de28165685a5` (`dgx21`
`tumbleweed-installed` cache, recipe `opensuse-tumbleweed-dvd-autoyast-v2`). It is
a local derived disk, not a vendor-signed image.

Defects found and fixed with regressions while building it:

- The vendor ARM DVD's hybrid MBR/platform-0 El Torito layout makes `xorriso
-boot_image any replay` fail (exit 32). The remaster re-declares the vendor FAT
  image as the UEFI El Torito entry (`TestTumbleweedRemasterPatchesEFIImageGRUB`).
- The first profile failed yast2-schema validation (`update_nvram` typed boolean,
  `install_recommends`), and with `final_halt` the installer rebooted into the DVD
  instead of powering off (`TestTumbleweedAutoYaSTBindsOwnedDiskPinnedMediaAndCredentials`;
  the profile now validates against the DVD's yast2-schema 5.0.3 RNG).
- The solver chose `cloud-init-config-MicroOS`; the profile now names
  `cloud-init-config-suse`.
- A first lifecycle failed after the reboot with `unable to authenticate`. Tumbleweed
  starts sshd in parallel with `systemd-user-sessions`, and pam_nologin rejects
  logins until `/run/nologin` is removed. A guest whose user-sessions start was
  delayed reproduced "Access denied … by PAM account configuration" for the same key.
  The golden orders sshd after that unit and validation checks it. A second
  pre-fix lifecycle (`tw-arm64-dgx21-lifecycle-diag1.json`,
  `eab13584b53e3460b55e5bd512bbe275b7cc7063d856965c58466eaafafc4a15`) passed.
- Dispatch recorded SELinux `not applicable` for zypper guests. It now reads
  `/sys/fs/selinux/enforce` (`TestSELinuxModeFromKernelEnforceState`).

Runtime: `dgx21`, native aarch64 KVM/QEMU 8.2.2, AAVMF `2024.02-2ubuntu0.10`
(Secure Boot disabled, SetupMode), virtio-blk, no TPM/desktop, user egress,
isolated local password/WebAuthn authority. Source is `4d74dcf` plus the
MutableDistros5 lab delta (`md5-source-tw2.patch`
`3a9bca0585cb3aaba93e79b6f91d0e79767c5dbceb74ba847e70c3f4c3e4a987`; the dispatch
rerun adds the SELinux observation, `md5-source-v3.patch`
`7b6b0d5a2096370f28f5280ba84b6f841d4a1d6a2c60bb03679df74c39bb17b4`). The signed
0.7.0/0.7.1 aarch64 RPMs are `396996dc…`/`8cedbe48…`.

| Lane      | Observed result                                                                                                                                            | Record / SHA-256                                                                                        |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Inspect   | 830 native RPM identities and independent detail comparison                                                                                                | `tw-arm64-dgx21-inspect-v2.json` / `76e793fdd477764a4b8c96afab993daa106ec99218e4ab880fde16d7921c2866`   |
| Lifecycle | Signed zypper 0.7.0→0.7.1 automatic trust: five 832-package publications, denied attempt 6 kept snapshot 5, epoch 1→3, revocation and missing-journal hold | `tw-arm64-dgx21-lifecycle-v2.json` / `d29350054997675adcb50bcd72deafa176456ec79b55877f595858eb04d7f37b` |
| Dispatch  | Nine native scenarios with real periodic intervals and revoked denial; SELinux Enforcing; supersession integration-only                                    | `tw-arm64-dgx21-dispatch-v3.json` / `ba180b62dde4cdf26a5117f8fcc29f55157f7c6a970b93c60cea09e7aa166308`  |

The v2 dispatch (`tw-arm64-dgx21-dispatch-v2.json`,
`9cc8db6ed3ed41254d9dea088b0d4a539ba70917d71af81b9c39a9d89f07f16e`) also passed,
but it carries the old `not applicable` SELinux label.

## Known gaps

Leap and Tumbleweed policy-level SELinux behavior (denials, custom modules) is not
established by these records; they only record the kernel enforcing state. Tumbleweed x86_64
still needs inspection, lifecycle and dispatch from its cloud image. Tumbleweed also
needs distribution-upgrade snapshot and rollback evidence: these lanes upgrade only
the agent package. The aarch64 golden is bound to the 20261007 snapshot. Once the
ports tree advances, building a new golden fails closed until the manifest is bumped
to that snapshot's DVD; an existing cached golden is still reused.
Desktop sessions, enterprise vendor installations, air-gap operation, encryption,
actions and physical hardware remain distinct gates. None is waived by signed
image availability or shared RPM code. See the authoritative
[qualification ledger](../verification.md#1-launch-platform-qualification) and
[resource matrix](../verification.md#resource-kind-coverage).
