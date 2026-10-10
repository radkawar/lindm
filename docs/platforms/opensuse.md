# openSUSE and SUSE boundaries

## Versions, architectures and qualification

This page covers mutable **Leap 16.0** and **Tumbleweed pinned snapshots**, not
MicroOS, Aeon or another transactional derivative. The launch allocation is x86_64,
with Leap GNOME, KDE and headless installations qualified separately. SLES 15 SP7
and 16, and SLED 15 SP7, are separate enterprise product rows, not results inherited
from openSUSE. [Verification](../verification.md#1-launch-platform-qualification)
is authoritative; no complete release cell is certified (`docs/verification.md:155-175,770-815`).

| Input                                         | Recorded boundary                                                                                                                                                                    |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Leap 16.0 Minimal-VM Cloud Build18.75, x86_64 | Authenticated acquisition; inspection exited 1 for the ndb rpmdb cause diagnosed below. Fixed, but no x86_64 rerun, lifecycle or dispatch pass yet.                                  |
| Tumbleweed Cloud Snapshot20261007, x86_64     | Authenticated acquisition and offline cache verification only; no native inspection/lifecycle pass.                                                                                  |
| Leap 16.0 Build18.75, aarch64                 | Native inspection (376 RPMs), full signed lifecycle and connected dispatch passed on dgx21 KVM after the ndb and disk fixes below; not an expansion of the x86_64 launch allocation. |
| Tumbleweed aarch64                            | No maintained cloud-image/installer-to-golden input; signed DVD/NET availability is not an installed guest.                                                                          |
| SLES/SLED                                     | Required independent vendor installation, entitlement and native lifecycle evidence; openSUSE results do not qualify them.                                                           |

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

## Lab inputs and recorded evidence

Image/version pins, sizes and signer fingerprints are in:

- [`opensuse-leap-16.0-x86_64.json`](../../lab/images/opensuse-leap-16.0-x86_64.json):2-18:
  Build18.75, image SHA-256 `71930479c898c4e83cb7a25215b648c991bd1265350449b021ea6c3e1f76cee0`.
- [`opensuse-tumbleweed-20261007-x86_64.json`](../../lab/images/opensuse-tumbleweed-20261007-x86_64.json):2-18:
  Snapshot20261007, image SHA-256 `ba2c573a5894fbd27e6d19916abae222e04daaadad7aa10e8ebface2ebaf0884`.
- [`opensuse-leap-16.0-aarch64.json`](../../lab/images/opensuse-leap-16.0-aarch64.json):2-18:
  Build18.75, image SHA-256 `bca1bd30a41622eb78727ba9375bff4d99ffaec1aed49bde1efa0ffc96ee58a8`.

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

## Known gaps

Leap x86_64 needs its own rerun of inspection, lifecycle and dispatch; the ARM
records above do not qualify it. Leap LSM enforcement is not established by these
records. Tumbleweed needs inspection, lifecycle, distribution-upgrade snapshot and
rollback evidence. Tumbleweed aarch64 has no official ARM Cloud/KVM image (the
advertised checksum links return 404), so its prerequisite is a maintained,
snapshot-pinned SUSE installer-to-golden workflow (signed Snapshot DVD/NET media
exist); an ISO cannot be relabeled as a provisioned cloud disk.
Desktop sessions, enterprise vendor installations, air-gap operation, encryption,
actions and physical hardware remain distinct gates. None is waived by signed
image availability or shared RPM code. See the authoritative
[qualification ledger](../verification.md#1-launch-platform-qualification) and
[resource matrix](../verification.md#resource-kind-coverage).
