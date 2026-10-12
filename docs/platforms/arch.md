# Arch Linux

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Arch Linux                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------------ |
| inventory         | implemented                                                                                |
| lifecycle         | implemented                                                                                |
| dispatch          | implemented                                                                                |
| packages          | implemented                                                                                |
| accounts          | implemented                                                                                |
| sysctl            | implemented                                                                                |
| definitions       | implemented                                                                                |
| password          | implemented                                                                                |
| firewall          | implemented                                                                                |
| encryption        | implemented                                                                                |
| wipe              | implemented                                                                                |
| report-loss       | implemented                                                                                |
| lock              | implemented                                                                                |
| recovery-sanitize | implemented                                                                                |
| self-update       | implemented                                                                                |
| assistance        | implemented                                                                                |
| advisories        | implemented                                                                                |
| os-update         | implemented                                                                                |
| release-upgrade   | gated: rolling whole-system snapshot update; use os-update, not a numbered release upgrade |

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

### Rolling evidence window

“Qualified” is scoped to the exact image, repository date, architecture, boot
topology and capability lane, never to Arch's moving repositories. The registry
sets a 14-day requalification cadence. A recorded pass remains historical evidence
after that window; it is not a current support certificate. Promotion of either
pin requires new evidence even when the manifest ID is unchanged.

`lab matrix plan -platform arch -rolling-requalification` lists the due lanes;
`lab matrix run -platform arch -rolling-requalification -evidence NEW_DIRECTORY`
runs the periodic lane set declared in `lab/matrix.json`, with the ordinary fixture
and cache arguments. That set includes every capability, retaining explicit gates
rather than silently omitting unsupported cells. Failed, partial, future-dated and
unrecorded results do not postpone requalification.

The matrix pins the local x86_64 lab's `ovmf` package version and 4 MiB
Secure-Boot-capable code with its non-enrolled variables template. Selecting
capable firmware does not assert enforced Secure Boot; ordinary unsigned Arch
installer lanes use noSB variables. Recovery requires an explicit enrolled
template and the separately qualified owner-key transition.

Offline disposable Arch guests use an explicit registry-scoped **host UTC RTC**
policy, not claimed NTP synchronization. The vendor cloud image orders its real
`pacman-init.service` before SSH and cloud-final but after `time-sync.target`.
A native restricted-network boot reached cloud-init's config stage in eleven
seconds, then waited indefinitely for network time. The upstream
[arch-boxes executor recipe](https://gitlab.archlinux.org/archlinux/arch-boxes/-/blob/7f733af26fe9a0c93fdabba13e7803cbe803374a/images/libvirt-executor.sh)
uses the virtual UTC hardware clock instead of that network wait.
The owned NoCloud fixture follows that policy: explicit QEMU UTC/host clock,
early `systemctl disable --now` of the registry's time-wait unit, and native
confirmation that it is disabled before recording the clock policy. It does not
skip pacman keyring initialization, weaken signature checks, widen guest egress,
mark the kernel NTP-synchronized, or alter production agent configuration.
Online and stock acceptance fixtures keep their vendor policy; Omarchy does not
inherit this cloud-image lab adjustment implicitly.

For failed encrypted golden provisioning, `lab vm encrypted -installer-log FILE`
explicitly retains both installer and first installed-boot serial output in one
new owner-only file, capped at 32 MiB. It can contain lab credentials: keep it
private and never add it to evidence or the ledger. Routine runs discard these
consoles. This diagnostic does not change passphrase delivery, SSH authentication,
firmware checks or readiness deadlines; a failed boot remains a failure.
The encrypted installer recipes explicitly create an empty
mode-0644 `/etc/machine-id` for the first boot. Only the LUKS install key and
the credential provisioning file are written under umask 077; `pacstrap`, the
chroot's system files and boot/desktop provisioning run under umask 022 (see
the D-Bus failure below). The encrypted Archive cache dimension is `archiso-v3`;
failed earlier machines cannot be reused under the corrected recipe.

The signed rolling resource prerequisite transaction uses the native exit status,
then independently queries every registry-declared package. A retained native
diagnostic observed exit zero, complete keyring/integrity checks and successful
installation, with only pacman's “up to date -- skipping” warnings on stderr.
That output is not transaction failure; nonzero exits, transport failures and
missing prerequisites still fail the lane. Both output streams remain available
in private failure diagnostics.

Select the owner's boot topology explicitly with `-manifest-id
arch-20261001-encrypted-systemd-boot-x86-64` or
`-manifest-id arch-20261001-encrypted-grub-x86-64`, together with
`-platform arch -architecture x86_64`. Evidence for one does not qualify the other.

Every new matrix record retains the exact selected manifest beside the lane
evidence. The ledger binds its SHA-256 and repository snapshot date separately
from the lane evidence SHA-256. An earlier snapshot's pass cannot qualify changed
image or repository bytes. Native evidence remains in the
[verification ledger](../verification.md#tier-capability-matrix).

## Packaging, signing, repositories, paths and LSM

The maintained `enroll-from-console` lane binds the disposable guest's vendor
repositories to the manifest's Archive date and performs the corresponding
whole-system upgrade before capturing the real console command. It verifies
absence and subsequent installation with pacman's database, never RPM/APT.
Only the captured command may install lindm's repository, signing trust, agent
or execution bootstrap; vendor snapshot preparation does not provide any of
those. The browser must confirm the resulting server-side enrollment before
guest teardown. The periodic rolling matrix includes this core installation path.

Console enrollment selects pacman for Arch only when the customer's own `lindmd`
has the signed native repository for that architecture. The command authenticates
the signer and server/bootstrap trust before installing and enrolling; missing
packages or signed database produce an explicit setup gate, not an AUR or
external-agent-host fallback. See the
[install runbook](../security-and-operations.md#enrollment-installation-from-your-server).
The APT/RPM console-enrollment lanes do not qualify pacman enrollment.
The copied command refreshes only lindmd's signed database through a restricted
temporary configuration, then installs its explicitly named agent with the
ordinary pacman configuration. This preserves existing distribution databases
for native dependencies such as the registry-required Python runtime without
performing a partial distribution-database refresh.
The console enrollment fixture publishes the signed pacman database and detached
package signatures before starting lindmd, and configures that exact signer.
Its architecture selection comes from lifecycle-enabled pacman registry rows;
building a generic arm64 package does not admit Arch Linux ARM.

A provisioning token offers only **cloud-init** for Arch (the official cloud
image); archinstall configurations are not generated. No provisioning lane has an
Arch record.

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

## Native configuration resources

The mutable registry enables packages, accounts, sysctl, managed files, systemd
runtime services and owned unit definitions, plus dedicated nftables firewall
zones coexisting with firewalld. Password/PAM qualification is separate below.
Omarchy selects the Arch native backend without inheriting unrelated desktop
session authority. Root provisioning and signed resource ownership remain required.

Package plans use pacman's dependency solver against a private copy of the local
database and only the approved snapshot repository. Signed databases and each
package are required, with an isolated keyring bound to the provisioned full
fingerprint; automatic key retrieval is disabled. Staged archives bind native
epoch/pkgver/pkgrel, SHA-256, size and the complete install/remove effect list.
The network-isolated commit helper retains one **libalpm transaction lock** from
native prepare through final database/policy revalidation, the one-shot permit,
commit, pin publication and post-effect observation. A separate `pacman --print`
process is not an authorization boundary. The adapter checks each staged archive's
SHA-256 and native signature inside that transaction and refuses downgrades,
`any`↔machine-architecture replacements, hidden removals and dependencies crossing
the agent self-update or independently owned resource boundary.

Pacman has **no native exact-version lock**. Exact selection is verified against
the installed database, while a labelled `IgnorePkg` block inside `/etc/pacman.conf`
prevents ordinary upgrades. Unowned options, includes and repository bytes are
preserved; overlapping `IgnorePkg`, `IgnoreGroup` and removal `HoldPkg` policy
fails closed. Signed selected package groups are checked explicitly: native
print/download modes accepting an ignored direct target do not waive the hold.
Every expanded Include path/content and effective hold list is bound during
preparation and reobserved before effect authority. The provider and journal share
one owned-block parser, so ordinary existing configuration is not mistaken for an
existing managed package. Release requires the same owned baseline and never
removes dependencies.
See the upstream [pacman manual](https://man.archlinux.org/man/pacman.8.en)
and [configuration expansion contract](https://man.archlinux.org/man/pacman-conf.8.en).

The registry pins the adapter's native ABI to `libalpm.so.16`, version `16.0.1`.
Its public headers and library came from the
[ALA pacman package](https://archive.archlinux.org/packages/p/pacman/pacman-7.1.0.r9.g54d9411-2-x86_64.pkg.tar.zst),
SHA-256 `2092ec7a0391416e4a1757c455bc071d7b58a124cedc83f582cb7d37d52f211b`.
The detached signature was independently verified using the
[Arch developer page's](https://archlinux.org/people/developers/#eworm)
primary key `02FD1C7A934E614545849F19A6234074498E9CEE`; the
[pinned upstream source](https://gitlab.archlinux.org/pacman/pacman/-/blob/54d9411/meson.build)
declares the same library version. These are repository-artifact observations,
not a native guest pass. Runtime checks the root-custodied ELF SONAME and
`alpm_version()` before using the public ABI. The agent package requires the
registry-declared Python runtime, including on Omarchy's inherited Arch backend.

The connected resources lane also holds the adapter at native readiness, attempts
a real competing `pacman -U`, requires its native lock refusal and an unchanged
database, then aborts without sending an effect permit. This disposable-guest
probe is distinct from the signed resource mutation/release scenarios; both
must pass before the lane can qualify the retained-lock boundary.

SIGTERM defers interruption to explicit protocol checkpoints instead of throwing
between native lock acquisition and recording ownership, or interrupting cleanup.
The native probe additionally injects SIGTERM at both acquisition/abort-cleanup
boundaries and cancels the real runner at readiness. Each case requires an
unchanged database, no retained owned lock and a subsequent real pacman transaction
acquisition. A second adapter's failed acquisition must retain the first owner's
lock; no recovery path unlinks an unowned lock file. These are required native
acceptance assertions, not a claim that the new cases have already passed.

The lab requires the registry's native fixture tools in the signed snapshot
closure, including pacman-conf, GnuPG, libarchive, Python, nftables and firewalld.
Its package fixtures publish separate immutable signed version repositories:
pacman sync databases contain only one version of a package. Resource regression
tests are not native qualification. Until linked passing records appear in the
[verification ledger](../verification.md#resource-kind-coverage), the Arch resource
and service lanes remain unqualified on both cloud and installed images.

## Password policy and native PAM ownership

Arch uses `pambase` and native `/etc/pam.d/system-auth`, not Debian
`pam-auth-update` or Red Hat `authselect`. The provider preserves the vendor
authentication, account and session lines. An approved adoption inserts a single
password include before the first password control, owns
`/etc/pam.d/lindm-password`, and adds an explicitly marked `use_authtok` to the
native `pam_unix` password writer only when an active owned module produces a
checked token. History-only `remember=0` leaves the native writer able to prompt;
switching nonzero owned history to zero removes that token requirement.
Release removes only that include/token wiring and owned policy settings, with
baseline, last-applied and protected-file readback checks. A pre-existing foreign
policy file, altered include, nested unmanaged stack or overriding module
argument is refused rather than replaced.

Quality needs `libpwquality`; history and lockout need `pam`. History uses an
exact local-user guard. The existing vendor faillock flow is inspected and
retained; the provider does not invent a replacement authentication stack.
Mixed owned and administrator-provided quality/history modules are refused:
inserting history before a native quality module could let its retry replace a
token after history checked it. Adopt the complete owned password-policy chain
rather than changing the administrator's module order implicitly.
The native modules live under `/usr/lib/security`. The implementation follows
the maintained [pambase stack](https://gitlab.archlinux.org/archlinux/packaging/packages/pambase/-/blob/main/system-auth),
but support is selected only by the registry's exact measured package pins,
not by upstream `main`.

The dated `2026/10/02` core/extra database lists `pambase 20260616-1`,
`pam 1.7.3-1` and `libpwquality 1.4.5-7`. These are repository observations,
not a native qualification receipt. Full package releases must match; an
unrecorded rolling package rebuild is unsupported. The password resource never
installs prerequisites or changes mirrors. The resource lane requires them from
the signed snapshot and keeps an active root recovery session during changes.
When prerequisite acquisition is necessary, the lane uses whole-system
`pacman -Syu` against that approved immutable snapshot, never a refreshed
database followed by a partial package upgrade.
The resource lane requires real ordinary-user `passwd` conversations over bounded
SSH PTYs, including weak-password refusal, successful strong changes, history-only
zero, nonzero-to-zero transition and mixed unowned quality/history refusal with
unchanged native bytes. It also checks length/classes, idempotency and owned
release. Managed conversations reject otherwise-valid 13/15-character candidates
for minimums 14/16; release must accept the same 15-character candidate previously
rejected by the managed stack. These are acceptance cases, not claimed passing
receipts; historical password reuse and lockout behavior remain separate evidence. See the
[verification ledger](../verification.md#resource-kind-coverage).

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

The maintained self-update lane builds signed native pacman packages, reinstalls
the initial package from lindmd's own HTTPS `/repo/arch` signed database and
exercises its independent signed release catalog with the native pacman update
manager. The repository is published before the server starts; no third-party
agent hosting or mutable live publication is substituted. The lab transport CA
does not replace the separately pinned package signer. Its interrupted-unpack witness holds the
old binary inode open: only a replacement inode being written by pacman in the
owned frozen transaction cgroup counts as interruption evidence. The target
version includes `pkgrel` (`-1` for lindm packages), not only the application
version. Lane availability is implementation, not a passing qualification record.

### Managed whole-system maintenance windows

The OS update provider admits only `ALL`, zero per-package deferral and an
explicit `rollingSnapshot.date` calendar date. The date selects the Arch Linux
Archive, never a moving mirror or an arbitrary repository URL. The runner uses
an isolated pacman configuration with the registry's native repository set and
native trusted package signatures. Its transaction is `pacman -Syyuu`: the second
`u` permits synchronization back to the explicitly approved dated snapshot,
including downgrades. No package subset, `IgnorePkg` exclusion, security-only
selection or third-party repository is introduced. Foreign packages remain
outside the vendor snapshot's coverage.
Before refresh and again before installation, `pacman-conf` resolves the host's
effective `IgnorePkg` and `IgnoreGroup` options, including native `Include` and
glob semantics. Any exclusion refuses the transaction; it is neither silently
discarded nor copied into a partial upgrade. The host configuration is unchanged.

Installation still requires the signed policy's maintenance window (or an
authorized patch-now action using the installed pin). Configuration changes use
the existing protected ownership journal and separately authorized native helper;
the unprivileged relay never supplies executable paths or shell commands.
The runner records package-database changes and schedules a conservative reboot
after an observed whole-system change. Native security classification is explicitly
`rolling_security_classification_unavailable`, not an available zero-security
count; the whole-system transaction receipt remains visible.

Rollback is explicitly `unavailable` unless the actual root filesystem is Btrfs,
snapper is installed, and its usable `root` configuration names `/`. A successful
pre-snapshot records its native number, not a claim that boot recovery, excluded
subvolumes, user files, application databases or execution-authority state can be
rolled back. No automatic rollback is attempted.

Before pre-snapshot creation and package mutation, root-only, fsynced receipts
are written to `/var/lib/lindm/os-update/run.binpb.rolling-in-progress` and
`/etc/lindm/os-update/rolling-in-progress.binpb`. A retained or malformed marker
refuses later transactions, including after reboot; the deferral ledger cannot
erase either marker. The root-side marker must share the root mount, and its exact
protected bytes must be present in the newly created snapshot before that
pre-snapshot is admitted. This checks actual retention: Btrfs can omit nested
subvolumes even when mount IDs are equal. Symlinks back to the live marker are
refused. A missing or different saved marker stops the transaction without
advertising rollback, retaining the recovery hold. Recovery requires an operator to inspect and
repair native package state and preserve executor authority/journal state before
explicitly clearing both markers. A successful durable receipt clears them.
Do not clear executor anti-rollback/recovery holds to make an OS rollback appear
successful; root filesystem recovery is not execution-authority recovery.

The `lab matrix run` OS update lane exercises real signed assignment, partial
selection refusal, timer ownership, outside-window refusal, a changed native
package database, scheduled reboot, retained-marker refusal and policy release.
It fails rather than calling a no-change transaction an upgrade pass. The
retained-marker fixture is not a power-loss test, and a pre-snapshot is not a
rollback qualification. See [verification](../verification.md); these are
implemented paths, not new native passing claims.

## Encryption and recovery

The passing inventory guest had no TPM and no encrypted-install qualification.
Do not infer LUKS escrow, binding or destructive-action support from pacman or
systemd availability. The generic action provider requires a configured qualified
target/operation; rotation preserves an independent owner recovery slot and needs
free keyslot/token capacity
([`provider_linux.go`](../../internal/agent/actionprovider/provider_linux.go):209-258).

The maintained encrypted installer now uses the
[official archiso startup-script hook](https://gitlab.archlinux.org/archlinux/archiso/-/raw/master/configs/releng/airootfs/root/.automated_script.sh)
and `pacstrap`, with the ISO image signature authenticated separately from the
dated Arch Linux Archive package repository. The owner explicitly selects
`systemd-boot-encrypted-lab` or `grub-encrypted-lab` media edition; the golden
cache binds both that choice and the repository date. A GPT ESP at `/boot/efi`,
FAT XBOOTLDR at `/boot`, and LUKS2 root preserve readable boot assets without
putting a disk key in them. The initramfs uses mkinitcpio's `systemd`/`sd-encrypt`
hooks and includes the TPM drivers. Installation does not enroll a TPM token:
the signed action must perform real `systemd-cryptenroll` and prove cold unlock.

Official Arch media do not provide vendor Secure Boot trust. Direct installation
under enforced Secure Boot remains refused; an ISO download signature is not an
EFI signature. The maintained owner-UKI recovery lane instead selects the explicit
[`systemd-boot-lab` baseline](../../lab/images/arch-20261001-systemd-boot-x86_64.json).
It installs an **unencrypted** root with the same ESP/XBOOTLDR layout from the
authenticated archiso and pinned Archive date, initially using a separate
package-owned non-Secure-Boot NVRAM template. This is not the encrypted golden,
the arch-boxes cloud image, or a remapping of the owner's GRUB selection.

After observing that baseline's noSB firmware and running systemd-boot, the lane
builds the installed kernel/initramfs into a UKI, signs both UKI and systemd-boot
with a fresh lab-private key, and verifies those signatures with `sbverify`.
The private key stays on the lab host, never in the guest or evidence. Only after
observed guest shutdown and successful QEMU exit does the lane replace its private
NVRAM with a package-pinned enrolled-template derivative containing that exact
public certificate in **db**. Existing PK, KEK, db trust and dbx revocations are
preserved by the enrollment verifier. The host's firmware is never modified.
The baseline cache stays unsigned/noSB; signer-specific disk overlays and NVRAM
are run-only. Cache identity binds recipe revision, exact ISO and repository date,
architecture, controller and bootstrap firmware bytes.

The next boot is a real cold start of the same overlay, storage identity, TPM
and SSH identity, not a separately enrolled recovery device. Evidence retains
bootstrap/final firmware, public certificate DER/PEM SHA-256 fingerprints, signed
loader and ordinary-UKI hashes, observed poweroff time and changed boot IDs.
The running guest must expose the exact owner certificate in db, SecureBoot=1,
SetupMode=0 and systemd-boot LoaderInfo before the ordinary original-device UKI
recovery flow is admitted. The signed recovery UKI uses that same signer and
the existing one-shot handoff, exact durable target allowlist, signed ready/grant,
two independent humans, fresh TPM quote and measured-initramfs verification.
No shim or fictional Arch vendor certificate is substituted.

For qualification, run `lab vm device-actions` with the encrypted systemd-boot
manifest as `-manifest`, the new unencrypted systemd-boot manifest above as
`-recovery-manifest`, `-scenario wipe`, `-wipe-phase recovery-nvme` (and separately
`recovery-sata`), `-secure-boot`, and `-bootstrap-firmware-vars` naming the
package-owned noSB template. `-firmware-vars` names the separately enrolled
Secure Boot template; both use the same explicitly pinned firmware code, package
and version. Supply the ordinary lab/server binaries, repository and evidence
paths. GRUB and encrypted recovery-manifest selections fail before acquisition;
their native qualification remains distinct.

The first owner-key lane failed during the ordinary image's first installed boot,
before enrollment or owner-key installation: pinned SSH did not become ready.
That failure is not recovery qualification. This unencrypted first-boot validation
now retains a bounded, private, credential-redacted serial tail and separate QEMU
stderr before deleting its disposable overlay. Its failure names the diagnostic
file; encrypted boots do not enable this collection, and readiness deadlines,
SSH host-key pins and firmware enforcement are unchanged.
For an ordinary cloud-image readiness failure, `lab vm inspect -diagnostics DIR`
uses the same bounded private boot capture. This lets an offline bootstrap
failure be investigated without enabling distribution network access or extending
the SSH deadline; the caller retains custody of the diagnostic directory.
The diagnostic seed emits at most eighty current-boot journal warnings and eighty
bus/network unit messages into that private capture. Exit statuses may have
informational priority, so the unit selection does not discard them. This permits
diagnosis without SSH and does not restart, disable or bypass a failed service.
Native ordinary systemd-boot attempts reached userspace and started SSH but
observed D-Bus broker failure and an unconfigured network. The retained bus
messages showed `dbus-broker-launch` failing in `launcher_run_child` with
`Permission denied` when the privilege-dropped broker read the machine ID. The
cause was the installer's top-level umask 077: `pacstrap` creates `/etc` and
`/var` with `mkdir -p -m`, which applies the caller's umask to the intermediate
directories, and pacman does not change the mode of existing directories. Both
directories were therefore root-only, and a mode-0644 `/etc/machine-id` alone
could not fix it. The ordinary and encrypted recipes now write only the install
key and the credential provisioning file under a subshell umask 077. Everything
else runs under umask 022. The FAT `/boot` and ESP mounts set explicit
`fmask=0077,dmask=0077` instead of inheriting the umask. Ordinary recipe
revision 3 and encrypted `archiso-v3` invalidate the faulty disks.
The ordinary installer script copies its stderr and failing line to the serial
console. A failed ordinary install retains only a bounded, credential-redacted
serial tail (`archiso-installer-failure`) in a private file. The encrypted
installer never enables this capture.

After these fixes, native runs on 2026-10-12 installed the revision-3 ordinary
golden and booted it with working D-Bus and networking. They enrolled the device
and moved it to the owner-enrolled firmware by a cold boot. Two further lab
defects then surfaced and are fixed. First, the cold boot restarts swtpm on the
same persistent TPM state, because QEMU's poweroff ends swtpm. Second, the
recovery closure collects every ELF ingredient's literal `PT_INTERP`. Arch's
helpers name `/lib64/ld-linux-x86-64.so.2`, but its `libc.so.6` names
`/usr/lib/ld-linux-x86-64.so.2`. Arch's nvme-cli 3.1 cannot address a pinned
descriptor, so native NVMe admin commands use `NVME_IOCTL_ADMIN_CMD` directly
(see [architecture](../architecture.md)).

Native qualification (2026-10-12): the x86_64 `recovery-sanitize` cell passed.
The run used the original enrolled device and generation on the revision-3
ordinary systemd-boot golden. The lab enrolled a short-lived owner signer into
a private copy of the Microsoft-enrolled OVMF variables and cold-booted. It then
signed systemd-boot, the ordinary UKI and the recovery UKI with that signer, and
predicted PCR 11. Two humans approved the action, and the server verified a
native NVMe user-data format of the original namespace.

| Record                                                                                           | SHA-256                                                            |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `~/.cache/lindm-tier2-matrix/arch-recovery-final-r9-0c1dae2f/arch/recovery-sanitize-x86_64.json` | `9dceb84e427c18cd38f2bbbc004ac73d027771c1a768bc6e312b167b2c64c942` |

This is an emulated QEMU NVMe, swtpm and package-pinned OVMF result with a lab
signer. It is not a fleet signing key, a physical firmware enrollment or flash
sanitization. The `recovery-sata` and `recovery-attestation-refusal` phases have
no Arch record.

The maintained qualification entry point is `lab matrix run -platform arch
-architecture x86_64 -cells recovery-sanitize -bootstrap-firmware-vars
<package-owned-noSB-vars> -evidence <new-directory>`. The cell's Secure Boot
template comes from `lab/matrix.json` `secureBootArgs`; the lab enrolls its
short-lived owner signer into a private copy. The matrix chooses the registry's explicit ordinary
`systemd-boot-lab` recovery edition and matching encrypted topology, sets Secure
Boot, and never remaps an explicitly selected GRUB manifest. It retains both
manifest byte streams and their SHA-256, repository dates, closure and repomd
digests in the ledger, so changing either boot input invalidates the old pass.
The dedicated recovery baseline is not the default inventory/lifecycle image.

Fleet owner trust is provisioned independently (for example with
[sbctl](https://github.com/Foxboron/sbctl)); operators must maintain signed installed
boot updates and sign the released recovery UKI with an actually enrolled db key.
The lab's short-lived generated key is not a fleet signing key. Runtime readiness
does not enroll keys or claim readiness from a platform name: it requires a
writable FAT ESP with measured capacity, enforced Secure Boot and the matching
running systemd-boot ESP. Stock noSB Arch must report:
**“Secure Boot not enforced: recovery sanitize requires an enrolled owner key”.**
Missing configuration, wrong loader/ESP, missing TPM proof, or wrong signing trust
remain independent refusals, not reasons to relax firmware or action authority.

The registry's `RecoveryOwnerKey` policy belongs to Arch's own row, not an
inferred derivative bootloader. Even before an ESP is configured, the root
executor can report disabled Secure Boot and the required UKI method without
guessing a mount or granting readiness. Unreadable firmware remains unknown,
not a fabricated disabled state. The control plane preserves the owner-key
reason only for a fresh, boot-bound unavailable observation; the UI names the
recovery method separately from availability and artifact admission.

This source change is not a native pass. Security-owner review and the native
positive/negative records are still required in the
[verification ledger](../verification.md#tier-capability-matrix), including both
controller methods, wrong/no owner trust, noSB, readiness method and the unchanged
original-device destruction witnesses. Encrypted owner-Secure-Boot installation
and GRUB recovery are not inferred from the unencrypted systemd-boot result.

## Device actions

The matrix's live device-action cell uses `-scenario=wipe -wipe-phase=live-actions`.
It requires native lock/quarantine, live-root erase and report-loss evidence,
without depending on recovery sanitize. The separately qualified recovery cell
cannot be promoted by those live results.

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

The maintained registry export is
[`issues/all.json`](https://security.archlinux.org/issues/all.json), with
[`advisories.json`](https://security.archlinux.org/advisories.json) as a separately
hashed publication-date companion. The 24-hour refresh limit measures acquisition,
not the age of every vendor assessment: the export supplies no trustworthy
snapshot-generation timestamp. Old ASA dates are retained and never replaced by
the fetch clock. A freshly fetched tracker cannot establish current comprehensive
coverage, nor does its package-name match authenticate an AUR or third-party
package as an official repository build. The same native epoch/pkgver/pkgrel
boundaries apply to pinned system snapshots; no release-date applicability or
Arch Linux ARM compatibility is invented. Actual fetched-byte hashes and the
separate native qualification boundary are in
[verification](../verification.md#rolling-advisory-source-evidence).

The registry uses that canonical issue-export path, not the `/all.json` redirect.
The native lane independently hashes the actual response URL and compares it to
each published artifact URL and digest. An attempt through the old alias failed
that exact provenance check despite publishing 2,512 records; it is retained as
a failure, not excused by accepting a URL mismatch. Historical feed fixture
provenance retains both the originally requested and final URLs.

The maintained native lane is `lab matrix run -platform arch -cells advisories
-architecture x86_64 -repo "$FIXTURE" -evidence NEW_DIRECTORY`. It needs the
normal native package builders, running development dependencies and release-stamped
server, plus controller HTTPS access to the registry's real vendor exports.
Guest package inventory comes from the enrolled agent and is compared completely
against native pacman output; no vulnerable package is invented or installed to
force a finding. The private, exclusively created record includes vendor transport
and publication SHA-256 values, the complete sorted package multiset and its
reproducible SHA-256, snapshot identity, server freshness and paginated findings.
The matrix ledger additionally hashes the final record.

**The qualification scope is partial-feed matching, not complete Arch coverage.**
A real nonempty feed publication and the current snapshot's actual server result
are required. If current packages produce no affected findings, a separately
labelled oracle selects real same-package versions from that publication and
compares the vulnerable/fixed boundary through native `vercmp` and the production
server version predicate. Those comparison inputs are not installed-package
exposure. `UNKNOWN/feed_partial_coverage` remains visible; an empty match alone,
stale feed, missing oracle, unsupported source or failed fetch does not pass.
Native qualification records belong in the
[verification ledger](../verification.md#tier-capability-matrix); implementation
of the lane is not evidence that it has run.

## Remote assistance capability roadmap

Arch requires a pinned desktop, compositor and portal backend in addition to the
rolling repository snapshot. The
[capability contract](../product-specification.md#remote-assistance-capabilities)
defines consent, off/limited/on policy, role permissions and audit for every tier.
Clipboard uses the existing RemoteDesktop Clipboard interface; uploads use local
FileChooser and downloads target Downloads with notification. A headless cloud
image or package presence proves none of those interfaces or local lock isolation.
All added capabilities, including keys/layouts, display selection, messages,
reconnect, recording and Tier 3, are
[not run](../verification.md#commercial-assistance-capability-qualification).

The maintained GNOME Wayland golden requests GNOME Shell, GDM, the GNOME portal,
PipeWire and its GStreamer plugin from the same pinned Archive snapshot.
Lab-only autologin is confined to the disposable guest; SSH remains key-only.
The baseline assistance lane records the installed pacman capture-stack versions
and must observe actual Wayland consent, capture and lock isolation. This source
implementation is not a native pass, and does not enable the separately gated
commercial assistance extensions. Native records belong in the
[verification ledger](../verification.md#tier-capability-matrix).
Qualify actual portal actions, clipboard nonces, two-head/input effects and content
hashes on each selected desktop; KDE/unattended work awaits parent confirmation.

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

### 2026-10-12 snapshot-pinned matrix (Archive 2026-10-02)

`lab matrix run -platform arch -architecture x86_64` from main, local KVM, with
each record in the [ledger](../verification.md#1-launch-platform-qualification):

| Cell           | Result                          | Record / SHA-256                                                                                                                             |
| -------------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Inventory      | pass                            | `~/.cache/lindm-arch-qualify/r1-inv/arch/inventory-x86_64.json` / `e4919a3926385d4a943ad08ff72e3a5dd16a26aba1a09def3b2e161cab99b5cb`         |
| Lifecycle      | pass                            | `~/.cache/lindm-arch-qualify/r8/arch/lifecycle-x86_64.json` / `58dc60279b56f5ae6fd0a1f0a6b9783394cbaf17e2e28d9e88c968021a8bd3d5`             |
| Dispatch       | pass                            | `~/.cache/lindm-arch-qualify/r7/arch/dispatch-x86_64.json` / `d30fcae2b15d41a5d4b7553e668d4c9645a701857404f9a788fe162c8b1053dd`              |
| Assistance     | pass                            | `~/.cache/lindm-arch-qualify/r7/arch/assistance-x86_64/assistance.json` / `d549bdfed3f73320c4b0e56adbf195a19e6b1ec3f2b4b9483b217a01a0e49c01` |
| Services       | pass                            | `~/.cache/lindm-arch-qualify/r7/arch/services-x86_64.json` / `d66570c2973f79ff504e10169b71e1314fcf8f941317afb836d156344543f214`              |
| Self-update    | pass                            | `~/.cache/lindm-arch-qualify/r10/arch/self-update-x86_64.json` / `2da464d722b05863dac4d481a65d9b3a29db35094c1b7d3c5c1789b73e2d6173`          |
| Advisories     | pass (partial tracker coverage) | `~/.cache/lindm-arch-qualify/r11/arch/advisories-x86_64.json` / `7c47a9264f23f333dfce5d1dda4f631da102424f799a124c8050e86b8224b140`           |
| Wipe/loss/lock | pass                            | `~/.cache/lindm-arch-qualify/r12/arch/device-actions-x86_64.json` / `deb8d134d8fa39d28e03338b6b15a193a9bfb2a0970d3a00522d4d0dac735794`       |

The os-update lane provisions its prerequisites at the image's Archive pin
(2026-10-02) and gives the whole-system policy the registry's later
`Lab.OSUpdateTargets` pin (Archive 2026-10-09): a policy at the provisioning date
left nothing to install. The self-update interruption probe lowers the guest's
dirty-page thresholds for pacman, which writes the replacement binary through the
page cache without fsync and otherwise finished before the slice bound applied.

The scheduled-reboot scenario, like the APT and DNF lanes, accepts the reboot
only with the server's fresh post-reboot patch status (new boot ID, no reboot
required); the native boot record alone is not signed evidence. The pacman
lock-boundary probe requires the resource fixture root and its ancestry to be
root-protected, not private: the root stays 0755 because it also holds the lab
accounts' homes.

The first encrypted GRUB golden boots only since installer umask 077 was scoped to
credential writers: pacstrap's `mkdir -p -m` had created `/etc` and `/var` as 0700,
so dbus-broker could not read `/etc/machine-id` and NetworkManager never started.
The agent's own `pacman -U` of a TUF-staged update verifies the detached signature
against the system keyring, so devices must locally sign the pinned package signer
there, as the console's pacman enrollment command does.

Air-gap bundles carry a signed pacman repository at
`https://SITE/offline/repositories/amd64/arch/` (database `lindm.db`, detached
package and database signatures) built from the release's amd64 Arch agent
package. Install with `SigLevel = PackageRequired DatabaseRequired TrustedOnly`,
the station key locally signed into the system keyring and the site CA passed to
`XferCommand` curl only for transport.

## Known gaps

Whole-system upgrade, interruption/rollback, encryption, desktop consent and
air-gap/physical gates remain open for this exact image/Archive pair. Each future
rolling candidate needs its own evidence. Arch Linux ARM cannot close any official
Arch x86_64 cell. Use the
[verification ledger](../verification.md#1-launch-platform-qualification), not
package-builder availability or shared provider code, as the support authority.
