# openSUSE and SUSE boundaries

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | openSUSE Tumbleweed                                                                        | openSUSE Leap 16.0                                                                                      | SLES 15                                                                                                 | SLED 15                                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| inventory         | implemented                                                                                | implemented                                                                                             | implemented                                                                                             | implemented                                                                                             |
| lifecycle         | implemented                                                                                | implemented                                                                                             | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| dispatch          | implemented                                                                                | implemented                                                                                             | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| packages          | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| accounts          | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| sysctl            | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| definitions       | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| password          | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| firewall          | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| encryption        | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| wipe              | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| report-loss       | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| lock              | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| recovery-sanitize | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| self-update       | implemented                                                                                | implemented                                                                                             | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| assistance        | implemented                                                                                | gated: not implemented for openSUSE Leap 16.0                                                           | gated: not implemented for SLES 15                                                                      | gated: not implemented for SLED 15                                                                      |
| advisories        | implemented                                                                                | implemented                                                                                             | implemented                                                                                             | gated: SLED is not mapped by the SUSE CSAF feed                                                         |
| os-update         | implemented                                                                                | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release |
| release-upgrade   | gated: rolling whole-system snapshot update; use os-update, not a numbered release upgrade | gated: release upgrade is not implemented                                                               | gated: release upgrade is not implemented                                                               | gated: release upgrade is not implemented                                                               |

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

### Tumbleweed rolling evidence window

Tumbleweed qualification names an exact image and repository snapshot, architecture,
boot topology and capability lane. A snapshot date on an installer or cloud image
does not pin later repository transactions. The registry sets a 14-day
requalification cadence; older passes remain historical evidence, not a current
support certificate. Leap and enterprise SUSE do not inherit that rolling model.

New x86_64 qualification selects the ordinary and encrypted Snapshot20261009
DVD recipes, both with repository date `2026-10-09`; aarch64 selects the
Snapshot20261007 DVD recipes with `2026-10-07`. The earlier x86_64
Snapshot20261007 cloud manifest remains historical input, not an implicit claim
that a later repository leaves its installed package generation unchanged.
The default rolling selection uses the newest checked-in repository date rather
than the first historical filename. An explicit `-manifest-id` still wins and
retains the owner's chosen snapshot and boot topology.

`lab matrix plan -platform opensuse-tumbleweed -rolling-requalification` selects
due lanes from the periodic set in `lab/matrix.json`. Run that selection with
`lab matrix run`, a new evidence directory and the ordinary fixture/cache arguments.
Every capability remains visible, including exact unsupported gates. Failed,
partial, future-dated and unrecorded results never defer requalification.

Matrix runs retain the selected manifest beside the native record and bind its
SHA-256 and repository snapshot date in the ledger. Changing the repository or
image bytes, even without changing the manifest ID, invalidates reuse of a rolling
pass. Results stay architecture-specific; an x86_64 archive does not establish
availability of an aarch64 archive. See the
[verification ledger](../verification.md#tier-capability-matrix).

Remote snapshot capture never recursively copies `-retained-metadata`.
The controller authenticates the pinned repomd and its exact referenced metadata
and delegated keys, then streams only verified immutable bytes into the admitted
Spark's private directory (at most 256 files and 512 MiB). The native capture
authenticates those pins again. Existing RPM reuse uses a separately authenticated
content-addressed snapshot and the bounded snapshot transfer protocol, not an
arbitrary retained directory or a full mirror. Before each remote lane streams a
closure, the controller runs `lab images snapshot-present` on the host; when the
host cache already authenticates that exact closure (manifest address, retained
tree, signed metadata and every file digest) the multi-GiB stream is skipped.
Re-streaming it per lane let three concurrent aarch64 lanes saturate the
controller link until SSH keepalives failed (`write |1: broken pipe`).

## Packaging, signing, repositories, paths and LSM

A provisioning token offers **cloud-init** and **AutoYaST** for Tumbleweed (and
AutoYaST for SLES/SLED 15; Leap 16.0's Agama installer is offered cloud-init only).
The AutoYaST snippet is a `chrooted` chroot-script: it installs the agent in the
target over the installer network and only enables units. YaST holds the system
zypp lock while scripts run, so the script exports
`ZYPP_LOCKFILE_ROOT=/var/run/autoyast` (the AutoYaST guide's documented lock root
for scripts); zypper then refreshes and installs from a `--reposd-dir` holding only
`lindm.repo`, so DVD or mirror repositories in the target cannot fail the install.
Chroot-script failures are not fatal to YaST; read
`/var/adm/autoinstall/logs/lindm-enroll.sh.log` when a device does not appear, and
delete the retained profile under `/var/adm/autoinstall/` after enrollment. The
`provision-autoyast` lane on Tumbleweed aarch64 has proven installation and
enrollment reservation; see the
[installer provisioning evidence](../verification.md#installer-provisioning-from-the-console-2026-10-12)
for its approval-to-Enrolled status.

The maintained `enroll-from-console` lane serves the manifest's verified vendor
closure for prerequisite packages and checks the native RPM database both before
and after the real copied zypper command. It does not treat zypper as DNF or fall
back to APT. Snapshot preparation installs only the distinct vendor repository
trust; lindm's own repository, trust, agent and execution bootstrap must come
exclusively from the browser-captured command. Browser confirmation of the
server-side enrollment precedes guest teardown. This path is included in the
periodic rolling matrix on each admitted architecture.

The `airgap` lane installs the first agent on Tumbleweed only from the imported
bundle's signed RPM repository, served by the site `lindmd` at
`/offline/repositories/<arch>/rpm/`. As the console command does, the guest adds
the site CA to the system trust store (libzypp has no per-repository CA file)
and imports the fingerprint-pinned station key into the RPM keyring; zypper then
uses a private repository directory containing only that site repository, with
repository and package signatures required. The disabled vendor repositories
are unreachable in the isolated site namespace and are never refreshed.

Package resources and agent self-updates commit verified local RPM files with
zypper against an empty private repository directory. `--disable-repositories`
is not used: it also disables zypper's command-line RPM repository, so every
commit failed with exit 104 (`_tmpRPMcache_:<name>=<evr>` not found). zypper
also refuses any transaction while `/` itself is a read-only mount ("The target
filesystem is mounted as read-only", exit 5), even when `/etc`, `/usr` and
`/var` are writable. The bounded package apply unit therefore keeps `/`
writable on Tumbleweed only; its other confinement (private network, protected
home, kernel and control-group protections, capability bound) is unchanged.
Tumbleweed reports OS-update backend `zypper` in host patch status; migration
00033 widened the patch-status projection's backend bound, which had refused
every Tumbleweed and Arch host observation carrying patch status.

Select the exact openSUSE release in the console for the zypper install-and-enroll
command. It uses signed RPM packages and metadata from the customer's own `lindmd`
HTTPS `/repo/rpm` endpoint, never an external agent repository or a DNF command
guessed from RPM identity. Signer and server/bootstrap trust are pinned before
installation. Missing release artifacts produce an explicit server setup remedy.
See the [install runbook](../security-and-operations.md#enrollment-installation-from-your-server).
APT/Fedora command evidence does not qualify this zypper path.

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

## Tumbleweed native configuration resources

The mutable Tumbleweed registry enables packages, accounts, sysctl, managed files,
systemd runtime services and owned unit definitions, plus dedicated nftables
zones coexisting with firewalld on x86_64 and aarch64. This does not promote Leap,
SLES, SLED or transactional derivatives. Password/PAM prerequisites and management
are independently qualified.

Package staging uses zypper's native solver and machine-readable transaction
summary with exactly one root-approved signed repository. Repository metadata is
independently checked against the full pinned fingerprint. Every staged RPM must
verify in both the isolated approved-key database and the system RPM key database.
There is no automatic key import or unsigned-package fallback. Exact epoch,
version, release and architecture, declared download bytes and dependency effects
are bound to the existing signed manifest and one-shot helper permit.
The commit is local-only, without repository refresh, recommendations or vendor
changes; downgrades, replacement/removal side effects and agent self-update
crossovers are refused.

The shared native runner allows only the needed
[documented libzypp environment keys](https://github.com/openSUSE/libzypp/blob/master/zypp/doc/autoinclude/EnvironmentVariables.doc):
`ZYPP_CONF`, `ZYPP_LOGFILE`, `ZYPP_LOCK_TIMEOUT` and `ZYPP_LOCKFILE_ROOT`.
Preparation selects a private lock root; live apply deliberately omits that
override and cannot inherit one from the agent's environment. Real subprocess
policy regressions cover both paths and retain rejection of unrelated overrides.

Owned `/etc/zypp/locks` blocks use one libzypp **complex name predicate** carrying
architecture and `!= EVR` restrictions. Separate `solvable_name` and
`solvable_arch` fields would be ORed and incorrectly lock unrelated packages;
they are not used for owned pins. Unrelated lock bytes are retained, and
overlapping or ambiguous external locks fail closed rather than being removed.
The journal shares the provider's owned-block framing, so unrelated existing
locks do not turn package creation into adoption. Native qualification queries
`zypper locks --solvables` against a signed fixture universe: the alternative EVR
must match, while the wanted EVR, unrelated same-architecture package and target
on `noarch` must not. Byte equality alone is not native pin evidence.
See [libzypp's predicate implementation](https://github.com/openSUSE/libzypp/blob/master/zypp/zypp/PoolQuery.cc)
and [locks(5)](https://github.com/openSUSE/libzypp/blob/master/zypp/doc/locks.5.txt).
The provider recognizes native ndb `Packages.db` as well as SQLite RPM databases.
The shadow provider queries the package owning `useradd`, not Fedora's
`shadow-utils` package name.

The signed snapshot closure must include the registry's RPM build/signing tools,
GnuPG, Python, nftables and firewalld before starting resource qualification.
Native resource, service, interruption and ownership-release records are required
per architecture; source implementation and regression tests alone do not establish
a passing cell in the [verification ledger](../verification.md#resource-kind-coverage).

## Password policy and pam-config

Tumbleweed's password provider uses SUSE `pam-config`, not `authselect` or
`pam-auth-update`. It accepts manager-owned `common-*` and `postlogin-*` symlinks
to their `*-pc` files, resolving `/etc/pam.d`, `/usr/lib/pam.d` and `/usr/etc/pam.d`
in vendor order. Regular administrator stacks are refused; the provider never
runs `--create`, `--initialize` or a forced conversion of unmanaged PAM files.
Installer provisioning must establish manager ownership first. The independent
`*-pc` input search must resolve to the same active object; orphan higher-priority
inputs are refused even if an inactive file happens to contain identical bytes.

Before a quality toggle, the provider round-trips every stack through the real
manager in a private temporary configuration directory. Any change to unrelated
modules, controls or arguments refuses adoption. Only the quality module and
the manager's associated `pam_unix use_authtok` change may differ. Activation
requires an existing manager-owned `/etc/pam.d/common-password` symlink.
The manager runs only against the private directory; its generated
`common-password-pc` is published through a lease-backed, descriptor-bound
native-file transaction after rechecking all active stacks. Authentication,
account and session files are never rewritten by a quality toggle, including
concurrent administrator edits. Changed inputs refuse publication and cannot
produce a successful convergence receipt. Success requires independent stack,
module and owned-file readback.
The [upstream manager](https://github.com/SUSE/pam-config) does not emit the
local-only history guard required by this resource, or a faillock flow; attempts
to activate those features are explicitly unsupported, not silently treated as
quality-only success.

Prerequisites are `pam`, `pam-config`, `pam_pwquality`, `libpwquality1` and
`libpwquality-tools`; the provider never installs them. Modules are under
`/usr/lib64/security` on both supported architectures. The quality library and
PAM module must have the same complete native package release. A vendor
`/usr/lib/security/pwquality.conf` with active settings and no `/etc` counterpart
requires administrator provisioning before adoption, avoiding loss of vendor
policy when creating the owned `/etc` file.

The [20261007 x86_64 repository](https://download.opensuse.org/history/20261007/tumbleweed/repo/oss/x86_64/?P=pam*)
lists `pam 1.7.3-1.1`, `pam-config 2.14+git.20260216-1.4` and
`pam_pwquality 1.4.5-5.7`. Repository inspection does not certify either
architecture. Exact snapshot/package pins and active root recovery access are
required; native resource evidence must qualify length/classes, repeat and
owned release on each architecture, with real ordinary-user `passwd` conversations
over bounded SSH PTYs that refuse weak passwords and accept strong changes.
Managed conversations reject otherwise-valid 13/15-character candidates for
minimums 14/16; release must accept the same 15-character candidate previously
rejected by the managed stack, not merely another long password.
The lane installs prerequisites only after dispatch selects its approved immutable
snapshot closure; it never enables moving repositories. These acceptance cases
are not a native qualification receipt. No Leap, SLES or SLED password support is
inferred. See the [verification ledger](../verification.md#resource-kind-coverage).

## Updates and snapshot boundaries

Leap requires a release-specific zypper/libzypp transaction model. Tumbleweed
requires a **tested distribution snapshot and native distribution-upgrade
semantics**, not Leap patch rules. Snapshot-pinned installation content, compatible
whole-system plans, interruption/reboot and rollback evidence remain separate
requirements (`docs/architecture.md:1294-1320`). A dated QCOW2 image alone does not
pin every subsequent repository transaction.

`lab images snapshot` retains a bounded dependency closure rather than claiming
that a rolling ARM origin is a dated archive. It enters the ordinary lab-host
FIFO, boots the authenticated pinned image on the selected native host, and
uses native zypper to solve a clean target root from the registry's exact
golden/action/resource/password/update/recovery prerequisites.
It includes recommendations to match AutoYaST's actual solver policy, including
the base/enhanced-base pattern RPMs and architecture-specific GRUB EFI BLS RPM.
The registry also explicitly requests `kernel-default=7.2.9-1.1` for
Snapshot20261007 aarch64 and Snapshot20261009 x86_64, as named by each target's
authenticated primary metadata. A missing dated, architecture-specific recipe
fails before capture. Base-system patterns and an unchanged bootstrap kernel
are not evidence that a clean-root closure contains the installer kernel.
The native clean solve must download that exact RPM; signature evidence records
its signed header and module configuration paths. The final golden does not
supplement a kernel-incomplete closure with a separately sourced DVD kernel.
Both ordinary and encrypted final AutoYaST profiles explicitly request the full
package name from those registry pins, rather than relying on an implicit
`kernel-default-base` selection. Before the installer may finish, the installed
chroot must report exactly the pinned RPM epoch, version and release; the
ordinary first-boot probes repeat that check. A mismatch fails closed instead of
accepting a different DVD kernel. Final recipe identity is
`opensuse-tumbleweed-dvd-autoyast-v10`. It resets `/etc/machine-id` explicitly
to an empty mode-0644 file, rather than inheriting the credential writer's
umask 077; unprivileged D-Bus must be able to read the first-boot identity.
YaST's `bootloader_finish` runs `systemd-machine-id-setup` after the chroot
provisioning script (installed `y2log`), which shipped one machine ID in every
v9 clone. An installation-system pre-script therefore installs a YaST hook,
`after_bootloader_finish_00_lindm-machine-id` in `/var/lib/YaST2/hooks`, that
empties the target identity again after that step.
SSH private keys and source markers retain their separate private modes.
In the DVD installation system `/etc/pki/trust/anchors` is read-only squashfs
and `update-ca-certificates` is absent, so v7's snapshot-trust pre-script
failed (`Read-only file system`) and AutoYaST stopped on `Failed to add product
from https://10.0.2.2:…/snapshots/…` before partitioning. Observed on the
aarch64 and x86_64 ordinary goldens, which then wait for the 45-minute installer
deadline; the encrypted profile uses the same pre-script. The v8 pre-script
writes the lab CA into `/etc/ssl/certs`, which the installation system's initrd
links into writable tmpfs and its libzypp verifies against, under the OpenSSL
subject hash the installation system's own `openssl` computes. The installed
system still receives the anchor and runs `update-ca-certificates`. A failed
ordinary golden install now retains a bounded, credential-redacted serial tail
(`snapshot-dvd-installer-failure`) in the private lab work directory, and a
failed first installed boot of that golden retains the same bounded console plus
journal warnings (`installed-image-first-boot-failure`).
AutoYaST reports a failed chroot provisioning command as a warning that times
out after 10 seconds, and the installation then continues. Provisioning
therefore writes the source marker as its last command, so the installed
`source_marker` probe refuses a partially provisioned golden.
A desktop profile also lists the registry's per-snapshot `DesktopTaboo`
packages under `<remove-packages>`. YaST's `en_US` locale selection recommends
`openconnect-lang` with the GNOME pattern, and the 20261007 aarch64 closure,
solved without requested locales, does not contain it. The installer refusal
accounting named it as the only gap, and the encrypted aarch64 GNOME install
stalled on it.
The encrypted golden identity also includes this AutoYaST recipe revision,
so a corrected installer cannot reuse an earlier encrypted disk merely because
its ISO and repository closure are unchanged.
The separate capture-only DVD bootstrap
does not request this final-closure kernel and does not run the final pin check.
Capture separately solves a native distribution upgrade against a copy of the pinned
base RPM database, allowing the native solver to handle renamed and obsoleted
bootstrap packages rather than forcing their old names into the target recipe.
The exact base inventory remains evidence. Both full download transactions are
then repeated with origin acquisition disabled. Native RPM signatures use only keys authenticated by
signed repomd; every retained RPM is also bound to the signed primary checksum.
Alternate roots receive the native filesystem's SELinux labels without changing
enforcement. Native key auto-import is confined to the already-authenticated
capture proxy, never to a mutable vendor origin.
DVD captures create a private, network-isolated bootstrap directly from the
authenticated DVD; they never depend on a final golden or its not-yet-captured
repository. Native keys are transferred over the pinned guest SSH connection,
without requiring curl in this bootstrap. The shared image cache is initialized
before any capture staging; a distinct explicit snapshot cache remains separate.
Native signature evidence also records signed kernel-header module config paths.

```sh
go run ./cmd/lab images snapshot \
  -manifest lab/images/opensuse-tumbleweed-20261007-aarch64.json \
  -host dgx21 -repo . -cache .cache/lab/images \
  -snapshot-date 2026-10-07 -repomd-sha256 "$REPOMD_SHA256" \
  -retained-metadata "$AUTHENTICATED_METADATA_DIRECTORY" \
  -max-bytes 4294967296 -max-packages 2500 \
  -record "$NEW_ACQUISITION_RECORD" \
  -firmware-code /usr/share/AAVMF/AAVMF_CODE.secboot.fd \
  -firmware-vars /usr/share/AAVMF/AAVMF_VARS.fd \
  -firmware-package qemu-efi-aarch64 -firmware-version 2024.02-2ubuntu0.10
```

The repomd digest and signed snapshot date are mandatory independent pins;
retained metadata is optional but always reauthenticated, never trusted by
pathname. Metadata drift, missing RPMs, solver conflicts, signature failures or
the byte/package ceiling abort publication. Default limits are 4 GiB/2,500 RPMs;
hard limits are 16 GiB/5,000 RPMs. This is not a full repository mirror.
Unchanged signed metadata paths and the complete acquired closure are published
read-only under
`CACHE/repository-snapshots/sha256/MANIFEST_SHA256/repository`. The manifest's
content address is SHA-256 of deterministic protobuf with its own digest field
empty. Native solver/replay output, exact prerequisite inputs, base inventory,
file hashes and resource bounds remain part of the closure evidence.
Authentication opens retained paths relative to pinned directory descriptors and
rejects symlinks and unlisted files. Signing keys, repomd and primary metadata
are verified from bounded, kernel-sealed immutable snapshots; each RPM's manifest
hash and signed metadata checksum are checked in the same stream. Concurrent
publication never replaces an existing content address: the loser authenticates
the winner or fails closed.
The acquisition proxy applies the same immutable verified-response rule to every
key, metadata and RPM response, with bounded admission and one spool. Any content
mismatch permanently fails that capture even if the pathname is later restored.
A request cancelled during verification returns no payload and does not by itself
invalidate the capture; an observed integrity or cleanup failure still does.
Native solver failure diagnostics retain the underlying capture failure as well
as the guest command result, rather than hiding it behind a repository HTTP error.
Failed unpublished trees regain owned directory write permission before cleanup;
an existing content-addressed winner is never repaired or overwritten.

A capture may reuse the image manifest's already-authenticated closure only when
its distribution, architecture, date, signed repomd and source pins match exactly.
Only native solver-requested files are copied, with fresh digest/size checks; both
new solves, offline replay and native RPM signatures remain mandatory. The new
manifest records the new exact input list and inventory, never the seed's claim.
Metadata-only remote staging exports at most 256 authenticated signed metadata/key
files and 512 MiB through verified immutable readers, not recursive directory sync.

The native x86_64 capture for `2026-10-09` completed its clean exact-kernel solve,
copied-base distribution upgrade, both offline replays and native RPM signature
checks on 2026-10-11. Both final DVD manifests now pin that actual closure:

- Manifest SHA-256:
  `ce7c2ff34cce5eb603eb4f40126d29b8fe4b66a278e84ff70cac1848323b6ace`.
- Signed repomd SHA-256:
  `54fa6d215972d7efb8a0835acac401327aca17b0b1eaf5c50eeb661635095aae`.
- Retained acquisition receipt `lindm-tier2-snapshot-x86-20261009-closure-kernel-final.json`,
  SHA-256 `72850f23dca84f456c4f3bc16cd16f7fa9508e17ecae2f88eabd8c1d3a110262`.
- 47 exact requested inputs, 2,043 RPMs, 2,073 files and 2,653,956,636 bytes,
  inside the declared 4 GiB/2,500-RPM limits.
- `kernel-default-7.2.9-1.1.x86_64.rpm`, SHA-256
  `0c27534bd93d6bfda1dbdd4cb0ebf910604dd1d1b8aee46e88f977f083d691b7`,
  passed native header and package RSA/SHA512 signatures. Its signed header names
  `/usr/lib/modules/7.2.9-1-default/config`.

The retained closure's `evidence/solver.txt` SHA-256 is
`0eb8a0b4b8ebf6a01ac7f42851221e79727f6820dd64d1510564554782d726f5`;
`evidence/signatures.txt` SHA-256 is
`ecbdb79d5513f56415959e3b26473a86bde1676564e2abff6bc30b1825b3766d`.
The older signed cloud image was only the native solver bootstrap. This proves
the bounded target closure, not a final DVD golden or any OS capability lane;
those still require their own matrix records.

Pin both `repository_snapshot_manifest_sha256` and
`repository_snapshot_repomd_sha256` alongside `repository_snapshot_date` in the
image manifest before using the read-only HTTPS lane server. Acquisition records
carry those same evidence names, independently of the ephemeral serving URL.
The HTTPS server retains at most sixteen admitted requests and one verified
private payload spool; excess clients receive a retryable HTTP 503 rather than
an unbounded queue of handlers. The matrix ledger binds both repository digests
in addition to the selected image manifest and evidence SHA-256.
Remote acquisition retains the immutable entry on Spark and returns it to the
controller through `images snapshot-export` / `snapshot-import`. Remote replay
stages the same exact closure on any selected host before starting the lane.
This framed stream admits a bounded content-addressed manifest first, then only
its exact sorted file sizes with per-file SHA-256 checks; unlisted files,
symlinks, oversized payloads and trailing bytes cannot become a recursive cache
copy. Vendor authentication runs again before atomic destination publication.
Arch capture is explicitly gated until a genuine signed pacman database backend
is maintained; an RPM closure is never relabeled as Arch support.

Bulk snapshot return has a separate, caller-cancellable 45-minute deadline,
not the five-minute cleanup budget for small lane records. A native ARM capture
published its authenticated closure but exceeded that old record-copy budget
during return; this is a transfer failure, not a failed native solve. Transfer
errors retain their actual context deadline and preserve the remote owned
evidence. Recovery streams the already published content address through the
same authenticated export/import protocol rather than rerunning acquisition.
File-count, byte, signature and immutable-publication checks are unchanged.

Fresh destinations first use the image cache's existing locked ownership-marker
initialization. A pre-existing unmarked nonempty directory is never adopted
merely because a repository closure is about to be imported.

**Native retained closure records (2026-10-11).** Both architectures completed
native clean-root and copied-base distribution-upgrade solves, both offline
replays, native RPM signature checks, and immutable publication. Each manifest
records 47 explicit target inputs, including `kernel-default=7.2.9-1.1`, with
bounds of 4,294,967,296 bytes and 2,500 RPMs. These qualify the retained closure,
not a final ordinary/encrypted golden or an OS-update/recovery lane.

| Target                      | Closure manifest SHA-256                                           | Signed repomd SHA-256                                              |
| --------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| Tumbleweed 20261007 aarch64 | `0d7092d787d82a590b2b1818db4c5516c940e05dc07d792657745269e87ff545` | `990c58b81cf28ff8d14ede123cfc6bc39c0cb0484ceba9f0e3e3e772e88d49ff` |
| Tumbleweed 20261009 x86_64  | `ce7c2ff34cce5eb603eb4f40126d29b8fe4b66a278e84ff70cac1848323b6ace` | `54fa6d215972d7efb8a0835acac401327aca17b0b1eaf5c50eeb661635095aae` |

The aarch64 closure contains 1,972 RPMs / 2,002 files / 2,543,337,377 bytes.
Its fresh, offline signed-DVD bootstrap reports 303 base packages. Acquisition
receipt `~/.cache/lindm-tier2-snapshot-20261007-closure-kernel-final.json` has
SHA-256 `55e9bb11fe605f90b8e8c664bc81fad86f12dac9e4e42ad7c16f8debe033ab60`.
The x86_64 closure contains 2,043 RPMs / 2,073 files / 2,653,956,636 bytes.
Its authentic 20261007 cloud image is only the solver bootstrap (367 base
packages), not a relabeled 20261009 golden. Its receipt
`~/.cache/lindm-tier2-snapshot-x86-20261009-closure-kernel-final.json` has SHA-256
`72850f23dca84f456c4f3bc16cd16f7fa9508e17ecae2f88eabd8c1d3a110262`.

Both manifests retain the actual signed `kernel-default` RPM and native header
evidence for `/usr/lib/modules/7.2.9-1-default/config`. The header and package
RSA/SHA512 signatures from key `29b700a4` passed, as did the payload digest.
Evidence is in each immutable repository's `evidence/solver.txt` and
`evidence/signatures.txt`.

Both complete entries are in the controller image cache
`/home/r/dev/minor/lindm/.cache/lab/images`; the ARM entry is also in Spark's
`/home/r/lindm-lab/images`. The original ARM controller command failed only
after successful native publication because bulk return inherited the small
record-copy deadline. A separate maintained, authenticated bounded export/import
completed in 435.92 seconds and populated the controller entry; this recovery is
not a claim that the original controller command exited successfully.

The implemented agent self-update helper installs only the admitted local package
using zypper `--no-refresh --reposd-dir <empty private directory>`, without
recommendations or vendor changes (see the command-line repository note above).
Interrupted same-version work can force reinstallation
([`native_linux.go`](../../internal/agent/update/native_linux.go), `zypperUpdateArgs`).
This is an agent-package path, not a Tumbleweed distribution upgrade or an atomic
OS updater. Signed metadata, immutable staging, authorization and observed native
recovery remain required (`docs/architecture.md:949-978`).

Do not promise that a filesystem/OS rollback also reverses application databases,
Flatpak state or user data (`docs/architecture.md:1315-1320`).

The Tumbleweed self-update lane selects zypper explicitly, never APT or a DNF
fallback. It builds signed native RPMs and reinstalls the initial package from
lindmd's own HTTPS `/repo/rpm` repository, requiring both signed `repomd.xml`
and package signatures. Publication finishes before the server opens its immutable
repository snapshot. The independent signed release catalog then delivers the
agent update. A zypper process in the owned frozen update cgroup plus an independently
observed partial RPM unpack file is required for its interruption witness; libzypp
names zypper's main thread `Zypp-main`, which is the frozen process's comm.
No SELinux mode is inferred from RPM packaging. Enabling this maintained lane
does not itself create a native pass in the verification ledger.

### Pinned Tumbleweed maintenance windows

Tumbleweed's OS update policy is a rolling whole-system operation, not a fictional
numbered release upgrade or Leap patch policy. A signed `rollingSnapshot` binds a
calendar date, an HTTPS OSS repository root and the exact SHA-256 of its signed
`repomd.xml`. `ALL` selection and zero per-package deferral are required. The
runner writes an isolated repository/service directory and runs native
`zypper dist-upgrade --no-allow-vendor-change`; it never uses the host's moving
repositories, disables signature checks or automatically imports signing keys.
Refresh must validate through native trust, and the cached metadata digest and
dated distro CPE must match the pin before package mutation. Expired archive
content, a missing package closure or a changed digest fails closed.
Before refresh and again before installation, native `zypper --xmlout locks`
resolves the effective libzypp lock source, including `configdir`,
`locksfile.path` and supported configuration overrides. Any configured lock
refuses the whole-system transaction; lindm never ignores locks or infers their
absence from an empty default `/etc/zypp/locks`.

The real x86_64 snapshot archive is
[`download.opensuse.org/history/`](https://download.opensuse.org/history/), with
dated `YYYYMMDD/tumbleweed/repo/oss/` roots. This is not evidence of an equivalent
aarch64 archive. The live ARM OSS URL is mutable; its installer before/after
snapshot check is not an immutable archive. ARM qualification must retain the
vendor-signed metadata and required RPM closure and serve that retained content
under an authenticated HTTPS root. The lab's temporary HTTPS endpoint is runtime
transport, not an immutable manifest identity.

The os-update lane provisions prerequisites at the image's own closure, so a
policy pinned to that same closure could not change a package. Its whole-system
policy targets `Lab.OSUpdateTargets`, a later, separately captured closure served
as a second lane origin: x86_64 targets the 2026-10-10 closure (manifest
`1165cc188e357a44320f9dee48974af28f76f0c6dd454d22e6d875526ac6ad3a`, signed repomd
`f48382bb7f18b6762f1fcf342954413c5ed88edd33a6c9215c4d80dc86e1f0d2`, 2,075 files,
2,657,776,978 bytes; acquisition receipt
`~/.cache/lindm-tw-qualify/capture-x86-20261010/capture.json`, SHA-256
`33c2a2635b44007ad2ecc41067b75294efbe5828a9c2546c7c8fff041b216a64`). The aarch64
ports repository has published nothing after the 2026-10-07 snapshot already
pinned by the aarch64 goldens (its repomd is still `990c58b8…`, revision
2026-10-08T02:08Z, observed 2026-10-12), so aarch64 has no later target and its
os-update lane cannot yet change a package.

Closure capture writes the installer's requested locale (`en_US`, the AutoYaST
`<language>`) into each solver root. libzypp selects `-lang` packages that
supplement requested locales; the 2026-10-07 aarch64 closure, solved without a
locale, lacked `openconnect-lang`, which YaST then requested for the GNOME
profile (recipe v10's desktop taboo excludes it for that snapshot).

The existing signed-resource authorization, ownership journal, native helper,
maintenance-window timer and authorized patch-now boundaries remain in force.
The transaction receipt records native package changes and explicit rollback
status. A configured, usable snapper `root` on an actual Btrfs root creates a
pre-snapshot; otherwise rollback is `unavailable`. Neither state proves a
bootable rollback or reversal of excluded subvolumes, databases, user data or
executor authority. No automatic filesystem rollback is performed.

Durable root-only receipts beside `run.binpb` and at
`/etc/lindm/os-update/rolling-in-progress.binpb` precede both snapshot creation
and package mutation. Either marker's survival (including malformed content)
holds further transactions until native recovery has been inspected and both
markers explicitly cleared. The root marker must share the root mount, and its
exact protected bytes must be read from the newly created snapshot before that
snapshot is admitted. Equal mount IDs alone do not suffice: Btrfs snapshots omit
nested subvolumes without separately mounted paths. Missing, changed or
symlinked saved markers stop package mutation and leave rollback unavailable and
the recovery hold retained. Package failure is not an automatic
retry, and the deferral ledger cannot erase the hold. Preserve executor
authority/journal anti-rollback and recovery boundaries; an OS rollback is not
authorization to rewind or repair those records. Whole-system success preserves
its receipt but reports security classification as
`rolling_security_classification_unavailable`, not a fabricated clean fleet result.

The native `lab matrix run` OS update lane requires changed native packages,
policy-triggered reboot and retained-marker refusal in addition to signed
assignment and ownership release. A marker fixture is not evidence of a real
power cut, and creation of a pre-snapshot is not rollback qualification.
[Verification](../verification.md) remains the authority for native results;
no new native pass is claimed by these source changes.

## Encryption and recovery

No Leap/Tumbleweed encrypted-install, recovery-escrow or TPM-binding pass is
recorded here. Generic LUKS code does not qualify a SUSE installer topology.
Storage effects require a qualified allowlisted target and operation; rotation
also requires an independent owner recovery slot and available keyslot/token
capacity ([`provider_linux.go`](../../internal/agent/actionprovider/provider_linux.go):209-258).

The encrypted GNOME golden extends the existing snapshot DVD AutoYaST recipe,
not a second installer implementation. It explicitly selects `grub2-bls`, a
1 GiB FAT ESP, unencrypted `/boot`, and a Btrfs root encrypted with LUKS2.
The vendor's
[GRUB2-BLS topology](https://news.opensuse.org/2025/11/13/tw-grub2-bls/)
stores active entries, kernels and initrds on the ESP and uses the Boot Loader
Interface for one-shot selection. It is not Fedora's `/boot/grub2/grubenv`
layout. No loader binary, kernel signature or firmware key is replaced.

The TPM boot variant installs the distribution's `udev` package (which owns
`systemd-cryptenroll`, `systemd-cryptsetup` and the TPM token library),
`tpm2.0-tools`, and dracut's `systemd-cryptsetup`/`tpm2-tss` modules. It rebuilds
the initrd but enrolls no token: native signed actions still own enrollment,
rotation, owner-slot preservation and cold-boot proof. Ordinary TPM event logs
are retained with SHA-256 in encrypted smoke evidence. Their presence alone
does not prove that GRUB measured the required final command and kernel into
PCRs 8/9.

Measured original-device recovery has a separate registry
`bls-loader-entry-oneshot` adapter on x86_64 and aarch64. It stages an
action-named initramfs and a last-sorted BLS entry on the vendor ESP, reusing the
exact measured kernel at its original nested ESP path. It never flattens a
machine-ID/kernel-version path into `/boot`, writes Fedora's `next_entry`,
regenerates GRUB configuration or replaces shim, GRUB, a kernel, firmware keys
or an owner entry. The registry supplies the boot directory and vendor EFI
configuration directory; distribution detection has no parallel distro table.
Kernel configuration is read from the registry-selected
`/usr/lib/modules/<release>/config` path. Existing Fedora/EL and Debian-family
recipes retain `/boot/config-<release>`; Arch selects its bounded compressed
`/proc/config.gz` after loading the registry's `configs` module. These acquisition
facts do not relax the required kernel configuration checks or establish a
native recovery pass.

Before arming, the adapter binds all BLS/loader configuration, vendor and fallback
EFI assets, optional vendor `grubenv` overrides and persistent/default EFI
selection variables into a bounded snapshot. It checks the kernel, staged
initramfs and entry digests again at the durable arm boundary. Data and containing
directories are synchronized before `bootctl set-oneshot` writes
`LoaderEntryOneShot`, and the variable must read back exactly. Rollback clears
only its own pending selection and removes only its digest-matching additions.
An interrupted stage, stale recovery entry or owner asset change refuses the
next handoff instead of overwriting or adopting it. FAT synchronization is not
a claim of hardware power-loss atomicity; interrupted-stage and rollback native
records remain required.

Readiness requires the running GRUB's Boot Loader Interface one-shot feature,
a `LoaderInfo` naming GRUB (upstream publishes `GRUB 2.14`; the openSUSE
build publishes `GRUB2 2.14`, observed on aarch64, and both are accepted; this
self-report is not chain authentication), the matching `LoaderDevicePartUUID`, a writable FAT ESP with measured capacity,
Secure Boot enabled outside SetupMode, a usable TPM resource manager and the
strict final measured kernel sequence. A separate XBOOTLDR kernel is not
silently mapped onto the ESP. Missing prerequisites report their actual reason,
not a platform-level implementation gate. `udev` supplies `bootctl`; the signed
snapshot closure must also retain the native GRUB2-BLS/shim, kernel, TPM, kmod,
zstd, e2fsprogs and nvme-cli inputs. No recovery transaction installs moving
repository packages or enrolls a fictional vendor key.
The ordinary and encrypted AutoYaST goldens both install the registry's action
and measured-recovery package lists from that closure and explicitly select
the vendor GRUB2-BLS loader. Recovery does not discover missing tools halfway
through an authorized handoff or silently fetch them from moving repositories.
The profile's GRUB menu timeout did not reach the golden. Booted with fresh
firmware variables, the first aarch64 boot waited at the GRUB2-BLS menu until the
SSH deadline (retained private first-boot console). The installed `y2log` shows
the order: the chroot provisioning script runs first, then `bootloader_finish`
runs `sdbootutil install`, `add-all-kernels` and `set-timeout -- 1`. That
`set-timeout` stores `LoaderConfigTimeout` in the installer's NVRAM, which the
golden does not keep. v9's `sdbootutil --no-variables set-timeout 1` in the
chroot script ran before `EFI/opensuse` existed and so wrote the removable
`EFI/BOOT` directory. GRUB2-BLS reads the `grubenv` beside its running
`grub.efi` in `EFI/opensuse`, so that write had no effect on the ordinary golden.
The target has no `grub2-editenv`. Provisioning therefore writes the
1024-byte environment block with POSIX tools into the registry's vendor
directory, `/boot/efi/EFI/opensuse/grubenv`, before the loader is installed, and
`sdbootutil install` does not remove it. The measured adapter binds that file as
owner state and never rewrites it.
Recipe revision 10 invalidates the earlier golden caches, so the
recovery-specific loader and tools cannot alias a revision-9 parity disk.
The offline solver bootstrap still installs its separate minimal DVD package list.

The registry admits this adapter, and
`lab matrix run -platform opensuse-tumbleweed -cells recovery-sanitize` qualifies
it per architecture. A pass requires retained ordinary/recovery TPM logs and a
verified ledger entry.
The matrix selects measured GRUB from the release's own registry row, requires
Secure Boot, and retains both exact image manifests and repository digest pins.
The package-owned Microsoft-enrolled template comes from `lab/matrix.json`
`secureBootArgs` on the scheduled host; the lane never modifies host firmware or
replaces vendor boot assets. Failed golden or action diagnostics return
privately in `<cell>-diagnostics` beside the evidence record.

The measurement source contract is upstream GRUB 2.14 `blsuki.c`,
`loader/efi/linux.c` and `commands/tpm.c`, plus the maintained
[openSUSE source revision](https://api.opensuse.org/public/source/openSUSE:Factory/grub2?rev=50cc75c719472639997e054ccf17fc06).
Its BLS entry generates `linux`, then `initrd`. The existing verifier requires,
in order, the final PCR 8 linux command, PCR 9 kernel bytes, PCR 8 kernel
command line, PCR 8 single-initrd command and PCR 9 initramfs bytes. Device
prefixes must agree or all be absent. Only the kernel EFI stub's recognized,
digest-bound load-options and initrd events may follow. The source-model BLS
regressions do not replace a captured event log and do not relax this sequence.
The TPM quote must still cover PCRs 4, 7, 8 and 9, have a valid restricted-key
signature, replay the bounded log and bind the fresh challenge and signed
BOOTED receipt. Signed ready/grant authority, exact durable target identity,
original-target allowlisting and independent human approval remain unchanged.

Native qualification (2026-10-12): the `recovery-sanitize` cell passed on both
architectures. Each run used the original enrolled device and generation on the
v10 ordinary GRUB2-BLS golden, under Microsoft-enrolled Secure Boot with swtpm.
The recovery initramfs was staged on the vendor ESP and selected through
`LoaderEntryOneShot`. The vendor shim, GRUB2-BLS and kernel booted it. The
server verified a fresh quote and event-log replay, and two humans approved a
native NVMe user-data format of the original namespace with the
`controller-serial-nsid` basis.

| Architecture               | Snapshot | Record                                                                                                              | SHA-256                                                            |
| -------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| aarch64 (dgx21 KVM, AAVMF) | 20261007 | `~/.cache/lindm-tier2-matrix/tw-arm-recovery-final-r16-23249a91/opensuse-tumbleweed/recovery-sanitize-aarch64.json` | `e5f34964970c99835394334f8f859baef54f3523084c490504921e864d2fe0fd` |
| x86_64 (local KVM, OVMF)   | 20261009 | `~/.cache/lindm-tier2-matrix/tw-recovery-final-r10-23249a91/opensuse-tumbleweed/recovery-sanitize-x86_64.json`      | `c8c9130f1fbebc93cbcc30e5f5707f9e761a831d5f9bab609995a3f923d97f71` |

The captured ordinary event logs are verifier fixtures in
`internal/measuredboot/testdata/tumbleweed-*-stock.eventlog`. The unchanged
strict parser accepts them: linux → kernel file → `kernel_cmdline` → initrd →
initrd file, for sdbootutil's nested
`/opensuse-tumbleweed/<release>/linux-<digest>` image. The measured kernel digest
equals each record's `recovery_vendor_kernel_sha256`. The running loader reports
`LoaderInfo` `GRUB2 2.14`.

The signed handoff's `kernel_path` admits `linux-<digest>` alongside
`vmlinuz-<release>`. Native NVMe admin commands use `NVME_IOCTL_ADMIN_CMD` on the
pinned descriptor, because Tumbleweed's nvme-cli 3.1 cannot address a
descriptor (see [architecture](../architecture.md)).

These are emulated QEMU NVMe and swtpm results, not physical TPM, firmware or
flash sanitization. The `recovery-sata` and `recovery-attestation-refusal`
phases have no Tumbleweed record. The [verification ledger](../verification.md#tier-capability-matrix)
is authoritative.

## Device actions

The matrix runs lock/quarantine, live-root erase and report-loss together through
`-scenario=wipe -wipe-phase=live-actions`. Recovery sanitize remains a distinct
capability and evidence cell; a measured-GRUB gate cannot suppress supported
live effects or be bypassed by their passing records.

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
A feed source resolves to its platform registry release
([`registry.go`](../../internal/platform/registry.go)), which supplies the product
CPE: SLES 15 with an explicit service pack (`15.N`), Leap 16.0, or Tumbleweed as
`rolling`. Leap 15.x, SLES 16 and Tumbleweed snapshot-dated sources are rejected
rather than mapped to a guessed CPE.
Feed authentication requires the vendor exact-filename checksum and detached
signature with pinned keys. SUSE coverage remains partial: no finding is not a
clean bill of health, and offline byte-pinned imports do not become fresh complete
coverage (`docs/architecture.md:1160-1196`). Do not interpret Tumbleweed GA notices
as rolling-snapshot vulnerability boundaries.
RPM `gpg-pubkey` signing-key rows without an architecture are keyring entries:
they neither match records nor make architecture coverage UNKNOWN
([Fedora advisory feeds](fedora.md#advisory-feeds)).

Tumbleweed also accepts the vendor's daily
[`opensuse.tumbleweed.xml.gz`](https://ftp.suse.com/pub/projects/security/oval/opensuse.tumbleweed.xml.gz)
vulnerability export through `FEED_FORMAT_SUSE_OVAL`. Registry product metadata
and the actual `openSUSE-release` RPM prerequisite both bind applicability.
The native package snapshot must satisfy the release EVR predicate; a dated
`VERSION_ID` alone cannot replace it. RPM names, EVRs and architecture
alternatives come from referenced OVAL objects/states, never prose comments.
`check="all"` requires every installed instance to satisfy the vendor condition,
including installonly kernel versions and secondary architectures. An older
kernel beside a fixed kernel is not converted into an `at least one` finding.
Unsupported referenced predicates, negation, foreign products and unresolved
references invalidate publication rather than silently widening applicability.

Acquisition stages at most 64 MiB compressed; two bounded XML passes index native
references then emit individual definitions, with a 512 MiB expanded ceiling.
Neither the complete XML nor the normalized export is materialized for server
publication. The exact compressed-byte digest is retained. HTTPS provenance is
not a detached SUSE signature. The generation timestamp bounds freshness; when
SUSE omits its timezone, the earliest possible UTC instant (displayed time minus
14 hours) prevents optimistic renewal. Re-fetching old bytes does not reset that
bound. Offline byte custody does not establish fresh complete coverage.

The [vendor README](https://ftp.suse.com/pub/projects/security/oval/README)
distinguishes this vulnerability export from `-affected` and `-patch` data.
The patch export includes patches still in QA and is not substituted. Coverage
remains partial for unreported, historical and third-party packages; no matches
does not certify a rolling snapshot. Live acquisition hashes, projected fixture
provenance and the separate native qualification boundary are recorded in
[verification](../verification.md#rolling-advisory-source-evidence).

Tumbleweed's maintained qualification command is `lab matrix run -platform
opensuse-tumbleweed -cells advisories -architecture x86_64 -repo "$FIXTURE"
-evidence NEW_DIRECTORY`; run a separate `-architecture aarch64` record with the
pinned architecture firmware. The lane selects the registry's primary real export,
not a CSAF fixture or an assumed Leap source. Native signed agent installation,
local password/WebAuthn fixture authentication, enrollment and full RPM inventory
comparison use the existing connected VM path. Controller HTTPS egress is required;
the native guest need not fetch vendor feeds.

The record retains fetched artifact/publication SHA-256 values, canonical snapshot
identity, the complete native-checked package multiset and its SHA-256, and the
actual paginated server findings with coverage reasons. A separate version-only
oracle selects actual vendor package versions from the same publication, compares
full EVRs using the guest's RPM Lua `rpm.ver` objects and checks the production
server vulnerable/fixed predicate. It never substitutes those comparison inputs
for installed package inventory. RPM's embedded Lua version-object API is required
(RPM 4.16 or newer); missing native tooling fails rather than simulating it.

**A passing partial-feed matching lane is not complete vulnerability coverage.**
Real nonzero normalized records and a positive native/server boundary oracle are
required even when current native packages have no affected matches.
`UNKNOWN/feed_partial_coverage` is retained; stale feeds, unrelated UNKNOWN
reasons, unsupported vendor criteria, missing evidence or failed acquisition
cannot become a clean result. Each snapshot/architecture's actual qualification
must be linked from the [verification ledger](../verification.md#tier-capability-matrix).

## Remote assistance capability roadmap

Leap and Tumbleweed, including their GNOME and Plasma editions, qualify separately.
The [capability contract](../product-specification.md#remote-assistance-capabilities)
defines all tiers' consent, off/limited/on policy, role permissions and audit.
Probe the selected portal backend: Clipboard must attach to the existing
RemoteDesktop session, FileChooser must mediate uploads, and notifications plus
lock/logout must bind the same local user. GNOME support does not prove KWin support.
Clipboard, keys/layouts, displays, messages, files, reconnect, recording and Tier 3
are [not run](../verification.md#commercial-assistance-capability-qualification).
Use pinned rolling snapshots and native nonce/hash, two-head and lifecycle evidence;
never silently substitute X11 capture. KDE qualification and unattended access
await parent confirmation.

The maintained installer requests GNOME, its portal backend, PipeWire and the
GStreamer capture plugin from the authenticated snapshot closure. The lab enables
disposable-guest GDM autologin only; installed SSH remains pinned-key-only. The
baseline GNOME Wayland lane is implemented, not natively qualified by source
changes, and does not enable clipboard/display/keyboard extensions without
their independent records in the
[verification ledger](../verification.md#tier-capability-matrix).

Encrypted requalification uses retained signed repository metadata and the
dependency-complete RPM closure. The private read-only HTTPS mirror supplies
only cached bytes under the snapshot manifest digest; a disposable lab CA
authenticates transport without replacing vendor RPM/repository trust. The
AutoYaST recipe installs that CA in both installer and installed-system trust.
Both encrypted and ordinary DVD recipes require that retained closure; the old
before/after live-snapshot fence is removed. A missing snapshot fails closed,
without fetching a moved repository or relabeling it as the qualified snapshot.

Repository acquisition does not depend on an already-built final golden. From an
empty derived-image cache, the capture driver installs a separate, ephemeral
`repository-bootstrap-v1` guest from the authenticated DVD alone: the base
pattern, SSH, sudo, RPM, zypper and iproute2, without recommends, cloud-init or a network
add-on. Both installer and first boot deny external egress; the capture driver
later exposes only its retained-repository proxy through pinned SSH. The shared
AutoYaST renderer installs per-run login and host keys directly. This disk is
never published to the ordinary/encrypted golden cache and cannot satisfy a
native golden qualification. Final goldens still require the captured, signed
closure and their own native records. The final ARM closure record above proves
cold signed-DVD bootstrap readiness and native solver/replay completion; it does
not qualify either final golden.
An authenticated Tumbleweed `minimal-vm-cloud` QCOW2 instead uses the normal
cloud-image guest and cloud-init readiness path. Bootstrap selection follows
the manifest's actual artifact edition, not the distribution's default DVD
installer; encrypted-golden manifests are never solver bootstraps.

The first cold aarch64 DVD capture reached the existing 45-minute installer
deadline; that failed attempt is not a bootstrap or snapshot-closure pass.
Capture-only installer failures now save a bounded, private JSON diagnostic
before deleting the disposable machine: separately bounded/redacted serial tail,
QEMU stderr, source ISO SHA256, and observed kernel/linuxrc/AutoYaST provisioning
stages. `-diagnostics DIR` selects the retained output directory. The original
failure remains the returned error and names this diagnostic. Routine encrypted
goldens still discard serial output. The separate explicit `-installer-log FILE`
option retains a capped owner-only installer and first installed-boot console;
it can contain lab credentials and is never public evidence. These diagnostics
do not relax signature checks, add online fallback, extend the installer timeout,
or promote a prior derived disk to clean-cache qualification.
The instrumented repeat retained
`lindm-cloud-init-3324746285.json`, SHA256
`82d9d3475ca08e46bd10a24aa0c787cfcace8135ec338b63d35c32e62cc76725`:
kernel output was observed, QEMU stderr was empty, and no AutoYaST profile stage
was observed before the 2026-10-11 16:49:52 UTC deadline. Its 162,794 serial
bytes exposed a diagnostic defect: the curses tail contained no LF, so the
initial partial-line safeguard withheld the whole tail. The diagnostic now
treats CR and ANSI cursor controls as terminal-text boundaries, with bounded
credential redaction still applied; this corrects evidence collection rather
than bypassing an installer failure.

The readable follow-up, `lindm-cloud-init-1879358902.json`, SHA256
`a69adbfba4ecc3a7972884418243e95edec99cd23bb0095976f60f9bd7176828`,
observed the profile pre-script and installation of 301 DVD packages, then the
modal **“No network running”** while saving installation settings. It expired at
2026-10-11 18:13:33 UTC without reaching provisioning. Read-only inspection of
the authenticated Snapshot20261007 DVD identified the missing declared
prerequisite: YaST's `NetworkService.isNetworkRunning` executes `/bin/ip addr`,
but its NetworkManager backend requests only `NetworkManager`, which merely
_recommends_ `iproute2`. The minimal bootstrap intentionally disables recommends.
Its registry package list now explicitly requests `iproute2`, and first-boot
readiness queries ownership of every declared bootstrap package with native RPM.
The networking backend, DHCP boot arguments, egress restriction, modal error
handling and installer deadline are unchanged. The final native ARM closure
`0d7092d787d82a590b2b1818db4c5516c940e05dc07d792657745269e87ff545`
subsequently passed the cold signed-DVD bootstrap and native solver/replay stages.
The two failed artifacts remain historical diagnostics, not qualification; the
successful capture is not a final ordinary/encrypted golden result.

Payloads inspected from the authenticated DVD (ISO SHA256
`bc84067c9a14aee474d151559b67fc8718295d2508d66669cb75edec587cb261`):

| DVD RPM                                             | SHA256                                                             |
| --------------------------------------------------- | ------------------------------------------------------------------ |
| `yast2-5.0.21-1.2.aarch64.rpm`                      | `3f9a9491ecac6fed4aaa31fa3e7bdc295e6f27bf7db9a120a036e6ebcfb54079` |
| `yast2-network-5.0.7-1.2.noarch.rpm`                | `f1991135f2fe94a5ba48e3b8c1b1f7641ee53167154fb77c60b02947cbe5f8dc` |
| `NetworkManager-1.58.1-1.1.aarch64.rpm`             | `576148a0674f8e5922222a026a7ba011e4fecf071735cc8ac9fdd91d6a6cecf4` |
| `iproute2-7.2-1.1.aarch64.rpm` (owns `/usr/bin/ip`) | `c9c1c598dc1db06cd520baf78e2291321f7c1f11180bcf7dbfcce8c711fb99b1` |

The first x86_64 final-golden inventory run failed acquisition, before any guest
boot: the vendor's Snapshot20261009 DVD checksum URL had advanced to HTTP 404.
The matrix retained that failure at
`lindm-tier2-rollinggoldens-tw-x86-inventory-v6-001/opensuse-tumbleweed/inventory-x86_64.log`,
SHA256 `28ac64395e4a6f334ead4c0c334d8219c722676ffc0ce8ce117acabf279f4bd7`.
The [Uzinfocom mirror](https://mirror.dc.uz/opensuse/tumbleweed/iso/) retained
the matching checksum and detached signature, but its maintained fetch failed
with `download body: context deadline exceeded` after 2,237.81 seconds; no
completed ISO acquisition was claimed. The ordinary/encrypted manifests now
select the [iHost mirror](https://mirror.ihost.md/opensuse/tumbleweed/iso/),
also listed in the [official mirror report](https://mirrors.opensuse.org/),
which retains the same dated checksum and detached signature. Snapshot date,
ISO SHA256 `902aff62e0de2ff0bf8075c1b878d3b7804c94f4ac40fe1c1f3f03f8a4567a02`,
4,687,134,720-byte size and pinned vendor signer remain unchanged. This is
transport relocation of identical authenticated media, not a snapshot
substitution or a golden qualification.
The maintained `lab images fetch` subsequently completed against iHost in
1,470.18 seconds: the full 4,687,134,720-byte ISO verified as
`CHECKSUM_MODE_DETACHED`, with both signer and primary fingerprint
`AD485664E901B867051AB15F35A2F86E29B700A4`. Its authenticated image, checksum,
signature and key are retained in the shared cache under
`sha256-902aff62e0de2ff0bf8075c1b878d3b7804c94f4ac40fe1c1f3f03f8a4567a02/`.
This establishes actual media acquisition only; final golden/action/session
qualification remains separately recorded by native matrix runs.

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
