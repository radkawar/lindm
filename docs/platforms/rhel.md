# Red Hat Enterprise Linux

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability            | RHEL 8                                                                                                                          | RHEL 9                                                                                                                        | RHEL 10                                                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| inventory             | implemented                                                                                                                     | implemented                                                                                                                   | implemented                                                                                                                   |
| lifecycle             | gated: not implemented for RHEL 8                                                                                               | implemented                                                                                                                   | implemented                                                                                                                   |
| dispatch              | gated: not implemented for RHEL 8                                                                                               | implemented                                                                                                                   | implemented                                                                                                                   |
| packages              | gated: systemd 239 rejects the package helper's transient-unit sandbox (ProtectKernelLogs=) and busctl has no --json before 240 | implemented                                                                                                                   | implemented                                                                                                                   |
| accounts              | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                                                                   | implemented                                                                                                                   |
| sysctl                | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                                                                   | implemented                                                                                                                   |
| definitions           | gated: systemd 239 is below the definition provider floor 252                                                                   | implemented                                                                                                                   | implemented                                                                                                                   |
| password              | gated: not implemented for RHEL 8                                                                                               | implemented                                                                                                                   | implemented                                                                                                                   |
| firewall              | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                                                                   | implemented                                                                                                                   |
| encryption            | gated: not implemented for RHEL 8                                                                                               | implemented                                                                                                                   | implemented                                                                                                                   |
| wipe                  | gated: not implemented for RHEL 8                                                                                               | implemented                                                                                                                   | implemented                                                                                                                   |
| report-loss           | gated: not implemented for RHEL 8                                                                                               | implemented                                                                                                                   | implemented                                                                                                                   |
| lock                  | gated: not implemented for RHEL 8                                                                                               | implemented                                                                                                                   | implemented                                                                                                                   |
| recovery-sanitize     | gated: not implemented for RHEL 8                                                                                               | implemented                                                                                                                   | implemented                                                                                                                   |
| self-update           | gated: not implemented for RHEL 8                                                                                               | implemented                                                                                                                   | implemented                                                                                                                   |
| assistance            | gated: not implemented for RHEL 8                                                                                               | implemented                                                                                                                   | implemented                                                                                                                   |
| assistance-clipboard  | gated: not implemented for RHEL 8                                                                                               | gated: not implemented for RHEL 9                                                                                             | gated: not implemented for RHEL 10                                                                                            |
| assistance-keyboard   | gated: not implemented for RHEL 8                                                                                               | gated: not implemented for RHEL 9                                                                                             | gated: not implemented for RHEL 10                                                                                            |
| assistance-displays   | gated: not implemented for RHEL 8                                                                                               | gated: not implemented for RHEL 9                                                                                             | gated: not implemented for RHEL 10                                                                                            |
| assistance-messages   | gated: not implemented for RHEL 8                                                                                               | gated: not implemented for RHEL 9                                                                                             | gated: not implemented for RHEL 10                                                                                            |
| assistance-files      | gated: local FileChooser consent, input isolation and secure transfer are not qualified on this release                         | gated: local FileChooser consent, input isolation and secure transfer are not qualified on this release                       | gated: local FileChooser consent, input isolation and secure transfer are not qualified on this release                       |
| assistance-reconnect  | gated: fresh consent after real logout/reboot and workflow expiry are not qualified on this release                             | gated: fresh consent after real logout/reboot and workflow expiry are not qualified on this release                           | gated: fresh consent after real logout/reboot and workflow expiry are not qualified on this release                           |
| assistance-recording  | gated: recording disclosure, encrypted storage and retention are not qualified on this release                                  | gated: recording disclosure, encrypted storage and retention are not qualified on this release                                | gated: recording disclosure, encrypted storage and retention are not qualified on this release                                |
| assistance-unattended | gated: a compositor-supported persistent remote-desktop grant, banner/stop and lock refusal are not qualified on this release   | gated: a compositor-supported persistent remote-desktop grant, banner/stop and lock refusal are not qualified on this release | gated: a compositor-supported persistent remote-desktop grant, banner/stop and lock refusal are not qualified on this release |
| assistance-elevation  | gated: pausing all remote injection around a local privileged prompt is not qualified on this release                           | gated: pausing all remote injection around a local privileged prompt is not qualified on this release                         | gated: pausing all remote injection around a local privileged prompt is not qualified on this release                         |
| assistance-annotation | gated: no qualified non-interactive compositor overlay exists on this release                                                   | gated: no qualified non-interactive compositor overlay exists on this release                                                 | gated: no qualified non-interactive compositor overlay exists on this release                                                 |
| assistance-audio      | gated: selected PipeWire output/microphone capture with local mute is not qualified on this release                             | gated: selected PipeWire output/microphone capture with local mute is not qualified on this release                           | gated: selected PipeWire output/microphone capture with local mute is not qualified on this release                           |
| assistance-kde        | gated: kde_plasma_desktop_unqualified: no native KDE Plasma Wayland lane on this release; the helper admits no KDE capability   | gated: kde_plasma_desktop_unqualified: no native KDE Plasma Wayland lane on this release; the helper admits no KDE capability | gated: kde_plasma_desktop_unqualified: no native KDE Plasma Wayland lane on this release; the helper admits no KDE capability |
| assistance-x11        | gated: x11_desktop_unqualified: no native X11 session lane on this release; X11 sessions end UNAVAILABLE                        | gated: x11_desktop_unqualified: no native X11 session lane on this release; X11 sessions end UNAVAILABLE                      | gated: x11_desktop_unqualified: no native X11 session lane on this release; X11 sessions end UNAVAILABLE                      |
| advisories            | implemented                                                                                                                     | implemented                                                                                                                   | implemented                                                                                                                   |
| os-update             | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release                         | implemented                                                                                                                   | implemented                                                                                                                   |
| release-upgrade       | gated: release upgrade is not implemented                                                                                       | gated: release upgrade is not implemented                                                                                     | gated: release upgrade is not implemented                                                                                     |

<!-- END GENERATED platform-capabilities -->

RHEL 9 and 10 on a supported minor are launch qualification targets; RHEL 8 is a
separate legacy row. x86_64 and vendor-image aarch64 server results must remain
independent. [Verification](../verification.md#1-launch-platform-qualification)
is authoritative and certifies no complete matrix cell. Rocky or AlmaLinux results
never substitute for RHEL entitlement, lifecycle or advisory applicability.

Pinned x86_64 inputs are
[`rhel-9.8-x86_64.json`](../../lab/images/rhel-9.8-x86_64.json) and
[`rhel-10.2-x86_64.json`](../../lab/images/rhel-10.2-x86_64.json).
RHEL 9.8 uses vendor-authenticated catalog SHA-256 provenance, not an OpenPGP cloud
image signature ([manifest:8-14](../../lab/images/rhel-9.8-x86_64.json#L8-L14)).
The vendor aarch64 KVM image is pinned as
[`rhel-9.8-aarch64.json`](../../lab/images/rhel-9.8-aarch64.json), acquired with
`lab images redhat fetch -version 9.8 -arch aarch64` (same authenticated catalog
checksum mode; the receipt schema now admits `x86_64` and `aarch64`). It runs on
the arm64 Sparks lab hosts and keeps independent results from x86_64.

## Packaging, signing, repositories, paths and LSM

Choose the target RHEL release in the console for one install-and-enroll command
using DNF and the customer's own `lindmd` HTTPS `/repo/rpm` endpoint. The command
authenticates the signer and server/bootstrap trust and requires package plus
repository signatures. It never redirects agent installation to an external
repository. RHEL vendor dependency access still requires the appropriate local
repositories or entitlement; lindmd does not redistribute the operating system.
Missing agent artifacts have an explicit server setup remedy. See the
[install runbook](../security-and-operations.md#enrollment-installation-from-your-server).
Fedora evidence does not qualify this RHEL path.

For unattended installs, a provisioning token offers **cloud-init** (KVM guest
image) and **Kickstart**. A Binary-DVD install needs no registration for the
agent itself: the snippet installs its DNF prerequisites only when `rpm -q` lacks
them (an unregistered DVD target has no enabled repository, and DNF 4 refuses an
install without one), then installs lindm-agent from `lindmd`'s repository alone
inside the `%post` chroot. RHEL 9.8 aarch64 from the Binary DVD, unregistered and
without any lab repository, passed end to end
([installer provisioning](../verification.md#installer-provisioning-from-the-console-2026-10-12));
RHEL 10, 8 and x86_64 are offered without a provisioning record.

The agent is a signed native RPM; building, signing and independent verification
precede publication ([`rpm.go:50-79`](../../internal/packaging/rpm.go#L50-L79)).
RPM configuration is `%config(noreplace)` and systemd lifecycle scriptlets are
part of the package ([`rpm.go:83-112`](../../internal/packaging/rpm.go#L83-L112)).
The installed binary is `/usr/libexec/lindm/lindm-agent`, with configuration under
`/etc/lindm` and distinct protected/network state under `/var/lib/lindm`.
Native RHEL service/trust/dispatch records below retained SELinux Enforcing;
permissive mode is not an equivalent qualification.

Image download, subscription registration and entitled repository access are three
different prerequisites. An offline API token is not a `subscription-manager`
activation key. The maintained lab creates a disposable registration credential,
sends it through bounded private input, records the actual consumer UUID, observes
identity and refreshes repository metadata
([`vm_redhat_linux.go:49-110`](../../internal/vmlab/vm_redhat_linux.go#L49-L110)).
The public run name and receipt survive guest teardown; native output and secrets
are suppressed ([`vm_redhat_linux.go:113-172`](../../internal/vmlab/vm_redhat_linux.go#L113-L172)).
Never publish token contents, activation credentials or temporary CDN URLs.

Use the documented `-redhat-token-file` and explicit `-allow-network` for a
registered connected lane. Restricted QEMU networking cannot reach the vendor:
`$HOME/.cache/lindm-platformlanes-20261009/rhel98-service-restricted-failure.json`,
SHA-256 `36bad86b993c56bd1ca9faa910e08b797456ed2237a7f2eb2f8336e158f21d78`,
records that prerequisite failure. A successful local RPM install with already
satisfied dependencies does not establish entitlement. Record registration,
identity, metadata refresh, unregister and activation-key deletion independently;
interrupted cleanup requires exact owned-consumer reconciliation, not broad tenant
deletion. Air-gap content authorization and mirrors require separate evidence.

### Native turnkey PostgreSQL dependency contract

Connected RHEL 9 turnkey installation explicitly enables the vendor
`postgresql:16` AppStream before installing `postgresql-server` and `postgresql`
from the configured, authenticated distribution repositories. No public repository
is added and no operator module-selection step is required. Vendor repository
access (normally RHSM entitlement) remains a host prerequisite.
See [Red Hat's PostgreSQL documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_using_database_servers/using-postgresql_configuring-and-using-database-servers).

The installer never resets modules or switches an existing PostgreSQL stream.
Conflicting/disabled PostgreSQL module policy, non-16 PostgreSQL server/client
packages, or a nonempty unrelated standard PostgreSQL data directory cause a
refusal. The remedy is a fresh supported turnkey host, not adoption, overwrite,
or major-version migration of an existing database. Other modules are untouched.
The private cluster remains under `/var/lib/pgsql/lindm`.

Before provisioning, the installer checks the actual `postgres`, `psql`,
`pg_dump` and `pg_restore` executables for PostgreSQL 16. Upgrade checks these
clients before its backup and rejects server/client major-version skew in
database preflight. Database URLs retain `channel_binding=require` and
`require_auth=scram-sha-256`; older libpq clients are not accommodated by removing
authentication requirements.

v0.1.0 RHEL 9 turnkey installation is connected-only. RHEL `--airgap` refuses
before mutation: “RHEL offline installation is not available in this release”.
The current snapshot contract does not establish PostgreSQL 16 module capability;
the existing generic PostgreSQL closure is not accepted as a PostgreSQL 13
fallback. An authenticated PostgreSQL 16 capable add-on is post-v0.1 roadmap
work. The capture/backend description below is not turnkey air-gap qualification.
Connected release exports remain snapshot-optional; Ubuntu air-gap is unchanged.

### Native air-gap server dependencies

The dedicated `internal/serverdeps` RPM backend targets RHEL 9 x86_64, not
openSUSE's `internal/vmlab/reposnapshot` format. Capture runs DNF4's real solver
on an admitted disposable, authenticated vendor image after protected RHSM
registration. It excludes the installed package sack, retains the complete
requested dependency graph, and records the image digest, fresh baseline,
solver versions, package NEVRAs, metadata hashes and native package signatures.
The native prerequisites are `postgresql-server`, `postgresql`, `openssl`,
`systemd`, `ca-certificates`, `rpm`, `cpio` and `policycoreutils`.
The `/usr/bin/rpm2cpio` utility belongs to the signed `rpm` payload, not a
separate RHEL package; replay records its actual native package owner.
Backup encryption uses the maintained `filippo.io/age` v1.3.2 Go library
compiled into the signed server executable and installer, not an external age
binary. The closure retains the native PostgreSQL client dependencies used by
`pg_dump` and `pg_restore`. No age RPM, EPEL, public mirror or preinstalled
dependency fallback is admitted.

BaseOS and AppStream acquisition keeps Red Hat's CA verification and entitlement
client authentication enabled. Official metadata is authenticated by vendor
TLS/RHSM, not a required `repomd.xml.asc`: the authenticated release manifest
binds the exact acquired index and metadata bytes, whose native checksums bind
each package. Offline installation independently verifies every RPM with an
isolated keyring containing only exact-pinned
[Red Hat product signing keys](https://access.redhat.com/security/team/key).
The full independently pinned fingerprints and exact armor hashes remain the
authority. Native signer IDs follow the key's OpenPGP version: release key 2
uses its fingerprint's low 64 bits; release key 4 uses the high 64 bits under
[RFC 9580 section 5.5.4.3](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4.3).
[Red Hat's native key listing](https://access.redhat.com/solutions/7136467)
records release key 4 as short ID `05707a62`; its download alias `6afedf8f` is
not the native version-6 signer ID.
On SELinux hosts, the newly created private parent takes the standard system
root label from `/`, matching the existing disposable native-solver pattern.
Its private keyring directory takes its label from the actual native RPM
database path, bounded to `/var/lib/rpm` or `/usr/lib/sysimage/rpm`. Only these
new private directories are relabeled; this changes no host database, keyring,
policy or enforcement setting.
It then invokes native DNF on local digest-checked RPMs, with repositories and
plugins disabled, `localpkg_gpgcheck=1`, and an empty transaction network
namespace. Missing dependency bytes fail; TLS, RPM signature verification and
SELinux enforcement are not disabled.
DNF's additional native signature check uses the operating system's existing
vendor trust roots. The consumer does not import release or vendor keys into the
host keyring. Replay records the actual pre-transaction native `gpg-pubkey`
inventory; absent native vendor trust fails closed rather than bootstrapping a
new host trust root.

Failed capture reports only a closed acquisition-stage code, never native
stderr, traceback, entitlement material or repository configuration. Private
RPM database initialization and exact-pinned vendor key import may additionally
classify permission, read-only filesystem, locked database, unsupported backend
or timeout failures. Key import identifies only the public release-key slot
(2 or 4), with fixed unsupported-key-version, algorithm or policy-rejection
codes when matched. Native stderr stays in a nonblocking 4 KiB anonymous pipe
and is discarded; unrecognized causes remain generic stage failures. These
codes are diagnosis, not successful acquisition or replay evidence. Both vendor
keys remain required; a failed import is not skipped or relaxed.
The pipe-size syscall command comes from Go's Linux constants, not
`fcntl.F_SETPIPE_SZ` (which Python exposes only
[since 3.10](https://docs.python.org/3.10/library/fcntl.html)). RHEL's native
DNF interpreter is retained; no newer Python prerequisite is introduced.

The privileged native installer owns a separate distro PostgreSQL 16 cluster
at `/var/lib/pgsql/lindm`, loopback port 5432 and `/run/lindm-postgresql`.
An existing port-5432 owner is a collision, not a cluster to adopt. Native
`restorecon` applies the standard data labels; installation does not disable
SELinux or create a custom high-port exception. Separate SCRAM runtime and
migration roles use verify-full TLS under the deployment's database CA.
The cluster config permits 64 connections and 256 MiB shared buffers; server
device and console pools are 16 and 4 respectively. Protected setup and
operations state live under `/var/lib/lindmd-operations`. RPM pre-transaction
checks refuse unsigned native-upgrade bypasses. RHEL 9 offline installation is
not available in v0.1.0 and refuses before mutation, even with a supplied add-on.

Native units use the distribution's systemd `LoadCredential=` support for distinct
runtime and migrator URLs. Persistent URL files remain root:root mode 0600;
neither role owns the at-rest secret. Restore republishes fresh target credentials
to the original stable paths while keeping native SELinux/privilege gates intact.
Actual owner/mode, both accounts' unreadability and native credential handoff are
required deploy-lane assertions, not a source-only qualification claim. See the
[root custody evidence boundary](../verification.md#turnkey-source-security-reinspection).

Bundled agent-repository reads preserve `RestrictSUIDSGID` and syscall filtering.
They use pinned `openat` descriptors with no symlinks in any path component,
including ancestry above the repository root. This retains the native sandbox
when `openat2` is refused; no SELinux or signature check is disabled. Ubuntu's
specific-source diagnosis and kernel regression do not qualify the RHEL server
lifecycle; that still requires its own signed-bundle `lab deploy` record.

The `internal/platform` registry's RHEL 9 server installation facts own the
snapshot filename, required native packages and PostgreSQL data/bin/port layout.
Consumers use the row's native package database and entitlement facts rather
than comparing distribution IDs. The closure retains its canonical RHEL 9
identity and actual base-image digest; captured guest evidence still records the
observed point release. Server facts are not inherited by derivatives and
deploy admission remains limited to RHEL 9 and Ubuntu 24.04 on x86_64.

A complete publication also requires actual native replay on a second fresh
image baseline with external VM egress denied. Capture alone is not qualification.
Production snapshots require the customer's entitled private release custodian
and approved content rights; `development-lab` custody never grants production
redistribution rights. Tokens, activation credentials, client certificates and
private keys are not release artifacts or evidence. Public hosting is not
supported. See [verification](../verification.md) for actual native records;
implementation alone is not an offline server installation verdict.

#### Actual acquisition evidence: blocked, not qualified

As of 2026-10-14, seven real fresh RHEL 9.8 x86_64 native acquisition attempts
failed. They used the vendor-authenticated raw image SHA-256
`b99091f1b4489111004d449398d9cc6aa024cb48b02c72fa99e6ca1fc48a7e4e`,
the eight prerequisites above and `development-lab` custody. No closure digest,
second fresh offline replay, common-store publication or air-gap installer
qualification resulted.

1. Producer source `15ee0569`; helper SHA-256
   `b6378386d3539a2eb93f2021513756d3b79e031ae69ac834a48ff4af73abb896`.
   Observed failure: guest exit 1; stage not classified.
2. Producer source `1ba3546b`; helper SHA-256
   `6eb0eca780434fc989b11908ea67b045f5861aba70eed449d8579bdec6c71895`.
   Observed failure: `native-keyring-initialization`.
3. Producer source `d1e74cd5`; helper SHA-256
   `37c54949731f1b400596e3168f07010e4a73e0df01d5f36b9afd689bd2cb07e1`.
   Observed failure: `native-keyring-database-init`; database label stage passed.
4. Producer source `8df8b36d`; helper SHA-256
   `e32a524b07f6b3632e73e97ebe1ce1341a6f32f9a3b30f251df358bedf22b33e`.
   Observed failure: `native-keyring-database-init`; cause unclassified.
5. Producer source `61127d6f`; helper SHA-256
   `7e0ceeaf0c35d1c882650437dde8dabba8f22ba37d505f931d085edef9362a6f`.
   Observed failure: `native-keyring-database-init-permission-denied`; denial
   mechanism not established.
6. Producer source `7f8ae6735`; helper SHA-256
   `d03de1d5173248a63ae82dc85a583d9d1d8ac38cfcf7a96dab998bea10eb1f51`.
   Observed failure: `vendor-key-import`; native database initialization passed,
   failed key not distinguished.
7. Producer source `c53bfab3a`; helper SHA-256
   `7c24c007980ebba9bc9991a85b9c660d560dd1ed474e6299b622c8211ccd87d6`.
   Observed failure: `vendor-key-import-release4-unsupported-key-version`;
   native database initialization and release-key-2 import passed.

A queued producer-7 request was separately canceled before its observed FIFO
admission for owner-demo priority; it is not an eighth native failure. The
same immutable producer was requeued only after both owner-demo workers were
admitted. No owner-demo process or unrelated guest was stopped.

Secret-free failure and source records are retained with mode `0600` outside
the repository under the private
`lindm-turnkey-rhel-serverdeps-20261013` cache prefix. Raw native diagnostics,
registration receipts and credentials are not published. The capture wrapper
defers bounded owned RHSM unregistration/activation-key deletion, exact owned
VM teardown and private staging removal, joining cleanup errors into the
failure. Attempt 7 returned only its capture-stage failure, with no additional
cleanup error; its private closure store was observed empty afterwards.
Failure-run RHSM boolean receipts and a separate VM-teardown receipt were not
retained, so independently recorded cleanup success is not asserted.

The remaining prerequisite is a vendor-supported RHEL 9 native key-verification
path that can import and verify the exact admitted release-key-4 bytes without
weakening signatures, crypto policy, TLS, SELinux or host trust.
[Red Hat documents V6-key compatibility symptoms on RHEL 9.7](https://access.redhat.com/solutions/7139122),
but that is not a verified remediation for this RPM import failure. Both
admitted vendor keys remain required; unsupported imports are not silently
omitted. The later native version-6 signer-ID correction (`f0f440110`, landed
as `c6591fbdd`) fixes identifier matching only: it does not repair this import
failure or establish capture/replay success.

## Agent services and sandbox

The root executor has AF_UNIX only, strict filesystem protection and private
devices. Action provisioning grants only reviewed target-specific exceptions;
network access belongs to the unprivileged `lindm` unit, which has no capabilities.
Sources: [`lindm-executor.service:10-61`](../../internal/packaging/assets/lindm-executor.service#L10-L61)
and [`lindm-agent.service:11-50`](../../internal/packaging/assets/lindm-agent.service#L11-L50).
Do not loosen SELinux or systemd protections to inherit another distro's result.

## Inventory and per-field quirks

RPM inventory preserves name, epoch, version, release, architecture and modularity
label. Selection requires exact OS identity and an existing native database, not
`ID_LIKE` ([`packages_linux.go:46-85`](../../internal/agent/inventory/packages_linux.go#L46-L85)).
RHEL's DNF4 configuration observer uses installed Python DNF4 APIs in isolated mode,
without plugins, metadata loading or network activity. The shared
[`dnf` helper](../../internal/agent/dnf/manager.go) identifies the installed native
manager and its version rather than deriving DNF4 from the distribution name.
The [configuration probe](../../internal/agent/inventory/platform_dnf.py) publishes
explicit releasever files in native precedence order, separately detected effective
releasever, and enabled repository IDs/configuration. Base URLs, metalink/mirrorlist,
package-signature checks and key locations preserve native settings; URL userinfo,
queries and fragments are removed with an explicit redaction marker. CPE remains
independent os-release evidence in the
[platform collector](../../internal/agent/inventory/platform_linux.go).

Unavailable release lock, successful empty repository list and collection failure
are different states. The unregistered RHEL captures in [verification](../verification.md)
had no configured lock and empty enabled repositories; these do not prove EUS/E4S
or entitled access. RHEL 9's lab CPU oracle uses portable `lscpu --json`, not the
newer `--hierarchic=never` option.

Current-schema RHEL9.8 x86_64 `lab vm inspect` passed all 490 native RPM records
with DNF4 repository/CPE/effective releasever observations `SUCCESS` (effective
major releasever `9`, no explicit lock, and zero enabled repositories on this
unregistered vendor image). See the `rhel98-inspect-readiness.json` record in
[verification](../verification.md); this is not entitlement or EUS/E4S evidence.
CPU model/source remain native procfs observations.

On a registered host, subscription-manager's `/etc/yum.repos.d/redhat.repo`
declares every repository the entitlement offers, most disabled: 200,272 bytes on
registered RHEL 9.8 aarch64 and 57,600 bytes on RHEL 10.2 aarch64 (measured
2026-10-12). The DNF configuration observer
([`platform_dnf.py`](../../internal/agent/inventory/platform_dnf.py)) bounded every
configuration file at 64 KiB, so registered RHEL 9 hosts reported repository
collection as over capacity and advisory matching found no servicing stream
(`rhel_platform_stream_unavailable`). `.repo` files are now bounded at 1 MiB each
(the 4 MiB aggregate bound is unchanged; other configuration files keep 64 KiB).

The fast Cloud image can finish SSH/cloud-init before NetworkManager finishes
IPv6 startup. Initial strict comparisons correctly returned no verdict when a
router advertisement added an address and default route between samples.
The maintained [readiness gate](../../internal/vmlab/vm_inspect_readiness_linux.go)
waits on systemd's startup-complete state and `nm-online -s -q`; the passing record
contains `degraded` (settled, not all-services-healthy) and NetworkManager
`complete`, with timestamps. No network field was removed or exempted.

## Updates

Distinguish agent self-update, package-resource transactions and vendor OS stream
upgrades. Native agent self-update verifies RPM name/version/architecture and
rejects immutable OS markers
([`update/native_linux.go:111-147`](../../internal/agent/update/native_linux.go#L111-L147)).
Unattended native self-update is qualified on RHEL 9.8 and 10.2 x86_64 KVM
guests under SELinux Enforcing: signed hold/rollback/mix-and-match/expiry/tamper
refusals, an actual DNF4 unpack frozen and interrupted by an owned guest reset,
completion by the boot recovery helper, and signed downgrade refusal (see
[verification](../verification.md#rhel-encrypted-device-actions-and-self-update)).
The executor never runs the DNF4 CLI: the verified update helper runs
`dnf --disablerepo=* --setopt=plugins=0 install|reinstall` on the staged,
digest-verified local RPM inside its own transient `systemd-run` unit
(`PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`), which is not under the
executor's read-only `/var`, so the hawkey-log limitation of the package-resource
path below does not apply
([`update/native_linux.go`](../../internal/agent/update/native_linux.go)).
Authenticity comes from the TUF-signed target digest/length plus RPM
name/version/architecture validation; the lane neither registered the guest nor
used repositories. The same lane passed natively on RHEL 9.8 and 10.2 aarch64 KVM
guests (matrix `self-update` cells); there DNF4's frozen unpack task is named
after its resolved `dnf-3` script rather than the `/usr/bin/dnf` symlink, which
the lab's unpack witness accepts. Not exercised: registered or EUS/E4S guests.

### Capability policy vendor source

A signed Packages capability on RHEL 9/10 approves the host's own vendor archive,
`rpm/12e3a0eb-c710-58d9-bd79-a491c614754c`. It does not register the device or send
customer credentials to lindmd. Registration remains a local administrator task:
the agent reads RHSM-managed `/etc/yum.repos.d/redhat.repo` and the device's local
entitlement certificate/key and Red Hat CA under root custody. A missing, disabled
or unsafe entitled source refuses before native observation or staging, with the
console remedy **Register this device with Red Hat**. The signed refusal preserves
that remedy on the managed item; it is not an instruction to enable an already
granted capability. A subsequent changed capability observation releases the hold.
Management observations and package admission re-read local prerequisites while
re-verifying the same stored signed policy against current enrollment/trust.
Registration or unregistration therefore changes availability without a policy
rotation, restart or new acceptance time; it cannot reactivate an inert grant.
The existing management loop hands changed protected capability status to the
sole inventory owner, which re-reads it for an ordinary durable host report.
Stable status does not cause repeated collections. This handoff does not mint a
policy, fabricate a signed inventory-refresh action, change its audit or bypass
the server's ordinary inventory admission cooldown; queued immutable reports
drain through the existing transport.
If entitlement disappears during staging, the same registration remedy is retained
and its unsupported hold is also released after a changed capability observation.

The registry admits exactly `rhel-9-for-<arch>-baseos-rpms` plus
`rhel-9-for-<arch>-appstream-rpms`, or the corresponding `rhel-10` IDs, with
`<arch>` equal to the device's `x86_64` or `aarch64`. It never inherits other enabled
host repositories, EUS/E4S, debug, source or mixed-architecture repositories.
Only those two definitions are written into the transaction's private repository
directory. Duplicate fields/stanzas, continuation values, foreign key/CA paths,
non-entitlement credential paths, URL credentials, proxies and disabled signature
or TLS verification are refused. Credentials remain local file references, never
source protocol fields, errors or server-side evidence. RHSM registration plugins
are not loaded by the package transaction.
RHSM's descriptive `ui_repoid_vars` is accepted but discarded, not used as an
execution option. `skip_if_unavailable` is accepted only as `0` or `false` and the
isolated output always forces `0`; unavailable sources are never silently skipped.

`$releasever` is resolved to the registry's standard major archive (`9` or `10`)
and `$basearch` to the matched architecture before DNF reads the isolated file;
other substitutions are refused. The transaction does not load ambient DNF
variable directories or implicitly follow a host EUS/minor-release lock.

CDN metadata has no required detached `repomd.xml` signature: the narrow RHSM
source authenticates it through verified HTTPS to the registry-pinned
`cdn.redhat.com` using `/etc/rhsm/ca/redhat-uep.pem` and matching local entitlement
certificate/key files under `/etc/pki/entitlement`. This is not a generic unsigned
RPM metadata switch and does not authorize arbitrary base URLs. Package signature
checks remain mandatory. Disconnected Satellite, public mirrors and alternate
servicing streams are not admitted by this source contract.

Both RHEL 9 and 10 pin Red Hat **release key 2**:
`567E347AD0044ADE55BA8A5F199E2F91FD431D51`, published with the installed
`/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release` path on the
[Red Hat product signing keys page](https://access.redhat.com/security/team/key)
([public key](https://security.access.redhat.com/data/fd431d51.txt)).
The installed file may also contain auxiliary or post-quantum keys; only the
cryptographically matching public release key is extracted, exported as a public
ASCII-armored key (required by native `rpm --import`) and imported into the
isolated RPM verification database. Their presence never expands signer
authority. The observed whole-file SHA-256 is bound into the approved source and
rechecked before staging; changed bytes or a different release fingerprint refuse.
New/PQ-only signers require a separately reviewed registry and native-verifier
cutover, not acceptance by UID, short key ID or a successful system RPM key import.

RPM verification requires every reported header/payload digest to be `OK` and at
least one `OK` signature from the pinned approved key. RHEL 10 dual-signs some
packages with release-key-2 RSA and a separate release-key-4
ML-DSA-87+Ed448 signature. A secondary, unapproved `NOKEY` signature is
non-authoritative; it neither grants trust nor invalidates the verified approved
signature. Only that exact case may account for native `rpmkeys` exit status 1.
Any bad or failed-verification signature, failed digest, approved-key `NOKEY`,
unknown/ambiguous output, warning or other execution failure refuses. The
isolated keyring still contains only release key 2, and native installation's
signature/digest verification flags remain unchanged.

Deterministic tests cover both releases/architectures, the signed capability and
item-refusal boundary, tampered local definitions and full fingerprint selection.
The `rhsm-upstream-model.repo` compatibility fixture is explicitly derived from
[upstream subscription-manager property names](https://github.com/candlepin/subscription-manager/blob/subscription-manager-1.19.2-1/src/subscription_manager/repolib.py),
with synthetic entitlement filenames: it is not a registered RHEL9/10 capture.
The separate
[`rhel9-registered-redacted.repo`](../../internal/agent/rhsm/testdata/rhel9-registered-redacted.repo)
fixture is an actual registered `rhel9-02` guest capture:
`registered-rhsm-public-stanzas-redacted-paths`, decoded SHA-256
`afd7e9c1bbf7de72412c14d03db418f757c627f205a18217ead20a85e31fb477`.
Only BaseOS/AppStream public definitions remain, with entitlement serials replaced
by `10101` and no certificate/key contents. It records `sslverifystatus`,
`metadata_expire` and `enabled_metadata`, without `ui_repoid_vars` on that guest.
The parser regression protects these observed fields, not successful native
package execution.
These fixtures are implementation/security regressions, not live entitlement,
package transaction or SELinux qualification.

The maintained registry-source lane passed separately on RHEL 9.8 and RHEL 10.2
x86_64 ([native parity record](../verification.md#registry-package-source-native-parity)).
RHEL 10.2's `~/.cache/lindm-pkg-source-proof/rhel10-04/proof.json` has SHA-256
`f1832d5ca1f5b1f54c9405d52232eced5f40051a6a370f7da81dff64adaef7df`.
It installed actual entitled `git 0:2.52.0-1.el10` from the exact registry
BaseOS/AppStream source with device-local RHSM credentials and the signed
Packages grant, without local provider opt-in. Native signature/digest checking
remained enabled through the committed installation. The same signed policy
then refused the unregistered device with `rhsm_registration_required`, visibly
showed **Register this device with Red Hat** on the Services tab, and recovered
with a new postregistration attested read-only convergence of the same assignment.
Both RHSM consumers were unregistered, their activation keys deleted, and exact
UUID API reconciliation observed both absent. These connected x86_64 results do
not qualify aarch64, EUS/E4S, Satellite, offline vendor packages or unmanaged
package adoption.

### Package resources (DNF4)

RHEL 9/10 package resources use their own DNF4 backend (`BACKEND_DNF4`), never
DNF5's stored/replayed transaction contract. The platform only selects which
generation is acceptable (`rhel`, `almalinux`, `rocky` → DNF4 4.7.0 or newer,
Fedora → DNF5); the installed manager must identify itself as that generation.
The DNF4 CLI cannot run under the executor's read-only `/var`: even `dnf
--version` builds an RPM database sack that opens `/var/log/hawkey.log` before
`--setopt=logdir` applies, and exits 1. DNF4 is therefore identified through the
`dnf` module imported by exactly the interpreter the native `/usr/bin/dnf`
entrypoint (a symlink to `dnf-3`) names, which also reports the native
versionlock plugin state
([`dnf4_linux.go`](../../internal/agent/packageprovider/dnf4_linux.go)).

Transactions use the fixed embedded
[DNF4 Python API adapter](../../internal/agent/packageprovider/dnf4_transaction.py),
run with `-I` under exactly the interpreter named by the native `/usr/bin/dnf`
shebang (`/usr/bin/python3.9` on EL9, `/usr/libexec/platform-python` on EL8).
It never reads ambient `dnf.conf`, drop-ins or repositories, and loads no plugin
except the native versionlock plugin. Staging is asynchronous like DNF5's:
`resolve` refreshes the approved repository (`repo_gpgcheck`) and declares exact
download sizes, `stage` re-resolves with non-expiring metadata, downloads into
the transaction directory and writes the same closed `transaction.json` shape the
Go provider already verifies (NEVRA, action, reason, repository, package path).
DNF4 refuses package downloads under `cacheonly`, so the stage phase pins
metadata expiry instead. The read-only staging sandbox cannot open
`/var/lib/dnf/history.sqlite` (libdnf's `Swdb` writes on open), so staging
resolves against a private consistent SQLite snapshot of it, which preserves
inherited install reasons. Before the signed start permit is consumed, a
`check` phase replays the staged bundle from local RPMs alone (`@commandline`
repository, dependencies chosen by the solver) and requires the identical
NEVRA/action/reason set; `apply` repeats that check after the lock is written
and runs the native RPM transaction.

Signatures are checked four times: every staged RPM against the approved key
only and against system RPM trust (`rpmkeys --checksig`, as for DNF5), by DNF's
`package_signature_check` in both stage and replay, and by RPM itself during the
transaction because the adapter sets `%_pkgverify_level all`. The approved key
must already be imported into system RPM trust.

Exact versions are persisted as an owned entry in the DNF4 versionlock plugin's
list `/etc/dnf/plugins/versionlock.list`: a `# lindm:<resource key>` comment
immediately followed by `name-epoch:version-release.arch`. Other lines are kept
byte for byte; an unmarked entry that can select the package (any NEVRA, NEVR,
NEV, NA or NAME reading, globs included) is an external pin that requires
adoption or is refused; a marker whose entry an operator replaced is orphaned
and never claims the following line. Because the list only has native effect
through the plugin, an exact version requires `python3-dnf-plugin-versionlock`
enabled with exactly that list (probed through the plugin's own configuration
at provider start); without it exact versions are `unsupported`. Staging sees
the candidate list through the read-only bind already used for DNF5; the list
is a packaged configuration file, so an empty rendering truncates rather than
deletes it.
A package without an architecture follows `rpm --eval %{_arch}` and uses the
plugin's NEVR form, `name-epoch:version-release`, which locks every installed
architecture of that name ([package identity](../engineering.md#native-package-resource-provider);
unit coverage only, no native record yet).

Scriptlets run under RPM's SELinux plugin: the transient apply unit runs in
`unconfined_service_t`, which the targeted policy allows to transition into
`rpm_script_t` (`allow unconfined_service_t rpm_script_t:process transition`),
and the apply unit keeps `NoNewPrivileges=` off for that exec transition.

Qualified natively on registered RHEL 9.8 aarch64 (vendor KVM image acquired with
`lab images redhat fetch -arch aarch64`, maintained registration with explicit
user egress, all ten package scenarios, SELinux Enforcing, scriptlets observed in
`rpm_script_t`): see
[verification](../verification.md#native-packages-on-el-dnf4-python-api-backend).
Not exercised on RHEL: x86_64, RHEL 10, EUS/E4S streams, module streams,
`Weak Dependency` and obsoleting transactions (refused by policy, not exercised),
and the DNF4 path without the versionlock plugin (exact versions are refused).
All eight resource kinds (packages, files, groups, users, sysctl, timers and
drop-ins, password policy, firewall zone) also passed together in one connected
lane on registered RHEL 9.8 aarch64 (73/73 scenarios); see
[verification](../verification.md#all-resource-kinds-in-one-connected-lane).

### Capability policy facts (signed provider grants)

RHEL rows carry no registry vendor archive, so a signed capability policy's
PACKAGES grant reports `platform_not_qualified` on RHEL 8, 9 and 10
([architecture](../architecture.md#capability-derivation)); package rows need an
operator-approved source in `executor.json`, as before. The RHEL archive is not
representable as registry facts: `cdn.redhat.com` serves BaseOS and AppStream
only to a host presenting its subscription entitlement client certificate
(`/etc/pki/entitlement`, issued per system by subscription-manager) and is itself
certified by Red Hat's private CA (`/etc/rhsm/ca/redhat-uep.pem`). On
2026-10-12 an unauthenticated HTTPS request for
`content/dist/rhel9/9/x86_64/baseos/os/repodata/repomd.xml` failed WebPKI
verification and, with verification skipped, returned HTTP 403. An approved
`RpmRepository` has no client-certificate or CA fields, and per-host
entitlement material is a secret, never registry data. FILES and
LOCAL_ACCOUNTS facts are not recorded for RHEL either (they were measured from
the AlmaLinux and Rocky Linux packages, not RHEL's), so they also report
`platform_not_qualified`; see
[AlmaLinux and Rocky Linux](alma-rocky.md#capability-policy-facts-signed-provider-grants)
for the rebuilds' derived sources.

## Host resource providers (EL 9)

Managed files, local groups and users, sysctl, systemd timers and drop-ins,
password policy and firewall zones use the same providers as Fedora. Their
platform gates accept `rhel` and `almalinux` only with an EL 9 or EL 10
`VERSION_ID` (EL 10 below); Rocky Linux and EL 8 are refused as unqualified. Password policy pins the
exact product (`rhel`/`almalinux` 9.8) and native releases observed there:
libpwquality 1.4.4, pam 1.5.1 (its `pam_pwhistory` reads
`/etc/security/pwhistory.conf`, `remember`, `enforce_for_root` and `file`) and
authselect 1.2.6 ([`version_linux.go`](../../internal/agent/passwordprovider/version_linux.go)).

Native quirks the providers handle:

- **Accounts.** EL 9's shadow-utils 4.9 takes the SELinux label of a rewritten
  `/etc/passwd`, `shadow`, `group` or `gshadow` from the `--prefix` path, so the
  private account root under `/var/lib/lindm` produced `var_run_t` databases:
  `sudo` then failed with "User not known to the underlying authentication
  module" and `sshd` could no longer read `passwd`. EL 9's `chage` also has no
  `--prefix`, and in a bare chroot it aborts (`avc_running` assertion) or reports
  "Permission denied". On EL 9 every shadow tool therefore chroots (`--root`)
  into an account root holding the exact host `/etc` bind, the private mail-spool
  scratch, the host procfs (non-recursive bind, with the `ProtectKernelTunables=`
  and `ProtectKernelLogs=` paths repeated read-only or inaccessible inside it),
  selinuxfs (already writable under `ProtectKernelTunables=`), a read-only `/usr`
  and the `/bin -> usr/bin` link, so the tools label the real `/etc` paths
  (`passwd_file_t`, `shadow_t`) and their own login-shell check sees the host
  shells ([`prefix_linux.go`](../../internal/agent/accountprovider/prefix_linux.go),
  [`resource_linux.go`](../../internal/agent/nativehelper/resource_linux.go)).
  Ubuntu and Fedora keep `--prefix`.
- **Timers and drop-ins.** EL 9 ships systemd 252 (its manager `Version` is
  `252-67.el9_8…`, without a dot); the provider's systemd floor is 252 on EL 9
  and 255 elsewhere.
- **Password policy.** The provider only manages authselect-owned stacks. The
  RHEL 9.8 KVM guest image (and AlmaLinux 9.8 GenericCloud) ship the pam
  package's own `system-auth`/`password-auth` with no authselect selection
  (`authselect check` exits 2, "No existing configuration detected"); a policy
  assigned there is refused as `unsupported` with no native change. An
  installer-provisioned host has a selection; the lane proves the refusal, then
  runs `authselect select sssd --force` (the vendor default, `pam_sss.so` from the
  installed `sssd-client`) and qualifies the managed path. EL 9 profiles live in
  `/usr/share/authselect/default` (`minimal`, `sssd`, `winbind`; there is no
  Fedora `local` profile) and authselect 1.2.6 has no `opt-out`.
- **Firewall zones.** Neither image installs firewalld or nftables; the lane
  installs both from the vendor repositories and keeps firewalld active. Boot
  restoration (`lindm-firewall-restore.service`) failed on both images in two
  ways the provider now handles
  ([`netlink_linux.go`](../../internal/agent/firewallprovider/netlink_linux.go)):
  firewalld, also ordered `Before=network-pre.target`, moved the nftables
  generation under the restore batch, and the kernel refused it (`ERESTART` on
  `BATCH_BEGIN`, surfaced by the netlink library as a receive error) before
  applying anything — the provider now re-observes and retries that batch (at
  most three attempts, only while lindm's own table is unchanged); and the EL 9
  5.14 kernel acknowledged a `NEWRULE` of the restore batch twice while modules
  autoloaded at boot — a repeated success for an object of the batch is now
  accepted (the applied table is verified by read-back as before) and the socket
  is replaced after every batch so late repeats cannot be read as replies to the
  next query. Both had been reported as an unknown outcome, which left the
  persisted zone `PENDING` and failed the unit.

Evidence and the unproven remainder are in
[verification](../verification.md#host-resource-providers-on-el-9).

## Host resource providers (EL 10)

The same providers and gates cover EL 10; password policy pins `rhel`/`almalinux`
10.2 with libpwquality 1.4.5, pam 1.6.1 and authselect 1.5.2. Native facts were
checked on the RHEL 10.2 KVM and AlmaLinux 10.2 GenericCloud aarch64 guests
(kernel 6.12, SELinux Enforcing, shadow-utils 4.15.0-11, systemd 257-23,
`yescrypt` password hashing):

- **Accounts.** shadow-utils 4.15 now offers `--prefix` for every tool including
  `chage`, but still labels the rewritten databases from the prefixed path
  (`var_lib_t` under `/var/lib/lindm`; `restorecon -n` wants `passwd_file_t` and
  `shadow_t`, and `chage -l` then fails with "cannot open /etc/passwd"). EL 10
  therefore uses the same chrooted account root as EL 9
  ([`ChrootAccountRoot`](../../internal/agent/accountprovider/prefix_linux.go));
  `groupadd`, `useradd`, `usermod` (shell, UID, lock, groups), `chage`,
  `userdel` and `groupdel` exit 0 there with correct labels. `/bin`, `/sbin` and
  `/lib64` are symlinks into `/usr`, as on EL 9.
- **Timers and drop-ins.** systemd 257 meets the general 255 floor; the EL 9
  exception (252) does not apply.
- **Password policy.** Unlike EL 9, both EL 10 images ship an authselect selection
  (`local`, no features; `authselect check` valid), so a policy is managed
  without the EL 9 profile step. EL 10 profiles are `local`, `sssd` and
  `winbind`; `local` offers `with-pwhistory` and `with-faillock`.
- **Firewall zones.** As on EL 9, neither image installs firewalld or nftables;
  the lane installs both and keeps firewalld active. The EL 9 boot-restoration
  fixes apply unchanged.

Evidence and the unproven remainder are in
[verification](../verification.md#host-resource-providers-on-el-10).

## OS update policy (EL 9 and EL 10)

RHEL 9 and 10 use DNF4 `dnf-automatic` (4.14 on EL 9, 4.20 on EL 10) under the
same lindm window timer, runner and release model as
[Ubuntu](ubuntu.md#os-update-policy-osupdatev1). AlmaLinux and Rocky are refused
as unsupported until their own records exist. Prerequisites are `dnf-automatic` and
`dnf-plugins-core` (for `dnf needs-restarting`). Updates come from the
registered system's entitled repositories, and the security classification is
the CDN updateinfo errata type. An unregistered host has no security metadata to
classify. The policy owns the policy file, the timer and its `timers.target`
drop-in; it does not touch the package's `%config` `/etc/dnf/automatic.conf`.
An enabled or active `dnf-automatic*.timer` is refused before any effect. Each run
writes `/run/lindm-os-update/automatic.conf` (`upgrade_type`, `random_sleep = 0`,
download and apply `yes`, `emit_via = stdio`, and `[base] excludepkgs` for
deferred `name.arch`, appended to `dnf.conf` excludes). It then runs
`dnf-automatic <conf> --installupdates`. The conf also sets `reboot = never`
(4.14 ignores the key); the reboot is always the lindm logind schedule. Listing uses
`dnf --cacheonly repoquery --upgrades --latest-limit 1 [--security]`. The reboot
oracle is `dnf -q --disablerepo=* needs-restarting -r`, which looks only at
installed core packages, as on [Fedora](fedora.md#os-update-policy-osupdatev1).
Records, the registration and consumer-UUID receipts, and SELinux state are in
[verification](../verification.md#os-update-policy-patch-now-and-patch-status).

## Encryption and recovery

No Fedora or Ubuntu LUKS2/TPM/recovery run certifies RHEL. Qualification requires
the RHEL kernel, cryptsetup/systemd/initramfs, firmware and actual target tuple,
plus independent recovery boots and signed action evidence. The default executor
hides disks and TPMs; action provisioning must preserve private-device isolation
and expose only exact approved nodes
([`lindm-executor.service:21-30`](../../internal/packaging/assets/lindm-executor.service#L21-L30)).

The encrypted lab installs from the authenticated **Binary DVD**
(`lab images redhat fetch -edition dvd`; pinned
[`rhel-9.8-encrypted-x86_64.json`](../../lab/images/rhel-9.8-encrypted-x86_64.json) and
[`rhel-10.2-encrypted-x86_64.json`](../../lab/images/rhel-10.2-encrypted-x86_64.json)),
not the Boot ISO, which needs entitled network repositories. The Anaconda
kickstart lays out LVM on LUKS2 with RHEL's autopart defaults (measured on the
goldens: 613,160 KiB vfat ESP; xfs `/boot` 1 GiB on 9.8, 2 GiB on 10.2),
keeps SELinux Enforcing and installs everything from the DVD: the
`@^workstation-product-environment` GNOME session (RHEL ships no KDE) with its
[assistance capture stack](#remote-assistance-session), the TPM user space and the
native action prerequisites, because the unregistered installed system has no
repository. EL 9's dracut 057 has no split `systemd-cryptsetup`
module (naming an absent module is fatal); EL 10's dracut 107 ships it, so the
registry selects the TPM module list per major. Both majors ship
`systemd-cryptenroll` with the `systemd-tpm2` token plugin; Secure Boot uses the
Microsoft-signed RHEL shim.

All five encryption scenarios (inventory/header agreement, KEK custody and
two-person reveal, rotation with retired-key rejection, crash convergence, TPM2
bind with unattended boot and PCR7-mismatch recovery) passed natively on RHEL 9.8
and 10.2 x86_64 with Secure Boot enforced; see
[verification](../verification.md#rhel-encrypted-device-actions-and-self-update).

RHEL 9.8 aarch64 passed the same five scenarios on a DGX Spark (native KVM,
AAVMF `2024.02-2ubuntu0.10`) with Secure Boot enforced by the package-owned
Microsoft-enrolled variables, on a **headless server golden**
(`vm device-actions -desktop=`) installed from
[`rhel-9.8-encrypted-aarch64.json`](../../lab/images/rhel-9.8-encrypted-aarch64.json):
`@core`, the TPM user space and action prerequisites from the DVD, no desktop.
The vendor shim, GRUB and kernel boot unchanged; no aarch64-specific product fix
was needed. A headless golden has no session to lock, so lock phases refuse it;
see [verification](../verification.md#rhel-98-aarch64-encryption-and-tpm).

The [persistent organization demo](../engineering.md#persistent-organization-demo)
runs the encrypted RHEL 9.8 aarch64 server (no desktop, Secure Boot enforced) for
IT/Helpdesk on a Spark. Demo admission requires that exact release/architecture's
own verified encryption record; an x86_64 record does not admit it. Before
registration the guest takes OS dependencies only from the authenticated aarch64
Binary DVD's BaseOS/AppStream (vendor RPM signatures still checked), installs the
agent through the console's signed RPM repository and provisions with the
group's token. TPM binding is the product device action, not a prebound golden.
The server is then registered with RHSM like a real organization's server: CSAF
findings need the servicing stream its entitled BaseOS repository corroborates
(unregistered, evaluation stays `rhel_platform_stream_unavailable`). The DVD
repository is retired once the entitled repositories are available; `-destroy`
removes the exact recorded RHSM consumer before deleting the VM. The controller
also records the consumer UUID and run name before any further guest operation,
so a destroy while the Spark is unreachable still removes that exact consumer
and leaves only the VM and device root pending for the host's return.

The executor's action sandbox drop-in names a LUKS target by its approved
`/dev/disk/by-uuid/<luks_uuid>` alias, verified at provisioning to be the
identity-checked block node. On RHEL 10.2 with a second virtio-SCSI disk the root
moved from `sda` to `sdb` across a cold boot, and the former kernel-name binding
kept the executor from starting (status 226/NAMESPACE); `openTarget` still checks
the device number, size and native identity of whatever path it opens.

Original-device recovery sanitize runs on the vendor KVM image, whose ESP is
200 MiB vfat with 196,772 KiB (9.8) and 195,420 KiB (10.2) free, measured read-only
from the pinned images. systemd-boot (`systemd-boot-unsigned`) and `systemd-ukify`
are published in BaseOS/AppStream for both majors and are installed through the
maintained registration (`vm device-actions -redhat-token-file`), held only for
that transaction. RHEL ships no BusyBox and no sbsigntools, and the recovery
image needs neither: its `/init` is the static lindm-agent and Authenticode is
verified in-process. It still needs a `CONFIG_RD_GZIP=y` kernel, the unchanged
distro-signed modules and host-side signing to build the image. The KVM image's
generic initramfs (about 240 MB) cannot fit the ESP in an ordinary UKI, so the
owned-boot fixture embeds a `dracut --hostonly` image instead. The signed
recovery UKI is 45.8–51.6 MB and fits the remaining ESP space. SATA and NVMe
passed on 9.8 and 10.2. NVMe on 9.8 first failed because inventory read the
approval scope with NVMe Identify passthrough from a capability-free unit, which
the 5.14 kernel refuses (Linux before 6.2 requires `CAP_SYS_ADMIN` for any admin
passthrough). Inventory now reads the kernel's sysfs projection of Identify on
every kernel; see
[verification](../verification.md#rhel-encrypted-device-actions-and-self-update).

Original-device recovery sanitize on stock RHEL uses
`RECOVERY_BOOT_MODE_MEASURED_GRUB` with the BLS flavor (shim+GRUB `blscfg`,
vendor-signed kernel, TPM-quoted lindm initramfs on `/boot`), as on
[Fedora](fedora.md#encryption-and-recovery). Readiness requires the current
boot's event log to show GRUB measuring the kernel, command line and initramfs
into PCRs 8/9, so a GRUB build without its `tpm` module refuses, and so does a
machine without a TPM. With XFS `/boot`, `grub2-editenv` writes the grubenv
file, and its short-lived unit gets the `/boot` device read-only. On RHEL 10.2,
the unit enters `bootloader_t`, which is why it runs without `NoNewPrivileges`.
Native measured passes with a real entitlement and cleaned-up registrations:
RHEL 9.8 SATA, and RHEL 10.2 SATA and NVMe
([verification](../verification.md#measured-grub-recovery-on-stock-vendor-boot-chains)).
RHEL 9.8 NVMe needs the sysfs-derived NVMe approval scope (kernel 5.14). The
method covers unencrypted roots only; LUKS roots use live crypto-erase.

On aarch64 the signed `grubaa64.efi` of RHEL 9.8 and 10.2 records no GRUB event
at all: the ordinary event logs captured by the measured run have no PCR 8 event,
so readiness refuses with `recovery_readiness_measured_grub_required`. The
registry records this as `Lab.MeasuredGRUBUnavailableOn["aarch64"]`, and
`lab matrix run` runs aarch64 recovery sanitize through the owned-boot UKI
fixture. The host's private pinned ukify builds it. Both releases passed NVMe
that way after the direct NVMe admin ioctl
([verification](../verification.md#rhel-matrix-completion-2026-10-12)).

### TPM2 unseal retry

EL 9's `systemd 252-67` backports the systemd 255 TPM2 code together with its
stale-session retry ([Ubuntu](ubuntu.md#tpm2-unseal-race)). After an unseal fails
with `TPM_RC_PCR_CHANGED`, the token fails with `EINVAL`
(`Failed to unseal secret using TPM2: Invalid argument`; the RHEL 9 source refuses
the reused session as "Missing encryption session"). `cryptsetup 2.8.1` logs
`systemd-tpm2 token handler returned -22. Changing to -2.` and opens the next
token. On Rocky Linux 9.8 aarch64 with one token, 15 of 30 and 9 of 30 token
unlocks succeeded while PCR 10 was extended every 100 ms and every 50 ms. With
four token references they were 26 of 30 and 23 of 30. The EL 9 rows therefore
carry `TPM2UnsealRetryNextToken`, and the managed bind writes four references to
its one sealed keyslot. With Secure Boot, EL 9's aarch64 kernel measured no
module loads (IMA runtime count 1–2), so its initrd does not race the unlock
there. EL 10's systemd 257 restarts the encryption session on each retry itself.
An EL 9 device bound with one token is reported in device encryption status and
repaired by a new TPM2 bind, which completes the existing keyslot's references
without a credential ([Ubuntu](ubuntu.md#tpm2-unseal-race)).
Evidence:
[verification](../verification.md#tpm2-unseal-race-and-unattended-boot-regression).

## Device actions

Signed service execution is not desktop lock, quarantine, restart, shutdown,
crypto-erase or sanitize evidence. Each requires its own authorization, native
effect and recovery/uncertainty record. Server/minimal and vendor GNOME-capable
installations remain separate qualification targets. "Implemented" in the table
above admits an action and its qualification lane; it is not qualification.
Per-minor native results are in
[verification](../verification.md#rhel-encrypted-device-actions-and-self-update);
consult them before enabling an action on a RHEL device.

## Advisory feeds

Connected turnkey servers automatically activate the registry's Red Hat CSAF
archive export for enrolled RHEL inventory only after the existing native CPE,
repository and release-lock checks prove its maintained servicing stream.
Automatic sources retain the observed exact minor and architecture; an EUS/E4S,
unknown or conflicting stream never borrows the standard export. RHEL 9 and 10
therefore keep their own product claims rather than relying on a compatible
rebuild. Initial-download timing is observed, not guaranteed. Air-gap and explicit
operator feed policy remain unchanged; see
[installation guidance](../install.md#wait-for-the-first-vulnerability-assessment).

RHEL uses vendor CSAF 2.0 security advisories and VEX, not Fedora updateinfo or a
version-string-only CVE join. Parsing checks publisher, final status, product tree
and supported relationships, retaining fixed, known affected, known not affected
and under-investigation distinctions
([normalization](../../internal/advisory/feed/redhat_claims.go),
[product policy](../../internal/advisory/feed/redhat.go)).
An individual advisory or legacy VEX is not complete coverage.
A Red Hat CSAF source must name a RHEL 8, 9 or 10
[registry release](../../internal/platform/registry.go) (major or exact minor);
the registry's per-stream fact, not the os-release ID string, makes hosts require
corroborated stream evidence and native module identity.
RHEL 10 standard-stream errata name minor products
(`cpe:/o:redhat:enterprise_linux:10.1`; for example `RHSA-2026:7675`), while RHEL 9
errata name the major (`enterprise_linux:9`). A minor CPE applies only to a source
naming that exact minor, so a RHEL 10 source configured as major `10` retains only
the major-wide VEX claims (all UNKNOWN on the 10.2 aarch64 lab guest: 34,324
findings, no fix) and must name the host's exact minor, e.g. `10.2`. The
advisories lab lane derives Red Hat sources from the image's exact minor for
both majors, and registers the guest first, because a stream is proved only by
the entitled BaseOS repository ID.
RPM `gpg-pubkey` signing-key rows without an architecture are keyring entries:
they neither match records nor make architecture coverage UNKNOWN
([Fedora advisory feeds](fedora.md#advisory-feeds)).
Product CPE applicability is established before applying advisory metadata policy,
so historical off-scope informational notices cannot poison a selected host feed.
Applicable final `csaf_informational_advisory` documents contribute no claims only
when their `vulnerabilities` property is absent, as required by
[CSAF 2.0 profile 3](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html).
The genuine RHEL 9 AppStream notice
[`RHSA-2023:6529`](../../internal/advisory/feed/testdata/redhat-rhsa-2023_6529.json)
is retained with [signed-archive provenance](../../internal/advisory/feed/testdata/redhat-rhsa-2023_6529-provenance.txt).
Informational notices containing even a null or empty vulnerability array are
refused; unsupported relevant categories, metadata and product trees still fail
the whole source rather than silently discarding potential claims.

VEX status references may identify declared products directly. A direct reference
is skipped only when its explicit, supported CPE syntax proves that the product
is outside the selected native RHEL scope; a missing relationship alone is not
proof of irrelevance. Missing product declarations, malformed or escaped CPEs,
unbound RPM products and relevant broad-platform statuses still fail rather than
inventing package-level fixes or clean assertions. The retained
[`CVE-2002-0059` VEX](../../internal/advisory/feed/testdata/redhat-cve-2002-0059.json)
with [vendor proofs and provenance](../../internal/advisory/feed/testdata/redhat-cve-2002-0059-provenance.txt)
demonstrates historical Red Hat Linux/Powertools direct fixes alongside four
authoritative RHEL 9 zlib binary/source not-affected relationships.
A valid nonnative product CPE can omit its version
([ANY under NISTIR 7695 URI binding](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf)),
as the layered RHSSO
product does in the retained
[`CVE-2020-25649` VEX](../../internal/advisory/feed/testdata/redhat-cve-2020-25649.json)
and its [provenance](../../internal/advisory/feed/testdata/redhat-cve-2020-25649-provenance.txt).
This does not permit a native RHEL CPE with an absent/empty version to establish
off-scope status; that unresolved applicability remains a failure.

Production `REDHAT_CSAF` and paired `REDHAT_CSAF_ARCHIVES` refreshes stage original
bytes in private temporary files, require the vendor SHA-256 and pinned-root
detached signature before parsing, and preserve original-byte artifact digests.
Optional configured pins and transfer CRC32C checks remain additional integrity
checks, not substitutes for signatures
([acquisition](../../internal/advisory/feed/signed.go)).
An offline individual CSAF import can be digest-pinned but gains neither a
signature timestamp nor complete coverage; a lone compressed archive is refused
rather than treated as the authenticated paired distribution.

The held-demo advisory configuration derives RHEL 9's paired CSAF archives from
registry facts, with standard-stream coverage for x86_64 and aarch64 and a
seven-day maximum age. Its controller-owned `advisory-cache` revalidates the
vendor exports and publishes through the production parser before waiting for a
current device evaluation. This feed configuration does not establish graphical
qualification.

Each JSON document is capped at **128 MiB**, independently of the
512 MiB compressed-archive and **32 GiB expanded-archive** limits. The measured
2026-10-04 signed advisory distribution contains four documents above the former
32 MiB limit; its largest, `RHSA-2024:9315`, is 46,707,671 bytes with 594 distinct
CVEs ([cardinality evidence](../../artifacts/rpm-advisory-cve-cardinality-20261010.json)).
The retained [original compressed fixture](../../internal/advisory/feed/testdata/redhat-rhsa-2024_9315.json.gz)
exercises that document, not a reduced substitute.
The paired VEX distribution contains 69,859 JSON entries and expands to
21,371,545,600 bytes (19.904 GiB), so the former 16 GiB aggregate limit could not
consume it. Its largest member, `CVE-2026-33186`, is 107,532,378 bytes and
explicitly includes native RHEL 9 products
([complete VEX expansion/scope evidence](../../artifacts/rhel-vex-expansion-scope-20261010.json)).
The larger aggregate expansion allowance does not retain the archive in memory:
entry, token, product-index and normalized-stage bounds remain independent.

The [incremental parser](../../internal/advisory/feed/redhat_json.go) uses a bounded
streaming JSON scanner rather than allocating `encoding/json.Decoder.Token`
values for ignored vendor content. It bounds each scalar at 64 KiB, JSON nesting
at 64, branch nesting at 12, branches and relationships at 250,000 each, and
retained product metadata text at 64 MiB. A first pass records the
vulnerability-array position and builds
the bounded product index; a second pass retains one vulnerability at a time
(at most 250,000 status references and 64 MiB of reference text). Parent indices
preserve inherited architecture and constraints even when child branches precede
their parent metadata. Arbitrary JSON key order does not require retaining a
whole document or vulnerability as `RawMessage`.
The [advisory-distribution metadata measurement](../../artifacts/rhel-csaf-tree-bounds-20261010.json)
records maxima of 3,438 branch products, 8,618 relationships, 2,643,893 bytes of
product-tree string values and a 41,523-byte scalar, providing measured headroom
for these independent limits.
The [complete VEX reference census](../../artifacts/rhel-vex-reference-shapes-20261010.json)
records maxima of 42,967 branch products, 42,954 relationships and a 7,119-byte
scalar. It found no undeclared status references or relationship-edge targets;
among native-RHEL-9-potential documents, the additional direct-reference forms
are nonnative versionless products and AMQ versions such as `2026.Q3`. Uppercase
version text does not case-fold or otherwise rewrite native product identity.

Repeated declarations are not automatically conflicting identities. Identical
relationship edges/helpers and product helpers/inherited architecture/constraints
are deduplicated, ignoring opaque display-label differences. A conflicting ID
remains explicitly ambiguous; it rejects a document only when encountered in a
relevant status dependency. Exclusion requires every declared platform
alternative to be provably off-scope. Initial applicability considers the union
of duplicate CPE declarations, so neither first- nor last-declaration order can
hide native ambiguity. Scope proofs retain the eight-edge traversal bound and
memoize indexed references within one vulnerability.
The [selected original VEX duplicate census](../../artifacts/rhel-selected-vex-duplicate-identities-20261010.json)
records 618 identical relationship redeclarations in `CVE-2026-33186` and 2,194
in `CVE-2023-44487`; their conflicting product-helper declarations are outside
native RHEL 9.8 dependencies and do not invalidate independent native claims.
One product ID declared once per module build shipping the same NEVRA, whose
PURLs differ only in `rpmmod` version:context (for example
`postgresql:15:9020020240213145157:rhel9` and
`postgresql:15:9030020240209100638:rhel9`), is the same normalized component:
both PURLs must parse as native RPMs with identical name, EVR, architecture,
source flag and module name/stream, and the product CPE must match. Any
normalized difference remains a conflict. The genuine
[`CVE-2024-0985`](../../internal/advisory/feed/testdata/redhat-cve-2024-0985-provenance.txt)
member carries 117 such redeclarations.

[Disk-backed reconciliation](../../internal/advisory/feed/redhat_reconcile.go)
preserves the earliest native RPM fix, first-observation ties, architecture,
source/binary and module separation, and suppression of bare affected claims
across the complete source, including both archives. Its private SQLite stage
has a 2 GiB database limit and an 8 MiB page cache. Ordinary batches contain at
most 500 claims; each vendor document uses a single disk-spilling transaction
so rejection rolls back its entire prefix before another document is accepted.
The configured total-claim limit applies separately from document-byte limits;
the materialized compatibility APIs retain their 500,000-claim/128 MiB bounds,
but streaming publication does not accumulate the normalized export in memory.
Only fully parsed and reconciled sources reach generation-staging callbacks.
A signature, malformed JSON, byte/structure bound, storage, cancellation or
consumer failure invalidates the entire generation; no earlier document may
become a partially published source
([streaming acquisition](../../internal/advisory/feed/redhat_fetch.go)).
An applicable document with invalid vendor semantics is instead rejected as a
whole and exposed in bounded rejected-record metadata, never repaired. The
configured rejection threshold is enforced (zero requires no rejected records);
diagnostics are capped at 48 KiB. Unscoped rejection preserves uncertainty for
all packages whose claims were rolled back, preventing a clean-coverage claim.

Servicing stream matching requires corroborating native Red Hat CPE, enabled
BaseOS/repository IDs, architecture and release-lock observations. Mixed streams,
missing BaseOS or ambiguous EUS/E4S locks do not establish applicability
([`advisory/platform.go:11-72`](../../internal/advisory/platform.go#L11-L72)).
Do not infer entitlement from `VERSION_ID`, rewrite a MAIN.EUS internal identifier
as an EUS CPE, or treat a derivative as Red Hat. Current complete paired archive
coverage and freshness are governed by [verification](../verification.md).

Streaming refresh has no size-derived deadline. A progress watchdog aborts only
when no source document completes and no publication batch commits for
`progress_timeout_seconds` (default 300); `refresh_timeout_seconds` (default
7,200) is the overall ceiling, and the staging lease is renewed every minute.
The real signed 2026-10-04 archive pair (advisories SHA-256
`708b53ef…5354afc1ee`, VEX `fa61b885…b82182345`, signer
`77E79ABE93673533ED09EBE2DCE3823597F5EAC4`) was published on 2026-10-10 through
`TestLiveRHEL9SignedArchivePublication` into an isolated `testdb` schema
(release `9`, `standard`, x86_64; workstation NVMe, shared host): 1,894,410
emitted and 1,892,833 unique claims, one rejected document, 7 min 28 s refresh
(7:28 wall), 236,744 KiB peak RSS, no swaps. The sole rejection is the genuine
`CVE-2023-44487` `nginx:1.24` RPM name above. The preceding run, before
module-build redeclarations were recognized, rejected 38 additional module
documents (PostgreSQL, Node.js, MariaDB, PHP, Ruby and others) as conflicting
identities (1,892,498 unique claims, 7 min 3 s, 241,884 KiB); each now parses
without rejection. Coverage remains partial, so freshness is not advertised as
clean completeness. Run logs are under `~/.cache/lindm-rhel-publication-20261010/`
(final `lindm-rhel-live-20261010-2.log` SHA-256
`74a1313711e73f229847b6d226a20582ba7d5e8a99c1d269da4e24dba05cd8bd`).

RPM PURL package names and versions use single path-component percent decoding,
not form/query decoding: a literal `+` remains `+`, and `gnutls-c%2B%2B` identifies
the native package `gnutls-c++`. Invalid escapes, decoded separators and residual
double encoding are refused, never repaired. The genuine
[`RHSA-2022:6854` fixture](../../internal/advisory/feed/testdata/redhat-rhsa-2022_6854.json)
and its [provenance](../../internal/advisory/feed/testdata/redhat-rhsa-2022_6854-provenance.txt)
retain this identity boundary.

Component identity follows Red Hat's
[PURL matching logic](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/#purl-matching-logic)
and [RPM PURL conventions](https://redhatproductsecurity.github.io/security-data-guidelines/purl/#identifying-rpm-packages):
PURLs identify components, CPEs identify products, and opaque product IDs join
them through relationships. Display labels are not a second RPM NEVRA assertion
and cannot override the PURL name, epoch or version. The native namespace is
exactly `redhat`, not a prefix: `redhat/rhacm2` and `redhat/rhel9` remain distinct,
out-of-scope namespaces, never suffix-repaired into host package names.
This agrees with the reference
[PURL namespace parser](https://github.com/package-url/packageurl-go/blob/c88ed7b2a2305ec91a087dd6cb7168ca1f42cfe3/packageurl.go#L711-L735)
and [Clair's native-RPM filter](https://github.com/quay/claircore/blob/7da686f8454001747e3ca122fcaf1d3647f06018/rhel/vex/parser.go#L1273-L1288).

`known_affected` is an unfixed package/source claim for the matched native product,
even when a component PURL happens to include a version; it does not invent an
exact affected-version interval from that value. This matches the reference
[Clair known-affected normalization](https://github.com/quay/claircore/blob/7da686f8454001747e3ca122fcaf1d3647f06018/rhel/vex/parser.go#L779-L831).
The source's original PURL remains unchanged. `fixed` retains the exact PURL EVR,
and source-wide reconciliation still suppresses a bare affected claim when a
native fix exists. Versioned `known_not_affected` claims remain version-specific,
not blanket clean assertions.

Modules require the documented
[`rpmmod` qualifier](https://redhatproductsecurity.github.io/security-data-guidelines/purl/#identifying-rpm-modules)
or an independently declared module relationship. A colon in an RPM name is not
permission to invent a module. The signed-archive specimens
[`CVE-2021-27358`](../../internal/advisory/feed/testdata/redhat-cve-2021-27358-provenance.txt),
[`CVE-2026-103111`](../../internal/advisory/feed/testdata/redhat-cve-2026-103111-provenance.txt)
and [`CVE-2023-44487`](../../internal/advisory/feed/testdata/redhat-cve-2023-44487-provenance.txt)
respectively exercise nested-namespace exclusion without discarding independent
native binary claims, a bare display label with a versioned unfixed PURL, and a
genuinely invalid `nginx:1.24` RPM name without module metadata. The
[completed source interpretation census](../../artifacts/rhel-vex-purl-interpretation-20261010.json)
distinguishes 115 out-of-scope namespace entries and 290 valid display-label
differences from that one remaining invalid document; the latter is rejected
unscoped, not normalized to `nginx`.

## Remote assistance capability roadmap

RHEL desktop releases require their own vendor-supported portal/backend versions;
Fedora GNOME evidence is not RHEL evidence. The
[capability contract](../product-specification.md#remote-assistance-capabilities)
defines every tier's consent, off/limited/on policy, role permissions and audit.
Clipboard requires Clipboard on the existing RemoteDesktop session, not a backported
version assumption; FileChooser governs user-selected uploads and Downloads governs
accepted downloads. SELinux and notification/session isolation remain enabled.
Clipboard, keys/layouts, displays, messages, files, reconnect, recording and Tier 3
are [not run](../verification.md#commercial-assistance-capability-qualification).
Qualify each release/architecture with actual portal actions, two-head guest effects,
nonces/hashes and termination evidence. Missing interfaces stay gated; unattended
and KDE implementation/qualification require parent confirmation.

### Remote assistance session

The lab session is the encrypted golden's GDM autologin into GNOME Wayland,
installed only from the Binary DVD's BaseOS/AppStream (registry
`rhelSession9`/`rhelSession10`). Its kickstart `%packages` add the capture stack
the session helper's `gst-launch-1.0` pipeline needs
(`internal/agent/desktop/gst.go`): `pipewire-gstreamer` (`pipewiresrc`),
`gstreamer1-plugins-base` (`videoconvert`, `videoscale`),
`gstreamer1-plugins-good` (`imagefreeze`, `vp8enc` over `libvpx`, `rtpvp8pay`,
`rtpstreampay`),
`gstreamer1` (`fdsink`, `gst-launch-1.0`/`gst-inspect-1.0`), `xdg-desktop-portal`
and `xdg-desktop-portal-gnome`. The assistance lane requires them with `rpm -q`,
because the unregistered guest has no repository to install from. The terminal
the lane types into is `gnome-terminal` on 9.8 and `ptyxis` on 10.2, the only
one each DVD ships.

| DVD         | xdg-desktop-portal / -gnome | PipeWire | GStreamer (base, good) | GNOME Shell / Mutter |
| ----------- | --------------------------- | -------- | ---------------------- | -------------------- |
| 9.8 (both)  | 1.12.6 / 41.2               | 1.4.9    | 1.22.12                | 40.10 / 40.9         |
| 10.2 (both) | 1.20.0 / 47.3               | 1.4.9    | 1.26.7                 | 49.4 / 49.4          |

Every package is in AppStream on all four pinned DVDs, and both
`workstation-product-environment` and `graphical-server-environment` (aarch64)
already default-install them through comps; the package query is
`$HOME/.cache/lindm-rhel-assist-20261013/dvd-package-query.txt` (SHA-256
`f1faeab3577b4ca63eafa72670369cbf003c1a90e25b4c3221d199fcc859f38a`).

RHEL 9.8 and 10.2 x86_64 pass every assistance scenario (9.8 after the EL 9
capture fix `5a10048e`); aarch64 is blocked: lab hosts offline
([verification](../verification.md#rhel-assistance-session-recipe-2026-10-13)).

## Lab

Use maintained image acquisition/offline verification and the registered native
lanes described in [agent enrollment](../agent-enrollment.md) and
[verification](../verification.md). Keep fixture and pinned source-build roots
separate; retain public registration receipts outside disposable VM state.

The following x86_64 KVM records are under
`$HOME/.cache/lindm-platformlanes-20261009/`; they retain SELinux Enforcing and
registered repository/cleanup evidence:

| Capability                          | Record                                  | SHA-256                                                            |
| ----------------------------------- | --------------------------------------- | ------------------------------------------------------------------ |
| RHEL 9.8 signed-service lifecycle   | `rhel98-service-egress-platform2.json`  | `6378848308eecfaad17e38ff76d7d0b275688f4f7618f6d7f3d618cedcd30ee8` |
| RHEL 10.2 signed-service lifecycle  | `rhel102-service-egress-platform2.json` | `3d0eebd689834efa9f7daf766a9bc8cdd29f994a3306360b9fda0a249751b78f` |
| RHEL 9.8 automatic trust lifecycle  | `rhel98-trust-receipts.json`            | `2cef05970f214a51f6a8573abf478a11cd228cc922b0f1371e94286f547e2ed2` |
| RHEL 10.2 automatic trust lifecycle | `rhel102-trust-receipts.json`           | `af60d409e6d367680655235e2a1e829448428aacca4fb2f57cbff0297d717723` |
| RHEL 9.8 connected dispatch         | `rhel98-dispatch-receipts.json`         | `7c6d4d0f715184ad4eb9b788f8815da69d874f6270d6f18d305fd89915fe5b62` |
| RHEL 10.2 connected dispatch        | `rhel102-dispatch-receipts.json`        | `0c8b04c278095080fbe43e9b388805c02fe5b74e3c34943de1d1527ad1f29783` |

Dispatch contains nine native scenarios; unstarted supersession is explicitly
integration-only, not a tenth native scenario. These records do not qualify aarch64,
physical hardware or disconnected vendor content.

The aarch64 Binary DVDs are pinned as
[`rhel-9.8-encrypted-aarch64.json`](../../lab/images/rhel-9.8-encrypted-aarch64.json)
(SHA-256 `1da7c7f9…df275fa92`, 13,307,215,872 bytes) and
[`rhel-10.2-encrypted-aarch64.json`](../../lab/images/rhel-10.2-encrypted-aarch64.json)
(`63b6c005…9cf52f60`, 10,413,670,400 bytes), acquired with `lab images redhat
fetch -edition dvd -arch aarch64` (vendor-authenticated checksum, edition
`dvd-encrypted-lab`). Their
AppStream comps define only `graphical-server-environment` and
`server-product-environment`, so the aarch64 encrypted GNOME golden installs
Server with GUI (registry `LabSession.ArchitectureDesktops`); x86_64 keeps
Workstation. The headless (`-desktop=`) golden installs no environment group.

The air-gap matrix lane is gated (`Lab.LaneGates`): RHEL CSAF matching requires a
corroborated servicing stream, which the host proves only with its entitled
BaseOS repository ID ([stream evidence](../../internal/advisory/platform.go)). The
air-gap guest has no route to Red Hat from boot and the lab has no disconnected
Satellite, so evaluation would remain `rhel_platform_stream_unavailable` and never
bind the bundle's feed. Connected console enrollment and advisory lanes register
the guest first, as a subscribed customer host is.

## Gaps

RHEL 8, physical TPM/media, entitled air-gap lifecycle (the gated lane above) and
each gated resource/action in the table above remain independent work. The
aarch64 encryption, lock, wipe and recovery
matrix cells passed on the Server with GUI golden
([verification](../verification.md#rhel-matrix-completion-2026-10-12)); the
encrypted Workstation (x86_64) and Server with GUI (aarch64) goldens qualify only
the lab's GDM autologin session, not every vendor desktop configuration.
DNF4 repository observation is not package mutation qualification. Standard,
EUS and E4S applicability must retain exact content provenance and cannot be
borrowed from another vendor or minor release.
