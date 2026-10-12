# AlmaLinux and Rocky Linux

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Rocky Linux 8                                                                                                                   | Rocky Linux 9                                                                        | Rocky Linux 10                                     | AlmaLinux 8                                                                                                                     | AlmaLinux 9                                                                          | AlmaLinux 10                                       | CentOS Stream 9                                                                                         | CentOS Stream 10                                                                                        |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| inventory         | implemented                                                                                                                     | implemented                                                                          | implemented                                        | implemented                                                                                                                     | implemented                                                                          | implemented                                        | implemented                                                                                             | implemented                                                                                             |
| lifecycle         | implemented                                                                                                                     | implemented                                                                          | implemented                                        | implemented                                                                                                                     | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| dispatch          | implemented                                                                                                                     | implemented                                                                          | implemented                                        | implemented                                                                                                                     | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| packages          | gated: systemd 239 rejects the package helper's transient-unit sandbox (ProtectKernelLogs=) and busctl has no --json before 240 | implemented                                                                          | implemented                                        | gated: systemd 239 rejects the package helper's transient-unit sandbox (ProtectKernelLogs=) and busctl has no --json before 240 | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| accounts          | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                          | implemented                                        | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| sysctl            | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                          | implemented                                        | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| definitions       | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                          | implemented                                        | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| password          | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                          | implemented                                        | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| firewall          | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                          | implemented                                        | gated: EL host providers are qualified only on RHEL, AlmaLinux and Rocky Linux 9/10                                             | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| encryption        | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| wipe              | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| report-loss       | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| lock              | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| recovery-sanitize | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| self-update       | implemented                                                                                                                     | implemented                                                                          | implemented                                        | implemented                                                                                                                     | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| assistance        | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: no maintained encrypted installer, native action prerequisites or graphical golden                                       | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| advisories        | implemented                                                                                                                     | implemented                                                                          | implemented                                        | implemented                                                                                                                     | implemented                                                                          | implemented                                        | gated: not implemented for CentOS Stream 9                                                              | gated: not implemented for CentOS Stream 10                                                             |
| os-update         | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release                         | implemented                                                                          | implemented                                        | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release                         | implemented                                                                          | implemented                                        | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release |
| release-upgrade   | gated: release upgrade is not implemented                                                                                       | gated: EL major upgrades need ELevate/Leapp, for which lindm has no upgrader or lane | gated: no successor release: EL 11 is not released | gated: release upgrade is not implemented                                                                                       | gated: EL major upgrades need ELevate/Leapp, for which lindm has no upgrader or lane | gated: no successor release: EL 11 is not released | gated: release upgrade is not implemented                                                               | gated: release upgrade is not implemented                                                               |

<!-- END GENERATED platform-capabilities -->

AlmaLinux and Rocky Linux are independent qualification rows, not aliases for RHEL
or for one another. The launch targets are each vendor's 9 and 10 current minors
on x86_64 and aarch64 server, with separate legacy 8 rows. These are requirements,
not certified support. [Verification](../verification.md#1-launch-platform-qualification)
is authoritative; a package architecture, acquired image or upstream compatibility
claim cannot qualify a native capability.

Exact image release, size, digest and signature provenance live in each
[`lab/images`](../../lab/images) manifest. For example,
[`almalinux-9.8-x86_64.json:2-18`](../../lab/images/almalinux-9.8-x86_64.json#L2-L18)
pins GenericCloud 9.8-20261005 and its detached checksum signature. Do not silently
replace the pinned image with the latest object behind a vendor directory.

## Packaging, signing, repositories, paths and LSM

Select the exact AlmaLinux or Rocky Linux release in the console for one DNF
install-and-enroll command. Agents come only from the customer's own `lindmd`
HTTPS `/repo/rpm` endpoint, with pinned signer and server/bootstrap trust and
both package and repository signature verification. Missing artifacts or target
architecture coverage have an explicit server setup remedy. See the
[install runbook](../security-and-operations.md#enrollment-installation-from-your-server).
This common delivery method does not transfer RHEL/Fedora or cross-derivative
qualification.

Use native RPMs, independently verified against the configured package signer.
The builder signs then verifies before recording the release artifact
([`packaging/rpm.go:50-79`](../../internal/packaging/rpm.go#L50-L79)).
RPM config files use `%config(noreplace)` and package lifecycle scriptlets
([`rpm.go:83-112`](../../internal/packaging/rpm.go#L83-L112)).
Repository/package trust is explicit: package and local-package checks remain on,
and repository metadata signing is separately represented
([`publish.go:43-58`](../../internal/packaging/publish.go#L43-L58)).
A local dependency-satisfied RPM transaction does not establish connected vendor
repository or air-gap lifecycle support.

The binary is `/usr/libexec/lindm/lindm-agent`; configuration is
`/etc/lindm/executor.json` and `/etc/lindm/agent.json`, with separate state below
`/var/lib/lindm/executor` and `/var/lib/lindm/agent`. Keep vendor SELinux Enforcing.
AlmaLinux 9.8 x86_64 dispatch and the independent Rocky 9.8/10.2 and AlmaLinux
8.10/9.8/10.2 ARM lifecycle and dispatch records below retained Enforcing; each
row stands only for its own release and architecture. RHEL subscription-manager
registration and Red Hat entitlement evidence
do not describe derivative repository access.

## Agent services and sandbox

The packaged root executor is AF_UNIX-only with strict filesystem protection,
private devices, no-new-privileges, no swap and no core dumps. The network agent
runs as `lindm` without capabilities and cannot access protected executor state.
Exact native action devices require the reviewed owned sandbox drop-in, not a
blanket device exception. Sources:
[`lindm-executor.service:10-61`](../../internal/packaging/assets/lindm-executor.service#L10-L61)
and [`lindm-agent.service:11-50`](../../internal/packaging/assets/lindm-agent.service#L11-L50).

AlmaLinux 9's **dbus-broker v28 argument-filter bug** is a real compatibility
boundary. `AddMatch` accepts `arg2='unit'` for systemd's `JobRemoved(uoss)` signal
but that match can silently lose the completion signal. The provider therefore
matches the authenticated manager's sender/path/interface/member and checks the
exact job and unit locally, rather than treating the lost signal as successful
execution or extending a timeout
([`serviceprovider/native_linux.go:271-281`](../../internal/agent/serviceprovider/native_linux.go#L271-L281)).
The wire regression documents simultaneous broad/argument-filtered native
observations ([`native_linux_test.go:71-75`](../../internal/agent/serviceprovider/native_linux_test.go#L71-L75)).
This correction is not permission to accept another job's result or to relax
sender authentication. Do not assume the same failure or success on Rocky solely
because its package family is RPM.

## Inventory and per-field quirks

The installed-package backend selects explicit `almalinux` or `rocky` identity,
requires an actual RPM database, and queries name, epoch, version, release,
architecture and modularity label. It does not select on `ID_LIKE` and rejects
OSTree/transactional markers
([`inventory/packages_linux.go:46-85`](../../internal/agent/inventory/packages_linux.go#L46-L85)).
Warnings or native failures do not become empty successful inventories
([`packages_linux.go:148-152`](../../internal/agent/inventory/packages_linux.go#L148-L152)).

The existing DNF4 configuration helper reads configured enabled repository IDs
and explicit releasever locks without plugins, metadata or network activity
([`platform_dnf.py:72-130`](../../internal/agent/inventory/platform_dnf.py#L72-L130)).
CPE is independent os-release evidence
([`platform_linux.go:41-64`](../../internal/agent/inventory/platform_linux.go#L41-L64)).
Missing configuration/API capability, absent lock, empty enabled repositories and
read failure must remain distinguishable. Derivative CPE/repository values must
not be relabeled as Red Hat EUS/E4S evidence.

## Updates

Agent self-update is not a generic package-management provider or a major-version
OS upgrade. Native agent update checks actual RPM identity and architecture,
and rejects immutable markers
([`update/native_linux.go:111-147`](../../internal/agent/update/native_linux.go#L111-L147)).
Fedora DNF5 update or package-resource evidence does not qualify these vendors'
DNF4 transaction behavior. Each derivative/minor needs its own signature rejection,
upgrade, reboot, removal/reinstall, recovery and interruption records.

Package resources use the same DNF4 backend as RHEL (Python API adapter,
asynchronous staging, owned versionlock-plugin entries, four signature checks
and RPM's SELinux scriptlet transition); see
[RHEL package resources](rhel.md#package-resources-dnf4). The provider accepts
`almalinux` and `rocky` with an installed DNF4 4.7.0 or newer; the adapter
falls back to a transactional `iterdump` history snapshot for EL8's
platform-python 3.6, which lacks SQLite's online backup API. Exact versions need
`python3-dnf-plugin-versionlock` (not installed in the AlmaLinux 9.8 cloud
image; the resource lane installs it from the vendor repository).

All ten connected package scenarios passed natively on AlmaLinux 9.8 and 10.2
aarch64 with SELinux Enforcing (EL10's entrypoint is `#! /usr/bin/python3 -s`;
`-s` is implied by the adapter's isolated mode). AlmaLinux 8.10 aarch64 is
**blocked**: its systemd 239 rejects the package helper's transient unit
(`ProtectKernelLogs=`; `Type=exec` and `RestrictSUIDSGID=` are also newer) before
any native effect, although DNF4 4.7.0 on platform-python 3.6 completed the
adapter phases in a scratch guest. Records and the diagnosis are in
[verification](../verification.md#native-packages-on-el-dnf4-python-api-backend).
Rocky Linux and x86_64 derivatives are not exercised.

## Host resource providers

Managed files, local groups and users, sysctl, systemd timers and drop-ins,
password policy and firewall zones accept `almalinux` (and `rhel`) only with an
EL 9 or EL 10 `VERSION_ID`; password policy pins AlmaLinux 9.8 and 10.2 exactly.
Rocky Linux and AlmaLinux 8 are refused as unqualified. The AlmaLinux 9.8 GenericCloud
image has the same native stack as RHEL 9.8 (shadow-utils 4.9-16, systemd 252,
authselect 1.2.6, pam 1.5.1, libpwquality 1.4.4, SELinux Enforcing, no
firewalld/nftables, pam-package stacks without an authselect selection), so the
EL 9 quirks in [RHEL host resource providers](rhel.md#host-resource-providers-el-9)
apply unchanged: chrooted shadow tools, the systemd 252 floor, refusal of an
unmanaged PAM stack before `authselect select sssd`, and the boot-restoration
handling of a concurrent nftables generation change and of repeated
acknowledgments. Records are in
[verification](../verification.md#host-resource-providers-on-el-9); AlmaLinux
records are derivative evidence, not RHEL qualification.

AlmaLinux 10.2 GenericCloud matches RHEL 10.2 natively (shadow-utils 4.15.0-11,
systemd 257, authselect 1.5.2 with the `local` profile already selected, pam
1.6.1, libpwquality 1.4.5, SELinux Enforcing, no firewalld/nftables), so the
[RHEL EL 10 notes](rhel.md#host-resource-providers-el-10) apply: chrooted shadow
tools (EL 10 `--prefix` still mislabels the databases), no profile step for
password policy. Records are in
[verification](../verification.md#host-resource-providers-on-el-10).

## Encryption and recovery

Do not inherit Fedora or Ubuntu LUKS2, cryptsetup, TPM, Secure Boot or recovery
results. Qualify the actual derivative kernel/initramfs/systemd stack, exact
storage identity, enrolled firmware keys and both normal and recovery boots.
The packaged executor intentionally hides disks and TPMs until reviewed exact-node
provisioning ([`lindm-executor.service:21-30`](../../internal/packaging/assets/lindm-executor.service#L21-L30)).
[Verification](../verification.md#encryption-and-imperative-action-evidence-l10-l13-l15)
defines the required independent evidence; successful RPM installation or service
dispatch is not a recovery/erase result.

The encrypted GNOME goldens install only from the pinned vendor DVD (no
repository is added during installation), SELinux Enforcing, with the vendor
"Server with GUI" environment (`@^graphical-server-environment`, whose
`gnome-desktop` group carries GDM and GNOME Shell) on both architectures. The
aarch64 DVD comps of Rocky and AlmaLinux 9.8/10.2 have no
`workstation-product-environment`; Anaconda stopped at its missing-environment
prompt on the first Rocky 10.2 aarch64 install. This is GNOME session evidence
for that environment, not Workstation-product evidence. The terminal is
`gnome-terminal` on 9 and `ptyxis` on 10. Unlike RHEL, the installed systems
keep their free vendor repositories, so action and owned-boot prerequisites
install through DNF with vendor signature checking.

Recovery sanitize uses the BLS flavor of `RECOVERY_BOOT_MODE_MEASURED_GRUB` on
x86_64: AlmaLinux 10.2 amd64 passed NVMe and SATA from the vendor cloud image
([verification](../verification.md#measured-grub-recovery-on-stock-vendor-boot-chains)).
On aarch64 the signed `grubaa64.efi` of Rocky and AlmaLinux 9.8/10.2 records no
PCR 8/9 event, so agent readiness refuses measured GRUB before approval. The
owned-boot UKI fixture boots there but needs `systemd-ukify` on the Spark hosts,
which they do not have yet. aarch64 SATA cannot boot at all, because AAVMF has no
AHCI driver.

Rocky Linux and AlmaLinux 9 share RHEL 9's `systemd 252-67`, whose TPM2 unseal
retry fails on a stale encryption session after a PCR change. The managed TPM2
bind therefore writes four token references to its sealed keyslot, as on RHEL 9;
see [RHEL](rhel.md#tpm2-unseal-retry) for the Rocky 9.8 measurements. The 10.2
rows ship systemd 257, which retries correctly, and keep one token.

## Device actions

The AlmaLinux service result below covers signed systemd service dispatch, not
GNOME lock, account lock, quarantine, power actions, encryption or sanitize.
Keep server/minimal and desktop rows separate and follow each action's native
qualification record in [verification](../verification.md). An unavailable native
capability must remain unavailable, not a compatibility fallback to an unrelated
distribution or command.

On the encrypted "Server with GUI" GNOME goldens, Rocky Linux and AlmaLinux
9.8/10.2 passed these lanes natively on aarch64, with SELinux Enforcing:

- the encryption scenarios, including TPM2 bind, unattended cold boot and
  PCR-mismatch recovery;
- compliance;
- live-root crypto-erase and report-loss;
- GNOME lock with nftables quarantine and release.

AlmaLinux 10.2 repeated encryption, erase, report-loss and lock/quarantine on
x86_64. Five-scenario remote assistance passed on Rocky and AlmaLinux 10.2
(GNOME 49) on aarch64 and on AlmaLinux 10.2 x86_64.

On 9.8 (GNOME 40), assistance ends with `UNAVAILABLE capture_no_frames`. The
vendor PipeWire 1.4.11 sends damage-frame and keepalive timestamps that stall
GStreamer's `pipewiresrc`; upstream PipeWire fixed this in `efd1526` and
`49300d8`, and no capture fallback is added. Records and the diagnosis are in
[verification](../verification.md#device-actions-encryption-configuration-and-assistance-ubuntu-2204-debian-1213-rocky-and-almalinux-98102).

## Advisory feeds

Fedora's updateinfo adapter explicitly refuses other distro identities
([`advisory/feed/rpm.go:51-59`](../../internal/advisory/feed/rpm.go#L51-L59)).
Red Hat CSAF applicability requires actual Red Hat CPE and corresponding native
repository/stream evidence
([`advisory/platform.go:11-72`](../../internal/advisory/platform.go#L11-L72)).
Therefore neither feed establishes AlmaLinux or Rocky coverage by compatibility
inference. Vendor-specific feed mapping and fresh complete coverage need their own
qualification; missing coverage is not zero exposure.
RPM `gpg-pubkey` signing-key rows without an architecture are keyring entries:
they neither match records nor make architecture coverage UNKNOWN
([Fedora advisory feeds](fedora.md#advisory-feeds)).

Each vendor's own OSV export is the maintained source:
`https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/all.zip` and
`…/Rocky%20Linux/all.zip`, ecosystems `AlmaLinux:N` / `Rocky Linux:N`. These are
major-scoped, so a source configured by the major (`release: "9"`) applies to
every `9.x` VERSION_ID of that row; an explicit minor applies only to that minor
([`feed.Applies`](../../internal/advisory/feed/feed.go)). Before that rule a
`10` source evaluated a `10.2` device as `feed_unavailable`. Parsing the
2026-10-12 exports: AlmaLinux 9 27,076 claims with 117 module-stream records
rejected (unsupported module ranges withhold a clean result), AlmaLinux 10 8,040
with none; Rocky Linux 9 2,433 with 430 rejected (356 SIG products such as
`distro=rocky-linux-9-sig-cloud`, 74 module streams) and Rocky Linux 10 992 with
188 SIG rejections. Rocky stays registry-partial (source-like package mappings),
so its evaluations remain `feed_partial_coverage`, never complete.

## Remote assistance capability roadmap

AlmaLinux and Rocky Linux each require their own desktop/portal qualification;
neither RHEL nor Fedora evidence transfers. The
[capability contract](../product-specification.md#remote-assistance-capabilities)
defines consent, off/limited/on policy, role permissions and audit for all tiers.
GNOME version, Clipboard on the existing RemoteDesktop session, FileChooser,
notifications and reliable lock/logout observation must be probed on each release.
Missing interfaces are explicit capability gates, not reasons to use X11/root
capture. Clipboard, keys/layouts, display selection, messages, files, reconnect,
recording and Tier 3 are all
[not run](../verification.md#commercial-assistance-capability-qualification)
for these platforms. Native scenarios must prove guest effects and digest-bound
artifacts independently; KDE/unattended work awaits parent confirmation.

## Lab

Use each vendor's pinned manifest with maintained `lab images fetch`, offline
`lab images verify`, then native inspection/lifecycle/dispatch as documented in
[agent enrollment](../agent-enrollment.md) and [verification](../verification.md).
Retain image, architecture, firmware, SELinux, native versions, source and result
digests. The current independent status is:

| Vendor/image           | Observed evidence boundary                                                                                                                                                                         |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rocky 9.8 x86_64       | Native inspection matched 422 RPM records; no completed lifecycle/dispatch is claimed here.                                                                                                        |
| Rocky 10.2 x86_64      | Native inspection matched 443 RPM records; no completed lifecycle/dispatch is claimed here.                                                                                                        |
| AlmaLinux 9.8 x86_64   | Native inspection matched 387 RPM records. Earlier packaged lifecycle failed signed service; corrected connected dispatch passed independently. A full packaged lifecycle rerun is still required. |
| AlmaLinux 10.2 x86_64  | Passed UEFI inspect (380 RPMs), full signed 0.7.0→0.7.1 lifecycle (five 382-package publications) and nine native dispatch scenarios locally; SELinux Enforcing (records below).                   |
| AlmaLinux 8.10 x86_64  | Passed UEFI inspect (434 RPMs), full signed lifecycle (five 436-package publications) and nine native dispatch scenarios locally after the systemd 239 readiness fix below; SELinux Enforcing.     |
| Legacy 8               | Consult each vendor's separate acquisition/native rows; do not inherit 9/10 results.                                                                                                               |
| Rocky 9.8 aarch64      | Passed inspect (418 RPMs), full signed 0.7.0→0.7.1 lifecycle (five 420-package publications), and nine native dispatch scenarios on dgx20 KVM; SELinux Enforcing.                                  |
| Rocky 10.2 aarch64     | Passed inspect (440 RPMs), full signed 0.7.0→0.7.1 lifecycle (five 442-package publications), and nine native dispatch scenarios on dgx20 KVM; SELinux Enforcing.                                  |
| AlmaLinux 9.8 aarch64  | Passed inspect (384 RPMs), full signed 0.7.0→0.7.1 lifecycle (five 386-package publications) and nine native dispatch scenarios on dgx20 KVM; SELinux Enforcing.                                   |
| AlmaLinux 10.2 aarch64 | Passed inspect (379 RPMs), full signed lifecycle (five 381-package publications) and nine native dispatch scenarios on dgx20 KVM; SELinux Enforcing.                                               |
| AlmaLinux 8.10 aarch64 | Passed inspect (430 RPMs), full signed lifecycle (five 432-package publications) and nine native dispatch scenarios on dgx20 KVM after the EL8 fixes below; SELinux Enforcing. Not Rocky/RHEL 8.   |
| Rocky 8.10 aarch64     | Passed inspect (450 RPMs), full signed lifecycle (five 452-package publications) and nine native dispatch scenarios on dgx21 KVM with the EL8 fixes below; SELinux Enforcing. Not RHEL 8.          |

The AlmaLinux corrected dispatch record is
`$HOME/.cache/lindm-alma-servicefix-20261010/alma9-dispatch-after.json`, SHA-256
`1879713374fba6153867c4a6eb24ad910ff9991a7299152cc15808b5f3b4cbd4`.
It proves nine native scenarios with SELinux Enforcing; the tenth listed scenario,
unstarted supersession, is explicitly integration-only. It does not rewrite the
historical failed packaged lifecycle.

The five aarch64 acquisitions (Rocky 9.8/10.2 and AlmaLinux 9.8/10.2/8.10) are
recorded in `$HOME/.cache/lindm-mutabledistros3-20261010/arm64-acquisition.json`,
SHA-256 `1c7b1bfe9711e92d513c768a72cfddc430bdc3dc3dac601e52c2885651d0d5fb`.
This is image authenticity/offline-cache evidence only, not an executed ARM pass.

Independent Rocky ARM passes use source `d303cecb69bc041328438538a2e3bbf084ac06fb`
plus lab-only diff `8c30afa7e3e809009ec39cc777f8130efdf0d076101035ff8ac5f6d24eab3263`.
The delta repairs missing native route/session truth and preserves signed package
basenames during remote staging; it does not alter product behavior or skip gates.
Runtime is native aarch64 KVM/QEMU 8.2.2, AAVMF `2024.02-2ubuntu0.10`, Secure Boot
disabled/SetupMode true, virtio-blk, no TPM/desktop and explicit user egress.
Both lifecycles passed signature rejection, enrollment, upgrade, changed-boot-ID
reboot, retained purge/reinstall identity, spool recovery, denied collection
preserving snapshot 5, independent final revocation and missing-journal hold.
Both dispatches passed periodic compliant recheck/drift remediation and revoked
denial; unstarted supersession remains integration-only. No x86_64, AlmaLinux,
air-gap, desktop or physical capability is inherited.

Records below are under `$HOME/.cache/lindm-mutabledistros3-20261010/`:

| Record                                    | SHA-256                                                            |
| ----------------------------------------- | ------------------------------------------------------------------ |
| `rocky9-arm64-dgx20-inspect.json`         | `e8b1d77d1c81b02ae833afc8cd7849d37557371b019f5726a264b9159f6bf3db` |
| `rocky9-arm64-dgx20-lifecycle.json`       | `c7b95fddeef7c28d396901993e920989c0970a56810de7b3f114ee345ad0c5d0` |
| `rocky9-arm64-dgx20-dispatch.json`        | `bb17111467ecef3bb47d0fb2fc898a49415c411dc0fd15e2c819f2e8b7830ed4` |
| `rocky10-arm64-dgx20-inspect.json`        | `8e82dfa7570d14b8e30b8da2f77cd3b48d63650519b11d9897827cd117743049` |
| `rocky10-arm64-dgx20-lifecycle.json`      | `c4713821b59c9938a44b81fec68c5df7d6e1ad922e0641c7690a835c2de04df9` |
| `rocky10-arm64-dgx20-dispatch.json`       | `34bd45508a999bc54cc861b8d5d9f8d31db8305b99396345a802953f47a192bc` |
| `alma9-arm64-dgx20-inspect.json`          | `4b27eebefe3cf6c4f0987f076c8e3d8cb36d8c3c0c83980b17b5d562fad3f525` |
| `alma9-arm64-dgx20-lifecycle.json`        | `3c76a258e81a63333f9e0937331ba2f70b0508392480505c77a77aad21d8827a` |
| `alma9-arm64-dgx20-dispatch.json`         | `8df0e0271385e3220bce78f9dcae62fa5cb9a2cfbd05ea2b694f8f3e7a4cb665` |
| `alma10-arm64-dgx20-inspect.json`         | `50fa3dd6a71b1b0d963a36a57dfcfe35cf30695ad26e286199e2d84980c4e1f6` |
| `alma10-arm64-dgx20-lifecycle.json`       | `5a8056cbeb509530f9f6aa053a775c7310055fbb36baf773d6b3d8559ee94498` |
| `alma10-arm64-dgx20-dispatch.json`        | `822336a8bcf022589772ea04a31247555b67dcf62146e989f7b0be8cc8e05830` |
| `alma8-arm64-dgx20-inspect-el8fix.json`   | `9e314b95621a350cb0c6c76029abfed18250f61dc3128442d705e9f08c816567` |
| `alma8-arm64-dgx20-lifecycle-el8fix.json` | `f336e9018b6682531f402db6e33b62bd42657cdb240bdad21eeb4f29481e400c` |
| `alma8-arm64-dgx20-dispatch-el8fix.json`  | `1e645149636351a18613562e197da23babd58602c364477686fb93952b88ad88` |

AlmaLinux 9.8/10.2 use the same `d303cec` + `8c30afa7…` source as Rocky.
AlmaLinux 8.10 required three EL8 compatibility fixes, each with regressions,
and ran from `d303cec` plus that delta and these fixes (lane-recorded source diff
SHA-256 `e10d895312dfb0bc99b139f6222ac07087ec7698321bc1d7b6df6e2ff0233de8`),
with 0.7.0/0.7.1 RPMs rebuilt from that source (`5e6043f9…`/`ac143d42…`):

- **util-linux 2.32.1 lsblk** lacks `FSVER`, `PTTYPE`, `PTUUID` and `MOUNTPOINTS`
  and exits 1 (`unknown column`). Agent and independent oracle now, only after that
  native failure, probe `lsblk --version` once and use a legacy column set for
  releases before 2.37; uncollected identity fields stay `UNAVAILABLE`
  ([`storage_linux.go`](../../internal/agent/inventory/storage_linux.go);
  captured fixture `testdata/lsblk-almalinux810-aarch64`).
- **Native exit status** was lost: the runner killed lsblk in the window after it
  closed stdout, reporting `INVALID_OUTPUT` instead of `NATIVE_COMMAND_FAILURE`.
  A drained tool is now waited for, not killed
  ([`packages_linux.go`](../../internal/agent/inventory/packages_linux.go):117-183;
  `TestNativeExitPrecedesParserRejection`).
- **systemd 239 busctl** has no `--json`. After a native busctl failure the agent
  reads `busctl --version` once; before v240 it parses busctl's fixed text output
  (`call ListUsers/ListSessions`, `get-property` per session) through the same
  logind validation ([`sessions_text_linux.go`](../../internal/agent/inventory/sessions_text_linux.go);
  `TestLegacyBusctlTextSessions`).

Rocky 8.10 aarch64 (GenericCloud Base `8.10-20240528.0`, new pinned manifest
[`rocky-8.10-aarch64.json`](../../lab/images/rocky-8.10-aarch64.json); signed
aggregate `CHECKSUM` by Rocky's 8 key `7051C470…6D745A60`) ran unchanged from the
exact AlmaLinux 8.10 pin above (same `e10d8953…` source, lab binary `96c29b5d…` and
RPMs `5e6043f9…`/`ac143d42…`), on `dgx21`; no further EL8 defect appeared. Records
are under `$HOME/.cache/lindm-mutabledistros5-20261010/`:

| Record                              | SHA-256                                                            |
| ----------------------------------- | ------------------------------------------------------------------ |
| `rocky8-arm64-dgx21-inspect.json`   | `a78440395d110ccea326f59a3d1d111d66a4cab354a8f6d13f7f8cd6ff8c9ea8` |
| `rocky8-arm64-dgx21-lifecycle.json` | `e550555f5f8624edcc55276ad4bb282e1324492f2945bf4b13017e36e8e15e18` |
| `rocky8-arm64-dgx21-dispatch.json`  | `6a7f8f8a1423fe5cda697e8342e86ca488e9700370cf88ddcfdeaa82c1f4bda2` |

AlmaLinux 10.2 and 8.10 x86_64 ran locally (KVM, OVMF `2024.02-2ubuntu0.10`,
Secure Boot disabled, virtio-blk, no TPM/desktop, isolated local password/WebAuthn
authority) from `4d74dcf` plus the MutableDistros5 lab delta, with signed x86_64
RPMs `ebafbefb…`/`f2c8da50…`. AlmaLinux 8.10 inspection first failed `native
system startup is not settled`. The inspection readiness gate added after the ARM
EL8 pin runs `systemctl is-system-running --wait`, but systemd 239 ignores `--wait`
there (support arrived in v240) and answers `starting` at once. Only after such a
transient answer and a `systemctl --version` below 240 does the gate now poll within
its one-minute deadline ([`vm_inspect_readiness_linux.go`](../../internal/vmlab/vm_inspect_readiness_linux.go);
`TestInspectReadinessPollsSystemdWithoutWait`). The passing record shows `degraded`
settled after 14 s. Records are in the same directory:

| Record                               | SHA-256                                                            |
| ------------------------------------ | ------------------------------------------------------------------ |
| `alma10-x86_64-local-inspect.json`   | `76575dcfc770c61da3d0c570f697c77c7fbea2d59845f79f2e0c7bfaf2bfc9bb` |
| `alma10-x86_64-local-lifecycle.json` | `0aaf17e8edcb8c4c9a51ec97bb285af804fea82ba19b6c9864a6f43941c2a060` |
| `alma10-x86_64-local-dispatch.json`  | `20be65dafef62626575e71eeabb5b3b133009cd1e163ad4af51b695248d70df8` |
| `alma8-x86_64-local-inspect.json`    | `c33350a7dc4f74c6174cbd2fedd73777da8e31c6b7ccaca93087f0097c429f3d` |
| `alma8-x86_64-local-lifecycle.json`  | `4ea01b9bf89e9a9610a45b229c65e99ff9cd104b08546d472020957b9ff0f769` |
| `alma8-x86_64-local-dispatch.json`   | `f3e10b1dd10eaf438415199911d7234b8c67941e91245d3b480ed1511acfdf5c` |

The Rocky 8.10 and AlmaLinux 8.10 ARM records predate that gate (`d303cec` pin); an
EL8 inspection at the current tree needs the readiness fix.

The original x86 records are under `$HOME/.cache/lindm-mutabledistros-20261010/`,
indexed by its `evidence-index.json`:

| Record                         | SHA-256                                                            |
| ------------------------------ | ------------------------------------------------------------------ |
| `rocky9-inspect-uefi.json`     | `7920e3335d6c54fefdb90c124efb5253aa0bc8658e0cbc1704aefadc7b4b2307` |
| `rocky10-inspect-uefi.json`    | `55d62d0aadd2bf1dbf51e1c6636578b8982399678bdf037eeae3fa526221b365` |
| `alma9-inspect.json`           | `487aecbba8bc98572eee98b0918b6918e09b796b2cb231df2fd2926bc3c93f54` |
| `alma9-lifecycle-failure.json` | `ab55a20dd1642391bb8d315d1e5346e01778636ea440553a983cbd0ded489b2f` |

## Gaps

Rocky x86_64 and a rerun AlmaLinux 9.8 x86_64 lifecycle still require the separate
complete cells. RHEL 8 inherits nothing from the AlmaLinux/Rocky 8.10 rows. EL8
device actions are not covered: the action
provider still requests `PTTYPE`/`PTUUID`/`MOUNTPOINTS`. Desktop, other legacy
rows, air-gap, actions and physical-machine evidence
remain exact-scope requirements. The dbus-broker fix closes a demonstrated AlmaLinux
signal-delivery issue, not the entire derivative matrix. Derivative advisory
coverage and generic package resources must not be inferred from RHEL/Fedora.
The OS update policy (`os.update.v1`) uses the same DNF 4 `dnf-automatic` runner
as RHEL 9 on Rocky Linux and AlmaLinux 9/10: natively qualified on aarch64
(maintenance-window security install, scheduled reboot, deferral and patch-now,
SELinux Enforcing; [verification](../verification.md#debian-el-and-ubuntu-2204-matrix-completion-2026-10-12)).
Release upgrade is gated: 9→10 needs ELevate/Leapp, which lindm does not drive,
and 10 has no released successor.
