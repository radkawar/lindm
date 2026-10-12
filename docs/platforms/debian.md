# Debian

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Debian 11                                                                                               | Debian 12                                                                                                                                                                                                                                   | Debian 13                                                                                                                                                                                            |
| ----------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| inventory         | implemented                                                                                             | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| lifecycle         | implemented                                                                                             | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| dispatch          | implemented                                                                                             | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| packages          | implemented                                                                                             | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| accounts          | implemented                                                                                             | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| sysctl            | gated: not implemented for Debian 11                                                                    | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| definitions       | gated: systemd 247 is below the definition provider floor 255                                           | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| password          | gated: not implemented for Debian 11                                                                    | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| firewall          | gated: not implemented for Debian 11                                                                    | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| encryption        | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| wipe              | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| report-loss       | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| lock              | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| recovery-sanitize | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented; gated on aarch64: bookworm's signed grubaa64.efi (grub-efi-arm64-signed 1+2.06+13+deb12u2) embeds no tpm module, so it records no PCR 8/9 event for measured recovery, and systemd 252 has no ukify for the owned recovery UKI | implemented                                                                                                                                                                                          |
| self-update       | implemented                                                                                             | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| assistance        | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| advisories        | implemented                                                                                             | implemented                                                                                                                                                                                                                                 | implemented                                                                                                                                                                                          |
| os-update         | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release | gated: the os-update runner selects Ubuntu origin:suite pairs; Debian's security suites (stable-security/oldstable-security) need codename/label Origins-Pattern selection, which is not implemented                                        | gated: the os-update runner selects Ubuntu origin:suite pairs; Debian's security suites (stable-security/oldstable-security) need codename/label Origins-Pattern selection, which is not implemented |
| release-upgrade   | gated: release upgrade is not implemented                                                               | gated: Debian has no unattended release upgrader (the documented path is a manual sources rewrite and apt full-upgrade); the lane drives only do-release-upgrade                                                                            | gated: no successor release: Debian 14 is not released                                                                                                                                               |

<!-- END GENERATED platform-capabilities -->

[Verification](../verification.md#1-launch-platform-qualification) is the authoritative
qualification ledger; the [shared platform contract](README.md) separates implementation,
recorded operation and complete release certification. Debian 13 is a required launch
branch, with GNOME/KDE and minimal installations requiring separate qualification on
x86_64 desktop/server and aarch64 server. Debian 12 LTS is a separate legacy branch, not
an inherited Debian 13 pass. No Debian whole-family or all-resource support is claimed.

The pinned installation inputs are Debian **13.7.0** and **12.15.0** netinst, each
with separate [amd64 13](../../lab/images/debian-13-amd64.json),
[amd64 12](../../lab/images/debian-12-amd64.json),
[arm64 13](../../lab/images/debian-13-arm64.json#L1) and
[arm64 12](../../lab/images/debian-12-arm64.json#L1) manifests. Version-pinned vendor
metadata lives at [13.7.0 arm64](https://cdimage.debian.org/debian-cd/13.7.0/arm64/iso-cd/)
and [12.15.0 arm64](https://cdimage.debian.org/cdimage/archive/12.15.0/arm64/iso-cd/).
The manifests require detached signed SHA512SUMS, exact image size, SHA-512
verification and the separately pinned SHA-256 cache identity, with signer
`DF9B9C49EAA9298432589D76DA87E80D6294BE9B`.

Debian 12/13 native **ARM KVM** inspection, packaged automatic-trust lifecycle and
connected service dispatch passed on `dgx20`. These are aarch64, QEMU 8.2.2,
AAVMF `2024.02-2ubuntu0.10`, Secure Boot disabled/SetupMode true, virtio-blk,
no TPM, no desktop, user-egress observations. They do not qualify the aborted x86_64
lifecycle or encrypted/desktop installs. Exact records appear in the lab section below.

## Packaging, signing, repositories, paths and LSM

Choose Debian in the console's enrollment dialog for one command that installs
from the customer's own `lindmd` HTTPS `/repo/apt` endpoint and enrolls the device.
The command verifies the pinned signer and server/bootstrap trust before creating
the deb822 `Signed-By` source. There is no external agent repository. Missing
release artifacts or architecture coverage block installation with a configuration
remedy. Follow the
[install runbook](../security-and-operations.md#enrollment-installation-from-your-server);
Ubuntu installation evidence does not qualify Debian.

A provisioning token offers only **cloud-init** for Debian (genericcloud images).
Debian's installer uses preseed, which the console does not generate, and Ubuntu
autoinstall is subiquity-only. No provisioning lane has a Debian record.

Agent packaging uses DEB/APT, not an RPM-derived path. Authentication is repository
`InRelease` signature → `Packages` hashes → exact archive digest; a built `.deb` is
not independently signed. Use a dedicated independently trusted `Signed-By` key, not
global `trusted.gpg` or an unauthenticated `dpkg -i` shortcut
([packaging contract](../../internal/packaging/doc.go#L14),
[deb822 source](../../internal/packaging/publish.go#L19)). The agent repository and
Debian installer-image signing keys have different purposes. The lab's `stable/main`
coordinates belong to lindm, not a request to change the vendor suite
([layout](../../internal/packaging/layout.go#L32)).

The shared binary is `/usr/libexec/lindm/lindm-agent`, with strict root/network
configuration at `/etc/lindm/executor.json` and `/etc/lindm/agent.json`.
`/var/lib/lindm/executor` owns root identity/journal, `/var/lib/lindm/agent` owns
transport state, and `/run/lindm` is root:lindm 0750. See the
[shared paths/sandbox contract](README.md#shared-implementation-boundaries),
[executor unit](../../internal/packaging/assets/lindm-executor.service#L8),
[network unit](../../internal/packaging/assets/lindm-agent.service#L9) and
[tmpfiles](../../internal/packaging/assets/tmpfiles.conf#L1).

Preserve the installation's LSM and capture its actual enforcement/profile state.
The cited Debian ARM records establish their recorded native operations and systemd
privilege boundaries, not an AppArmor profile or SELinux-enforcing qualification.
Do not infer either from family resemblance or weaken policy to obtain a pass.

## Agent services and sandbox

`lindm-executor.service` runs as root; `lindm-agent.service` runs as `lindm` with
empty capabilities. Both use `PrivateDevices=yes`, `NoNewPrivileges=yes`,
`ProtectSystem=strict`, `ProtectHome=yes` and `ProtectProc=invisible`. The executor's
AF_UNIX boundary and the transport's configured IP/resolver families remain separate
([executor](../../internal/packaging/assets/lindm-executor.service#L17),
[transport](../../internal/packaging/assets/lindm-agent.service#L18)).

Current privileged inventory uses the fixed `inventory-observe` transient helper:
read-only block-device access, empty capabilities, no network, inaccessible lindm
configuration/state, bounded lifetime/output and boot/timestamp validation
([root observer](../../internal/agent/executor/root_inventory_linux.go#L28),
[properties](../../internal/agent/executor/root_inventory_linux.go#L89)). This is a
shared implementation, not a retroactive claim that historical Debian ARM packages
contained the later Ubuntu-driven helper correction. Native Debian encrypted
publication must qualify that topology independently. Imperative actions need their
own exact-device provisioning; do not disable the persistent sandbox.

## Inventory and per-field quirks

Debian 13 ARM inspection matched **353** installed native dpkg identities; Debian 12
matched **361**. The packaged lifecycle adds the agent, producing five **354** and
**362** package publications respectively. Package equality is not sufficient by
itself: the complete native oracle compares routes, active-session properties and
field health, rejecting identical failures.

The Debian 13 initial ARM oracle omitted per-interface IPv4/IPv6 default routes and
active-session properties. Correcting the independent oracle yielded the explicitly
named `inspect-complete-oracle` pass; it did not change absent observations into
success. [Verification](../verification.md) retains that history and the exact runner
provenance.

Dpkg packages also carry APT origin evidence (the lists indexes listing each exact
installed version, see [architecture](../architecture.md#distro-advisory-findings)).
The native oracle compares it with `apt-cache policy` and requires stock Debian
sources to verify. The recorded Debian inspections predate this field and its
oracle; they are not evidence for it.

The maintained [unavailability rules](../../internal/vmlab/inventory_unavailable_linux.go#L7)
are exact, capability-backed and accept only `UNAVAILABLE`, never permission denied,
timeout, invalid output or native command failure:

| Observation             | Debian-specific or capability-dependent interpretation                                                                                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OS CPE                  | Debian os-release need not supply `CPE_NAME`; absent means unavailable, not a synthesized CPE.                                                                                                    |
| dpkg module             | RPM modularity is inapplicable only for actual `dpkg` package records.                                                                                                                            |
| Repository/release lock | Releasever override is optional; RPM/DNF repository inventory is inapplicable only with successful dpkg-present/RPM-absent observations. This says nothing about APT repository authentication.   |
| Snap/Flatpak            | An absent backend permits unavailable application inventory only after successful backend detection. An installed backend failure cannot be excused.                                              |
| aarch64 CPU             | x86-64 ISA level is inapplicable; ARM execution evidence does not certify an x86 CPU baseline.                                                                                                    |
| Secure Boot/TPM         | BIOS lacks UEFI state; a present UEFI must be observed. TPM version may be unavailable only with a successful false presence observation. The ARM lanes explicitly observed disabled Secure Boot. |
| Sessions                | Remote/tty sessions may lack a seat; active-session properties still require real logind observations.                                                                                            |
| Storage                 | Missing virtio serial/WWN/model, unmounted devices and non-LUKS/non-NVMe fields have individual rules. Present LUKS metadata failure is not an absence exception.                                 |

Sources: [field rules](../../internal/vmlab/inventory_unavailable_linux.go#L20),
[storage rules](../../internal/vmlab/inventory_unavailable_linux.go#L33),
[non-DNF predicate](../../internal/vmlab/inventory_unavailable_linux.go#L62).

## Updates

Debian's authenticated 0.7.0→0.7.1 agent package lifecycle is qualified on the cited
ARM images. It includes reboot/reinstall, retained purge identity, spool recovery,
automatic authority rotation, final revocation and missing-journal hold. The signed
collection-denial attempt preserves the previous accepted snapshot rather than
publishing an empty successful inventory. Different stamps from one source tree
are not historical-release compatibility evidence.

The shared unattended agent updater has an APT-specific requirement: put the exact
verified archive at `lindm-agent_<version>_<architecture>.deb` inside the protected
transaction cache; percent-escape `:`/`_` in the version as `%3a`/`%5f`.
Use that directory for `Dir::Cache::archives`, including its private `partial`
directory. A generic filename outside an empty cache can fail under `--no-download`.
The native transaction simulates, restricts effects to the admitted agent, disables
repositories/downloads/removals/recommends and recovers only that package's interrupted
unpack/configure ([archive naming](../../internal/agent/update/native_linux.go#L83),
[APT transaction](../../internal/agent/update/native_linux.go#L407)).
APT 2.8.3's [canonical resolution](https://salsa.debian.org/apt-team/apt/-/blob/2.8.3/apt-pkg/acquire-item.cc#L3464)
explains this constraint; it is not a claim that every Debian image has that APT version.

Ubuntu's separately measured unattended update/interruption pass is not Debian
qualification. Neither the ARM agent lifecycle nor this implementation qualifies
Debian major upgrades, whole-system rollback, arbitrary package dependency plans or
the new generic package resource provider. These need their own native evidence.

## Encryption and recovery

The maintained **unencrypted** Debian netinst recipe uses regular partitioning
(`partman-auto/method string regular`) and installs standard plus SSH-server tasks;
the successful ARM inventory/lifecycle/dispatch records use it with no TPM and no
encryption fixture ([preseed](../../internal/vmlab/debian_installer_linux.go)).

The separate **encrypted** golden (`lab vm encrypted` with
`lab/images/debian-{12,13}-*.json`) preseeds Debian's own guided LVM-on-LUKS2
(`partman-auto/method string crypto`, `partman-crypto/passphrase`), installs the
registry's tasksel desktop tasks (`desktop, gnome-desktop`) and configures GDM
autologin through `/etc/gdm3/daemon.conf` — Debian's gdm3 does not read Ubuntu's
patched `custom.conf`. debconf strips surrounding whitespace, so such passphrases
are refused. The TPM-boot variant installs dracut with the release's packages
(bookworm: `libtss2-tcti-device0`, crypt-integrated systemd-cryptsetup; trixie:
`libtss2-tcti-device0t64`, split `systemd-cryptsetup` package and dracut module)
and rebuilds every installed kernel's initrd. `preseed/late_command` runs
**before** finish-install's apt-cdrom-setup comments out the netinst disc source;
trixie's netinst carries some of those dependencies, so apt blocked forever on a
"Media change" prompt (diagnosed natively with an in-guest process watchdog). The
late script now applies that same `deb cdrom:` edit first and closes apt's stdin.
Debian's arm64 kernels build TPM CRB but not the TIS platform driver that QEMU's
aarch64 `virt` TPM uses, so arm64 goldens are a separate TPM-absent tuple
(`-tpm=false`); an attached-but-unobservable TPM is refused. The owned-boot
recovery fixture needs `systemd-ukify` (systemd 253+), so bookworm recovers only
through measured GRUB (below). A passing golden is not escrow, rotation, TPM
unlock or wipe qualification; those are separate device-action records in
[verification](../verification.md).

Stable targeting requires server-returned signed identities and native revalidation,
not a device path. Shared target construction prefers WWN+serial; the explicitly
absent-WWN encrypted GPT fallback requires a unique serial, disk/target sizes,
GPT disk GUID and LUKS UUID. The ordinary unencrypted Debian virtio fixture cannot
acquire this fallback just because its disk lacks a WWN
([construction](../../internal/device/inventory/storage_targets.go#L116),
[revalidation](../../internal/agent/actionprovider/target_linux.go#L157)).
Recovery media capacity, independent cold boots, escrow/rotation and destructive
wipe remain separately gated by [verification](../verification.md).

Debian 12/13 use the same grub.d `custom.cfg` flavor of
`RECOVERY_BOOT_MODE_MEASURED_GRUB` as Ubuntu
([architecture](../architecture.md#measured-grub-recovery-recovery_boot_mode_measured_grub)).
Debian 13 and Debian 12 amd64 passed SATA and NVMe natively. The recovery guests
were netinst goldens built from the signed 13.7.0 and 12.15.0 ISOs, with `/boot`
on the ext4 root, shim+GRUB 2.12/2.06 and kernels 6.12/6.1. 10_linux's `echo`
commands are skipped only when they are digest-bound
([verification](../verification.md#measured-grub-recovery-on-stock-vendor-boot-chains)).
Debian 12 has no owned-boot fixture (`Lab.OwnedBootUnavailable`): the lab refuses
that mode before boot and the matrix runs its recovery cell in measured mode.
Debian 12 arm64 recovery sanitize is a product gate (`ArchitectureGates`):
bookworm's signed `grubaa64.efi` (`grub-efi-arm64-signed 1+2.06+13+deb12u2`)
embeds 116 GRUB modules and no `tpm`, so GRUB records no PCR 8/9 event for
measured recovery, and systemd 252 has no ukify for the owned recovery UKI.
Trixie's arm64 GRUB (`1+2.12+9+deb13u2`) does embed `tpm`, so Debian 13 arm64
is not gated. The lab cannot present a TPM to either Debian arm64 kernel: QEMU
8.2's `virt` machine on the Sparks offers only `tpm-tis-device` and
`tpm-tis-i2c`, while `linux-image-6.1.0-50-arm64` and
`linux-image-6.12.107+deb13-arm64` set `# CONFIG_TCG_TIS is not set` and
`# CONFIG_TCG_TIS_I2C is not set` (only `CONFIG_TCG_CRB=y`). That is a lab-only
limit: arm64 hardware with a CRB TPM binds `tpm_crb`. Evidence:
[verification](../verification.md#debian-el-and-ubuntu-2204-matrix-completion-2026-10-12).

## Device actions

The two ARM dispatch records qualify nine connected **systemd service** scenarios,
including real five-minute compliant/drift checks, ±90-second clock skew and final
revoked-device denial. Unstarted supersession is integration-only, not a tenth native
scenario. Service dispatch is not session lock, firewall quarantine, power, account
lock, encryption or sanitize qualification.

The shared session provider uses authenticated root-owned logind over the fixed
system bus; lock acknowledgment is not physical desktop visibility
([session provider](../../internal/agent/actionprovider/sessions_linux.go#L38),
[evidence semantics](../../internal/agent/actionprovider/network_linux.go#L257)).
Power checks native capabilities, schedules and inhibitors without an unsafe fallback
([power](../../internal/agent/actionprovider/power_linux.go#L172)). Nftables quarantine
has kernel expiry and reports lost management delivery as unknown
([quarantine](../../internal/agent/actionprovider/network_linux.go#L260)).
None of those implementation paths supplies missing Debian GNOME/KDE/GDM or native
action evidence. Preserve authorization, exact target identity and irreversible-effect
warnings rather than using Ubuntu's action pass as a Debian substitute.

On the encrypted GNOME goldens, Debian 12 and 13 passed these lanes natively on
aarch64 (dgx20/dgx21) and on x86_64:

- the encryption scenarios (escrow, audited reveal, rotation, cold-boot recovery)
  and compliance;
- live-root crypto-erase and report-loss;
- GNOME lock with nftables quarantine and release;
- five-scenario remote assistance.

Debian 13 x86_64 also bound TPM2 and cold-booted unattended. The arm64 goldens are
TPM-absent, so their TPM phase records the server's `tpm2_unavailable` denial.
Records and hashes are in
[verification](../verification.md#device-actions-encryption-configuration-and-assistance-ubuntu-2204-debian-1213-rocky-and-almalinux-98102).

Debian 12's `systemd 252.39-1~deb12u2` keeps the systemd-stable 252 unseal loop.
That loop reuses the parameter-encryption session but does not refuse it, so it
restarts the policy session after a `TPM_RC_PCR_CHANGED` unseal, unlike Ubuntu
24.04's 255.4 ([TPM2 unseal race](ubuntu.md#tpm2-unseal-race)). On the x86_64
golden with Secure Boot enforced (109 IMA runtime measurements), one token
unlocked 30 of 30 times while PCR 10 was extended every 100 ms and every 50 ms.
Debian 13's systemd 257 creates a fresh session for each retry. Both releases
therefore keep one token per TPM2 bind. On x86_64 they qualify unattended unlock
through the `tpm-unattended-boots` cell
([verification](../verification.md#tpm2-unseal-race-and-unattended-boot-regression)).

## Advisory feeds

Debian's security-tracker export is **source-package** data. `repositories` describes
current archive source versions, not a binary mapping and not the first fixed version;
source/binary version divergence matters. The parser selects the exact configured
Debian release and rejects unsupported/contradictory shapes
([tracker contract](../../internal/advisory/feed/debian_tracker.go#L17),
[release filtering](../../internal/advisory/feed/debian_tracker.go#L99)).

- `resolved` requires a fixed version; fixed version `0` means not affected.
- `open` is not fixed; `undetermined` carries an explicit unknown assessment.
- No-DSA, ignored/postponed and next-point-update policy do not make a package fixed.
- Architecture and publication date remain absent when upstream supplies neither.
- Even the full export is not a package-universe completeness claim: untracked or
  removed source packages are not proven clean.

These are [native parser semantics](../../internal/advisory/feed/debian_tracker.go#L123),
not inferred vulnerability counts. Preserve native dpkg ordering, source mapping,
feed and inventory freshness independently. The verification ledger's source/binary
backport regressions are controlled applicability tests, not historical Debian
installations. Ubuntu USNs and malformed Ubuntu OSV purl handling do not substitute
for Debian tracker coverage.

A complete 2026-10-10 census of the separate canonical Debian OSV export
(`https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip`) inspected
70,305 records and found a maximum of 838 distinct CVEs in `DLA-4008-1`
(Debian 11). This is an OSV-export cardinality measurement, not a claim about every
historical Debian format or device exposure. The shared 2,048-CVE bound also
admits Ubuntu's measured 1,416-CVE kernel notices while retaining byte limits.
Source SHA-256: `4e1ad05000a2f1dcc0729e33ac80086ec2e5125ce20bcf31a83cf52d626c221f`.
Evidence: [`debian-osv-cve-cardinality-20261010.json`](../../artifacts/debian-osv-cve-cardinality-20261010.json),
SHA-256 `3688a041de7c2b3c3fb3287ce5bbefcdf5ff63465ea44a878645ded4c3dd9900`.

The registry's maintained export for Debian 12/13 is that OSV `all.zip` (primary
feed; a configuration admits one source per distribution release). Its current
records qualify source purls with the release **codename**
(`pkg:deb/debian/NAME?arch=source&distro=bookworm`, `distro=trixie`); on
2026-10-12 the export carried 57,053 `Debian:12`/`bookworm` and 57,714
`Debian:13`/`trixie` affected entries. The registry's `PURLDistro` is therefore
the codename. The earlier `debian-12` spelling rejected every such record as a
conflicting product qualifier and exceeded the rejected-record metadata bound,
so the feed refresh failed (`debian13-arm64` advisories record in
[verification](../verification.md#debian-el-and-ubuntu-2204-matrix-completion-2026-10-12)).
After the correction one Debian 13 record (`DEBIAN-CVE-2023-45288`, invalid native
version) is rejected and Debian 12 none. The `advisories` and `airgap` matrix lanes
use this export; the security-tracker JSON remains a separately configurable source.

## Remote assistance capability roadmap

Debian does not inherit Ubuntu's portal or GNOME results. The
[capability contract](../product-specification.md#remote-assistance-capabilities)
defines consent, off/limited/on policy, role permissions and audit for clipboard,
keys/layouts, displays, notifications, files, reconnect, recording and Tier 3.
Each release needs pinned portal/frontend/backend/compositor capability probes.
Clipboard requires the existing RemoteDesktop Clipboard interface; file upload
requires FileChooser and download targets the session user's Downloads.
No X11 fallback bypasses consent. All added capabilities are
[not run](../verification.md#commercial-assistance-capability-qualification)
on Debian; qualify actual guest effects, two monitors, clipboard nonces, transfer
hashes and recording/reconnect boundaries independently. KDE/unattended work awaits
parent confirmation.

## Lab

The Debian path deliberately avoids pretending current cloud checksums have a vendor
signature. It authenticates the signed netinst ISO, remasters only boot/preseed inputs,
installs from signed Debian repositories, integrity-pins the resulting local ext4
golden disk and rechecks it before disposable overlays. The derived disk is neither
vendor-signed nor a reproducible archive snapshot
([verification provenance](../verification.md),
[installer recipe](../../internal/vmlab/debian_installer_linux.go#L17)).
The recipe maps 12→bookworm and 13→trixie and permits only owned guest disk types;
preseed disables root login and uses the native installer rather than relabeling an ISO
as a cloud disk ([suite and target selection](../../internal/vmlab/debian_installer_linux.go#L19)).

Run maintained `lab images fetch`/`verify` against the chosen manifest before
`lab vm inspect`, `lifecycle` or `dispatch`. Native ARM uses the separately pinned
ARM input and native KVM, not cross-architecture inference. Preserve firmware package,
Secure Boot, storage, egress, source, agent and runner hashes in each record.

Records under `$HOME/.cache/lindm-mutabledistros3-20261010/`:

| Version / native operation                                    | Record                                              | SHA-256                                                            |
| ------------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------ |
| 13 / inspection, 353 packages                                 | `debian13-arm64-dgx20-inspect-complete-oracle.json` | `a67af59b3846199900abff8744dd078c36ccc0e1de0b4ad579632c54ade98f23` |
| 13 / automatic-trust lifecycle, five 354-package publications | `debian13-arm64-dgx20-lifecycle-stagingfix.json`    | `be19db1bcf1197a534d6425d8944d3e68173e3cd9245dd0c9abac452abce8c05` |
| 13 / nine service dispatch scenarios                          | `debian13-arm64-dgx20-dispatch.json`                | `0973b1cf434265359808e6553f4c0766a29042c03e788ebe29996e7cf18376a0` |
| 12 / inspection, 361 packages                                 | `debian12-arm64-dgx20-inspect.json`                 | `5b872dedd2a611d7f6847b15cdacad6a0a941dd0d12c99c21ff6df7bea62bcc2` |
| 12 / automatic-trust lifecycle, five 362-package publications | `debian12-arm64-dgx20-lifecycle.json`               | `1bda2586f58dee2764b8ca69e20cf99883412ad01e9414d540d5579d0af8d95a` |
| 12 / nine service dispatch scenarios                          | `debian12-arm64-dgx20-dispatch.json`                | `f29b8cdf4d4342c66e3928cc2d9ff5416fb1b92f243601e01682319376c7a8b0` |

The ARM passes include real isolated local password/WebAuthn authority and independent
final revocation. Both lifecycle records retain snapshot 5 after denied attempt 6,
with epoch 1→3. They do not erase x86_64 history: Debian 13's older packaged lane
failed final approval after earlier successful stages; the subsequent local automatic-
trust attempt was owner-cancelled for host contention after enrolled/upgraded/rebooted
publications. [Verification](../verification.md) retains exact failure/cancellation
records. Debian 12 amd64 remains separate from the successful ARM record.

## Gaps

- No complete Debian release matrix cell is certified. Architecture/edition,
  physical hardware and air-gap claims require their own evidence.
- Debian 13 amd64's final-approval failure and later host-contention cancellation
  are not a native lifecycle pass; ARM success does not retroactively change them.
- Debian encrypted installation, Secure Boot enabled, TPM, GNOME/KDE and recovery/
  destructive-action paths are not qualified by unencrypted headless ARM lanes.
- The new read-only transient inventory helper and generic native package resources
  need matching-version Debian runtime evidence, not historical package counts.
- Agent lifecycle upgrades do not establish Debian major upgrades, unattended
  interruption recovery, arbitrary dependency plans or system rollback.
- The OS update policy (`os.update.v1`) is gated on Debian, not implemented: the
  runner renders Ubuntu `Allowed-Origins` `origin:suite` pairs
  (`${distro_id}:${distro_codename}-security`), which unattended-upgrades matches
  against the archive **suite**. Debian's security archive is suite
  `stable-security`/`oldstable-security` (codename `…-security`, label
  `Debian-Security`), so it needs `Origins-Pattern` codename/label selection that
  the runner does not render. The runner likewise reports patch status
  `native_platform_unsupported` and fails patch-now runs.
- Release upgrade is gated: Debian has no unattended release upgrader (its
  documented path is a manual sources rewrite and `apt full-upgrade`), and the
  lane drives only `do-release-upgrade`. Debian 13 has no released successor.
- Security-tracker source records and no-DSA policy cannot establish complete clean
  binary-package coverage without native applicability/source mapping and freshness.
