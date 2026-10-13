# Fedora

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability           | Fedora 43                                                                                                                                                               | Fedora 44                                                                                                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| inventory            | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| lifecycle            | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| dispatch             | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| packages             | gated: Fedora 43 ships dnf5 5.2.18.0; the package provider requires 5.4.6.0 to store a transaction without privileges                                                   | implemented                                                                                                                                                             |
| accounts             | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| sysctl               | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| definitions          | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| password             | gated: libpwquality/PAM/manager versions not measured on this release                                                                                                   | implemented                                                                                                                                                             |
| firewall             | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| encryption           | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| wipe                 | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| report-loss          | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| lock                 | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| recovery-sanitize    | implemented; gated on aarch64: the vendor aarch64 kernel has no Authenticode signature, so shim refuses it under the Secure Boot that original-device recovery requires | implemented; gated on aarch64: the vendor aarch64 kernel has no Authenticode signature, so shim refuses it under the Secure Boot that original-device recovery requires |
| self-update          | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| assistance           | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| assistance-clipboard | gated: not implemented for Fedora 43                                                                                                                                    | implemented                                                                                                                                                             |
| assistance-keyboard  | gated: not implemented for Fedora 43                                                                                                                                    | implemented                                                                                                                                                             |
| assistance-displays  | gated: not implemented for Fedora 43                                                                                                                                    | implemented                                                                                                                                                             |
| assistance-messages  | gated: not implemented for Fedora 43                                                                                                                                    | implemented                                                                                                                                                             |
| advisories           | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| os-update            | implemented                                                                                                                                                             | implemented                                                                                                                                                             |
| release-upgrade      | gated: release upgrade is not implemented                                                                                                                               | gated: release upgrade is not implemented                                                                                                                               |

<!-- END GENERATED platform-capabilities -->

This page covers mutable Fedora, not Silverblue or Kinoite. Fedora 43 and 44,
x86_64 desktop/server and aarch64 server are qualification targets, not blanket
support claims. [Verification](../verification.md#1-launch-platform-qualification)
is authoritative: no complete matrix cell is certified. A cloud-server result
neither qualifies Workstation/KDE nor another architecture.

The pinned Fedora 43 Cloud Base Generic 43-1.6 inputs, exact size, digest and signer
are in [`lab/images/fedora-43-x86_64.json:2-17`](../../lab/images/fedora-43-x86_64.json#L2-L17)
and [`lab/images/fedora-43-aarch64.json:2-17`](../../lab/images/fedora-43-aarch64.json#L2-L17)
(both CHECKSUM files clearsigned by the Fedora 43 key `C6E7F081CF80E13146676E88829B606631645531`).
The encrypted-installer and Kickstart lanes boot the signed Fedora 43 Server DVD
43-1.6, pinned in [`lab/images/fedora-43-encrypted-x86_64.json`](../../lab/images/fedora-43-encrypted-x86_64.json)
and [`lab/images/fedora-43-encrypted-aarch64.json`](../../lab/images/fedora-43-encrypted-aarch64.json)
(same key); the installed root adds packages from the signed `releases/43/Everything`
tree, as on Fedora 44.
Fedora 44 encrypted Server with added GNOME packages is a distinct installation,
not proof of the stock Workstation installer.

## Packaging, signing, repositories, paths and LSM

Choose mutable Fedora in the console's enrollment dialog and run the single
install-and-enroll command. It obtains the agent only from the customer's own
`lindmd` HTTPS `/repo/rpm` endpoint, authenticates the signer and server/bootstrap
trust, then uses DNF with both package and repository signature checks enabled.
Missing artifacts or architecture coverage have an explicit server setup remedy.
See the [install runbook](../security-and-operations.md#enrollment-installation-from-your-server).
Fedora Atomic is separately gated; a mutable DNF install is not an rpm-ostree
deployment or evidence for another Fedora release.

For unattended installs, a provisioning token offers **cloud-init** (Fedora Cloud)
and **Kickstart** (Anaconda). The Kickstart `%post --erroronfail` installs the agent
in the target chroot over the installer's network and only enables units; a
missing network or failed signature check fails the installation. The snippet
restores SELinux labels of `/etc/lindm` and its unit and runs no script from `/etc`,
so the first boot stays Enforcing. Anaconda keeps the profile, with the token, in
`/root/anaconda-ks.cfg` and `/root/original-ks.cfg`; delete them after enrollment.
Fedora 44 aarch64 passed both formats end to end
([installer provisioning](../verification.md#installer-provisioning-from-the-console-2026-10-12)).
Fedora 43 aarch64 also passed both on `dgx20`: cloud-init from Cloud Base 43-1.6
(`$HOME/.cache/lindm-matrix/fedora-prov4-arm-20261012T175625Z/fedora-43/provision-cloud-init-aarch64.json`,
SHA-256 `25458939f96597b77a0d2255e418c25e34406717a2c6fd90819cbcb805bee15e`) and
Kickstart from the Server DVD 43-1.6
(`$HOME/.cache/lindm-matrix/fedora-prov6-arm-20261012T183959Z/fedora-43/provision-kickstart-aarch64.json`,
SHA-256 `b76ffe7657afa4e59590472614bec07f3a46c41512733546d671af2a7b7be848`);
each ended Enrolled after independent approval with `lindm-provision.service`
successful and the token removed. On x86_64 local KVM all four cells passed the
same way, in `$HOME/.cache/lindm-matrix/fedora-prov6-x86-20261012T184712Z/`:
Fedora 43 cloud-init (`fedora-43/provision-cloud-init-x86_64.json`, SHA-256
`aab2f6ce694a268b4e02d0d47b08cb31fb4af58ab4622c6512ce279596c38970`) and Kickstart
(`fedora-43/provision-kickstart-x86_64.json`, SHA-256
`43d53060ae2142b92584fcfd564a46b47b8db11d69b3991f41e62c21c98258c4`), Fedora 44
cloud-init (`fedora-44/provision-cloud-init-x86_64.json`, SHA-256
`0383f96d97578dca8aa588cafc68f0663733733cde7ff3feb183718a23f652a6`) and Kickstart
(`fedora-44/provision-kickstart-x86_64.json`, SHA-256
`ef1a956abce79ea465e9b07f16fa96a4ae49bbe8842bcd40563373852e41e6d0`).

Use native signed RPM delivery. The builder signs and independently verifies the
RPM before publishing its digest
([`internal/packaging/rpm.go:50-79`](../../internal/packaging/rpm.go#L50-L79)).
Configuration uses RPM `%config(noreplace)` and lifecycle scriptlets
([`rpm.go:83-112`](../../internal/packaging/rpm.go#L83-L112)). Repository generation
retains package/local-package checks and records whether metadata is signed;
do not describe an unsigned repository as authenticated
([`publish.go:43-58`](../../internal/packaging/publish.go#L43-L58)).

The binary is `/usr/libexec/lindm/lindm-agent`; protected configuration is
`/etc/lindm/executor.json`, network configuration `/etc/lindm/agent.json`.
State is separated between `/var/lib/lindm/executor` and `/var/lib/lindm/agent`.
Keep SELinux Enforcing. The native Fedora update evidence below retained it;
disabling SELinux to make a lane work invalidates that qualification.

## Agent services and sandbox

[`lindm-executor.service:10-61`](../../internal/packaging/assets/lindm-executor.service#L10-L61)
runs root with AF_UNIX only, strict filesystem protection, private devices,
no-new-privileges, no core dumps and no swap. Exact action targets require the
owned `action-sandbox -install` drop-in; do not disable PrivateDevices or expose
all disks. [`lindm-agent.service:11-50`](../../internal/packaging/assets/lindm-agent.service#L11-L50)
runs as `lindm`, has no capabilities, owns network transport and cannot read root
executor state. Service start limits remain part of the installed contract.

The executor starts the root `inventory-observe` helper as a transient unit over
PID 1's private socket `/run/systemd/private` and passes its output pipes directly
to PID 1 ([`root_inventory_systemd_linux.go`](../../internal/agent/executor/root_inventory_systemd_linux.go)).
It previously executed `systemd-run --pipe --wait`, which uses the system bus and
passes its stdio descriptors through the broker. On Fedora 44 (systemd
`259.5-1.fc44`, selinux-policy-targeted `43.3-1.fc44`, Enforcing) dbus-broker is
denied writing the executor's pipe. The denial is `dontaudit`ed and appears only
after `semodule -DB`:
`avc: denied { write } for comm="dbus-broker" path="pipe:[17498]"
scontext=system_u:system_r:system_dbusd_t:s0-s0:c0.c1023
tcontext=system_u:system_r:unconfined_service_t:s0 tclass=fifo_file permissive=0`.
The broker drops the connection and the executor journal records
`stage=run ... exit_status=1 diagnostic="Failed to start transient service unit:
Connection reset by peer"`. An unsandboxed `unconfined_service_t` unit failed the
same way, so the executor sandbox was not the cause. Every published host
observation then carried storage `UNAVAILABLE` with
`recovery_readiness_executor_unavailable`. Do not relabel the executor, add a policy
module or disable SELinux: the direct PID 1 connection needs no broker permission.
Ubuntu 24.04 (AppArmor) was unaffected and passes with the same launcher. The
executor logs every readiness failure as `recovery readiness observation failed`
with its stage, unit, systemd job/unit result, exit status and bounded helper
stderr. Evidence and record digests are in
[verification](../verification.md#customer-journey-release-acceptance).

The private socket has its own race. sd-bus reads authentication greedily, so a
busy PID 1 can read BEGIN together with the client's first call. Package
installation, `systemctl enable --now`, daemon-reload or a policy load all made
PID 1 busy enough. A first call that carries descriptors is then rejected with
the connection (`start transient unit: read unix @->/run/systemd/private: recvmsg:
connection reset by peer`). A call without descriptors stays unparsed until more
bytes arrive. Fedora 44 x86_64 release acceptance failed on the reset. The
executor now sends descriptor-free `Peer.Ping` calls and repeats each unanswered
one, which wakes PID 1, before it passes any descriptor. A stop after a lost
connection uses a new connection. Readiness also ignores the `UnitRemoved`
signals that daemon-reload sends for still-running units. No AVC accompanied
either failure.

### Fedora 43 Cloud: group-writable `/`

The agent runs a native tool only when every directory from `/` to the tool is
owned by root and writable by neither group nor other
([`nativeexec.Executable`](../../internal/agent/nativeexec/exec_linux.go),
[`custody.RootProtected`](../../internal/custody/open_linux.go)). The signed
Fedora Cloud Base Generic 43-1.6 images (x86_64 `846574c8…`, aarch64
`66031aea…`) ship `/` as `root:root 0775`; the `filesystem` package records
`dr-xr-xr-x` (0555), and Fedora 44 1.7 ships 0755. On a stock Fedora 43 cloud
machine the agent therefore refuses `rpm`, `dnf5`, `lsblk`, `ip`, `busctl` and
every other tool: inventory fields report a native command failure, and resource
and update actions fail. The custody check is not relaxed for group root.

Inventory reports the condition as `NativeDetails.tool_custody` (path, owner,
mode). The device page shows it with the remedy, labels every refused field
"Refused: / is writable by group or other", and a resource refused before any
tool runs carries `RESOURCE_ADMISSION_REFUSAL_REASON_UNSAFE_NATIVE_TOOL_PATH`
(server reason `native_tool_path_unprotected`). Until 2026-10-12 the signed
record and status schemas omitted that reason, so the refusal failed validation
and was retried as an internal error; it is now admitted (deterministic test
`TestResourceAdmissionRefusalIsDurableAuthenticatedAndNeverAnEffect/unsafe-tool-path`,
not yet re-run on a stock Fedora 43 cloud image). The remedy, as root, is
`rpm --restore filesystem` (RPM 6's name for `--setperms`; restores the packaged 0555) or `chmod go-w /`; the
next inventory clears the alert.

Lab lanes on Fedora 43 run the registry's `Lab.RootPermissionsRepair`
(`rpm --restore filesystem`) once, as the first cloud-init `bootcmd` of the first
boot (`cloud-init-per once`), before the agent is installed; later boots, such as
interrupted-update recovery, do not take the RPM transaction lock again.
`enroll-from-console` keeps the vendor mode, as a customer's stock image would,
and passes only when the console shows the alert with both remedies for the
exact enrolled device.

Fedora 43 carries dnf5 5.2.18.0 in both its release and updates repositories.
The package resource provider requires 5.4.6.0 (see the
[DNF5 floor](#capability-policy-facts-signed-provider-grants)), so `packages` is
gated on Fedora 43: the native
resources record failed preparation with `native dnf5 5.4.6.0 or newer required`.
OS update policy (`os.update.v1`) runs dnf5 itself and is qualified.

Fedora 43's shadow-utils 4.18.0 labels files written under `--prefix` by the
prefixed path. With the account helper's private `account-root/etc` bind of
`/etc`, a `useradd` left `/etc/passwd`, `/etc/shadow`, `/etc/group` and
`/etc/gshadow` as `system_u:object_r:var_lib_t:s0`; sudo then failed with
`PAM account management error: User not known to the underlying authentication
module` for every local user, including the lab account (observed on
`fedora-cloud-43-1.6-aarch64`, SELinux Enforcing). Fedora 43 therefore uses the
chroot account root (`Quirks.AccountChroot`, `--root`) like EL 9/10, which writes
the databases at their `/etc` paths. Fedora 44's 4.19.0 is unaffected.

## Inventory and per-field quirks

Installed packages come from `rpm --query --all`, including epoch, version,
release, architecture and modularity label; DNF CLI output is not the installed
package oracle. Exact OS identity and a real RPM database are required. Unknown
Fedora variants and OSTree/transactional markers are rejected by the mutable
selector ([`packages_linux.go:46-85`](../../internal/agent/inventory/packages_linux.go#L46-L85)).
A native warning is not an empty successful inventory
([`packages_linux.go:148-152`](../../internal/agent/inventory/packages_linux.go#L148-L152)).

Fedora switched its default CLI to DNF5 in Fedora 41
([Fedora 41 change](https://fedoraproject.org/wiki/Changes/SwitchToDnf5)).
DNF4 Python configuration APIs are not evidence of DNF5 repository state; both
Python bindings are installed in the captured Fedora 44 Cloud image. The
[`dnf` identity helper](../../internal/agent/dnf/manager.go) selects installed
executables and parses their native version, independently of the distribution.
The [inventory probe](../../internal/agent/inventory/platform_dnf.py) then uses
supported `libdnf5` bindings for DNF5 configuration without plugins, repository
metadata or network access. An unset optional native `OptionString` must be tested
with `empty()` before reading its value; it is not a failed repository observation.

The native API capture in
[`testdata/dnf5-fedora44`](../../internal/agent/inventory/testdata/dnf5-fedora44)
comes from untouched Fedora 44 Cloud 44-1.7 aarch64 under KVM: DNF5, libdnf5 and
python3-libdnf5 `5.4.1.0-1.fc44`, Python `3.14.3-2.fc44`. The reference source is
[DNF5 5.4.1.0](https://github.com/rpm-software-management/dnf5/tree/d413edbb78a9160274b80c8ec23ac9b1c69073fe),
cloned at `~/dev/minor/clones/linux-flavour/dnf5`.

Enabled repository evidence includes IDs, base URLs, metalink/mirrorlist, package
signature-check setting and signing-key locations. URL userinfo, whole queries
and fragments are omitted and marked `urls_redacted`, not leaked as inventory.
Effective releasever is distinct from an explicit configured releasever lock;
neither repository configuration nor releasever proves entitled/reachable content.
CPE stays independent os-release evidence. Native RPM `MODULARITYLABEL` continues
to report per-package module/stream identities. The supported config-only DNF5
API does not enumerate persisted enabled/disabled module states; never report a
successful empty module-state list from an unloaded metadata sack. `dnf5 module
list --json` is unsupported in the captured version.

ARM `/proc/cpuinfo` commonly lacks `model name`. The
[CPU model collector](../../internal/agent/inventory/cpu_model_linux.go) prefers
populated SMBIOS type-4 processor-version evidence, read by the protected executor,
then decodes native procfs/sysfs MIDR implementer/part. Model source is explicit.
Its small ARM-name table is based on
[util-linux v2.41](https://github.com/util-linux/util-linux/blob/caa26876bc75041833c9644491cc2670d623f750/sys-utils/lscpu-arm.c);
unlisted pairs produce exact `ARM implementer 0x.. part 0x...` labels, not a guessed
brand or unavailable observation. x86 keeps native procfs model identity.
The real dgx20 Fedora44 guest
[CPU fixtures](../../internal/agent/inventory/testdata/cpu-fedora44-aarch64)
contain QEMU SMBIOS processor version `virt-8.2`, which correctly takes precedence
over MIDR `0x41/0xd85` (`Cortex-X925`). This is virtual firmware identity, not a
claim that SMBIOS identifies the physical host's marketing CPU model.

Fedora44 logind has active user-manager sessions without seats. Captured native
[session fixtures](../../internal/agent/inventory/testdata/sessions-fedora44-aarch64)
show both `user/tty/Remote=yes` and `manager/unspecified/Remote=no`, each with an
empty seat. The [session collector](../../internal/agent/inventory/sessions_linux.go)
reports `NOT_APPLICABLE` only with successful per-session Class/Type/Remote evidence
of manager/background, remote or tty context. Local graphical user sessions with
missing seats still fail as `UNAVAILABLE`; malformed or failed reads are never
hidden by this classification. See the schema's `session.seat_applicability` rule,
not a distro-wide absence exception.
The independent `loginctl` oracle has table regressions for absent, empty and
populated seats across these contexts and incomplete context reads. It also replays
both retained Fedora44 sessions through the inventory-health check. These parser
regressions do not add native qualification beyond the recorded
[inventory evidence](../verification.md).

On this Cloud image, Btrfs uses the same device for `/` and `/var`.
The independent inventory oracle must read `lsblk MOUNTPOINTS`, not only the last
selected `MOUNTPOINT`; otherwise it loses root-backing ancestry. The agent already
preserves the complete native mount list and prefers `/` for its scalar display.

## Updates

Agent self-update is distinct from generic managed-package resources. Existing
self-update verifies the installed native RPM identity and refuses immutable
systems ([`update/native_linux.go:111-147`](../../internal/agent/update/native_linux.go#L111-L147)).
Fedora 44 unattended agent update passed signed hold/negative phases, interrupted
unpack, boot-helper completion, retained identity and downgrade refusal with
SELinux Enforcing. Evidence:
`$HOME/.cache/lindm-updatequal-20261010/fedora44-updates-06.json`, SHA-256
`ae15ffd9663b050455c4e46a313038dd3dfaf7f88320d231908c0a665b0841e6`.
This is QEMU/development-signing evidence, not historical release compatibility or
physical power-loss proof; see [verification](../verification.md).

The separately developed generic DNF5 package provider is not qualified by that
self-update result. Its pending strict stored/replayed transaction design requires
both signed repository metadata and signed RPMs, not a DNF4 alias fallback.
Official Fedora metadata may not satisfy that policy; qualification needs an
approved signed repository, never a signature-check bypass. Private-worktree
implementation is not a landed capability claim.

### Air-gapped offline bundles

Offline sites install from the bundle's per-architecture RPM repository served at
`https://SITE/offline/repositories/<amd64|arm64>/rpm/`. The lane writes one repo file
into a private `reposdir` (DNF5 accepts `--setopt=reposdir=`), with `gpgcheck=1`,
`repo_gpgcheck=1` (createrepo_c `repomd.xml.asc` signed by the station package key),
`gpgkey=file://` for the pinned key and `sslcacert` for the site CA; no Fedora mirror
is consulted. The advisory snapshot is the updates `repomd.xml`-referenced
`updateinfo.xml.zst`, verified against repomd at acquisition and recorded with both
URLs.

`lab vm airgap` passed on Fedora 44 x86_64 with SELinux Enforcing inside a no-route
namespace: `$HOME/.cache/lindm-airgap-20261011/records/fedora-44-r1.json`, SHA-256
`f7aa073c11240b3ba93cd069a36c1e114c4474576a855f107da508264a175f38`
([verification L16](../verification.md#3-acceptance-scenario-families)): install from
the site repository, enrollment, rejected expired/corrupt/forged/replayed bundles,
paused staging, audited update to 0.30.1 and advisory freshness advanced to the
second bundle's signed acquisition time. aarch64 RPM repositories are built but not
exercised.

## Encryption and recovery

Fedora 44 Server GNOME, TPM-capable dracut, Secure Boot on and software TPM2 passed
two passphrase cold boots and independent stopped-disk LUKS2 header comparison:
`artifacts/encrypted-fedora44-x86_64-secureboot-qualified-20261010.json`, SHA-256
`f8b5fe1c35c8cbb242628aa26d5760b9234e36ee5f3b6991b450d5b8209f9866`.
The later complete encryption run proved escrow/reveal, rotation and retired-key
rejection, crash recovery, TPM bind, PCR7 mismatch and revealed-key recovery:
`$HOME/.cache/lindm-encryptionqual-20261010/fedora44-encryption-11.json`, SHA-256
`33ae1246cc71ec97a83e7b7ccf319103d0fc46513cd089760155285ad9eb71a5`.
These x86_64 tuples do not qualify physical TPMs or ARM.

The separate [Fedora 44 aarch64 encryption and TPM record](../verification.md#fedora-44-aarch64-encryption-and-tpm)
passed the full product encryption lane on `dgx21` KVM: escrow/reveal, rotation,
retired-key rejection, interrupted-rotation recovery, signed TPM bind and
unattended cold boot, PCR7 mismatch and revealed-key recovery. It uses AAVMF
`2024.02-2ubuntu0.10`, swtpm2 and **Secure Boot not enforced** (SetupMode).
The vendor aarch64 installer kernel has no PE signature; the enrolled template
correctly rejects it. PCR7 binding on this explicitly approved non-Secure-Boot
tuple does not prove an authenticated boot chain or physical TPM security.
The assistance and TPM results are separate runs, not a single post-bind
assistance session.

The [persistent organization demo](../engineering.md#persistent-organization-demo)
uses this explicitly non-Secure-Boot aarch64 GNOME tuple for Finance, installs the
agent from the console's signed RPM repository, and performs the product TPM
action on its own retained encrypted overlay. It does not change firmware
security to obtain a pass or treat the demo as new platform qualification.

Fedora 43 (systemd 258, GNOME 49) uses the same Anaconda LUKS2/LVM recipe from
its own Server DVD. On aarch64 (`dgx20` KVM, AAVMF `2024.02-2ubuntu0.10`,
swtpm2, **Secure Boot not enforced**) the matrix `encrypted` cell passed
(`$HOME/.cache/lindm-matrix/fedora-act43-arm-20261012T140712Z/fedora-43/encrypted-aarch64.json`,
SHA-256 `1bfa7d95d4ecb54bdb7560fbcf2e46ca8c85f09a6d606d58989f2ee88f4684a3`)
and so did the live device-action cell (lock, quarantine, wipe and loss without
recovery; `device-actions-aarch64.json` in that directory, SHA-256
`ae7c067cb9fc8f27124cb4818d78ee4ea05218c62a6d2a755fa7243f21bc29c6`).
On x86_64 local KVM (OVMF, swtpm2) Fedora 43 passed the `encrypted` cell
(`$HOME/.cache/lindm-matrix/fedora-act43c-x86-20261012T214357Z/fedora-43/encrypted-x86_64.json`,
SHA-256 `f069272d649e3cd5f7ac760b3e95479480926b94404bba8cdad6cad229124164`), the
live device-action cell (`device-actions-x86_64.json` in that directory, SHA-256
`14362f944903fbabd8be70e55866dfd17b845810af7eeb3ff296cec060e8eca5`) and, with
Secure Boot enforced, 30 unattended TPM2 boots
(`$HOME/.cache/lindm-matrix/fedora-tpm2-x86-20261012T214357Z/fedora-43/tpm-unattended-boots-x86_64.json`,
SHA-256 `ececce4093e36982393a426ef190ee8ef3704faaa3290334ea3fd56281366dae`);
Fedora 44 passed the same TPM cell
(`fedora-44/tpm-unattended-boots-x86_64.json` in that directory, SHA-256
`0a67cc3d35441ae433fde5132ed2a42f364aa7d2a8d0c2ce19d63d26f4e2c647`).
Original-device recovery on Fedora 43 aarch64 is gated like Fedora 44: the
release kernel `kernel-core-6.17.1-300.fc43.aarch64` (RPM SHA-256
`9328e61443dcd71e5671806fbef4345eb15a988229b011340fac8b856315c3ee`) ships a
`vmlinuz` with an empty PE security directory, while the x86_64 kernel of the
same build carries a 1,896-byte Authenticode signature; under enforced Secure
Boot the encrypted golden never reached SSH
(`recovery-sanitize-aarch64.json` in that directory, SHA-256
`14531ff8ad37a620002d4647f6a3435f0ce672b296808828dc115c7d1985ecb0`).
On x86_64 (local KVM, OVMF Secure Boot enforced, swtpm2, NVMe) Fedora 43
measured-GRUB recovery sanitize passed after the direct NVMe sanitize ioctl
(9b4e6f5f):
`$HOME/.cache/lindm-matrix/fedora-act43-x86-20261012T140712Z/fedora-43/recovery-sanitize-x86_64.json`,
SHA-256 `a544f489e505e2d53905754a97cbae09c918491dd640f3660d6dd22a836d55df`.
The Secure Boot `tpm-unattended-boots` cell is gated on aarch64 for both Fedora
releases (registry `Lab.SecureBootUnavailableOn`): with the Microsoft template
enforced, neither Server DVD installer booted before the installer deadline
(`$HOME/.cache/lindm-matrix/fedora-tpm-arm-20261012T184633Z/fedora-43/tpm-unattended-boots-aarch64.json`,
SHA-256 `64238590dfa6dcac7b0daaa8053437a27012e30db9de4b7bccf5a3e2c650b904`;
`fedora-44/tpm-unattended-boots-aarch64.json`, SHA-256
`07fcc84bdf13e4d87a9208ac825ca6ae2c5d84a47b40b8ab5eb390937c8a669b`). TPM bind
and unattended cold boot without Secure Boot remain covered by the aarch64
`encrypted` cells.

Fedora dracut 108 separates the `systemd-cryptsetup` module from `crypt`
([`encrypted_installer_linux.go:205-213`](../../internal/vmlab/encrypted_installer_linux.go#L205-L213)).
Incorrect-passphrase diagnostics can stay in the initramfs journal without a
repeated serial prompt. The lab includes a disposable-clone service drop-in with
`dracut --force --include` to route those diagnostics to the console; a timeout
never counts as rejection
([`vm_device_actions_linux.go:133-139`](../../internal/vmlab/vm_device_actions_linux.go#L133-L139),
[systemd v259.5 source](https://github.com/systemd/systemd/blob/b3d8fc43e9cb531d958c17ef2cd93b374bc14e8a/src/cryptsetup/cryptsetup.c)).

The earlier **unsupported: ESP capacity** cell for the owned systemd-boot UKI
path was a property of that lab fixture, not of the stock ESP. The 100 MiB
vendor ESP has 82,089,984 bytes free; the UKI fixture first installs its own
signed ordinary UKI and systemd-boot there, leaving 14,888,960 bytes, less than
the 18,479,464-byte vendor kernel. Those records remain historical refusals under
`$HOME/.cache/lindm-recovery-time-20261010/`:

- `fedora-vendor-kernel-capacity.json`, SHA-256
  `71b98e75098a7fed49322457d7b644455117122ef39d97ff2e5b1e174c598eed`.
- `fedora44-recovery-sata-02.json`, SHA-256
  `90d08fb2c7ac139e520bdfd0087e62081fcbb2b25031510a5eca4cf6f26ca008`.
- `fedora44-recovery-nvme-02.json`, SHA-256
  `39ee001297527b4d1e762b5a93160956e2b75f6c0ac203dc38f29663f16420cb`.

A stock Fedora machine runs Microsoft-signed shim, Fedora-signed GRUB 2.12
(`bli` publishes `LoaderInfo=GRUB 2.12`) and has no deployment key in firmware
`db`, so it uses `RECOVERY_BOOT_MODE_MEASURED_GRUB` with the BLS flavor
([architecture](../architecture.md#measured-grub-recovery-recovery_boot_mode_measured_grub)).
Fedora specifics:

- `/boot` is the `boot` subvolume of the btrfs root. BLS entry paths are
  GRUB-relative (`/boot/vmlinuz-…`) and staging reuses the prefix GRUB measured.
- GRUB keeps its environment in the btrfs bootloader `env_block`
  (`env_block=512+1`); `grub2-editenv` writes it through the raw `/boot` block
  device. The executor keeps `PrivateDevices` and exposes only `/dev/tpmrm0`.
  `grub2-editenv` runs in a separate short-lived unit that is allowed that
  exact device. The unit runs without `NoNewPrivileges` so that Fedora's
  targeted policy can enter `bootloader_t`; with NNP, exec failed with status 203. Go PID 1 records `fedora44-mgrub-sata-x86-05.json` and
  `fedora44-mgrub-nvme-x86-02.json`/`-03.json` passed. Hashes are in
  [verification](../verification.md#measured-grub-recovery-on-stock-vendor-boot-chains).
  Fedora 44 aarch64 stays unsupported, because its vendor kernel is unsigned
  and shim rejects it.
- Fedora's `blscfg` sorts entries by RPM version comparison of the file name,
  so a `lindm-…` name would become the default when `saved_entry` is unset; the
  `~lindm-recovery-<action>` name sorts last. Observed: the vendor entry stayed
  default, `grub2-editenv - set next_entry=…` booted the entry once and GRUB
  cleared it.
- GRUB measures `grub_cmd:` and `kernel_cmdline:` text into PCR 8 and every
  file it loads (configs, BLS entries, kernel, initramfs) into PCR 9. The kernel
  EFI stub logs no separate initrd event. `/proc/cmdline` carries GRUB's
  `BOOT_IMAGE=` prefix, which is not part of the measured options.
- Fedora kernels build `tpm_tis`/`tpm_crb`, securityfs and IMA in; IMA's PCR 10
  is not quoted.

Without a TPM the device reports `recovery_readiness_tpm_attestation_unavailable`
and approval is refused. Native records are under
`$HOME/.cache/lindm-fedoragaps-20261011/` (Fedora Cloud 44-1.7 x86_64, KVM, OVMF
`2024.02-2ubuntu0.10` with Microsoft keys, Secure Boot enforced, swtpm 0.7.3):

- `fedora44-measured-sata-04.json`, SHA-256
  `5e05df3feabf4934117996e6d54c0fe31b0b287a3e8890b1cab8f37bdfeacaf0`: passed.
  Two humans approved; the vendor kernel booted the 30,023,469-byte lindm
  initramfs once from `/boot`; the server verified the quote before the grant;
  the whole 10 GiB SATA target was overwritten and three independent stopped-disk
  samples read zero. The vendor ESP was not changed.
- `fedora44-measured-nvme-01.json`, SHA-256
  `2171c51da9beb72c4ea630077062fc22d6691a49c38cc9bcf0d9fb53938eb0bc`: passed.
  The same path ran a native NVMe user-data format under the approved
  controller-serial/NSID scope with a 35,104,440-byte initramfs; the server
  verified the scoped result and stopped-disk samples read zero.
- `fedora44-measured-notpm-01.json`, SHA-256
  `65d25e3578b26a5199850ba0bd52bd8fb816a8cc8cf6f1a22504c49d7f8a435c`: passed
  refusal. A TPM-less guest reported the capability gate, two-human approval
  creation failed with `device_action_recovery_attestation_unavailable`, and no
  action, BLS entry, initramfs or one-shot existed.

Do not resize the ESP, delete vendor boot files or substitute a kernel. A TPM-less
machine needs the UKI path with an enrolled deployment key or external recovery.

## Resource providers

The agent executes only generic signed resource intents. The server dispatches
a kind only when its per-kind qualification table lists it with native Ubuntu
24.04 and Fedora 44 records (see
[verification](../verification.md#generic-resource-executor-cutover-phase-2)):
systemd services, native packages, managed files, local groups and users,
sysctl, systemd timers and drop-ins, password policy, encryption compliance, firewall zones and the
OS update policy are
dispatched; other kinds show
`resource_executor_not_available`. The Fedora 44 records are aarch64 cloud-image
guests with SELinux enforcing; new files get their label from `matchpathcon`,
and btrfs compression/copy-on-write file flags are storage details, not refused
special files.

Native mechanisms on Fedora: packages require DNF5 5.4.6.0 or newer (detected
by the shared [`dnf`](../../internal/agent/dnf/manager.go) helper; DNF4 and
older DNF5 releases, including the 5.4.1.0 in the 44 release image, are refused
because they cannot store a transaction from the read-only staging sandbox) in
asynchronously staged transient units, with an owned
`/etc/dnf/versionlock.toml` entry for exact versions. The approved repository's
signing key must already be imported into system RPM trust (`rpmkeys --import`);
RPM 6 signature output is matched by full key fingerprint. Package scriptlets
run under RPM's SELinux transition, so the apply unit does not set
`NoNewPrivileges=`. Password policy uses
authselect feature transactions; sysctl persistence is an
owned `/etc/sysctl.d/60-lindm-<sha256(key)>.conf`; local accounts use the shadow
tools against the exact host `/etc` bound into a private account root.
Firewall restoration and its rollback supervisor units ship disabled.

A package row without an architecture (`rpm/git`) follows `rpm --eval %{_arch}`
(`x86_64` or `aarch64`) and also matches an installed `noarch` package. DNF is
asked for the bare name, so its best-architecture choice never selects a multilib
sibling, and the owned versionlock entry binds only the EVR, so it holds every
installed architecture of that name. Unit coverage only: no native record exercises
a row without an architecture yet; see
[package identity](../engineering.md#native-package-resource-provider).

An installed package lindm did not install (one the image ships, or one
installed by hand) is acquired only if preparation proves its provenance. With the
metalink-authenticated metadata refreshed, `dnf5 repoquery --available` must
list the exact installed NEVRA in `fedora` or `updates`, and `dnf5 download`
fetches it into private staging scratch. The approved key must verify its
signature in the isolated keyring, its `SHA256HEADER` must equal the installed
header's (rpm keeps the installed header, which binds payload and file
digests), and `rpm --verify --nodeps --noscripts` must report no missing
non-config file and no size, digest or link-target change. `updates` keeps only
current builds, so a package the image installed and `updates` has since
superseded is `existing_package_unverified` until the device is updated. A
proven package is BLOCKED `existing_package` under create-only ownership.
Approved adoption pins it in `versionlock.toml` without a package transaction;
`RESTORE_OWNED` release removes only that entry. DNF5 stages nothing for a
request the installed package already satisfies: for a package installed
outside DNF (`rpm -i`, an image build) libdnf5 would resolve a "Reason Change"
to user-installed, which is DNF history rather than a package effect and which
lindm's resolver refuses as an unsafe action. The x86_64 connected package
lane qualifies the four adoption cases against an `rpm -i`-installed signed
fixture after the guest's DNF5 5.4.6.0 update
([records](../verification.md#native-package-approved-adoption)); DNF4 (EL)
has no proof, a stock 44 image still refuses package rows as
`native_tool_outdated` first, and aarch64 is not exercised.

The typed kernel-module blocklist needs the kernel-module blocklist device
capability (a signed capability policy) or the root executor's local
`fileProvider.kernelModuleBlocklist`. Fedora 44 uses native `modprobe` and
`dracut --regenerate-all --force`; both tools must be installed. While the stanza
exists, fixed `--include` arguments include that same path in generic as well as
host-only images. Release to an absent baseline omits that inclusion. The fixed
owned modprobe file retains the native SELinux label. The provider streams
gzip/zstd/newc images to check their embedded stanza and detects initramfs-only
drift even when the on-disk modprobe file matches. Loaded drivers remain pending
restart; built-in drivers are not applicable. No live driver is unloaded and
Fedora 43, Atomic and derivatives do not inherit this setting's qualification.
The native aarch64 KVM lane passed all ten scenarios with SELinux enforcing,
including reboot/load refusal, same-inode initramfs-only drift repair, built-in
`kvm` findings and release. See [receipts and limits](../verification.md#typed-kernel-module-blocklist).

SSH banner-only desired state uses the existing SSH resource model and reloads
`sshd.service`, never restarts or starts a service. It manages the fixed Banner
drop-in and `/etc/issue.net`; creation predicts the native SELinux file context
and atomic replacement preserves captured security attributes. The dedicated
[native lane](../verification.md#ssh-login-banner) checks `matchpathcon` and
SELinux enforcing alongside the fresh banner exchange, authenticated login,
automatic content drift repair and baseline/removal release cases. Existing
distribution includes (including the crypto-policy symlink and its root-protected
hardlinked target) are read, not rewritten or claimed as replaceable files.
The stock `/etc/issue.net` symlink is not adoptable: a native administrator must
prepare a regular notice file before explicit adoption. The disposable native lane
does this as an operator fixture, never by relaxing provider custody.
Authentication/listener controls remain unqualified; see
[ownership and prerequisites](../security-and-operations.md#ssh-login-banner).
The recorded aarch64 KVM lane passed all eleven cases with SELinux Enforcing,
including terminal pre-effect refusals for an unsafe Include alias and an empty
writable Include search directory. Protected vendor links remain supported.

Delivered password hashes (`HashedPasswordPolicy`) use `chpasswd --encrypted`
reading `name:hash` on stdin with `--prefix` (shadow-utils 4.14 and later).
With `-e`, Fedora's chpasswd accepts only `$y$`, `$2[abxy]$`, `$6$`, `$5$`, a `!`
prefix, `*` or an empty field and rejects lock markers such as `!!`, so lindm
restores pure lock markers with `usermod --password` and sends only real hashes
through chpasswd. Upstream source shows that `--prefix` skips SELinux
file-context handling, as `useradd`/`usermod --prefix` already do; the record
does not separately inspect the `/etc/shadow` label. Managed local-admin rotation runs
`/usr/sbin/chpasswd` in `/` with system PAM hashing and needs the
`action-sandbox` exception described in
[security and operations](../security-and-operations.md#managed-secrets-and-local-admin-passwords).
Both paths are qualified on Fedora 44 aarch64 with SELinux enforcing and SSH
password logins
([secret delivery and local-admin records](../verification.md#secret-delivered-password-hash-and-managed-local-admin-password)).

Local account adoption and refusals, sysctl reboot persistence and `net.*`
namespace scope, timer firing and the POSIX ACL refusal behave as on
[Ubuntu](ubuntu.md#resource-providers), with SELinux enforcing throughout. On
the image's btrfs root an access ACL is the `system.posix_acl_access` attribute
that the provider refuses to discard; other filesystems are not exercised.

Firewall zones use the same dedicated `inet lindm_z_<zone>` netlink table, root
provisioning, packaged guard/restore units, dedicated probe peer and static
probe targets as on [Ubuntu](ubuntu.md#resource-providers); dispatch follows the
server qualification table. The Fedora Cloud 44 aarch64 image does not install
firewalld; the coexistence lane installs and enables it (default zone `public`,
which then binds both NICs) before any zone exists and opens only the oracle
ports in that zone. Its `inet firewalld` table (base chains at priority
`filter + 10`, the same priority as the lindm zone; either order yields the same
verdict because both must accept) stays byte-identical, with handles, across
every lindm operation; `firewall-cmd --reload` recreates it without changing the
zone table's objects or handles, and a fresh verification converges. The real
quarantine action, the withheld reconciliation during quarantine, drift refusal
and the interrupted-apply recovery behave as on
[Ubuntu](ubuntu.md#resource-providers), here with SELinux enforcing
([verification](../verification.md#firewall-zone-create-restore-coexistence--two-guest-probe-lane)).
NetworkManager owns the data link (a
MAC-matched keyfile). SELinux stayed enforcing; the packaged guard, restore and
probe units needed no policy change. The 6.19 kernel needed the same two fixes
as Ubuntu (ptrace-gated `/proc/1/ns/net`, explicit boolean bitwise operation on
read-back).

### Capability policy facts (signed provider grants)

A signed capability policy names only catalogue capabilities; the agent derives
every provider setting from `internal/platform/registry.go`
([architecture](../architecture.md#capability-derivation)). Fedora 44 carries
these facts; Fedora 43 reports `platform_not_qualified` for PACKAGES (its gate)
and for every capability needing registry facts it lacks.

Fedora 43 stays gated rather than receiving vendor archive facts: its dnf5
cannot reach the 5.4.6.0 floor below. On 2026-10-12 the `f43` and `f43-updates`
repositories both carry `dnf5-5.2.18.0-5.fc43` (`mdapi.fedoraproject.org`), and
every Bodhi update of `dnf5` for F43 is a 5.2.x build (newest
`dnf5-5.2.18.0-5.fc43`, stable 2026-08-22); no 5.3 or 5.4 build was ever
submitted for F43.

| Capability                            | Fedora 44 derivation                                                                                                                                                                                                                            |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PACKAGES                              | repository `12e3a0eb-c710-58d9-bd79-a491c614754c` (`rpm/<uuid>`): native id `fedora` (`https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=<arch>`) plus additional repository `updates` (`…?repo=updates-released-f44&arch=<arch>`) |
| FILES                                 | `/etc/issue.d`, `/etc/motd.d`                                                                                                                                                                                                                   |
| KERNEL_MODULE_BLOCKLIST               | the typed template with `dracut` (see above)                                                                                                                                                                                                    |
| LOCAL_ACCOUNTS                        | home root `/home` (`f0047cfe-68c5-5850-a2b5-b9adc55d4f43`), UID/GID 1000–59999                                                                                                                                                                  |
| OS_UPDATES, FIREWALL, KERNEL_SETTINGS | as the local providers                                                                                                                                                                                                                          |

Account creation and home creation under `/home` behave as on
[Ubuntu](ubuntu.md#capability-policy-facts-signed-provider-grants).

Key: the regular file `/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary` (the
`-x86_64`/`-aarch64` names are symlinks to it and are not used), accepted
SHA-256 `93642aec521a1e5e96dd715f7ae0ec0850ebc9de09a94ce03cae5263f26cc18a`
(1672 bytes), primary-key fingerprint
`36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`. How it was obtained (2026-10-12):
`fedora-gpg-keys-44-1.noarch.rpm` (releases/44) and `-44-2` (updates/44) were
downloaded over HTTPS from `dl.fedoraproject.org`; both ship identical key
bytes, both packages' RSA/SHA256 header signatures verify with that key
(`rpmkeys -Kv`), and the fingerprint matches the one Fedora publishes at
`fedoraproject.org/security`. Other key bytes report `vendor_key_unrecognized`.

Fedora publishes no repository metadata signature: `repodata/repomd.xml.asc`
returned HTTP 404 for `releases/44/Everything/x86_64/os` and
`updates/44/Everything/x86_64` (2026-10-12). Approved RPM sources therefore
set `require_metadata_signature=false`, which the agent accepts only when every
repository of the source is an HTTPS metalink on the host the release pins
(`mirrors.fedoraproject.org`); a plain base URL without signed metadata is
always refused (config load, `checkSource` and the root helper). The generated
DNF configuration has one section per native id, `gpgcheck=1` always and
`repo_gpgcheck=0` only in this case; packages from either native id (or their
`@stored_transaction(<id>)` form) are accepted. The trust decision is recorded in
[security and operations](../security-and-operations.md#vendor-rpm-metadata-trust).

DNF5 floor: lindm stores the transaction from a staging unit whose `/usr` and
`/var` are read-only (`ProtectSystem=strict`). In DNF5 ≤ 5.4.2.1 `--store` counts
as a system-modifying command (`Context::Impl::cmd_requires_privileges`), so
DNF5 refuses with "/usr is configured to be read-only" before resolving and
takes a write lock on the system repository lock file (under
`/usr/lib/sysimage/libdnf5` in 5.4.1.0). 5.4.3.0 added "when storing a
transaction, system should not be modified" and takes a read lock; 5.4.2.1
moved the lock to `/var/lib/dnf`. No option bypasses the read-only check in
5.4.1.0, so the 44 release image's DNF5 cannot be used. The floor stays at the
natively qualified 5.4.6.0 (Fedora 44 updates); 5.4.3.0–5.4.5.0 were not
exercised. A stock Fedora 44 image refuses package rows with
`native_tool_outdated` until DNF5 is updated. The console's copy for that detail
says to apply all OS updates on the device once, and that a security-only policy
does not update dnf5. The OS update policy is the product
path for that. It needs only `dnf5` and `rpm` (see below), so it converges on the
stock image: Fedora-Server-dvd-aarch64-44-1.7 with the Workstation environment
has `dnf5 5.4.1.0` and `dnf5-plugins 5.4.1.0` but no `dnf5-plugin-automatic`.
Before this change the policy was refused there as `native_tool_missing`
([verification](../verification.md#out-of-box-capability-policy-two-desktop-demo-2026-10-12)).
A window run that installs all updates upgrades DNF5 to the current updates
build, and package rows prepared after that pass the floor.

A security-only policy does not raise DNF5. This includes the Company
baseline's `system` row. On 2026-10-12 Bodhi listed no Fedora 44 dnf5 update
after 5.4.1.0 (5.4.2.0 through 5.4.6.0) as a security advisory. The last
security advisory was for 5.4.0.0-2, which 5.4.1.0 already resolves.
`dnf5 upgrade --security` skips advisories the installed version resolves
(libdnf5 `filter_latest_unresolved_advisories`). Such a device needs one run
that installs all updates: either a policy with selection all, or patch now
with selection all where `allow_patch_now` is opted in. A package row already
recorded `native_tool_outdated` is dispatched again once the device commits a
package snapshot with changed content, such as the one after that run
([architecture](../architecture.md#server-issuance-of-capability-policies)). Native
verification of this stock-image path is pending: on 2026-10-12 the local KVM
host was busy with other lanes and the Sparks were down.

### OS update policy (`os.update.v1`)

Fedora 44 uses `dnf5 automatic` when `dnf5-plugin-automatic` is installed. It
runs under the same lindm window timer, runner and release model as
[Ubuntu](ubuntu.md#os-update-policy-osupdatev1). The only prerequisites are
`dnf5` and `rpm`. A stock Fedora 44 Workstation has no `dnf5-plugin-automatic`,
and may also lack `dnf5-plugins` (for `dnf5 needs-restarting`). The runner then
reaches the same transaction through `dnf5` itself and the same reboot verdict
through rpm (see below). The observed native version names
`dnf5-plugin-automatic` when it is installed, and `dnf5` otherwise. On the lab's
Fedora 44 x86_64 GNOME desktop (Fedora-Server-dvd-x86_64-44-1.7 with the
Workstation environment: `dnf5 5.4.1.0`, no `dnf5-plugin-automatic`) the policy
granted by the default OS_UPDATES capability converged, verified, with the owned
`/etc/dnf/automatic.conf` and timer; no window run was observed
([verification](../verification.md#out-of-box-capability-policy-two-desktop-demo-2026-10-12)).
`dnf5 automatic` accepts no configuration path. It reads
`/usr/share/dnf5/dnf5-plugins/automatic.conf`, then
`/etc/dnf/dnf5-plugins/automatic.conf`, then `/etc/dnf/automatic.conf`, and later
files win per key. The policy therefore owns the `%ghost`
`/etc/dnf/automatic.conf` in place of the APT override, with or without the
plugin, so installing the plugin later changes no owned state. Its content is
`upgrade_type = security|default`, `random_sleep = 0`, download and apply `yes`,
`reboot = never` and `emit_via = stdio`. An existing unowned file, or an enabled
or active `dnf5-automatic*.timer`/`dnf-automatic*.timer`, is refused before any
effect; the provider never disables native units it does not own.

A window run calls `dnf5 -q makecache --refresh`. It lists pending updates with
`dnf5 --cacheonly repoquery --upgrades --latest-limit=1 [--security]`; security
means the repository's updateinfo advisory type. With `dnf5-plugin-automatic`
installed, it then folds the three automatic configuration files in dnf5's order
and refuses a mismatch as `FAILED` `dnf5_automatic_config_mismatch`. Finally it
runs `dnf5 [--exclude=name.arch …] automatic --installupdates`.

Without the plugin, and for patch now, the run uses the same native solver goal
directly: `dnf5 [--exclude=name.arch …] --assumeyes upgrade [--security]`. Patch
now needs this path because it cannot pass its own selection to
`dnf5 automatic`. Automatic's `run()` and `upgrade --security` both build
`add_rpm_upgrade` with a security advisory filter (DNF5 5.4.1.0 source).
Global `--exclude` appends to `excludepkgs` and reaches either goal.

With `dnf5-plugins` installed, the reboot oracle is
`dnf5 -q --disable-repo=* needs-restarting -r`. With repositories enabled,
`needs-restarting` also loads filelists and updateinfo, and fails cache-only
when filelists were never downloaded. Disabling them keeps the verdict on
installed core packages. Reboot hints that only repository advisories carry are
not consulted.

Without `dnf5-plugins`, the runner computes that same rpmdb-only verdict itself
from `rpm -qa --qf '%{NAME}\t%{INSTALLTIME}\n'`. A reboot is required when one of
libdnf5's reboot-suggesting core packages was installed after boot. Those are
5.4.1.0's `CORE_PACKAGE_NAMES`: `kernel`, `kernel-core`, `kernel-PAE`,
`kernel-rt`, `kernel-smp`, `kernel-xen`, `linux-firmware`, `microcode_ctl`,
`dbus`, `dbus-broker`, `dbus-daemon`, `glibc`, `hal`, `systemd`, `udev`,
`gnutls` and `openssl-libs`. "After boot" means an install time later than the
boot second. The runner derives the boot second as `CLOCK_REALTIME` minus
`CLOCK_BOOTTIME`, the `/proc/stat` `btime` derivation. `needs-restarting`
prefers systemd's `UnitsLoadStartTimestamp` instead, which is later by the
early-boot seconds. Missing cached metadata in the offline status reports
`native_metadata_unavailable`.
[Verification](../verification.md#os-update-policy-patch-now-and-patch-status)
records the native runs with SELinux enforcing. Those runs had both plugins
installed, so the plugin-less path has not been verified natively yet.

Independent `rebootWindow` and bounded `employeeDeferral` use the same protected
runner state, logind scheduling and authenticated desktop-helper path described
for Ubuntu. DNF remains configured with `reboot = never`; it cannot bypass the
signed restart window. The executor's sandbox permits only the dedicated
`/var/lib/lindm/os-update` state directory in addition to its existing writable
paths. Fedora qualification must preserve enforcing SELinux and prove the actual
GNOME notification action, native schedule change and subsequent changed boot,
not inherit Ubuntu's desktop result. The dedicated `-reboot-policy` lane is
documented in [verification](../verification.md#independent-reboot-window-and-employee-deferral).

The 2026-10-11 Fedora 44 aarch64 GNOME 50/Wayland KVM run passed the signed
independent-window, actual employee deferral, executor-restart persistence and
scheduled-reboot scenarios, including mandatory fixture cleanup, with SELinux
Enforcing. The notification moved the owned restart from 20:33 to 20:38 UTC,
retained its 22:09:18 UTC deadline and removed the exhausted action; the accepted
native schedule produced a changed boot. Receipt SHA-256:
`9bce6605aa2b73e968d96e04fd8fb01b26191d2866e2c57d078c469ec25c6b14`.
The prerequisite reinstalled the exact vendor-authenticated
`kernel-core-6.19.10-300.fc44.aarch64` through DNF/RPM verification, without
changing its version or synthesizing a reboot marker. This used the maintained
non-Secure-Boot aarch64 firmware tuple, not the unsigned DVD kernel under
enforced Secure Boot. The linked verification record binds package signatures,
source, desktop captures and changed boot; physical input, suspend and real-clock
DST remain unqualified.

## Device actions

Encryption success does not imply power, desktop lock, account lock, quarantine
or sanitize success. Follow the per-action records in [verification](../verification.md#encryption-and-imperative-action-evidence-l10-l13-l15).
Fedora 44 ships nftables 1.1.6, whose JSON prints a `typeof` set's key as the
typeof expression rather than `integer`; the quarantine read-back accepts both
forms, so the real quarantine action no longer ends `OUTCOME_UNKNOWN` and rolls
itself back on Fedora. Quarantine admits loopback only from its `127.0.0.1`
endpoint, so the systemd-resolved stub's `127.0.0.53` replies are dropped while
quarantined.

The lock/release/account-disable/quarantine lane **passed** on the Fedora 44
encrypted GNOME golden (x86_64, KVM, OVMF Secure Boot, swtpm, virtio-scsi)
without product changes:
`$HOME/.cache/lindm-fedoragaps-20261011/fedora44-lock-quarantine-01.json`,
SHA-256 `50985538321bb481f9baa94dbc9864564a204116ddf3e7494a89d350443428da`.
A real GDM `gdm-autologin` Wayland session went from unlocked to logind
`LockedHint` and GNOME ScreenSaver active, and stayed locked after the signed
release. The password-enabled account was locked and expired, then restored
byte-for-byte; a second cycle preserved an intervening administrator expiry
edit. Two quarantine/release cycles blocked the namespace peer and routed host
endpoint while keeping the management endpoint and explicit DNS; kernel-timer
expiry restored traffic with agent and executor stopped. An offline start was
refused with `device_action_offline`. Not covered: physical displays, X11, KDE,
multi-user seats and aarch64.

The historical Fedora credential-helper SELinux denial used D-Bus forwarding of
an SSH-session FIFO; the corrected lab uses a no-swap/no-core scope without
relaxing policy. Failed record
`$HOME/.cache/lindm-wipequal-20261010/fedora-live-erase-02.json`, SHA-256
`14b3f2416533882ef77632d5cdf8fd4bf5ba2948dc6ebbdfe4ac3c0aa3c5a78e`,
is not erase proof. Later action records, not this historical failure or encryption
result, determine the current capability status.

Patch now behaves as on [Ubuntu](ubuntu.md#device-actions), except that the
Fedora run calls `dnf5 upgrade` instead of `dnf5 automatic` (see above).

## Desktop session helper and remote assistance

The package installs the user unit `/usr/lib/systemd/user/lindm-session.service`.
Configure runs `systemctl --global enable`, so the unit starts with
`graphical-session.target` at the next graphical login. The user manager reaches
that target in the GDM GNOME/Wayland session (observed active in the Fedora 44
autologin session). The package also installs the `%config(noreplace)` file
`/etc/xdg/autostart/lindm-session.desktop` for session managers that never
activate that target; GNOME's systemd-managed session skips it
(`X-systemd-skip=true`).

The executor serves `/run/lindm-session/session.sock` only when
`/etc/lindm/executor.json` sets `remote_assistance.enabled`. The packaged default
is disabled. The tmpfiles directory is `root:root` 0755.

The RPM declares these as weak `Recommends`, not hard dependencies, so server
installs stay lean:

- `pipewire-gstreamer`, which provides `pipewiresrc`.
- `gstreamer1-plugins-good`, which provides `imagefreeze`, `vp8enc`,
  `rtpvp8pay` and `rtpstreampay`.
- `gstreamer1`, which provides `gst-launch-1.0` (installed under `/usr/sbin` on
  Fedora 44; the helper resolves it through `PATH`).

The helper checks all eight elements with `gst-inspect-1.0`. If any is missing it
ends the session as `UNAVAILABLE` with detail `gst_element_missing:<name>`. There
is no X11 or screenshot fallback.

The Fedora 44 desktop golden used for qualification had these components:

- GNOME 50.0.
- xdg-desktop-portal 1.21.1 and xdg-desktop-portal-gnome 50.0, with ScreenCast v5
  (source types and cursor modes 7) and RemoteDesktop v2 (device types 7).
- GStreamer 1.28.1 (pipewire-gstreamer 1.6.2).
- gnome-shell notifications with the `actions` capability.

New assistance records also capture the installed `mutter` package version so
the compositor, portal and capture-stack tuple is explicit.

In the RemoteDesktop dialog, keyboard and pointer access is the **Allow Remote
Interaction** switch, which is off by default. Sharing without it grants view only.

On lock, the session ends `SESSION_LOCKED` through the same five-second
portal-close settle window used for GNOME 46.

The first login on the golden shows gnome-tour's welcome dialog and the overview,
and idle lock is enabled. The lab disables both for the session; the product does
not change them.

Held Fedora 44 assistance demos configure the registry's complete RPM
repomd/updateinfo exports for the guest's x86_64 or aarch64 architecture, with
online refresh and a one-day maximum age. The controller's persistent
`advisory-cache` revalidates vendor bytes before production publication. The demo
announces readiness only after the first refresh and a current, non-unknown
device evaluation, reporting real paginated finding counts. SSH-native hosts use
the workstation control plane and forwarded admin path described in the
[held-demo instructions](../engineering.md); `-colocated` retains host-local
placement. Feed support does not qualify an ARM graphical desktop.

Qualified: emulated x86_64 GNOME/Wayland consent, view, control, operator and local
stop, decline, portal cancel and lock termination, with audit, in
[`fedora44-assistance-03`](../verification.md#built-in-graphical-remote-assistance-l09-l12).
The same five scenarios also passed on aarch64 KVM on `dgx21`, with GNOME
Shell/Mutter 50.0, portal 1.21.1/portal-gnome 50.0, PipeWire 1.6.2 and
GStreamer 1.28.1, through colocated relay-only TURN (console over TCP):
[`fedora44-aarch64-assistance-03`](../verification.md#fedora-44-aarch64-gnome-assistance).
Its AAVMF `2024.02-2ubuntu0.10` tuple has **Secure Boot not enforced**,
SetupMode and swtpm2. The signed Fedora 44-1.7 aarch64 Server DVD contains an
unsigned installer kernel: enrolled AAVMF loads shim and GRUB, but GRUB rejects
the kernel with `bad shim signature`. This is not a missing firmware CA.
The linked evidence preserves that failure and vendor PE inspection; no key
enrollment, replacement kernel or capability-gate relaxation was used.
Assistance starts from a passphrase-unlocked encrypted clone, not a prebound TPM
token.

Fedora 43 GNOME 49 passed the matrix assistance cell on aarch64 KVM (`dgx20`,
same non-Secure-Boot AAVMF tuple): control, re-request, view, decline, portal
cancel and lock, with GNOME Shell/Mutter `49.1-1.fc43`, portal
`1.20.3-2.fc43`/portal-gnome `49.0-1.fc43`, PipeWire `1.4.8-2.fc43` and
GStreamer good `1.26.6-1.fc43`:
`$HOME/.cache/lindm-matrix/fedora-asst43-arm-20261012T175248Z/fedora-43/assistance-aarch64/assistance.json`,
SHA-256 `0f4b6fc35fed597846adeda036648e115f8dc02fea570747142a60ea47de6248`.
The same six scenarios passed on x86_64 local KVM with the x86_64 builds of those
packages:
`$HOME/.cache/lindm-matrix/fedora-act43b-x86-20261012T175315Z/fedora-43/assistance-x86_64/assistance.json`,
SHA-256 `d861375523fd28d22437027f069ef6015cf4863f39aff15df5469536d24e0c81`.
Not qualified: aarch64 Secure Boot, KDE Plasma spin, X11, Atomic desktops,
physical displays and multi-user seats.

### Commercial assistance capability roadmap

The [capability contract](../product-specification.md#remote-assistance-capabilities)
defines each user story, consent, off/limited/on policy, per-role permission and
audit. Fedora 44 GNOME 50 x86_64 Wayland is an initial target, not a completed
capability suite. Clipboard uses Clipboard on the existing RemoteDesktop session;
frontend, GNOME backend and Mutter support must be proven from the pinned sources
and actual session. No private compositor/root API or X11 clipboard fallback is
permitted. Fedora 43, Atomic, ARM and the Plasma spin need separate evidence.

[Pinned upstream inspection](../architecture.md#inspected-gnome-portal-sources)
finds Clipboard v1 support in portal 1.21.1, portal-gnome 50.0 and upstream
Mutter 50.0. Request Clipboard before RemoteDesktop Start and require the returned
`clipboard_enabled` grant. GNOME's separate **Allow Clipboard Access** switch can
deny it. The 50.0 backend normalizes Mutter's MIME tuple to the public array shape;
method acceptance still does not prove paste or successful peer receipt.
Record the actual Fedora `mutter` package and distro patches in new evidence,
rather than equating GNOME Shell 50.0 with exact Mutter provenance. FileChooser in
portal-gnome 50 delegates to Nautilus; record and qualify its installed version
for user-to-admin file selection.

Special keys/layouts require the RemoteDesktop keyboard grant. Multiple monitor
selection uses ScreenCast sources on that same session, selects only granted stream
IDs and binds pointer coordinates to the selected stream. Full screen/scaling are
browser presentation, not broader capture consent. Messages use the bound user's
GNOME notification service. File transfer remains off by default and separately
authorized, with Downloads/FileChooser, per-file consent, size/type limits and
hash audit. Reboot/logout reconnect needs fresh local/portal grants; recording
needs visible disclosure, encrypted storage and retention.

All added capabilities are
[not run](../verification.md#commercial-assistance-capability-qualification).
Qualify real clipboard nonces, shortcut/layout effects, two-head virtio-gpu
selection/pointer coordinates, visible message/file notifications, transfer hashes,
reboot/logout isolation and encrypted-recording retention on this exact tuple.
SELinux stays enforcing. Annotation/audio require separately qualified native
mechanisms; elevation leaves credential entry to the employee. Unattended
implementation and KDE qualification await parent confirmation; X11 is not a
silent fallback.

## Advisory feeds

Fedora uses repository **updateinfo**, not Red Hat CSAF/VEX. The adapter requires
`distro=fedora`, a supported explicit architecture and bounded compressed XML
([`advisory/feed/rpm.go:51-79`](../../internal/advisory/feed/rpm.go#L51-L79)).
Parser architecture acceptance is not machine qualification. Stale or absent feed
coverage must not become a clean exposure report.

Native `rpm --query --all` lists each imported signing key as a `gpg-pubkey`
record with no ARCH tag; inventory preserves it with an empty architecture,
matching the independent native oracle. Matching treats exactly that identity
(`manager=rpm`, `name=gpg-pubkey`, empty architecture) as a keyring entry, not a
package: it neither matches advisory records nor makes the device's
architecture coverage UNKNOWN
([`advisories.sql` `AdvisoryArchitectures`/`AdvisoryCandidates`](../../db/queries/advisory/advisories.sql)).
Before this rule every Fedora device in the 2026-10-10 release acceptance run
reported `package_architecture_uncovered`. Any other architecture-less package
still makes coverage UNKNOWN. This applies to every RPM distribution.

On 2026-10-10, complete current `updates/Everything` metadata for Fedora 43 and 44
was fetched separately for x86_64 and aarch64. Compressed SHA256 values matched
the corresponding primary-vendor `repomd.xml` over verified HTTPS; this is not a
Fedora signing-key verification. Counting distinct CVEs from structured references
plus exact tokens disclosed in summary/description, as the provider does, found:

| Release | Update entries per architecture | Eligible security advisories (x86_64 / aarch64) | Maximum CVEs per advisory | Advisory                 |
| ------- | ------------------------------- | ----------------------------------------------- | ------------------------- | ------------------------ |
| 43      | 4,382                           | 501 / 498                                       | 23                        | `FEDORA-2026-ec8e535c6e` |
| 44      | 3,114                           | 407 / 405                                       | 21                        | `FEDORA-2026-83fdfd7e0e` |

Eligibility requires stable security metadata, the exact release label and a
matching-architecture or `noarch` package. These are measured snapshot maxima,
not an all-time or future Fedora bound; testing, release media, other repositories
and removed historical advisories are outside the measured scope. Structured
references alone disclosed no CVEs in these security records, so omitting vendor
summary/description tokens would lose the measured CVEs.

The retained [measurement record](../../artifacts/rpm-advisory-cve-cardinality-20261010.json)
contains source URLs, acquisition timestamps, artifact sizes/digests, counts and
the extraction method. Its SHA256 is
`b3b78c5a21511a7a08fa96eede3b42d198cc2791dbb6bdd4948ca0e44b532085`.

## Lab

Use maintained `lab images fetch` and `lab images verify`, then the exact
`vm inspect`, `vm lifecycle`, `vm dispatch`, `vm updates` or encrypted/action lane
from [verification](../verification.md) and [agent enrollment](../agent-enrollment.md).
Record the image, binary/source digest, firmware, architecture, SELinux mode and
capability-specific result. Fedora 43 inventory matched 430 RPM records:
`$HOME/.cache/lindm-platformlanes-20261009/fedora43-inspect.json`, SHA-256
`3972591860a7edc1b876d4670880fb0ef13856904878bd6c08e281f32ab6e8ba`.
The subsequent service attempt failed on an out-of-date shared laboratory database,
not a demonstrated Fedora defect:
`fedora43-service-shared-schema-failure.json` in that directory, SHA-256
`926c6a14e0be040189b8f62c4a0871b1f338d3da10970fc74141007b9c8168b6`.
The corrected Fedora 43 signed-service lifecycle subsequently passed:
`fedora43-service-refreshed.json` in that directory, SHA-256
`0ba24f41374f177eef632a3905f0bd9563d6f8aa1d11bc914d3eccca35d21667`.
This x86_64 KVM/SeaBIOS/virtio-blk run retained SELinux Enforcing and restricted
user networking, matched five 432-package publications, and exercised signed
service effects, upgrade, reboot/reinstall retention, rejection cases, spool
recovery, revocation and missing-journal hold.

Fedora 43 automatic control-plane trust also passed with the same pinned
01495af+receipt-patch lab/server and 0.7.0→0.7.1 RPM pair:
`fedora43-trust-receipts.json` in that directory, SHA-256
`111ca61db75624529310d9622d5cbc417c924070260b9915af76e6e3a582a3e6`,
device `ba01d7b7-1042-4968-b8de-3b3d2cc6c6a4`, generation
`42e63e47-a1a3-4910-b59a-3168d12ab192`. SELinux remained Enforcing with
restricted user networking. Automatic authority rotation/revocation, rollback
denial, exact retry after restart, unchanged TLS, no service effects, and
reboot/reinstall retention passed alongside lifecycle recovery checks.
The separate connected-dispatch lane also passed:
`fedora43-dispatch-receipts.json`, SHA-256
`2a03eddaa60af6f1a921a24f9b3c73a678487e44a932d8e76c1c63c262db0e7b`,
device `80622c4c-727d-4530-8f1d-467a997059e1`, generation
`a4f6a110-9d3b-45ff-ae42-fc86f20357e0`. Same pinned source and binaries;
RPM SHA-256 `1346b0f3640a25a0b6df5e2808fc2bf918a75f260385b0563190fb640021cfac`.
SELinux remained Enforcing with restricted user networking. Nine native
scenarios cover signed convergence, periodic 300-second compliance without
a start grant, drift remediation, restart, ±90-second clocks and revocation.
Unstarted supersession is integration-only evidence, not native coverage.

The stock customer-journey gate is separate:
[`lab acceptance`](../verification.md#customer-journey-release-acceptance) leaves
vendor timers unchanged, uses signed native package installation and a provisioning
token issued through the real console. Its first x86_64 virtio-blk/no-WWN run
enrolled successfully but failed strict inventory on a seatless native logind
session with successful class `manager`, type `unspecified` and remote `false`.
The before/after native and agent observations agreed; matching `UNAVAILABLE`
alone was correctly not treated as success. Any not-applicable exception must
require that actual session-class context, not permit arbitrary missing seats.
The later profile phase was blocked by the harness's protected service-name prefix;
it did not prove a Fedora service-provider failure. Evidence:
`~/.cache/lindm-acceptance-20261010-01/acceptance.json`, SHA-256
`5ef007bd0cc52698432d4add4bcce2bfbc13754d70a78ebcaa605250543ba252`.
See [`acceptance_observation_linux.go`](../../internal/vmlab/acceptance_observation_linux.go)
and [`inventory_unavailable_linux.go`](../../internal/vmlab/inventory_unavailable_linux.go).

## Gaps

Full desktop/edition coverage, remaining aarch64 cells, physical TPM/media,
enforced Secure Boot on the pinned aarch64 media, and air-gap topology beyond
the x86_64 offline-bundle lane (site DNS/NTP/IdP, server install/restore from a bundle)
and production signing custody remain separate obligations. Fedora 43
inspection/signed-service lifecycle, Fedora 44 self-update and Fedora 44 encryption
cover different cells. DNF5 package
resource work is not qualified by any of them. Measured-BLS recovery is qualified
only with swtpm and the cloud image's btrfs `/boot`; physical TPMs, ext4/XFS
`/boot`, XBOOTLDR and Workstation installs are unqualified.
