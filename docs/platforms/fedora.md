# Fedora

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Fedora 43                                                                                               | Fedora 44                                 |
| ----------------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| inventory         | implemented                                                                                             | implemented                               |
| lifecycle         | implemented                                                                                             | implemented                               |
| dispatch          | implemented                                                                                             | implemented                               |
| packages          | implemented                                                                                             | implemented                               |
| accounts          | implemented                                                                                             | implemented                               |
| sysctl            | implemented                                                                                             | implemented                               |
| definitions       | implemented                                                                                             | implemented                               |
| password          | gated: libpwquality/PAM/manager versions not measured on this release                                   | implemented                               |
| firewall          | implemented                                                                                             | implemented                               |
| encryption        | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                               |
| wipe              | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                               |
| report-loss       | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                               |
| lock              | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                               |
| recovery-sanitize | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                               |
| self-update       | implemented                                                                                             | implemented                               |
| assistance        | gated: no maintained encrypted installer, native action prerequisites or graphical golden               | implemented                               |
| advisories        | implemented                                                                                             | implemented                               |
| os-update         | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release | implemented                               |
| release-upgrade   | gated: release upgrade is not implemented                                                               | gated: release upgrade is not implemented |

<!-- END GENERATED platform-capabilities -->

This page covers mutable Fedora, not Silverblue or Kinoite. Fedora 43 and 44,
x86_64 desktop/server and aarch64 server are qualification targets, not blanket
support claims. [Verification](../verification.md#1-launch-platform-qualification)
is authoritative: no complete matrix cell is certified. A cloud-server result
neither qualifies Workstation/KDE nor another architecture.

The pinned Fedora 43 Cloud Base Generic 43-1.6 input, exact size, digest and signer
are in [`lab/images/fedora-43-x86_64.json:2-17`](../../lab/images/fedora-43-x86_64.json#L2-L17).
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
  device. The executor keeps `PrivateDevices` and exposes only `/dev/tpmrm0`;
  `grub2-editenv` runs in a separate short-lived unit allowed that exact device.
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

### OS update policy (`os.update.v1`)

Fedora 44 uses `dnf5 automatic` under the same lindm window timer, runner and
release model as [Ubuntu](ubuntu.md#os-update-policy-osupdatev1). Prerequisites
are `dnf5-plugin-automatic` and `dnf5-plugins` (for `dnf5 needs-restarting`).
`dnf5 automatic` accepts no configuration path. It reads
`/usr/share/dnf5/dnf5-plugins/automatic.conf`, then
`/etc/dnf/dnf5-plugins/automatic.conf`, then `/etc/dnf/automatic.conf`, and later
files win per key. The policy therefore owns the `%ghost`
`/etc/dnf/automatic.conf` in place of the APT override. Its content is
`upgrade_type = security|default`, `random_sleep = 0`, download and apply `yes`,
`reboot = never` and `emit_via = stdio`. An existing unowned file, or an enabled
or active `dnf5-automatic*.timer`/`dnf-automatic*.timer`, is refused before any
effect; the provider never disables native units it does not own.

A window run calls `dnf5 -q makecache --refresh`. It lists pending updates with
`dnf5 --cacheonly repoquery --upgrades --latest-limit=1 [--security]`; security
means the repository's updateinfo advisory type. It then folds the three
automatic configuration files in dnf5's order and refuses a mismatch as `FAILED`
`dnf5_automatic_config_mismatch`. Finally it runs
`dnf5 [--exclude=name.arch …] automatic --installupdates`. Global `--exclude`
appends to `excludepkgs` and reaches automatic's upgrade goal. Patch now cannot
pass its own selection to `dnf5 automatic`, so it uses the same native solver
directly: `dnf5 --assumeyes upgrade [--security]`. The reboot oracle is
`dnf5 -q --disable-repo=* needs-restarting -r`. With repositories enabled,
`needs-restarting` also loads filelists and updateinfo, and fails cache-only
when filelists were never downloaded. Disabling them keeps the verdict on
installed core packages (kernel, glibc, systemd, dbus, linux-firmware and
configured extras). Reboot hints that only repository advisories carry are not
consulted. Missing cached metadata in the offline status reports
`native_metadata_unavailable`.
[Verification](../verification.md#os-update-policy-patch-now-and-patch-status)
records the native runs with SELinux enforcing.

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
autologin session).

The executor serves `/run/lindm-session/session.sock` only when
`/etc/lindm/executor.json` sets `remote_assistance.enabled`. The packaged default
is disabled. The tmpfiles directory is `root:root` 0755.

The RPM declares these as weak `Recommends`, not hard dependencies, so server
installs stay lean:

- `pipewire-gstreamer`, which provides `pipewiresrc`.
- `gstreamer1-plugins-good`, which provides `vp8enc`, `rtpvp8pay` and
  `rtpstreampay`.
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
token. Not qualified: aarch64 Secure Boot, KDE Plasma spin, X11, Fedora 43,
Atomic desktops, physical displays and multi-user seats.

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
