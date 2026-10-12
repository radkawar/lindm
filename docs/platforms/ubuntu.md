# Ubuntu

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Ubuntu 22.04 LTS                                                                                                                                                                 | Ubuntu 24.04 LTS | Ubuntu 26.04 LTS                                                 |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ---------------------------------------------------------------- |
| inventory         | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| lifecycle         | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| dispatch          | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| packages          | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| accounts          | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| sysctl            | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| definitions       | gated: systemd 249 is below the definition provider floor 255                                                                                                                    | implemented      | implemented                                                      |
| password          | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| firewall          | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| encryption        | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| wipe              | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| report-loss       | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| lock              | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| recovery-sanitize | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| self-update       | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| assistance        | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| advisories        | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| os-update         | implemented                                                                                                                                                                      | implemented      | implemented                                                      |
| release-upgrade   | gated: 22.04→24.04 post-upgrade reconvergence is not implemented: after do-release-upgrade the owned sysctl fails its postcondition and the managed file is refused at admission | implemented      | gated: no successor release: the next Ubuntu LTS is not released |

<!-- END GENERATED platform-capabilities -->

[Verification](../verification.md#1-launch-platform-qualification) is authoritative for
qualification, including later evidence and failures. This page describes implementation
and narrowly identified observations, not general production readiness or all-resource support.
Ubuntu 24.04 and 26.04 LTS are required launch branches: official GNOME Desktop and
Server/minimal, x86_64 desktop/server and aarch64 server; Kubuntu/KDE needs separate
qualification. Ubuntu 22.04 is a separate legacy row. Ubuntu Core is not this platform.

Pinned cloud inputs are Noble 20260926 ([amd64](../../lab/images/ubuntu-noble-amd64.json#L1),
[arm64](../../lab/images/ubuntu-noble-arm64.json#L1)) and Resolute release-20260927
([amd64](../../lab/images/ubuntu-resolute-amd64.json#L1),
[arm64](../../lab/images/ubuntu-resolute-arm64.json#L1)). Release-20260927 is the
current Resolute cloud build after the 26.04.1 point release (2026-08-27); the amd64
image is generic amd64, not amd64v3. Image manifests bind exact vendor URL,
architecture, size, SHA-256 and the Ubuntu cloud-image signing fingerprint
`D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`. The 26.04.1 encrypted-installer input is
the official GNOME desktop ISO
([`ubuntu-26.04.1-desktop-amd64.iso`](../../lab/images/ubuntu-resolute-desktop-encrypted-amd64.json#L1),
SHA-256 `601e30fbf5d97759367c632e2c33630665039b7e2158fd068403da3ccf1bda1f`,
6,482,409,472 bytes), bound to the signed `releases.ubuntu.com/26.04.1/SHA256SUMS`
and the Ubuntu CD image key `843938DF228D22F7B3742BC0D94AA3F0EFE21092`, as the
Noble live-server manifests are. All three passed `lab images fetch` on 2026-10-11.
A verified image is an input, not a successful installation, desktop, encryption or
agent lifecycle result.

## Ubuntu 26.04.1 (Resolute Raccoon)

Every Ubuntu 24.04 lane has a native 26.04.1 record (air-gap bundle and console
enrollment through `lab matrix run` on both architectures), plus aarch64 desktop wipe, report-loss, lock and compliance
cells that 24.04 lacks; names, digests, commands and failed attempts are in
[verification](../verification.md#ubuntu-26041-parity-records-2026-10-11). Cloud
lanes ran on both architectures (local KVM x86_64, dgx20/dgx21 KVM aarch64 with
AAVMF); desktop lanes ran from the official amd64 desktop ISO on local KVM and from
the arm64 desktop ISO on dgx21 (AAVMF Secure Boot, swtpm, virtio-gpu). This is VM
evidence, not physical-machine or air-gap qualification.
The earlier `ubuntu26-trust-platform2.json`/`ubuntu26-dispatch-platform2.json`
records (release-20260927 amd64, before the resource-provider cutover) are
superseded by those records.

### Native deltas from 24.04

Observed from native dpkg inventories, read-only image inspection and lane behaviour
(the per-slice notes are referenced from verification):

| Area              | 26.04.1                                                                                                                                                                                                                                                                                                                                                          | Consequence                                                                                                                                                                                                                                |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Kernel            | Cloud image `linux-image-7.0.0-34-generic`; the desktop install and the release upgrade end on `7.0.0-38-generic` (security pocket); desktop ISO ships `7.0.0-30`                                                                                                                                                                                                | Larger vendor kernel (17.3 MB) feeds the recovery ESP budget below.                                                                                                                                                                        |
| systemd           | `259.5-0ubuntu3.4`, built `-UTMP` (Ubuntu `debian/rules`); a `Class=manager` logind session (`Service=systemd-user`) accompanies each user session                                                                                                                                                                                                               | Session oracles filter `Class=user`. Without utmp, SSH logins register in logind with an empty `TTY` ([LP 2168583](https://bugs.launchpad.net/bugs/2168583)), so `wall` (and logind's scheduled-shutdown wall) cannot reach SSH terminals. |
| Initramfs         | `dracut 110-11ubuntu0.1` is the default generator (non-hostonly; 72,091,068-byte cloud initrd vs 30,699,974 with 24.04's initramfs-tools); dracut ships the `update-initramfs` wrapper and splits `systemd-cryptsetup` out of `crypt`                                                                                                                            | Encrypted recipe must not install `cryptsetup-initramfs` (it would pull initramfs-tools and remove dracut); TPM recipe adds the `systemd-cryptsetup` module and `tpm2-tools`. Upgraded 24.04 systems keep initramfs-tools.                 |
| sudo              | `sudo-rs 0.2.13` is `/usr/bin/sudo` (`/etc/alternatives/sudo → /usr/lib/cargo/bin/sudo`); GNU `sudo 1.9.17p2` remains installed                                                                                                                                                                                                                                  | Every lane drives the guest with `sudo -n …`/`sudo -n -u USER …`/`/etc/sudoers.d` NOPASSWD; all passed unchanged.                                                                                                                          |
| coreutils         | `coreutils-from-uutils` → `rust-coreutils 0.10.0` (0.8.0 on the desktop ISO); `cp`/`mv`/`rm` stay GNU (`gnucp`…), `gnu-coreutils 9.7` installed alongside                                                                                                                                                                                                        | No lane or product change; `install -o/-g/-m`, `stat`, `sha256sum`, `timeout`, `date -u` behaved identically.                                                                                                                              |
| APT/dpkg          | `apt 3.2.0`, `dpkg 1.23.7ubuntu1`; images ship `gpgv 2.4.8` and no `sqv`                                                                                                                                                                                                                                                                                         | APT verifies with gpgv. APT 3/OpenSSL requires TLS `close_notify` from HTTPS repositories (lab fixture fixed). Self-update staging semantics are unchanged from 2.8.3 ([Updates](#updates)).                                               |
| Shadow/PAM        | `passwd 1:4.17.4`, `login` from util-linux 2.41.3, `libpam-modules 1.7.0-5ubuntu3.2`, `libpwquality 1.4.5-5build1`, PAM manager `pam-auth-update`                                                                                                                                                                                                                | Password pins in the registry row; the account helper's `--prefix`/`--root` probe selects tooling, no code change.                                                                                                                         |
| Firewall          | `ufw 0.36.2` on `iptables 1.8.11` (nft), `nftables 1.1.6`                                                                                                                                                                                                                                                                                                        | Coexistence unchanged: UFW's `ip`/`ip6 filter` tables stay byte-identical across zone operations.                                                                                                                                          |
| GNOME             | `gnome-shell 50.1`, `gdm3 50.1`, `libmutter-18-0`/`mutter-common 50.1`, Wayland only (no `xsessions`), terminal **Ptyxis 50.1** (no gnome-terminal), `xdg-desktop-portal 1.21.1`/`-gnome 50.0` (ScreenCast v5, RemoteDesktop v2), PipeWire 1.6.2, GStreamer 1.28.2; new user unit `gnome-initial-setup-upgrade-login.service` ("Welcome to Ubuntu 26.04.1 LTS!") | Registry `Lab.Session` selects Ptyxis, records `libmutter-18-0` and pre-creates `~/.config/gnome-initial-setup/upgrade-26.04-done` in disposable lab users only. Portal dialogs, wording and geometry are unchanged from GNOME 46.         |
| Desktop installer | `ubuntu-desktop-bootstrap` snap rev 665 (Flutter UI, subiquity backend); one `Try or Install Ubuntu` GRUB entry; system and GNOME come from on-media squashfs layers; optional "enhanced-secureboot" (core-boot, snapd-sealed TPM FDE) source variation                                                                                                          | The lab seeds subiquity autoinstall through nocloud on the media; no network packages. The core-boot TPM FDE is not used: lindm manages systemd-cryptenroll TPM2 tokens on LUKS2 with the vendor GRUB chain, not snapd-sealed keys.        |
| Other             | `openssh 1:10.2p1`, `openssl 3.5.5`, `cloud-init 26.1`, `snapd 2.76.3`, `apparmor 5.0.2`, `chrony 4.8`, `shim-signed 1.59+15.8`, GRUB 2.14, `ubuntu-release-upgrader 1:26.04.25`; arm64 sources use `archive.ubuntu.com`/`security.ubuntu.com` (no `ports`)                                                                                                      | Snap inventory now returns successful (empty) collection; restricted-network cloud guests settle `degraded` only through `systemd-networkd-wait-online` (no slirp router) and that unit is now named in inspect records.                   |

Lab fixture finding: `systemctl mask --now` on an active timer reloads before it
stops, and systemd 259 then fails the masked timer (`Unit to trigger vanished`);
the cloud fixture now stops before masking.

### Encryption, recovery and device actions

The encrypted golden is installed from the official desktop ISO (edition
`desktop-encrypted-lab`), keeping the vendor shim/GRUB/kernel, Secure Boot and
swtpm. The stock variant uses the installer's own dracut initramfs; the TPM-capable
variant adds the dracut drop-in (`systemd crypt tpm2-tss lvm systemd-cryptsetup`,
`/etc/crypttab` with `tpm2-device=auto`) and `tpm2-tools`, which dracut's
`tpm2-tss` module requires and the desktop media lack. systemd 259's
`systemd-cryptsetup` in the dracut initrd reports a rejected passphrase only in the
journal, so the registry marks the console as silent (`CryptsetupConsole`), as for
Debian 13 and Fedora. Encryption scenarios 1–5, compliance, live erase, report-loss
and GDM lock/quarantine passed on this golden. The arm64 desktop ISO uses the same
recipe on QEMU `virt` with AAVMF Secure Boot: GRUB on the EFI console, the kernel on
PL011 `ttyAMA0`, virtio-gpu for GNOME; the same cells passed there. Measured-GRUB
recovery sanitize passed on aarch64 NVMe; SATA is refused before boot because AAVMF
has no AHCI driver.

Recovery sanitize in owned-UKI mode is refused natively on the stock cloud image:
the ordinary UKI built from the vendor kernel and the generic 72 MB dracut initrd
leaves 13,998,592 bytes of the 105 MiB ESP, and the signed recovery image needs
50,653,240, so pre-approval readiness reports `device_action_esp_insufficient`. A
dracut `--hostonly` ordinary UKI (the RHEL fixture variant) still leaves only
42,247,680 bytes against 46.7–50.4 MB, so UKI mode stays a native refusal.
`RECOVERY_BOOT_MODE_MEASURED_GRUB` (below) stages on the 1 GB ext4 `/boot` and passed
NVMe format and SATA overwrite. Linux 7.0's EFI stub appends two PCR 9
`EV_EVENT_TAG` events (LoadOptions and initrd) after GRUB's measurements; the parser
accepts them in order, at most once, bound to the GRUB initrd digest. GRUB 2.14's
LoadOptions digest includes the trailing U+0000 that 24.04's GRUB 2.12 omits.

### Updates and OS patch policy

APT 3.2.0 keeps the canonical archive name, the existing-archive size check,
`--no-download` and simulation output that self-update relies on (pinned
[3.2.0 acquire-item.cc](https://salsa.debian.org/apt-team/apt/-/blob/3.2.0/apt-pkg/acquire-item.cc#L3549),
[private-install.cc](https://salsa.debian.org/apt-team/apt/-/blob/3.2.0/apt-private/private-install.cc#L256)).
3.x substitutes `Architecture-Variant` for the architecture in archive names when a
package declares one; the agent DEB declares none. The OS patch policy runs with
`unattended-upgrades 2.12ubuntu9`, `needrestart 3.11-1ubuntu2` and
`update-notifier-common 3.207.2`. Its reboot notice reaches local PAM/TTY sessions;
SSH sessions do not receive it on 26.04 (empty logind `TTY`, above), and
`PatchRunSummary.notified_sessions` counts graphical recipients only, never wall
delivery.

### Advisories

Configure resolute numerically (`release: "26.04"`); `noble` remains the only
codename alias. The canonical export's resolute records are `Ubuntu:26.04:LTS`
(91,587 affected entries in the 2026-10-10 archive); `Ubuntu:Pro:26.04:LTS`
(`esm-apps/resolute`) is a separate, unconfigured product; the 15 development-series
`Ubuntu:26.04` records are all withdrawn and dropped. No resolute record is
malformed. Publication admitted 529,408 claims per architecture with zero rejections.

## Release upgrade 24.04 → 26.04

`lab vm resources -phase release-upgrade` enrolls a 24.04 cloud guest, converges a
package, file, sysctl and service profile, publishes both the 24.04 and 26.04 OSV
feeds, then runs the supported `do-release-upgrade -f DistUpgradeViewNonInteractive`
in a transient unit and reboots. The registry row `ubuntu-24.04` names
`UpgradeTo: ubuntu-26.04`; `ubuntu-26.04` has no successor and keeps the
release-upgrade gate. Observed behaviour (upgrader `1:26.04.25`):

- Identity: the installation, device, enrollment generation, certificate and session
  epoch are unchanged; there is no re-enrollment. Both agent units stay active with
  the same sandbox properties and unit files. The server records `os_version` 26.04
  from fresh authenticated inventory equal to native dpkg truth.
- The upgrader disables the third-party agent source
  (`/etc/apt/sources.list.d/lindm-agent.sources` gets `Enabled: no`, "unknown
  mirror"/"unknown dist", even with `--allow-third-party`, because suite `stable`
  is not in its mirror map). lindm does not re-enable or edit operator APT sources;
  agent self-update uses signed TUF targets through the protected transaction cache,
  not that source. Re-enable it after re-verifying its key if APT installs from it
  are wanted.
- `lindm-agent` is reported foreign and skipped by obsolete/purge handling, so it
  survives. Owned `/etc/apt/preferences.d/lindm-*` pins do not block the upgrade and
  keep their inode and content.
- While the upgrader holds dpkg's frontend lock, package staging, database reads and
  the pre-effect commit check return busy: the executor signs
  `RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY` before its effect gate and lindmd records
  `BLOCKED`/`native_package_manager_busy`, re-dispatching one reconcile interval later.
  Releases refused this way report `release_conflict/native_package_manager_busy`.
  After the reboot every resource re-converges; only the changed package needs an
  effect.
- Advisory findings switch from the 24.04 feed to the 26.04 feed with none
  attributed to any other feed.
- `do-release-upgrade` itself refuses pending non-phased updates and a pending
  kernel/libc reboot; the lane runs `apt-get full-upgrade` and reboots first.

The cloud lane does not cover a GNOME 46→50 desktop or an encrypted-root upgrade.

## Release upgrade 22.04 → 24.04

Not implemented; the registry gates it with the observed reason. With a temporary
`UpgradeTo: ubuntu-24.04` the same lane ran on native aarch64 (`dgx20`, AAVMF,
upgrader `1:24.04.29`): `do-release-upgrade` finished in 980 s, the guest booted
24.04 (`6.8.0-146-generic`, systemd 255) with the same installation, device and
enrollment generation and both agent units active. Post-upgrade reconvergence then
failed within its deadline: the owned `vm.swappiness` sysctl (runtime and persistent
value still 31) failed its verification postcondition (`verification_drifted`), and
the owned `/etc/lindm-resource-lab/release-upgrade.conf` was refused at executor
admission (`admission_precondition`, native evidence unavailable). Record
`release-upgrade-aarch64.log` in
`~/.cache/lindm-matrix/debianel-u22ru-arm-20261011T225545Z/ubuntu-22.04/`
([verification](../verification.md#debian-el-and-ubuntu-2204-matrix-completion-2026-10-12)).
The 24.04 → 26.04 behaviour above does not transfer to this path.

## Packaging, signing, repositories, paths and LSM

For a bare Ubuntu machine, choose Ubuntu in the console's enrollment dialog and
run its single install-and-enroll command. Agent packages come only from the
customer's own `lindmd` HTTPS `/repo/apt` endpoint. The command pins the repository
signer and server/bootstrap trust before writing the deb822 `Signed-By` source;
it never substitutes an external agent repository. Missing packages or architecture
coverage have a server-configuration remedy. See the
[install runbook](../security-and-operations.md#enrollment-installation-from-your-server).
This delivery path does not transfer qualification between Ubuntu releases.

Use the native `lindm-agent` DEB and authenticated APT repository, not `dpkg -i` as a
signature check. Authentication is signed `InRelease` → hashed `Packages` → archive
SHA-256; the DEB does not carry an embedded package signature. The generated deb822
source uses a dedicated `Signed-By` key and rejects system `trusted.gpg` locations
([packaging contract](../../internal/packaging/doc.go#L14),
[source generation](../../internal/packaging/publish.go#L19)). Independently verify
the package-signing fingerprint; the image-signing key is not the agent repository key.
The lab archive coordinates `stable/main` are lindm-owned coordinates, not an Ubuntu
release upgrade channel ([layout](../../internal/packaging/layout.go#L32)).

Packaged executables live at `/usr/libexec/lindm/lindm-agent`; configuration is
`/etc/lindm/{executor,agent}.json`. Root journal/identity state lives under
`/var/lib/lindm/executor`, transport state under `/var/lib/lindm/agent`, and the
root-owned runtime socket directory is `/run/lindm` (0750 root:lindm).
See [executor unit](../../internal/packaging/assets/lindm-executor.service#L8),
[network unit](../../internal/packaging/assets/lindm-agent.service#L9) and
[tmpfiles](../../internal/packaging/assets/tmpfiles.conf#L1).

Do not disable AppArmor or systemd confinement to make a lane pass. The evidence
below establishes the recorded systemd boundaries, not an AppArmor profile/enforcement
qualification. Record native LSM state separately in any new installation acceptance run;
neither an Ubuntu name nor absence of logged denials proves that boundary.

## Agent services and sandbox

`lindm-executor.service` runs as root and owns privileged observation/execution;
`lindm-agent.service` runs as `lindm`, has empty capability sets and owns outbound TLS.
Both retain `PrivateDevices=yes`, `ProtectSystem=strict`, `ProtectHome=yes` and
`ProtectProc=invisible`. The executor normally allows only AF_UNIX; the network
unit permits its specified IP/resolver families. The units exclude each other's
private state directories (unit references above).

An encrypted-root observation exposed a real boundary: executor `PrivateDevices`
hid block nodes, so ordinary `lsblk` could see sysfs mappings but omit device-mapper
children; reading public LUKS metadata also failed. The correction is a fresh,
fixed-command transient `inventory-observe` service, **not** weaker persistent units.
Only this helper uses `PrivateDevices=no`, with `DevicePolicy=closed`, `block-* r`,
empty capabilities, private networking, strict filesystem protection and inaccessible
lindm config/state. It has a 10-second runtime limit, 80-KiB stdout/8-KiB diagnostic
bounds and strict typed output, boot and timestamp admission. Cancellation stops and
joins the transient unit ([implementation](../../internal/agent/executor/root_inventory_linux.go#L21),
[exact properties](../../internal/agent/executor/root_inventory_linux.go#L89)).
This read-only observer is distinct from action-sandbox provisioning: imperative
actions require their own qualified exact-device drop-in, not `block-*` write access
([executor unit](../../internal/packaging/assets/lindm-executor.service#L17)).

## Inventory and per-field quirks

Inventory reports status per observation. A successful empty collection, absent
capability, permission denial and failed command are different outcomes. The native
oracle's [capability-guarded allowlist](../../internal/vmlab/inventory_unavailable_linux.go#L7)
accepts only exact `UNAVAILABLE` cases; it never turns other failure statuses into a pass.

| Field or backend          | Ubuntu interpretation                                                                                                                                                                                                                                                                                                 |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native packages           | `dpkg` identities and versions; no RPM module label. The module exception requires an actual dpkg record.                                                                                                                                                                                                             |
| APT origin                | Per package, every `/var/lib/apt/lists` index listing the exact installed version, with Release identity and the agent's own signature verification. Empty lists are a successful empty observation. Ubuntu's own advisory matching ignores it; it decides coverage only for derivatives. Oracle: `apt-cache policy`. |
| Snap                      | Query local `/run/snapd.socket`, `GET /v2/snaps`. HTTP 200 with typed `sync`/`OK` and `result: []` is successful empty inventory. `snap list`'s informational stderr is not an installed application. Missing/null results, malformed output and native failures are not empty success.                               |
| Flatpak                   | Absent backend permits unavailable application inventory only when backend detection itself succeeded with false. Installed-but-failing Flatpak or Snap must fail visibly.                                                                                                                                            |
| CPE                       | Stock Ubuntu os-release need not provide `CPE_NAME`; absent CPE is unavailable, not an invented identifier.                                                                                                                                                                                                           |
| Release lock/repositories | Optional releasever lock and RPM/DNF repository observations are not an APT package failure. Non-DNF exemption requires dpkg present and RPM absent.                                                                                                                                                                  |
| DMI serial                | A root-only blank QEMU serial remains unavailable after privileged observation. Do not fabricate one or retain a network-process permission error as truth.                                                                                                                                                           |
| Firmware/TPM              | BIOS cannot supply UEFI Secure Boot; an EFI partition does not prove UEFI boot. TPM version is unavailable only when successful TPM presence is false.                                                                                                                                                                |
| Sessions                  | Remote/tty sessions may lack a graphical seat; logind collection must still succeed.                                                                                                                                                                                                                                  |
| Storage                   | Unmounted media, whole-disk partition IDs, virtio WWNs and non-NVMe sanitize identity have separate applicability rules. LUKS metadata cannot be excused as absent when LUKS is present.                                                                                                                              |

Sources: [Snap collector/parser](../../internal/agent/inventory/snap_linux.go#L22),
[platform/backend exceptions](../../internal/vmlab/inventory_unavailable_linux.go#L20),
[storage capability predicates](../../internal/vmlab/inventory_unavailable_linux.go#L33).

The real Ubuntu24 console guest was upgraded through signed APT 0.1.0→0.1.1.
Among 220 status-bearing fields only two changed: Snap native-command failure became
successful empty inventory, and root-observed blank hardware serial became unavailable
instead of permission denied. Other fields remained successful or truthfully unavailable;
identity/generation and persistent sandbox settings were retained, and host/package
sequence 3 was published. Evidence:
`/home/r/work/lindm-lab/console-ubuntu-20261010/inventory/diagnosis.txt`, SHA-256
`b534ff1c979aa1b7336c0d54b568a7605771e5b1515c8d09756e5eebd69a6e4b`.
That record identifies the before/after JSON, exhaustive CSV and native APT transcript.

Encrypted observer prerequisites separately passed read-only transient `lsblk` and
public LUKS inspection: `vda→vda3→dm_crypt-0→ubuntu--vg-ubuntu--lv` mounted at `/`,
one keyslot and zero tokens. Raw LUKS JSON was not retained.
`/home/r/work/lindm-lab/console-encrypted-ubuntu-20261010/transient-observer-fix.txt`,
SHA-256 `fed3b8d980d86db1d92e5f0348e7bf48c68101d7e3aa0c7e7636440dad38eabc`,
records this narrower proof. At this handoff the combined signed 0.1.2 package awaits
owner-authorized server restart/guest upgrade: accepted post-upgrade encrypted
projection and target selectability are **not yet established**.

## Updates

Agent self-update is not a general Ubuntu distribution upgrade. APT staging must use
`lindm-agent_<native-version>_<architecture>.deb`, with `:` escaped as `%3a` and `_`
as `%5f` in the version. The protected transaction directory itself is
`Dir::Cache::archives`; staging a generic `agent.deb` outside a separate empty cache
breaks `--no-download` with “Pathname to install is not absolute”. Do not work around
that by allowing downloads. The provider simulates the bounded operation, admits
only the owned package, uses no repositories/downloads/removals/recommends and
fails on missing dependencies. Interrupted recovery re-unpacks/configures only the
admitted agent package ([naming](../../internal/agent/update/native_linux.go#L83),
[APT transaction](../../internal/agent/update/native_linux.go#L407)).

Pinned upstream explanation: APT 2.8.3
[canonical archive resolution](https://salsa.debian.org/apt-team/apt/-/blob/2.8.3/apt-pkg/acquire-item.cc#L3464)
and [no-download acquisition handling](https://salsa.debian.org/apt-team/apt/-/blob/2.8.3/apt-private/private-install.cc#L183).

Ubuntu24's unattended native lane passed six signed negative/hold phases, an actual
interrupted unpack witness, boot-helper completion at 0.2.0, retained identity,
fresh authenticated inventory/session and signed downgrade refusal:
`$HOME/.cache/lindm-updatequal-20261010/ubuntu24-updates-05.json`, SHA-256
`7716aa65b6d846dd935f2b087fa7a019563d33f124efda2e39ee81adc5da860c`.
This is one-source, differently stamped package qualification, not historical release
compatibility, arbitrary dependency management or physical power-loss evidence.
The same lane passed natively on aarch64 (dgx20 KVM, AAVMF) for 24.04 and 26.04
through `lab matrix run`, so the registry admits it on both architectures
([records](../verification.md#ubuntu-24042604-matrix-completion-2026-10-12)).

### Air-gapped offline bundles

Offline sites install from the bundle's per-architecture APT archive served by the
site server at `https://SITE/offline/repositories/<amd64|arm64>/apt/` (suite
`stable`, component `main`). Pin the station package key with `Signed-By` (an
ASCII-armored `.asc` is accepted by Ubuntu 24.04's APT 2.7) and the site CA with
`Acquire::https::CAInfo`; the lane uses isolated `Dir::Etc::sourceparts`, lists and
archives so no vendor source is consulted. Agent updates still stage through the
protected transaction cache above, from TUF targets the site imported. The bundle's
advisory snapshot for this release is the Ubuntu OSV `all.zip` (≈778 MB on
2026-10-11), acquired by the station without a whole-request client timeout.

`lab vm airgap` passed on Ubuntu 24.04 amd64 inside a no-route namespace:
`$HOME/.cache/lindm-airgap-20261011/records/ubuntu-24.04-r2.json`, SHA-256
`14773263f4ea519b5cc74d2c3eff6a78e530998a7c010c35d8041f126e8523a1`
([verification L16](../verification.md#3-acceptance-scenario-families)). It covers
the restricted-slirp guest (public DNS/TCP failed; the slirp IPv6 router advertisement
still installs a default route), install, enrollment, rejected expired/corrupt/forged/
replayed bundles, paused staging and the audited update to 0.30.1. Ubuntu device
findings reached the lane's 20,000-row read bound; counts are lower bounds. arm64
repositories are built into bundles but not exercised.

## Encryption and recovery

Ubuntu 24.04's stock encrypted installer uses `cryptsetup-initramfs`, `CRYPTSETUP=y` and
`update-initramfs -u -k all`. TPM boot is a distinct lab variant: after curtin finishes,
it installs dracut/systemd/TPM dependencies, removes `cryptsetup-initramfs` and rebuilds
initrds with dracut. Noble's dracut conflicts with initramfs-tools; do not silently
reinterpret a stock-initramfs pass as TPM-token unlock qualification
([installer](../../internal/vmlab/encrypted_installer_linux.go#L85)).

Ubuntu 22.04 (`lab/images/ubuntu-jammy-encrypted-amd64.json`, 22.04.5 live server)
differs in three native ways. Its dracut 051 has no `tpm2-tss` module (naming it
is fatal), so the TPM variant lists `systemd crypt lvm` and installs the TSS2
libraries systemd 249's cryptsetup loads (`libtss2-{esys,mu,rc,tctildr,tcti-device}`
from the multiarch directory) plus `tpm_tis`/`tpm_crb`, with the pre-t64
`libtss2-tcti-device0`. Its subiquity hands the identity to cloud-init, which creates
`lindm-lab` only on first boot, so late commands must not chown to it; the pinned
login key arrives through autoinstall `ssh.authorized-keys` instead. systemd 249's
`systemd-cryptenroll` has no `--unlock-key-file` (252+), and the product never
passes a secret by argv or environment, so TPM2 binding is unsupported on 22.04:
the server refuses it before signing with `device_action_tpm2_binding_unsupported`
(registry systemd 249 below `platform.TPM2BindSystemdFloor`), the storage-target
listing reports the same reason, and the root provider's native
`systemd-cryptenroll --version` probe refuses it as
`systemd_cryptenroll_tpm2_binding_unsupported`. The owned-boot recovery fixture needs
`systemd-ukify` (253+), so 22.04 recovers only through measured GRUB (below).

On the 22.04 GNOME 42 golden, these lanes passed natively on aarch64:

- the encryption scenarios (escrow, reveal, rotation, cold-boot recovery, and the
  explicit TPM2 refusal);
- compliance;
- live-root crypto-erase and report-loss;
- lock/quarantine;
- five-scenario assistance.

Lock/quarantine and assistance also passed on x86_64. Records are in
[verification](../verification.md#device-actions-encryption-configuration-and-assistance-ubuntu-2204-debian-1213-rocky-and-almalinux-98102).

Ubuntu 24.04.5 amd64 encrypted UEFI installation, Secure Boot with enrolled keys,
swtpm and virtio-blk passed two passphrase cold boots and independent LUKS-header
equality. `artifacts/encrypted-ubuntu2404-amd64-secureboot-20261010.json`, SHA-256
`e21191c8b7b149299f6f51b1e7164d239271c047772ced0d8114d4a2c5e1dc69`, explicitly
uses stock initramfs and no desktop. It does not qualify TPM-token unlock, key
rotation, wipe, ARM or Secure Boot off. The historical ARM TCG installer timeout
remains a failed qualification attempt in [verification](../verification.md);
the later native KVM evidence below does not turn that timeout into a pass.

Ubuntu 24.04.5 **aarch64 full encryption and product TPM binding passed** on
2026-10-11: native `dgx20` KVM, GNOME installer golden, virtio-scsi, swtpm2,
AAVMF `qemu-efi-aarch64=2024.02-2ubuntu0.10`, **Secure Boot enforced**
with the package-owned `AAVMF_CODE.secboot.fd` and `AAVMF_VARS.ms.fd`
(SetupMode false). The unchanged vendor boot chain needed no replacement kernel,
custom enrolled key or aarch64-specific product fix. Record:
`$HOME/.cache/lindm-assistqual-20261011/ubuntu24-aarch64-encryption-01.json`,
SHA-256 `0dfcccf1cead839012e86b2f20981cff144ff45a35261cd801ecccb8062d7dac`.
It proves escrow/custody and audited reveal, rotation and retired-key rejection,
hard-crash recovery, eight authorization negatives, the signed TPM bind action,
unattended cold boot, PCR7 mismatch refusal and revealed-key recovery.
The [full invocation and provenance](../verification.md#ubuntu-2404-aarch64-encryption-and-tpm)
bind source and native binary/package digests. This is the dracut TPM variant
above, not stock `cryptsetup-initramfs` TPM unlock; physical TPM/firmware/media,
Secure Boot off, wipe/recovery-sanitize and assistance after TPM-bound boot
remain separate qualification.

A stock Ubuntu machine without a deployment key in firmware `db` uses
`RECOVERY_BOOT_MODE_MEASURED_GRUB` with the grub.d flavor
([architecture](../architecture.md#measured-grub-recovery-recovery_boot_mode_measured_grub)).
Staging writes one `--unrestricted` menuentry to `/boot/grub/custom.cfg`, which
the vendor `grub.cfg` already sources through `41_custom`. The entry locates the
separate ext4 `/boot` by its udev filesystem UUID and uses `($root)`-qualified
paths, and it is armed with `grub-editenv - set next_entry=…`. Staging refuses a
pre-existing `custom.cfg` and never runs `update-grub`. Ubuntu's vendor entries
pass `linux /vmlinuz-…` without a device. The kernel's EFI stub then adds PCR 9
load-options and initrd events, and both are bound to what GRUB measured. On
arm64, GRUB measures the gzip `vmlinuz` decompressed, and the release's
`.kernel` target uses that form. Ubuntu 24.04 passed natively on amd64 SATA and
NVMe, plus additional arm64 NVMe on `dgx21`. Ubuntu 22.04 amd64 (signed GRUB
2.06, kernel 5.15) passed SATA and NVMe; its NVMe needs the sysfs-derived NVMe
approval scope. 22.04's recovery sanitize is measured GRUB only, because its lab
owned-boot UKI fixture lacks ukify. On 24.04 aarch64 the owned-boot fixture is
refused too (`Lab.OwnedBootUnavailableOn`): the signed arm64 `vmlinuz` is a
gzip-compressed Image that GRUB unpacks, which `ukify` cannot scrape or embed, so
the matrix runs measured GRUB there and that NVMe cell passed with Secure Boot
enforced. Jammy's arm64 GRUB records no PCR 8/9
measurements, so readiness refuses there. Record hashes are in
[verification](../verification.md#measured-grub-recovery-on-stock-vendor-boot-chains).
Ubuntu 26.04.1 amd64 NVMe and SATA also passed
([26.04 section](#encryption-recovery-and-device-actions)).

Stable storage selection is hardware-dependent, not an Ubuntu guarantee. The encrypted
demo's virtio disk supplies serial `lindm-demo-encrypted` at
`/sys/dev/block/253:0/serial`, but no WWID or `device/serial`. Native evidence under
`/home/r/work/lindm-lab/console-encrypted-ubuntu-20261010/`:

| Record                                | SHA-256                                                            |
| ------------------------------------- | ------------------------------------------------------------------ |
| `lsblk-native-baseline.json`          | `ac845af43a0e65e0323d7f8c54887e89bc771d4ccde64dc70f454aad723595ba` |
| `native-sysfs-identity-baseline.json` | `6f9cc1c2af109de2c275665c2d151ec74e765e1c5f405583d5f97e4bda445b55` |

The signed identity basis prefers `WWN_SERIAL`. An explicitly absent WWN may permit
`SERIAL_GPT_LUKS` only for an encrypted GPT partition with unique physical serial,
exact GPT/LUKS UUIDs and both disk/target sizes. Failed or contradictory WWN evidence
cannot downgrade. Paths are not authority, and the fallback does not qualify NVMe
sanitize ([target construction](../../internal/device/inventory/storage_targets.go#L116),
[native revalidation](../../internal/agent/actionprovider/target_linux.go#L157)).

### TPM2 unseal race

With Secure Boot enforced, Ubuntu 24.04's unattended TPM2 unlock of the root
volume races initrd module loading. The signed `6.8.0-146-generic` kernel
(`CONFIG_IMA_ARCH_POLICY=y`) adds IMA's Secure Boot rule
`measure func=MODULE_CHECK`, so every module load extends PCR 10 (53–63 runtime
measurements on the arm64 golden, 67 on amd64). Any PCR extension changes the
TPM's global `pcrUpdateCounter`. A `TPM2_Unseal` whose policy session ran
`TPM2_PolicyPCR` before that change fails with `TPM_RC_PCR_CHANGED` (0x128),
whichever PCR the token is sealed to. In the arm64 dracut initrd, udev loads
`xhci-pci`, about 15 CPU-feature crypto modules (`sha*-ce`, `sm3`/`sm4-ce`,
`ghash-ce`, `polyval-ce`, `crct10dif-ce`) and the USB HID modules between 0.98
and 1.45 s, which is exactly when `systemd-cryptsetup@` unseals. The other
suspects do not extend during the unlock: systemd-pcrphase, -pcrextend,
-pcrmachine and -tpm2-setup are skipped (`ConditionSecurity=measured-uki`),
crypttab has no `tpm2-measure-pcr=`, and GRUB and firmware measure before the
kernel starts.

systemd `255.4-1ubuntu8.17` retries a `TPM_RC_PCR_CHANGED` unseal up to 30
times but reuses its parameter-encryption session. tpm2-tss `4.0.1` clears that
session's `TPMA_SESSION_DECRYPT` for `Esys_Unseal`, because the command has no
parameter to encrypt, and restores it only after a successful response. The
retry therefore stops at "Missing encryption session" and the token fails with
`EINVAL` (`Failed to unseal secret using TPM2: Invalid argument`). Upstream fixed
this in [1923e213165d](https://github.com/systemd/systemd/commit/1923e213165d1510b553473b1a14c33cb5124bcb)
([#31881](https://github.com/systemd/systemd/issues/31881)), released in systemd
256 and systemd-stable 255.5; Ubuntu noble's systemd does not carry it.
`systemd-cryptsetup` opens the TPM2 tokens twice per boot, first every token
and then the `systemd-tpm2` ones. A boot prompts for the passphrase when both
unseals collide.

The managed bind fixes this with a native mechanism and the same PCR 7 policy:
libcryptsetup 2.7 maps the token plugin's `-EINVAL` to `-ENOENT` and opens the
next token. The registry's `TPM2UnsealRetryNextToken` quirk makes the agent add
three byte-identical copies of the token `systemd-cryptenroll` wrote, all
naming its one new keyslot. The result is four tokens for the same sealed object
and policy, and so eight independent unseals per boot, each with fresh sessions.
No keyslot or secret is added. The bind is refused before its effect gate when
the header lacks four free tokens or the LUKS2 JSON room
(`no_free_token`, `luks2_metadata_space_exhausted`). Verification requires exactly
four identical references and a token unlock of that keyslot
([bind](../../internal/agent/actionprovider/luks_linux.go),
[quirk](../../internal/platform/platform.go)). Pop!_OS 24.04 and Linux Mint 22
inherit the quirk from this row. A binding made before this change keeps one
token; bind again to add a referenced slot, after which the old token is tried
first. Ubuntu 26.04's systemd 259 starts a new session on every retry and keeps
one token. In its arm64 regression cell, 29 of 30 boots logged one or two
`0x00000128` unseals, and every boot still unlocked through the first token.

On dgx20 (arm64, 3 concurrent guests) and on local KVM (amd64), both with Secure
Boot enforced and the product's `systemd-cryptenroll --tpm2-pcrs=7` bind, one
token gave:

| Guest | Cold boots | Passphrase prompt | Collisions absorbed by the second unseal |
| ----- | ---------- | ----------------- | ---------------------------------------- |
| arm64 | 33         | 1 (3.0%)          | 4 boots                                  |
| amd64 | 33         | 0                 | 0                                        |

The prompted arm64 boot logged two `0x00000128` unseals, at 1.150 s and 1.292 s.
Evidence, hashes, the four-reference results and the
`tpm-unattended-boots` regression cell (30 product-bound cold boots that must
all unlock) are in
[verification](../verification.md#tpm2-unseal-race-and-unattended-boot-regression).

## Resource providers

The agent executes only generic signed resource intents. The server dispatches
a kind only when its per-kind qualification table lists it with native Ubuntu
24.04 and Fedora 44 records (see
[verification](../verification.md#generic-resource-executor-cutover-phase-2)):
systemd services, native packages, managed files, local groups and users,
sysctl, systemd timers and drop-ins, password policy, encryption compliance, firewall zones and the
OS update policy are
dispatched; other kinds show
`resource_executor_not_available`. The 24.04 records are aarch64 cloud-image
guests.

Native mechanisms on Ubuntu: packages use apt/dpkg in asynchronously staged
transient units with an owned `/etc/apt/preferences.d/lindm-*` exact-version
pin; password policy uses owned `pam-auth-update` profiles and requires the
`libpam-pwquality` module package for quality controls; sysctl persistence is an
owned `/etc/sysctl.d/60-lindm-<sha256(key)>.conf`; local accounts use the shadow
tools against the exact host `/etc` bound into a private account root.
Firewall restoration and its rollback supervisor units ship disabled.

The typed kernel-module blocklist is enabled explicitly in the root executor's
`fileProvider.kernelModuleBlocklist`. Ubuntu 24.04 uses native `modprobe` and
`update-initramfs -u -k all`; `initramfs-tools` must be installed. Existing dracut
installations are not guessed compatible. Other Ubuntu releases and derivatives
do not inherit this setting's qualification, including Ubuntu 26.04 desktops
whose native tooling is dracut. The provider streams gzip/zstd/newc images to
check their embedded owned stanza, reports active drivers as pending restart and
built-in drivers as not applicable, and never unloads drivers.
If the native tool's state directory is absent, that effect helper receives its
existing parent `/var/lib` writable so the vendor command can create state after
the effect permit. Later helpers narrow to `/var/lib/initramfs-tools`; sandbox
preparation itself never creates it.
The native arm64 KVM lane passed all ten scenarios, including initially absent
tool state, actual reboot/load refusal, both drift repairs, built-in `kvm` findings
and release. See [receipts and limits](../verification.md#typed-kernel-module-blocklist).

SSH banner-only desired state uses the existing SSH resource model and reloads
`ssh.service`, never restarts or starts a service. It manages the fixed Banner
drop-in and `/etc/issue.net`, preserving an explicitly adopted distribution
notice for release. Native syntax/effective configuration and a fresh
host-key-verified loopback banner exchange bind verification to the actual
pre-authentication text; content-only drift is repairable, inode/security changes
are not. Authentication/listener controls remain unqualified. Prerequisites and
collision semantics are in [SSH login banner](../security-and-operations.md#ssh-login-banner);
the dedicated [native lane](../verification.md#ssh-login-banner) also proves
fresh authenticated connectivity, automatic drift repair and release.
The recorded aarch64 KVM lane passed all eleven cases, including terminal
pre-effect refusals for an unsafe Include alias and an empty writable Include
search directory. This is banner-only qualification, not arbitrary SSH policy.

Delivered password hashes (`HashedPasswordPolicy`) use `chpasswd --encrypted`
reading `name:hash` on stdin. Ubuntu 24.04 shadow 4.13
(`passwd 1:4.13+dfsg1-4ubuntu3.2`) has no `chpasswd --prefix`, so the root
helper uses `--root` (a chroot, needing `CAP_SYS_CHROOT`, already granted for
`chage`). Shadow 4.13 does not validate hash formats with `-e`, so lindm
validates shape and algorithm itself. Managed local-admin rotation runs
`/usr/sbin/chpasswd` in `/` with system PAM hashing (yescrypt by default) and
needs the `action-sandbox` exception described in
[security and operations](../security-and-operations.md#managed-secrets-and-local-admin-passwords).
`chpasswd` updates the shadow last-change field; lindm does not own it. Both
paths are qualified on Ubuntu 24.04 aarch64 with SSH password logins
([secret delivery and local-admin records](../verification.md#secret-delivered-password-hash-and-managed-local-admin-password)).

Local accounts: approved adoption of an existing local user or group is
dispatched. Adoption owns only the managed dimensions (for example shell,
password lock, aging, GID or additive members), and release restores their
recorded baseline; a lock keeps the existing shadow hash, so unlocking restores
it unchanged. A desired UID held by another, unmanaged account is refused, and so
is an owned account deleted and recreated outside lindm under the same name with
another UID (a reused native identity, for reconcile and release alike). lindm
keeps no tombstone for released UIDs: after release the shadow tools may assign
the UID to another name, and the home preserved on release stays owned by that
number (not exercised natively).

Sysctl persistence survives a real reboot: `systemd-sysctl` applies the owned
stanza at boot, the post-boot observation converges without a start grant and
reports reboot persistence, and release after the reboot restores the baseline.
A live value's native identity is boot-scoped; across a boot it remains lindm's
only while the owned stanza is byte-identical and still the effective source.
`net.*` keys are per network namespace: lindm manages the host (PID 1)
namespace, which the executor observes and the helper joins for `net.*` keys
(no `PrivateNetwork=`); other namespaces, such as containers', are never
managed. `net.ipv4.ip_forward` is the exercised `net.*` key; a namespace created
while it was managed started with the host's IPv4 value (the record shows `1`),
which lindm neither tracks nor restores there.

Timers fire natively: an interval timer runs its target service
(`OnActiveSec=` then `OnUnitActiveSec=`), and a daily UTC calendar timer runs it
at its minute; with `Persistent=no` a missed calendar time is not caught up.

Managed files have no ACL dimension, and the provider preserves only `user.*`
and `security.selinux` extended attributes, so it fails closed: a file with a
POSIX access ACL is not adopted, and no file is created where a directory's
default ACL would be inherited. Both are signed `UNSUPPORTED_NATIVE` refusals;
`getfacl`, content and the directory stay unchanged.

Ubuntu 24.04 ships no `/etc/motd.d`, although `pam_motd` (`noupdate` in
`/etc/pam.d/sshd` and `login`) reads it. The provider never creates an approved
root: a managed file under an absent protected ancestor is a signed
`PRECONDITION` refusal. Create the approved root (root:root 0755) when opting in;
the persistent organization demo does this for its `fileProvider` roots
([verification](../verification.md#organization-demo-resource-convergence-two-desktops-2026-10-12)).

Firewall zones are a dedicated `inet lindm_z_<zone>` nftables table written over
netlink at priority 10 (the agent does not run the `nft` CLI). Native records for
the two-guest lane exist (see
[verification](../verification.md#generic-resource-executor-cutover-phase-2));
dispatch still follows the server qualification table. Root provisioning is
required on the device: `executor.json` `firewall_provider` (approved data
interface by permanent MAC plus kernel name, and the probe peers' HTTPS control
endpoints as management endpoints) and `connectivity_guard` (4–32 identical
dual-stack allow/deny probe targets and the controller's execution start public
key), `systemctl enable lindm-firewall-restore.service`,
`systemctl enable --now lindm-connectivity-guard.service`, then an executor
restart. The server's `connectivity_probes` must equal the device targets, and a
dedicated unenrolled peer runs `lindm-connectivity-probe.service` with a TLS leaf
from the enrollment transport CA. Probe targets are static root policy, so a
zone released to absence still needs an independent deny for each DENY target;
the lab uses its own priority-100 table that drops only those exact tuples.

Coexistence with an active UFW (the 24.04 cloud image ships it inactive; the
lane enables it with only SSH and the oracle ports allowed before any zone
exists) is native-qualified on aarch64. UFW's iptables-nft `ip filter` and `ip6
filter` tables (priority 0) stay byte-identical, with handles, across every lindm
operation (zone create, reconcile, quarantine, drift, crash and release). Only
the deliberate `ufw reload` and the reboot recreate them; the reload leaves the
zone table's objects and handles unchanged, and after both a fresh verification
converges. The
real signed quarantine action's `lindm_q_<action>` table (priority -10) is final:
the peer's TCP 8080/8081/8083 time out and UDP egress gets `EPERM`, while SSH
from the slirp gateway, loopback to the controller and DNS to the explicit
`10.0.2.3` still work; the zone table is untouched. The server issues no zone
work while the device is quarantined (`device_quarantined`); after the signed
release the withheld verification converges and the zone behaves exactly as
before. Quarantine admits loopback only from its `127.0.0.1` endpoint, so the
systemd-resolved stub (`127.0.0.53`) is unreachable while quarantined: names
resolve only from `/etc/hosts` (the lab adds the Debian `127.0.1.1` hostname line
for `sudo`) or by explicit queries to a configured DNS server. An external rule
added to, or an owned rule deleted from, the zone table is refused with a signed
precondition failure and never overwritten; removing the added rule converges
again, and a deleted rule is restored only by boot replay. A helper killed after
the kernel batch ends `OUTCOME_UNKNOWN`; the supervisor restores the exact prior
table and committed file, and the next signed reconcile resolves ownership from
that rollback and applies a new generation
([verification](../verification.md#firewall-zone-create-restore-coexistence--two-guest-probe-lane)).
Native findings: `/proc/1/ns/net` is ptrace-gated for
the capability-bounded helper, guard and restore units, so the host-namespace
check compares per-namespace `/proc/<pid>/net/dev` entries; the 6.8 kernel reads
back boolean bitwise expressions with an explicit `NFTA_BITWISE_OP=0`, which the
expression digest normalizes.

### OS update policy (`os.update.v1`)

Ubuntu 22.04 uses the same provider and runner (`unattended-upgrades 2.8ubuntu1`,
`needrestart 3.5-5ubuntu2.5`, `update-notifier-common 3.192.54.8`) and passed on
both architectures. Its scenario needs a pending reboot-requiring security update:
the default `jammy-release-20261004` pin already carries the current kernel, so the
records use the signed `jammy-release-20260926` serial
([verification](../verification.md#debian-el-and-ubuntu-2204-matrix-completion-2026-10-12)).

The provider configures native automatic updates; it never installs anything
itself. It needs the root-local opt-in `os_update_provider: {"enabled": true}` in
`executor.json` and the native `unattended-upgrades`, `needrestart` and
`update-notifier-common` packages (a missing one is a precondition failure
naming it). A signed policy owns exactly four objects:
`/etc/lindm/os-update/policy.binpb` (0600, the runner's validated policy),
`/etc/systemd/system/lindm-os-update.timer` (one `OnCalendar=` per weekday in the
policy's IANA zone, `Persistent=true`),
`/etc/systemd/system/timers.target.d/lindm-os-update.conf` (`Wants=` the timer)
and `/etc/apt/apt.conf.d/99lindm-os-update`
(`APT::Periodic::Unattended-Upgrade "0";`). The last one stops the native
`apt-daily-upgrade` run from installing outside the window; `apt-daily`'s
metadata refresh keeps running. Any of these paths present but unowned refuses
the policy, which never adopts files. Release stops the timer, removes exactly
these files and reloads systemd, which restores the distribution's periodic
behaviour. The package's tmpfiles entries create the parent directories. The
plan predicts the effective `APT::Periodic::Unattended-Upgrade` with the
candidate override in place. It uses a private copy of `apt.conf.d` named by
`Dir::Etc::parts` in a temporary `APT_CONFIG`. A later part or
`/etc/apt/apt.conf` that keeps the value non-zero is refused before any effect
([provider](../../internal/agent/osupdateprovider/apt_candidate_linux.go)).
A provider effect takes the runner's lock (`/run/lindm/os-update/run.lock`)
without waiting, before its ownership effect begins, and holds it until the
completion is recorded. While a window, patch-now or status run holds it, the
change is refused `NATIVE_BUSY` with no effect and the server retries. A
package transaction never races an effect, and a run that starts meanwhile
waits for the effect to finish.

The static `lindm-os-update.service` runs `lindm-agent os-update run` as root
without a sandbox, because the package manager writes the whole system
([runner](../../internal/agent/osupdate/backend_linux.go)). A start outside an
open window, such as a `Persistent=` catch-up, records `SKIPPED_OUTSIDE_WINDOW`.
Inside it the runner calls `apt-get update` and lists pending updates from
`apt-get -s dist-upgrade` `Inst` lines; a candidate counts as security when one
of its origin archives ends in `-security`. It then applies the deferral and runs
`unattended-upgrade -v` with a per-run `APT_CONFIG`. That file points
`Dir::Etc::main` at a per-run file, which APT reads after every part. The file
`#clear`s and sets `Unattended-Upgrade::Allowed-Origins`. SECURITY means
`${distro_id}:${distro_codename}-security` and the ESM apps/infra security
origins; ALL adds `-updates` and the release pocket. Deferred names go to
`Package-Blacklist`, and `Automatic-Reboot` is forced to `false`.
`NEEDRESTART_MODE=a` and `needrestart -r a -l` restart affected services. Reboot
required means `/run/reboot-required` or a needrestart kernel status
(`NEEDRESTART-KSTA`) of 2 or 3. Native unattended-upgrades defaults stay in
force: on battery, on a metered connection or for phased updates a run can
succeed with nothing installed.

Deferral is per package name and architecture. It counts calendar days in the
window's zone from the window start at which the update was first seen pending.
Patch now (below) ignores both window and deferral. systemd skips a window start
that does not exist on a daylight-saving spring-forward day, so that day's
window does not open. The independent optional `rebootWindow` uses the same IANA
zone, spring-gap, first-fold and elapsed-duration rules. A running package
transaction is never stopped at either window end. With reboot mode `SCHEDULED`,
logind receives a reboot instant inside that window and no later than the first
pending reboot's `maxDelayMinutes` deadline. With no restart window or employee
deferral, the initial instant remains completion plus the maximum delay.
Otherwise the first eligible instant is at least five minutes after completion.
No eligible instant produces `no_window_before_deadline`; an expired deadline
produces `reboot_deadline_elapsed`, never an out-of-window reboot.

`employeeDeferral` authorizes 1–10 postponements of 5–1440 minutes each, bounded
by that same deadline and the next eligible window instant. The installed
`lindm-session.service` displays the action to an active, unlocked local graphical
session. Its separate executor socket checks kernel peer credentials and logind;
no caller-selected restart time is accepted. The protected runner state retains
the accepted schedule and count separately from a durable pending native attempt.
Fresh logind observation commits an accepted attempt or preserves the original
schedule after rejection; an ambiguous reply is reconciled without replay.
A clicked deferral that races the update/status lock receives a retryable error,
not an acknowledgement. The helper reports “Restart deferral not confirmed”
and retains the same request and session-bound prompt until the lock is free;
the original native restart still applies meanwhile.
Executor restarts retain the deadline, count and request identity. Later update
policies do not rewrite an outstanding reboot's original policy or deadline.
Another boot invalidates the notice. Corrupt state refuses execution rather than
resetting the deadline. An existing foreign schedule, shutdown preparation or
blocking inhibitor refuses deferral. Deferral invalidates cached patch status
before its native effect, so inventory requests an offline refresh instead of
reporting the old schedule/count for the cache lifetime. The employee socket is
also enabled for `allow_patch_now` without scheduled OS-update management.
Assistance admission invalidates employee prompts and blocks simultaneous
deferral. Without employee deferral, graphical notifications still use the
logind UID/GID child and `/run/user/<uid>/bus`; all scheduled reboots retain wall
notices. Device patch status reports the owned restart deadline and used count.

The Ubuntu 24.04.5 arm64 GNOME/Wayland native KVM lane passed on 2026-10-11
with enrolled Secure Boot. Its signed independent windows scheduled 20:20 UTC;
the actual employee notification action deferred to 20:25 UTC, preserved the
21:51:02 UTC deadline across an executor restart and produced a changed boot.
The prerequisite was a vendor-authenticated reinstall of the exact running
`linux-image-6.8.0-146-generic=6.8.0-146.146`, not a newer/security-version upgrade
or a synthetic reboot marker. The complete receipt, including successful
mandatory grant/device cleanup, has SHA-256
`f955a1f336558b3894c270a3127ba1b0cdbc54a2374488978aeeff1350ff59e9`;
[verification](../verification.md#independent-reboot-window-and-employee-deferral)
records the source, package, signature, real desktop captures and qualification
boundaries. Real-clock DST and physical employee input remain unqualified.

`lindm-os-update-status.service` (`PrivateNetwork=yes`) computes the patch
status offline from the cache: pending security/total/deferred counts, the
reboot oracle, metadata time, the last run and success, and a pending logind
reboot. The executor publishes it as inventory `patch_status` and starts the
unit when the status is stale. Empty `/var/lib/apt/lists` reports
`native_metadata_unavailable`, never zero updates. The metadata time is the
newest `*Release` modification time, which APT sets to the server's
`Last-Modified`, not the local refresh time. Evidence and limits are in
[verification](../verification.md#os-update-policy-patch-now-and-patch-status).

## Device actions

Logind is the session/power boundary, not a shell wrapper. Lock requests require
remaining graphical sessions to acknowledge `LockedHint`; acknowledgment is not
physical desktop visibility or boot lock. Termination is irreversible. The lab's
Ubuntu GNOME setup uses `/etc/gdm3/custom.conf`, `gdm3` and session `ubuntu`; KDE needs
its own observation ([sessions](../../internal/agent/actionprovider/sessions_linux.go#L38),
[lock evidence](../../internal/agent/actionprovider/network_linux.go#L257),
[GDM recipe](../../internal/vmlab/encrypted_installer_linux.go#L232)).

Power operations inspect native capability, pending schedules and inhibitors; they
do not replace an existing schedule or fall back to inhibitor-bypassing calls
([power provider](../../internal/agent/actionprovider/power_linux.go#L172)).
Nftables quarantine uses an automatically expiring kernel active-set fence; transport
loss remains unknown, not successful containment/reachability proof
([network provider](../../internal/agent/actionprovider/network_linux.go#L260)).
Use the exact Ubuntu24 power/refresh and device-action evidence in
[verification](../verification.md); service dispatch alone does not qualify account
lock, desktop lock, encryption, recovery or wipe. Destructive targets require fresh
inventory, exact signed identity and separately authorized provisioning.

Patch now (`device.patch-now.v1`, local opt-in `allow_patch_now`) writes a
deterministic request to `/run/lindm/os-update/patch-now.binpb` (root 0700
directory) after the signed gate. It then starts the static
`lindm-os-update-now.service` without waiting, and the action proves only that
the native run started. The installation outcome is the patch status `last_run`
carrying the action ID. A running window or patch-now run refuses a second one
as `patch_run_in_progress`.

## Desktop session helper and remote assistance

The package installs the user unit `/usr/lib/systemd/user/lindm-session.service`.
Configure runs `systemctl --global enable`, so the unit starts with
`graphical-session.target` at the next graphical login. The user manager reaches
that target in the GDM GNOME/Wayland session (observed active in the 24.04
autologin session). The package also installs the conffile
`/etc/xdg/autostart/lindm-session.desktop` for session managers that never
activate that target; GNOME's systemd-managed session skips it
(`X-systemd-skip=true`).

The executor serves `/run/lindm-session/session.sock` only when
`/etc/lindm/executor.json` sets `remote_assistance.enabled`. The packaged default
is disabled. The tmpfiles directory is `root:root` 0755.

The DEB declares these as `Recommends`, not hard dependencies, so server installs
stay lean:

- `gstreamer1.0-pipewire`, which provides `pipewiresrc`.
- `gstreamer1.0-plugins-good`, which provides `vp8enc`, `rtpvp8pay` and
  `rtpstreampay`.
- `gstreamer1.0-tools`, which provides `gst-launch-1.0`.

The helper checks all eight elements with `gst-inspect-1.0`. If any is missing it
ends the session as `UNAVAILABLE` with detail `gst_element_missing:<name>`. There
is no X11 or screenshot fallback.

The 24.04 desktop golden used for qualification had these components:

- GNOME 46.0.
- xdg-desktop-portal 1.18.4 and xdg-desktop-portal-gnome 46.2, with ScreenCast v5
  (source types and cursor modes 7) and RemoteDesktop v2 (device types 7).
- GStreamer 1.24.2.
- gnome-shell notifications with the `actions` capability.

New assistance records also capture `mutter-common` and, on 24.04, the
`libmutter-14-0` ABI package version, so the compositor, portal and capture-stack
tuple is explicit.

In the RemoteDesktop dialog, keyboard and pointer access is the **Allow Remote
Interaction** switch, which is off by default. Sharing without it grants view only.

When the screen locks, GNOME 46 closes the portal session before logind sets
`LockedHint`. The executor's five-second portal-close settle window records
`SESSION_LOCKED`.

The first login on the golden shows the release-upgrade prompt, and idle lock is
enabled after five minutes. The lab disables both for the session; the product does
not change them.

The arm64 lane uses the independently signed encrypted installer manifest
`lab/images/ubuntu-noble-encrypted-arm64.json`, package-pinned AAVMF and native
KVM on an SSH lab host. It now defaults to a split topology: the controller
workstation owns PostgreSQL, `lindmd` and TURN; QEMU and operator Chromium stay
on the Spark. Guest device and relay traffic leaves QEMU user NAT over the
routed LAN. Admin HTTPS and TURN TCP use SSH reverse forwards; the owner's
browser uses corresponding local forwards to the controller. `-colocated`
retains the explicitly host-local fixture used by the older records below.
Remote browser prerequisites are user-owned pinned Node and
package-lock-selected Playwright Chromium; the lane does not install system
libraries. See the [held-demo instructions](../engineering.md) for access,
secret custody and choosing a free Spark without changing manifest identity.

Held Ubuntu 24.04 demos derive the complete Ubuntu OSV export from the platform
registry, scoped to the guest's amd64/arm64 architecture, with online refresh and
a one-day maximum age. The first production refresh is bounded to 4 GiB and two
hours and uses the controller's persistent `advisory-cache` with ETag/
Last-Modified revalidation and content-digest verification. Cached bytes alone
never establish current vendor freshness. The running banner waits for a current,
non-unknown device evaluation and reports real paginated finding counts.
Rows without maintained feed facts and unsupported architectures fail explicitly.

The [persistent organization demo](../engineering.md#persistent-organization-demo)
uses an encrypted Ubuntu 24.04 GNOME Engineering device and the console's signed
APT installation command. Its requested TPM bind is separately admitted against
the exact architecture's maintained encryption ledger record; aarch64 assistance
qualification alone never admits TPM binding. Missing qualification is a startup
gate, not a silently passphrase-only device.

Qualified: virtual x86_64 and native-KVM aarch64 GNOME/Wayland consent, view,
control, operator and local stop, decline, portal cancel and lock termination,
with audit, in
[`ubuntu24-assistance-06` and `ubuntu24-aarch64-assistance-04`/`-05`](../verification.md#built-in-graphical-remote-assistance-l09-l12).
The arm64 run used GNOME Shell 46.0, Mutter 46.2
(`46.2-1ubuntu0.24.04.18`), portal 1.18.4 / portal-gnome 46.2, PipeWire 1.0.5,
GStreamer 1.24.2 and host-local Chromium 156.0.8078.4, with console TURN over
TCP and guest TURN over UDP. An SSH-native held demo also passed startup,
remote guest screenshot response and clean teardown with credentials excluded
from returned evidence. The
[split held smoke](../verification.md#routed-split-topology-assistance) additionally
observed Spark-to-workstation device connections, real advisory publication and
evaluation, screenshot response and complete process/listener/database teardown.
The same split lane passed all five assistance scenarios on `dgx20`, with the
guest's device/media traffic routed over the LAN to the workstation and the
console selecting the SSH-forwarded TURN TCP URL; the linked record binds the
route, media statistics, expected end causes and audit evidence.
This is not a physical ARM desktop claim.
Ubuntu 26.04.1 GNOME 50 Wayland passed the same five scenarios on x86_64 and on
native-KVM aarch64 (split topology, dgx21)
([26.04 deltas](#native-deltas-from-2404)). Not qualified: KDE/Kubuntu, X11,
physical displays or multi-user seats.

### Commercial assistance capability roadmap

The [capability contract](../product-specification.md#remote-assistance-capabilities)
defines each user story, consent, off/limited/on policy, per-role permission and
audit. Ubuntu 24.04 GNOME 46 x86_64 Wayland is an initial target, not a completed
capability suite. Clipboard uses Clipboard on the existing RemoteDesktop session;
the frontend, GNOME backend and Mutter source versions must all support that path.
No upgrade, private compositor API or X11 utility is substituted for a missing
portal interface. Ubuntu 26.04 and ARM need separate capability evidence.

[Pinned upstream inspection](../architecture.md#inspected-gnome-portal-sources)
finds Clipboard v1 support in portal 1.18.4, portal-gnome 46.2 and upstream
Mutter 46.0; GNOME 46 is not generically clipboard-unsupported. Request it before
RemoteDesktop Start and require `clipboard_enabled=true`; GNOME presents a
separate **Allow Clipboard Access** switch. The 46.2 backend forwards MIME types
as `(as)` instead of the public `as` shape, requiring narrowly typed normalization
after observing the distro wire behavior. Version checks alone miss this quirk.
Some older FD/backend errors return success, so only independent nonce checks
establish transfer success. Native tests must also record `libmutter-14-0` and
`mutter-common` plus distro patch correspondence: prior GNOME Shell version
evidence did not identify the installed Mutter build.

Special keys/layouts use the RemoteDesktop keyboard grant; monitor selection
requests multiple ScreenCast monitor sources on that same session and may choose
only returned streams. Full screen/scaling change the browser display only.
Messages use GNOME notifications for the bound user. File transfer is off by
default, uses Downloads for accepted incoming files and local FileChooser for
outgoing files; hashes, limits and per-file consent remain independent of control.
Reconnect requires fresh consent after reboot/logout. Recording requires visible
disclosure, separate permission, encrypted storage and retention.

All added capabilities are
[not run](../verification.md#commercial-assistance-capability-qualification).
Required native evidence includes clipboard nonces in both directions where the
portal supports them, special-key/layout guest effects, two-head virtio-gpu monitor
and pointer checks, visible message/file notifications, transfer hashes, real
reboot/logout re-consent and encrypted-recording retention. Elevation never bypasses
polkit; annotation/audio need separate native grants. KDE/Kubuntu and X11 do not
inherit GNOME evidence, and unattended implementation/KDE qualification await
parent confirmation.

## Advisory feeds

Two-human advisory exceptions use the shared control-plane approval mechanism;
there is no Ubuntu-specific exception executor. The disposable
`lab vm dispatch -advisory-exceptions -local-authority` lane requires a real
affected vendor finding from the installed Ubuntu agent and records independent
human approval, refusal and exact-retry evidence. It does not manufacture a
finding when the installed package is already fixed. See the
[L11 evidence ledger](../verification.md#l11-distro-advisory-classification) for
qualification status; server-host and guest platforms are recorded separately.
The source-`4823cb85` arm64 KVM run passed on an Ubuntu 24.04.5 guest and
Ubuntu 24.04.4 control-plane host: receipt
`artifacts/org-exception-approval/ubuntu24-arm-native-precision.json`, SHA-256
`fccaaf6a248e9e3fa189fd8802215bf9e7cd11919978ef2293dc6db3c3b29f38`.
It binds the actual installed kernel-module vendor finding to independent
approval and a consumed, exactly retryable exception, including pre-effect
refusals. It does not claim a physical installation or a corrected package.
The combined runtime-authority checkpoint `7bfe853f` additionally passed enabling
this gate after requester sign-in, with the same original session observing
revision zero to one, refusing unapproved acceptance and completing independent
review. Its receipt `ubuntu24-arm-runtime-approval.json` in the same directory has
SHA-256 `ab45a6f6bd21399d516789d5803d007e2b694316c0c12c103fea970a83245b6a`;
the ledger distinguishes this qualification checkpoint from independent landings.

Ubuntu assessments use native dpkg versions and vendor backports, not upstream
version ordering alone. The maintained full archive is
`https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip`; a stale
`Ubuntu:24.04:LTS` export or an arbitrary mirror named `all.zip` is not a replacement
for canonical complete-source coverage. Completeness remains scoped to configured
product/release/architecture and source mapping
([coverage decision](../../internal/advisory/feed/osv_archive.go)).

A real upstream malformed record, `UBUNTU-CVE-2023-25812`, contains
`pkg:deb/ubuntu/golang-github-minio-minio-go?arch=src?distro=noble`.
The second `?` must not be repaired into a new package identity. The parser rejects
that **record atomically**, retains explicit ID/reason/package-name rejection metadata
and conservative unknown source/binary markers. Valid siblings can publish; a rejected
record is not evidence that the affected package is clean. Unscoped rejection degrades
snapshot completeness. See [record atomicity](../../internal/advisory/feed/osv_archive.go)
and [exact regression](../../internal/advisory/feed/osv_rejections_test.go#L17).

Archive decoding uses at most four workers (and no more than `GOMAXPROCS`), with
one reusable raw-document buffer per worker. The publisher consumes results in
original ZIP order: callback delivery, rejection manifests and normalized claim
bytes do not depend on scheduling. Each worker retains at most two bounded
record results, including the record being consumed; cancellation joins every
worker before temporary archive cleanup. This changes throughput, not the
4 MiB record, archive expansion, claim-count or rejection bounds.

A complete 70,180-entry Ubuntu export census found 1,416 distinct CVEs per
advisory at the maximum (`USN-8728-1`, `-2`, `-3`). The former 1,000-CVE ceiling
incorrectly rejected legitimate kernel notices. The shared ceiling is now 2,048,
44.6% above that observed maximum; the per-entry and normalized byte limits still
bound memory. The exact 451,752-byte vendor notice is preserved as
[`ubuntu-USN-8728-1.json`](../../internal/advisory/feed/testdata/ubuntu-USN-8728-1.json),
SHA-256 `e3ac740c07cc0c15e50c63bfc71cf235070eaf1b4cc9125c15dfae0dc88f5a54`,
and [the regression](../../internal/advisory/feed/large_cves_test.go) requires all
1,416 CVEs without rejection or unknown classification. Census:
[`ubuntu-osv-cve-cardinality-20261010.json`](../../artifacts/ubuntu-osv-cve-cardinality-20261010.json).
SHA-256 `a10f81832aaed3921eb996a766aff5d47f0b88648db4580b66bdc3ceba14a384`.

An initial measured full-source publication completed on 2026-10-10: 2,157,214
unique claims, ten rejected records, 217.64 seconds wall time and 99,948 KiB peak
RSS, with no swaps. Publication was atomic with zero remaining batch rows and
reported complete **scoped** coverage; rejected packages carried unknown assessments.
This initial performance record predates correction of six legitimate kernel notices
incorrectly rejected by the former CVE-count bound.
Evidence: `artifacts/ubuntu-advisory-stream-20261010.json`, SHA-256
`87cc2dedc998bbd4214caa371a6c960710139a91a49c968d15c423d4b09c6aa4`.
The source archive digest is
`c45c2791452b55990d08ae1ba4962a712081d6e0134bc5c5c6707d09adf50aba`.
Corrected republication admitted 2,157,314 unique claims with only the four malformed
MinIO records rejected, zero legitimate kernel-notice rejections, current complete
scoped coverage and zero batch rows. Publication took 213.69 seconds with
102,068 KiB peak RSS and no swaps. Retired-generation cleanup reached its separate
30-second deadline after the successful switch; invisible retired rows require
the maintained cleanup continuation. Corrected evidence:
[`ubuntu-advisory-stream-cve2048-20261010.json`](../../artifacts/ubuntu-advisory-stream-cve2048-20261010.json),
SHA-256 `17f2bb24327bcfc6e2bbe45cb217ac8ffa6b9eadb2adbcc6ebe6c0d2703b1c9b`.
The maintained follow-up uses migration `00013` and a durable cleanup queue:
5,000-row transactions resume on startup, explicit refresh and the periodic worker.
Ten-minute staging leases fence expired writers; historical inactive generations
receive 35 minutes' migration grace. Isolated PostgreSQL integration coverage
exercises cancellation/resumption, active-generation protection, concurrent cleanup
and expired-writer publication refusal
([regressions](../../internal/advisory/publication_cleanup_integration_test.go)).
Applying the migration and draining this demo's old rows remains gated on its
owner-approved bundled migration/restart; no direct row deletion was used.
This proves feed publication, not authenticated device-findings evaluation or
scheduled refresh in the already running server. The record explicitly leaves those
and new rejection UI fields pending the approved bundled restart. Keep feed and
inventory freshness independent, as required by [verification](../verification.md).

The native `advisories` matrix lane (`lab vm advisories`) runs on 24.04 and 26.04:
it refreshes the registry's OSV `all.zip` export through the production pipeline,
waits for the server's evaluation of the enrolled agent's snapshot, requires every
finding to name an installed dpkg package, and cross-checks a real vulnerable/fixed
pair from the publication with native `dpkg --compare-versions` (vendor versions are
positional shell data). The registry's 4 GiB archive allowance sizes the lab refresh
(45 minutes, for slow controller links; the recorded refreshes took 89–307 s).
Qualified on both architectures for both releases
([records](../verification.md#ubuntu-24042604-matrix-completion-2026-10-12)):
native matching, not complete device coverage.

## Lab

Use maintained `lab images fetch` and `lab images verify` with the exact manifests,
then the relevant `lab vm inspect`, `lifecycle`, `dispatch`, `updates` or `encrypted`
lane. Keep runner/source/package/image hashes and native firmware/TPM/storage/desktop
settings with each record. Cloud smoke is not installer acceptance. The ordinary
cloud fixture masks native automatic-update timers; stock acceptance removes this
fixture override ([fixture distinction](../../internal/vmlab/vm_linux.go#L221)).
Device-action lanes stop and mask the same units in their disposable encrypted
clone before installing action prerequisites: the persistent
`apt-daily-upgrade.timer` can start `unattended-upgrade` within an hour of the
clone's first boot, and waiting for it could exhaust the prerequisite bound (24.04
aarch64 timed out there four times, then passed once quiesced;
[records](../verification.md#ubuntu-24042604-matrix-completion-2026-10-12)).
The encrypted golden's first-boot posture check permits an explicitly absent TPM;
that is separate from installing the TPM-capable boot stack. Failed native checks
now identify root ancestry, TPM version, SecureBoot or SetupMode independently
and retain recognized native stderr reasons while redacting guest paths
([posture checks](../../internal/vmlab/encrypted_smoke_linux.go#L116)).
The 2026-10-10 acceptance attempt at
`$HOME/.cache/lindm-acceptance-20261010-01/acceptance.json` failed the earlier
combined posture check (exit 1, 105 stderr bytes); it does not identify which
prerequisite failed or establish an encrypted-guest acceptance pass. The improved
diagnostics have not yet been exercised by that record.
A browser dependency installation or prepared browser baseline does not qualify a
native desktop journey. Preserve explicit egress/air-gap mode and owned guest cleanup;
never reuse development credentials as deployment instructions.

The browser-only correction record
`$HOME/.cache/lindm-acceptance-browser-correction-20261010-01/acceptance.json`
(SHA-256 `e846e5944651f2c8926a2593ef847a267b08ccd680c1ddf8aee71b513a00f2db`)
passed real owner enrollment, sign-in/sign-out/fresh sign-in, one-time grant and
provisioning-token issuance in Chromium 156.0.8078.4 and Firefox 157.0.1 with
geckodriver 0.37.1. Owned fixture cleanup passed. Firefox's native WebDriver
authenticator requires disabling `security.webauth.webauthn_enable_usbtoken`
and enabling `security.webauth.webauthn_enable_softtoken` in its disposable
automation profile: the
[157.0.1 native dispatcher](https://hg.mozilla.org/releases/mozilla-release/raw-file/FIREFOX_157_0_1_RELEASE/dom/webauthn/authrs_bridge/src/lib.rs)
otherwise chooses physical USB before the native test-token manager.
The [runner](../../web/acceptance/drivers.mjs) uses native CTAP2 with user
verification, not an injected page credential implementation.

That record deliberately remains failed overall: Ubuntu's WebKitGTK
`2.52.6-0ubuntu0.24.04.1` driver returned `unknown command` for the native
virtual-authenticator endpoint. Its secure HTTPS page reported
`PublicKeyCredential` and both JSON option parsers absent. The real console
capability guard therefore prevented even the password POST; the password
phase is explicitly unqualified, not an Origin/Referrer or sign-in pass.
Masked failure screenshots and these capability flags are retained in the
record's evidence directory. Installing the maintained
[browser prerequisites](../../web/acceptance/install-browsers.sh) does not
remove that native WebKit build prerequisite or qualify Ubuntu desktop,
native profile application, storage selection, or a full release.

A subsequent maintained browser-only run at
`$HOME/.cache/lindm-acceptance-origin-20261010-02/acceptance.json`
(SHA-256 `fac61c6f48c46c3420bccab821b64ef6d42fe22794e0b34af675e56afff2654a`)
again passed the Chromium and Firefox journeys, with owned cleanup complete.
WebKit additionally passed the separate
[same-origin invalid-request diagnostic](../../web/acceptance/origin-post.mjs):
the real document returned HTTP 200, `Referrer-Policy: same-origin` and its
actual self-only connection CSP. The console's own loaded `beginLogin` client
sent a secret-free invalid request and received HTTP 400, not the origin
gate's HTTP 403. This establishes that browser's origin-policy acceptance,
not valid-password or passkey authentication. Its native authenticator remains
unavailable and its ordinary sign-in UI still makes no password POST. No
credential API, request headers, referrer setting, or application capability
guard was replaced.

Release policy since 2026-10-10: that missing WebDriver virtual-authenticator
command is an upstream WebKitGTK prerequisite. The record marks WebKit's passkey
phase `unqualified_upstream_prerequisite` and it no longer fails the release
gate. The WebKit Origin/Referrer diagnostic remains mandatory; any other WebKit
authenticator failure still fails the gate.

### Runtime organization authorization

The maintained `lab vm dispatch -runtime-authorization -local-authority` passed
on `dgx21` with an Ubuntu 24.04.4 arm64 server and an actually enrolled Ubuntu
24.04.5 arm64 guest (kernel `6.8.0-142-generic`). Source checkpoint
`34f74f75f4f69343cc072ba626cee9673bb7826d` and the
[runtime authority receipt](../verification.md#runtime-authorization-and-organization-accounts)
bind the signed package, server and runner. The record
`$HOME/.cache/lindm-org-runtime-20261011/runtime-authorization-arm64-a7.json` has
SHA-256 `6bf4347354847e86106a758f51047798c4123012db5dfbee9fc313c46e3838e7`.

All thirteen checks passed: two-human runtime CAS/replay, changed-request refusal,
persisted precedence after changed bootstrap config and server restart, another
real server instance, enrolled-device scope/session fencing, browser-session
organization account apply including partial shown-once secrets, CLI runtime
apply without browser account authority, and the six audited policy revisions.
The native fixture must forward the actual dynamic signed console origin as well
as the device endpoint; a fixed legacy enrollment alias does not qualify the normal
CLI. Earlier missing-firmware and transport failures are retained in verification.

This is native aarch64 KVM/QEMU 8.2.2 with pinned AAVMF
`2024.02-2ubuntu0.10`, virtio-blk, Secure Boot disabled/SetupMode, no TPM and no
desktop. It does not expand the server deployment matrix to arm64 packages or
claim physical or graphical qualification. Runtime authorization has no
distribution-specific agent effect requiring a separate Fedora run.

## Gaps

- Desktop GNOME/KDE, aarch64, physical hardware and air-gap gates beyond the amd64
  offline-bundle lane (site DNS/NTP/IdP, server installation and restore from a
  bundle) remain independent; do not extrapolate from the cited x86_64 records.
- The encrypted read-only transient prerequisite is not yet a published 0.1.2 inventory
  or selectable-target proof at this handoff.
- Agent self-update and systemd service lanes do not qualify the new generic native
  package provider, rollback, all device actions or LSM policy. The release-upgrade
  lane covers cloud 24.04→26.04 only, not desktop or encrypted-root upgrades.
- Stock initramfs/passphrase, TPM-token unlock, recovery rotation and wipe require
  separate evidence. Missing target identity is a safety refusal, not permission to
  choose `/dev/vda` manually.
- Feed freshness and malformed-record coverage must remain visible. Successful
  full-source publication is not proof of authenticated device exposure evaluation.
