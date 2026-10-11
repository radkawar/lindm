# Linux Mint

Tier 1, desktop-first: current Linux Mint release, Cinnamon edition, x86_64. Full
parity with Ubuntu 24.04 is required
([tiers](../product-specification.md#supported-os-tiers)). Mint is built on an Ubuntu
LTS base, but **no Ubuntu evidence carries over** to it.

## Supported versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Linux Mint 22.3                                                                                                                            |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| inventory         | implemented                                                                                                                                |
| lifecycle         | implemented                                                                                                                                |
| dispatch          | implemented                                                                                                                                |
| packages          | implemented                                                                                                                                |
| accounts          | implemented                                                                                                                                |
| sysctl            | implemented                                                                                                                                |
| definitions       | implemented                                                                                                                                |
| password          | implemented                                                                                                                                |
| firewall          | implemented                                                                                                                                |
| encryption        | implemented                                                                                                                                |
| wipe              | implemented                                                                                                                                |
| report-loss       | implemented                                                                                                                                |
| lock              | implemented                                                                                                                                |
| recovery-sanitize | implemented                                                                                                                                |
| self-update       | implemented                                                                                                                                |
| assistance        | gated: portal_screencast_unavailable: xdg-desktop-portal-xapp/-gtk implement no ScreenCast or RemoteDesktop; lindm has no X11 capture path |
| advisories        | partial: vendor feed unavailable for Linux Mint packages                                                                                   |
| os-update         | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release                                    |
| release-upgrade   | gated: release upgrade is not implemented                                                                                                  |

<!-- END GENERATED platform-capabilities -->

Linux Mint 22.3 "Zena" Cinnamon on x86_64 only; Mint publishes no arm64 build.
Records are listed under [Lab records](#lab-records); a cell without a record is
not qualified.

## Identity and base

The installed system reports `ID=linuxmint`, `VERSION_ID=22.3`,
`VERSION_CODENAME=zena`, `UBUNTU_CODENAME=noble` and `ID_LIKE="ubuntu debian"`
(observed in the lab golden). The registry row `linuxmint-22.3` names
`ubuntu-24.04` as its explicit `Base`; providers and lab scripts select base
tooling from that row, never from `ID_LIKE`. Lab guest scripts that switch on
os-release receive the base identity through `nativeScriptIdentity`
(`internal/vmlab/vm_distribution_linux.go`), so the Mint guest runs the Ubuntu
24.04 branches while inventory and lane records keep Mint's own identity.

## Repositories and pinning

Observed on the golden: `/etc/apt/sources.list.d/official-package-repositories.list`
(one-line format) lists `packages.linuxmint.com zena main upstream import backport`
plus the Ubuntu `noble`, `noble-updates`, `noble-backports` and
`security.ubuntu.com noble-security` suites. The Mint archive publishes
`Release` + `Release.gpg` (no `InRelease`) with `Origin: linuxmint`,
`Label: linuxmint`, `Suite/Codename: zena`, `Version: 22.3` and
`Architectures: i386 amd64`; index files are stored uncompressed. Mint's key is
installed both as `/etc/apt/trusted.gpg.d/linuxmint-keyring.gpg` (identical to
`/usr/share/keyrings/linuxmint-keyring.gpg`) and as the ASCII-armored
`/etc/apt/trusted.gpg.d/linuxmint.key.asc`. `/etc/apt/preferences.d` holds
`nosnap.pref` (`Package: snapd`, `Pin: release a=*`, `Pin-Priority: -10`),
`official-package-repositories.pref` (`o=linuxmint,c=upstream` at 700) and
`official-extra-repositories.pref` (origin `build.linuxmint.com` at 700).
The ISO ships `mintupdate 7.1.4` and `timeshift 25.12.4+zena`; their effect on
OS patch policy and wipe/rollback remains unqualified.

Choose Linux Mint in the console to install and enroll from the customer's own
`lindmd` HTTPS `/repo/apt` endpoint. The one command authenticates the repository
signer and server/bootstrap trust and writes a dedicated deb822 `Signed-By`
source. No external agent repository is used. Missing artifacts produce an
explicit setup remedy; successful Ubuntu installation does not qualify Mint.
See the [install runbook](../security-and-operations.md#enrollment-installation-from-your-server).

## Installer and golden recipe

Media: [`linuxmint-22.3-cinnamon-amd64.json`](../../lab/images/linuxmint-22.3-cinnamon-amd64.json)
and [`linuxmint-22.3-cinnamon-encrypted-amd64.json`](../../lab/images/linuxmint-22.3-cinnamon-encrypted-amd64.json)
pin the same ISO (3091660800 bytes, SHA-256
`a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4`) through the
detached-signed [`sha256sum.txt`](https://pub.linuxmint.io/stable/22.3/sha256sum.txt),
signer `27DEB15644C6B3CF3BD7D291300F846BA25BAE09` ("Linux Mint ISO Signing Key",
provenance [linuxmint.com/verify.php](https://linuxmint.com/verify.php)). The
signature was verified (good, made 2026-01-11) before pinning.

Mint ships only Ubiquity (`ubiquity 24.04.3+mint19`); there is no Subiquity
autoinstall. The maintained unattended path is a debconf preseed with casper's
`noninteractive` argument: `start-ubiquity-dm` then runs `ubiquity
noninteractive` instead of the live session
([upstream](https://github.com/linuxmint/ubiquity/blob/master/bin/start-ubiquity-dm)).
The remaster changes only `/boot/grub/grub.cfg` (appending
`noninteractive noprompt file=/cdrom/lindm-seed/preseed.cfg` and the serial
console, after dropping the vendor's trailing `--`, `quiet` and `splash`) and adds
`/lindm-seed/preseed.cfg`; vendor kernel, initrd, shim and GRUB are untouched
(`internal/vmlab/mint_installer_linux.go`, installer kind `ubiquity` in
`internal/platform/lab.go`).

Native findings that shaped the recipe:

- `time/zone string UTC` is rejected by Ubiquity ("Could not understand
  timezone"); `Etc/UTC` is required.
- `grub-installer/force-efi-extra-removable` makes Mint's grub-installer pass
  `--force-extra-removable`, which Noble's `grub-install` rejects and aborts the
  install. It is omitted; Ubiquity still writes `EFI/BOOT/BOOTX64.EFI`, which the
  first-boot probe requires.
- The noninteractive frontend only reboots on success
  (`ubiquity/reboot=true`) and neither reboots nor runs
  `ubiquity/failure_command` after a failed step, so the installer QEMU runs with
  `-no-reboot` and a failure ends at the 45-minute installer deadline.
- `ubiquity/success_command` runs in the live system after Ubiquity's own
  cleanup; the recipe binds `/dev`, `/proc`, `/sys`, efivars and `/run` into
  `/target`, chroots, and always unmounts them. It installs `openssh-server`
  (and `cloud-init` for the unencrypted golden) from the signed archives, writes
  the lab SSH material and the root-only installer source marker, locks the
  random installer password, and restores `umask 022` after the credential
  writer (`umask 077`) so the emptied `/etc/machine-id` stays world-readable.
- The unencrypted golden validates on a fresh-NVRAM boot: NoCloud SSH, `ID`,
  `VERSION_ID`, `UBUNTU_CODENAME=noble`, source marker, ext4 root, dpkg/apt,
  sudo, `EFI/BOOT/BOOTX64.EFI` and `/usr/share/xsessions/cinnamon.desktop`.

The encrypted variant uses Ubiquity's `partman-auto/method crypto` (LVM on LUKS,
the installer's "Encrypt the new installation"), serial console GRUB, baked lab
SSH keys and a lab-only LightDM drop-in
`/etc/lightdm/lightdm.conf.d/90-lindm-lab.conf` (`autologin-user=lindm-lab`,
`autologin-session=cinnamon`). `-tpm-boot` replaces initramfs-tools with
Ubuntu's dracut stack exactly as on Ubuntu 24.04.

## Inventory oracle

The independent Flatpak oracle now lists system applications through
`sudo -n` with the agent's clean environment. As the unprivileged lab user, the
same `flatpak list --system --app` on Mint failed natively while the root agent
succeeded, which the lane reported as a `details.flatpak.status` mismatch;
regression `TestNativeFlatpakTruthUsesAgentPrivilegeAndEnvironment`.

## Desktop, lock and assistance

Cinnamon (X11) under LightDM/slick-greeter. Assistance is gated:
`portal_screencast_unavailable` (the ISO's `xdg-desktop-portal-xapp` and
`-gtk` provide no ScreenCast/RemoteDesktop portal and lindm has no X11 capture
path). Lock behavior (`cinnamon-screensaver`, logind `LockedHint`) is owned by
the desktop-session lane and recorded there.

## Lab records

None yet.

## Remote assistance capability roadmap

Mint/Cinnamon inherits no Ubuntu GNOME portal qualification. The
[capability contract](../product-specification.md#remote-assistance-capabilities)
defines all tiers' consent, off/limited/on policy, role permissions and audit.
Require a reliable native lock/stop boundary before admitting any capability;
Clipboard must use the existing RemoteDesktop interface and uploads must use
FileChooser, never X11 clipboard/capture utilities. Keys/layouts, two-head display
selection, messages, clipboard, files, reconnect, recording and Tier 3 are
[not run](../verification.md#commercial-assistance-capability-qualification).
Keep missing native mechanisms explicitly gated. Qualify Cinnamon with its actual
portal backend and independent nonce/hash/guest screenshot evidence; unattended
and KDE work require parent confirmation.

## Known gaps

- Vendor advisory feed: none for Mint packages (registry `partial`).
- `mintupdate` automatic updates and Timeshift snapshots versus OS patch policy
  and wipe/rollback claims are not specified or qualified.
