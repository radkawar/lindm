# Pop!\_OS

Tier 1, desktop-first: current Pop!\_OS LTS with the COSMIC desktop, x86_64. Full
parity with Ubuntu 24.04 is required
([tiers](../product-specification.md#supported-os-tiers)). Pop!\_OS is built on
Ubuntu, but **no Ubuntu evidence carries over** to it.

## Supported versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Pop!\_OS 24.04 LTS                                                                                                                                                                                                                                   |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| inventory         | implemented                                                                                                                                                                                                                                          |
| lifecycle         | implemented                                                                                                                                                                                                                                          |
| dispatch          | implemented                                                                                                                                                                                                                                          |
| packages          | implemented                                                                                                                                                                                                                                          |
| accounts          | implemented                                                                                                                                                                                                                                          |
| sysctl            | implemented                                                                                                                                                                                                                                          |
| definitions       | implemented                                                                                                                                                                                                                                          |
| password          | implemented                                                                                                                                                                                                                                          |
| firewall          | implemented                                                                                                                                                                                                                                          |
| encryption        | implemented                                                                                                                                                                                                                                          |
| wipe              | implemented                                                                                                                                                                                                                                          |
| report-loss       | implemented                                                                                                                                                                                                                                          |
| lock              | implemented                                                                                                                                                                                                                                          |
| recovery-sanitize | gated: original-device recovery requires Secure Boot; Pop!\_OS's installed systemd-boot (EFI/systemd/systemd-bootx64.efi and its EFI/BOOT/BOOTX64.EFI copy) carries no Authenticode signature, so the installed system cannot boot under Secure Boot |
| self-update       | implemented                                                                                                                                                                                                                                          |
| assistance        | implemented                                                                                                                                                                                                                                          |
| advisories        | partial: vendor feed unavailable for Pop!\_OS packages                                                                                                                                                                                               |
| os-update         | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release                                                                                                                                              |
| release-upgrade   | gated: release upgrade is not implemented                                                                                                                                                                                                            |

<!-- END GENERATED platform-capabilities -->

Current LTS on x86_64: Pop!\_OS 24.04 LTS, `generic` build 28 (System76's
`api.pop-os.org/builds/24.04/generic` names it the current non-NVIDIA build for
Intel and AMD graphics; the `intel` channel's build 20 is an older, separately
maintained image and `nvidia` adds the proprietary driver). System76 arm64 images
are not part of this row. No capability cell is qualified yet; see the
[tier capability matrix](../verification.md#tier-capability-matrix) and
[Known gaps](#known-gaps).

## Media and identity

`lab/images/pop-os-24.04-amd64.json` (edition `cosmic`) and
`lab/images/pop-os-24.04-encrypted-amd64.json` (edition `cosmic-encrypted-lab`) pin
`pop-os_24.04_amd64_generic_28.iso`, 3526164480 bytes, SHA-256
`8d78e500fc95da765a91cddcf2ab7ba71ce4e7997e4f008456d4d872ee8f8221`, through the
build directory's `SHA256SUMS` and detached `SHA256SUMS.gpg`. `gpgv` reports the
issuer fingerprint `63C46DF0140D738961429F4E204DD8AEC33A7AFF` (signature created
2026-09-17). The full fingerprint's independent vendor publication is
[apt-origin.pop-os.org](https://apt-origin.pop-os.org/), which names it "the
Pop!\_OS ISO key"; the [pop-os/iso README](https://github.com/pop-os/iso) gives
only the key ID `204DD8AEC33A7AFF`. The live medium reports
`Pop_OS 24.04 "Noble Numbat" - Release amd64 (20260818)` and carries casper
`1.498`, distinst/libdistinst `0.3.2~1780341724~24.04~16037d2`, kernelstub
`3.1.4`, systemd/systemd-boot `255.4-1ubuntu8.15pop0`, kernel
`7.0.11-76070011-generic`, cosmic-comp `0.1~1786994555`, cosmic-greeter
`0.1.0~1786995903` and xdg-desktop-portal-cosmic `0.1.0pop1~1785249581`.
The installed system reports `ID=pop`, `VERSION_ID=24.04` and
`VERSION_CODENAME=noble`; the registry row is selected by exact `ID`, never
`ID_LIKE`.

## Installer-to-golden recipe

Pop!\_OS has no unattended installer mode: pop-installer
(`io.elementary.installer`) and the `distinst` CLI in the live image both drive
libdistinst. The lab remasters only `/boot/grub/grub.cfg` and `/lindm-seed/install.sh`
(registry installer `distinst`); the vendor kernel, initrd, squashfs and signed
shim/GRUB are untouched. The kernel command line adds
`"systemd.run=/bin/sh -eu /cdrom/lindm-seed/install.sh"` with
`systemd.run_success_action=poweroff` and `systemd.run_failure_action=poweroff`:
systemd-run-generator boots casper's live root into `kernel-command-line.service`
instead of `graphical.target`, so neither cosmic-greeter nor the pop-installer
autostart runs (the script also refuses to start if a display manager or
installer is active). The script starts NetworkManager, then runs `distinst` with
pop-installer's "Clean Install" layout for libdistinst 0.3.2: 1 GiB FAT32 ESP,
4 GiB FAT32 `/recovery`, root (ext4, or `enc=cryptdata,data` LVM on LUKS with a
`data/root` ext4 volume) and 4 GiB swap, plus `--modify-boot --hardware-support`
(the GUI's `MODIFY_BOOT_ORDER | INSTALL_HARDWARE_SUPPORT`) and the GUI's default
profile icon, which the CLI requires with `--username`. The CLI cannot name the
recovery partition, so the script sets its GPT name to `recovery` as libdistinst's
erase layout does. Provisioning then runs in a chroot of the installed root:
signed Pop/Ubuntu APT installs `openssh-server` (and `cloud-init` for the
unencrypted golden), the serial console is added with
`kernelstub --add-options` (the encrypted golden also removes distinst's
`quiet loglevel=0 systemd.show_status=false splash` so the initramfs passphrase
prompt reaches the serial console), and the lab account's password is locked.
kernelstub is never bypassed: loader entries and ESP kernel copies are its own.
`-desktop cosmic` configures greetd's native lab-only autologin by appending an
`[initial_session]` (`start-cosmic`, user `lindm-lab`) to
`/etc/greetd/cosmic-greeter.toml`; `-tpm-boot` swaps initramfs-tools for the
shared dracut TPM2 tuple and reruns kernelstub. Only `x86_64` is accepted, and
passphrases that distinst's `:`/`,` field syntax cannot carry are refused.

Natively observed in the first guest install (2026-10-11): distinst ran
`bootctl install --path=/boot/efi --no-variables`, kernelstub copied the kernel
and initrd to the ESP with the boot options above, and `efibootmgr` created
`Pop!_OS 24.04 LTS` → `\EFI\systemd\systemd-bootx64.efi`. The first attempt
exposed two recipe faults, both fixed with regressions in
`internal/vmlab/pop_installer_linux_test.go`: the CLI requires
`--profile_icon`, and an inherited `umask 077` (from the credential-writing
helper) left `/etc/machine-id` mode 0600, so D-Bus activation of polkit,
NetworkManager, accounts-daemon and cosmic-greeter-daemon timed out and the guest
had no network. Provisioning now restores `umask 022` after the credential files.

The unencrypted golden then passed every first-boot probe on a fresh NVRAM with
a fresh NoCloud seed: source marker, `ID=pop`, `VERSION_ID=24.04`, codename
`noble`, ext4 root, dpkg/apt, sudo, `EFI/systemd/systemd-bootx64.efi` and
`EFI/BOOT/BOOTX64.EFI`, the kernelstub-managed serial console in
`/proc/cmdline`, a vfat `/recovery` with `recovery.conf` and GPT name `recovery`,
and the COSMIC session with `cosmic-greeter.service` enabled. Its private cache
entry is `pop-installed/sha256-72676a590253bbaa9259a74c2463aa20054f025399396239bd5c537bef98dad3`
(installed disk SHA-256
`598260f9b8d00b0d165d1536ee0d6b33eb35248067c15c676978671310d0069b`); the disk is
lab-derived, not vendor-signed, and its packages reflect the signed archives at
installation time.

## Quirks

- **COSMIC compositor.** The live image's
  `/usr/share/xdg-desktop-portal/portals/cosmic.portal` declares Access,
  FileChooser, Screenshot, Settings and ScreenCast, and **no RemoteDesktop**; the
  image also lacks `gstreamer1.0-pipewire`, which the agent package recommends.
  Assistance CONTROL therefore cannot be offered on this build. Lock goes through
  cosmic-greeter and logind; `LockedHint` and portal closure ordering are not yet
  observed natively.
- **Display manager.** `display-manager.service` is `cosmic-greeter.service`,
  i.e. `greetd --config /etc/greetd/cosmic-greeter.toml` with PAM service
  `cosmic-greeter`; the COSMIC session is `/usr/bin/start-cosmic`. greetd's own
  autologin (`[initial_session]`, used by the encrypted golden) registers in
  logind as `Service=cosmic-greeter`, `Type=tty` and an empty `Desktop`, because
  it receives none of the session environment cosmic-greeter passes on a real
  login (`XDG_SESSION_TYPE=wayland`, `XDG_SESSION_DESKTOP`,
  `XDG_CURRENT_DESKTOP`); lindm then sees no graphical session (observed by the
  desktop-session lane, record `pop2404-lock-quarantine-02`). An autologin that
  must count as a COSMIC session needs a PAM service that sets that environment.
- **systemd-boot and kernelstub.** The installed `EFI/systemd/systemd-bootx64.efi`
  (and its `EFI/BOOT/BOOTX64.EFI` copy) carries no Authenticode signature table
  (`sbverify --list`), so the lab runs Pop with the unenrolled `OVMF_VARS_4M.fd`
  (SecureBoot off) only. kernelstub owns `loader/entries/Pop_OS-current.conf`
  (kernel and initrd copied to `EFI/Pop_OS-<root UUID>/`, options from its
  configuration); distinst adds `Recovery-<FAT serial>.conf` booting the casper
  copy on `/recovery` from `EFI/Recovery-<FAT serial>/` (observed in the golden).
  Registry `Lab.SecureBootUnavailable` records this, so every lab matrix cell
  that requires Secure Boot (`tpm-unattended-boots`, `recovery-sanitize`) is
  gated with that reason, and recovery-sanitize is gated for Pop!\_OS: original-
  device recovery relies on Secure Boot (measured GRUB PCR 7 or a signed
  recovery UKI), which an unsigned systemd-boot cannot provide. The TPM2 bind
  and its unattended boots run without Secure Boot (PCR 7 then measures
  SecureBoot=0), which is how Pop!\_OS boots by default.
- **Repositories.** `pop-os-apps.sources` (`apt.pop-os.org/proprietary`),
  `pop-os-release.sources` (`apt.pop-os.org/release`) and `system.sources`
  (`apt.pop-os.org/ubuntu`, noble/-security/-updates/-backports) are the installed
  sources; `/etc/apt/preferences.d/pop-default-settings` pins
  `o=pop-os-release` at priority 1001. That pin made `apt-cache policy` print
  package-file lines at a 7-column indent, which the native APT-origin oracle first
  rejected (fixed with a 1001-pin regression).
- **System updater.** `com.system76.SystemUpdater.service` (`pop-system-updater`
  `0.1.0~1706713830~24.04~c208318`, enabled in `multi-user.target`) runs
  `apt-get update` as soon as it starts and every 12 hours
  ([daemon/src/service/system.rs](https://github.com/pop-os/system-updater/blob/c208318/daemon/src/service/system.rs));
  automatic upgrades default to off. Its boot-time refresh held the dpkg
  frontend lock and failed a lab agent install with exit 100, so lab guests stop
  and mask it together with `apt-daily*`. Its unit uses `KillMode=process`, so
  stopping it leaves a running `apt-get` (with guest egress it then held the APT
  lists lock against the lab's fixture repository); the lab waits until no
  `apt-get` or `dpkg` remains (regression
  `TestLabQuiescePackageUnitsStopsPopUpdater`). On a real Pop!\_OS desktop the
  updater keeps running and owns package refreshes (and upgrades, when the user
  enables them); lindm does not stop it. While it holds dpkg's frontend lock a
  lindm package change must end as the explicit, retried
  `RESOURCE_EXECUTION_FAILURE_NATIVE_BUSY` hold (server reason
  `native_package_manager_busy`) before any effect. The connected resources lane
  checks this natively: its `vendor-updater-native-busy` scenario unmasks the
  updater, calls its `UpdateSystem` D-Bus method, and assigns a package change
  while the updater holds the lock (registry `Lab.Updater`; needs
  `-allow-network`).
- **Random-key swap.** distinst always adds
  `cryptswap UUID=… /dev/urandom swap,plain,offset=1024,cipher=aes-xts-plain64,size=512`:
  a plain dm-crypt swap whose key comes from the kernel RNG at each activation and
  is never stored. The server's live-root crypto-erase set requires every
  encrypted mapping to be covered, so every installer-encrypted Pop!\_OS machine
  was refused `device_action_storage_target_set_mismatch` (observed natively,
  `device-actions-wipe-live-erase-01-snap10-failed.json`). The agent now reports
  `StorageIdentity.ephemeral_key` only with native proof, read by the
  capability-free root inventory helper (kernel dm UUID exactly
  `CRYPT-PLAIN-<mapping>`, the mapping's only kernel slave is its observed
  parent, crypttab's single entry for it keys it from `/dev/urandom` or
  `/dev/random` in plain mode with no null cipher, no LUKS1/LUKS2 header magic on
  the backing device; any failed step leaves it UNAVAILABLE and the refusal
  stands), and the server exempts exactly those mappings. The helper has no
  `CAP_SYS_ADMIN`, so the live `dmsetup table` is not part of the agent's proof
  (the first version used it and was refused the same way on Pop!\_OS,
  `device-actions-wipe-live-erase-01-snap11-failed.json`); the wipe lane's
  independent oracle still reads it as root. The console's storage table and the
  crypto-erase form name the mappings ("ephemeral random-key swap; destroyed at
  power-off"), as does the wipe lane's record. An observation from an older agent
  carries no proof, so a fresh inventory from an updated agent is required first.
  Linux Mint's Ubiquity LUKS layout puts swap inside its LVM on LUKS and has no
  such mapping.
- **zram swappiness.** `pop-default-settings-zram.service` (`pop-zram-config`)
  runs `sysctl -w vm.swappiness=180` at every boot after `systemd-sysctl`, so a
  managed `vm.swappiness` reverts at boot until lindm's next reconcile reapplies
  it (observed: `reboot-persists` failed natively). The resources lane therefore
  uses `vm.vfs_cache_pressure` on Pop!\_OS (registry `Lab.SysctlKey`).
- **Identity.** `os-release` reports `ID=pop` with `ID_LIKE="ubuntu debian"`;
  behavior is selected by the registry row, never resemblance.

## Packaging

Choose Pop!\_OS in the console to install and enroll from the customer's own
`lindmd` HTTPS `/repo/apt` endpoint. The one command authenticates the repository
signer and server/bootstrap trust before writing a dedicated deb822 `Signed-By`
source. No external agent repository is used. Missing artifacts produce an
explicit setup remedy; successful Ubuntu installation does not qualify Pop!\_OS.
See the [install runbook](../security-and-operations.md#enrollment-installation-from-your-server).

The Ubuntu-base DEB is expected to apply through authenticated APT. Not yet
recorded on Pop!\_OS.

## Services and sandbox

As in the [shared boundaries](README.md#shared-implementation-boundaries); not yet
observed on Pop!\_OS.

## Updates

Not recorded. Pop!\_OS ships its own update tooling (COSMIC Store, `pop-upgrade`),
and its ownership relative to OS patch policy must be specified.

## Inventory

Not recorded. The first `lab vm inspect` run failed in the lab's APT-origin oracle
(see Repositories above), not in the agent; it must be rerun.

## Encryption and recovery

Not recorded. The encrypted golden (`-desktop cosmic -tpm-boot`) is implemented
but not yet built.

## Actions

Not recorded. Lock/release/quarantine, live-root crypto-erase, report-loss and
recovery sanitize each need native evidence here.

## Advisory feeds

System76 publishes no machine-readable advisory feed for Pop!\_OS, so exposure of
System76's own packages is never known. Pop!\_OS 24.04 (the exact `pop-24.04`
registry row, base `ubuntu-24.04`) is evaluated against the configured Ubuntu 24.04
feed **only for packages of verified Ubuntu origin**, and the evaluation state is
always `partial` with reason `vendor_feed_unavailable_pop`, shown
in the console as "vendor feed unavailable for Pop!\_OS packages". Any other Pop!\_OS
release keeps `feed_unavailable`.

- **Origin evidence.** The agent collects per-package APT index origins and
  verifies Release signatures itself, exactly as described for
  [Linux Mint](mint.md#advisory-feeds). Pop!\_OS serves Ubuntu's archive from its
  own mirror (`apt.pop-os.org/ubuntu`); those `InRelease` files are Ubuntu's own,
  signed by the Ubuntu archive key, so mirrored Ubuntu packages are covered. Its
  release repository (`apt.pop-os.org/release`, `Origin: pop-os-release`) and
  proprietary repository (`apt.pop-os.org/proprietary`, `Origin: system76`) also
  use `Codename: noble` and are signed by the Pop!\_OS key
  `63C46DF0140D738961429F4E204DD8AEC33A7AFF`; origin and signer, never the
  codename, separate them (all observed 2026-10-11).
- **Coverage.** Packages listed only by those System76 repositories are UNKNOWN
  with `vendor_feed_unavailable`; Pop!\_OS rebuilds of Ubuntu packages that keep a
  version also published by Ubuntu are `origin_ambiguous`; the remaining reasons
  and the `package_origin_unavailable` rule are as for Mint.

Natively unverified until a Pop!\_OS 24.04 guest run records evidence: that the
Pop!\_OS and Ubuntu keys are in the scanned keyring locations, that the installed
system's sources match the repositories above, and that lists are stored
uncompressed or gzip.

## Remote assistance capability roadmap

Pop!_OS/COSMIC inherits no Ubuntu GNOME portal qualification. The
[capability contract](../product-specification.md#remote-assistance-capabilities)
defines all tiers' consent, off/limited/on policy, role permissions and audit.
Probe COSMIC's own RemoteDesktop/ScreenCast, Clipboard, FileChooser and notification
interfaces and preserve native lock/logout isolation. Clipboard attaches only to
the consented RemoteDesktop session; no compositor-private/root fallback is allowed.
Keys/layouts, two-head displays, messages, clipboard, files, reconnect, recording
and Tier 3 are
[not run](../verification.md#commercial-assistance-capability-qualification).
Each needs actual portal interactions and independent nonce/hash/guest screenshot
evidence. Unsupported interfaces remain explicit gates; unattended/KDE work awaits
parent confirmation.

## Lab

x86_64 only, on the local KVM host under lease admission (no arm64 build is used
for this row), with the host's `ovmf` `2024.02-2ubuntu0.10`
`OVMF_CODE_4M.secboot.fd` and unenrolled `OVMF_VARS_4M.fd`. Both goldens come from
the recipe above; ISO relabels are not used.

## Known gaps

No capability cell is qualified. Built and probed: the unencrypted golden only.
Pending native runs: inspect (rerun after the oracle fix), lifecycle, dispatch and
power actions, resources (executor and connected), the encrypted golden and its
encryption/wipe/lock/quarantine actions, agent self-update and assistance.
Assistance CONTROL is expected UNAVAILABLE on build 28 (no RemoteDesktop portal).
