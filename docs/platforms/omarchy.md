# Omarchy

Tier 2: the current Omarchy release on a pinned Arch Linux snapshot, Hyprland,
x86_64 ([tiers](../product-specification.md#supported-os-tiers)). Omarchy is an
opinionated setup layered on Arch. **No [Arch](arch.md) evidence carries over** to
it.

## Supported versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability            | Omarchy 4.0.4                                                                                                                                                                                                                                                                                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| inventory             | implemented                                                                                                                                                                                                                                                                                                                                                         |
| lifecycle             | implemented                                                                                                                                                                                                                                                                                                                                                         |
| dispatch              | implemented                                                                                                                                                                                                                                                                                                                                                         |
| packages              | implemented                                                                                                                                                                                                                                                                                                                                                         |
| accounts              | implemented                                                                                                                                                                                                                                                                                                                                                         |
| sysctl                | implemented                                                                                                                                                                                                                                                                                                                                                         |
| definitions           | implemented                                                                                                                                                                                                                                                                                                                                                         |
| password              | gated: Omarchy 4.0.4 ships pam 1.7.2-2 (Arch pins measured 1.7.3-1) and rewrites system-auth (pam_faillock deny=10); its own PAM stack has no measured password pins                                                                                                                                                                                                |
| firewall              | gated: the Arch firewall provider manages firewalld zones; Omarchy 4.0.4 runs ufw active by default and its ISO carries no firewalld                                                                                                                                                                                                                                |
| encryption            | implemented                                                                                                                                                                                                                                                                                                                                                         |
| wipe                  | implemented                                                                                                                                                                                                                                                                                                                                                         |
| report-loss           | implemented                                                                                                                                                                                                                                                                                                                                                         |
| lock                  | implemented                                                                                                                                                                                                                                                                                                                                                         |
| recovery-sanitize     | gated: owned-boot recovery fixture packages (systemd-ukify, sbsigntools, busybox) are not on the authenticated Omarchy ISO and partial pacman upgrades are unsupported                                                                                                                                                                                              |
| self-update           | implemented                                                                                                                                                                                                                                                                                                                                                         |
| assistance            | gated: notification_actions_unverified: stock Quickshell advertises actions without rendering consent buttons; session_lock_state_unreported: Omarchy's Quickshell WlSessionLock bypasses logind (no Lock listener, no LockedHint) and Hyprland screencopy keeps streaming a locked screen; CONTROL additionally lacks RemoteDesktop in xdg-desktop-portal-hyprland |
| assistance-clipboard  | gated: not implemented for Omarchy 4.0.4                                                                                                                                                                                                                                                                                                                            |
| assistance-keyboard   | gated: not implemented for Omarchy 4.0.4                                                                                                                                                                                                                                                                                                                            |
| assistance-displays   | gated: not implemented for Omarchy 4.0.4                                                                                                                                                                                                                                                                                                                            |
| assistance-messages   | gated: not implemented for Omarchy 4.0.4                                                                                                                                                                                                                                                                                                                            |
| assistance-files      | gated: local FileChooser consent, input isolation and secure transfer are not qualified on this release                                                                                                                                                                                                                                                             |
| assistance-reconnect  | gated: fresh consent after real logout/reboot and workflow expiry are not qualified on this release                                                                                                                                                                                                                                                                 |
| assistance-recording  | gated: recording disclosure, encrypted storage and retention are not qualified on this release                                                                                                                                                                                                                                                                      |
| assistance-unattended | gated: a compositor-supported persistent remote-desktop grant, banner/stop and lock refusal are not qualified on this release                                                                                                                                                                                                                                       |
| assistance-elevation  | gated: pausing all remote injection around a local privileged prompt is not qualified on this release                                                                                                                                                                                                                                                               |
| assistance-annotation | gated: no qualified non-interactive compositor overlay exists on this release                                                                                                                                                                                                                                                                                       |
| assistance-audio      | gated: selected PipeWire output/microphone capture with local mute is not qualified on this release                                                                                                                                                                                                                                                                 |
| assistance-kde        | gated: kde_plasma_desktop_unqualified: no native KDE Plasma Wayland lane on this release; the helper admits no KDE capability                                                                                                                                                                                                                                       |
| assistance-x11        | gated: x11_desktop_unqualified: no native X11 session lane on this release; X11 sessions end UNAVAILABLE                                                                                                                                                                                                                                                            |
| advisories            | gated: no vendor advisory feed; the Arch feed does not cover Omarchy packages                                                                                                                                                                                                                                                                                       |
| os-update             | gated: Omarchy 4.0.4's ALPM guard aborts direct pacman system upgrades (only `omarchy update` may run them), and its moving stable mirrors have no immutable snapshot for a pinned rolling update                                                                                                                                                                   |
| release-upgrade       | gated: release upgrade is not implemented                                                                                                                                                                                                                                                                                                                           |

<!-- END GENERATED platform-capabilities -->

Omarchy 4.0.4 x86_64 is pinned by its signed ISO
(`lab/images/omarchy-4.0.4-x86_64.json`, cloud-init golden for inspect, lifecycle,
dispatch and updates; `omarchy-4.0.4-encrypted-x86_64.json`, edition
`hyprland-encrypted-lab`, for encryption, wipe, lock and assistance). The release
tag is [v4.0.4](https://github.com/omacom/omarchy/releases/tag/v4.0.4) (commit
`c668141e9c42b13c80c9ca4ea108e11708c5e8a5`). The ISO installs only from its own
bundled offline package repository, so the installed package set is fixed by the
ISO digest rather than by an Arch Linux Archive date. x86_64 only. See
[Records](#records) for what has actually passed.

## Identity

The installed `/etc/os-release` is Omarchy's own (`ID=omarchy`,
`VERSION_ID="4.0.4"`, `ID_LIKE=arch`, no `CPE_NAME`): `omarchy-settings`
`post_install` copies `/usr/share/omarchy/etc-overrides/os-release` over Arch's
symlink on every install and upgrade (except Apple Silicon). Selection is by
`ID=omarchy` in the registry; native tooling comes from the `arch` row (pacman,
`/var/lib/pacman/local`). Arch's `ID_LIKE` never selects behaviour.

## Media and installer

- **Authentication.** The ISO carries a detached OpenPGP signature over the image
  bytes (`omarchy-4.0.4.iso.sig`, Ed25519, signer
  `40DFB630FF42BCFFB047046CF0134EE680CAC571`), verified with the lab's
  `CHECKSUM_MODE_DETACHED_IMAGE` (streamed `gpgv` plus the SHA-256 pin
  `ddeded2758c48318d201dfdac905ecb28f570441883f0c052ea3cd5d05acf92d`, 6185304064
  bytes). The fingerprint's independent publication is
  [manual/48-security.md at the pinned commit](https://raw.githubusercontent.com/omacom/omarchy/c668141e9c42b13c80c9ca4ea108e11708c5e8a5/manual/48-security.md);
  the key comes from keys.openpgp.org. The `.sha256` sidecar is unsigned and only
  cross-checked.
- **Unattended install.** The vendor's
  [unattended mode](https://raw.githubusercontent.com/omacom/omarchy/c668141e9c42b13c80c9ca4ea108e11708c5e8a5/manual/51-unattended-installs.md)
  reads the configurator's archinstall files from a second drive labeled
  `cidata`; the ISO is not remastered. Layout: 2 GiB FAT32 ESP at `/boot`, Btrfs
  root with `@`, `@home`, `@log`, `@pkg` (zstd), Limine with the removable
  fallback, `linux-omarchy` 7.2.5, UKI built by `limine-update`, snapper. The
  encrypted edition LUKS2-encrypts the root partition (`encrypt` hook,
  `cryptdevice=`), and the vendor writes SDDM autologin into `omarchy.desktop`
  only for encrypted installs.
- **Lab provisioning** (documented in [engineering](../engineering.md)): host key,
  NOPASSWD sudo for `lindm-lab` and the source marker are written offline; signed
  packages (`cloud-init`, the device-action prerequisites `cryptsetup nftables
iproute2 iputils tpm2-tools bind curl`, and in the cloud golden the resource
  lane's tools `gnupg openssl python attr acl curl libarchive zstd pacman-contrib
nftables libpwquality pam pambase`) come only from the ISO's offline repository
  with package signatures required. The resource lane only verifies these tools
  (`Lab.Guest.FromInstaller`); Omarchy has no immutable online snapshot to refresh
  against. The encrypted golden adds `console=tty0 console=ttyS0,115200`,
  virtio/AHCI/NVMe modules and removes the `plymouth` initramfs hook (lab-only:
  plymouth's password display redraws the prompt per keystroke and hides
  cryptsetup's wrong-key message on the serial console) through the vendor
  `limine-entry-tool.d` and `mkinitcpio.conf.d` drop-ins.

## Quirks observed

- **No distribution sync databases after install.** The offline install leaves
  no core/extra/multilib/omarchy databases in `/var/lib/pacman/sync`, so repository
  queries print missing-database notices. The bootstrap prerequisites
  (`ca-certificates curl gnupg openssl`) and the agent's native runtime
  dependencies are already installed on the 4.0.4 ISO. Console enrollment checks
  installed prerequisites using `pacman --config /dev/null --query`, then
  refreshes and installs from a temporary configuration containing **only the
  customer's signed lindm repository**. Pacman resolves dependencies against its
  local installed database; it cannot pull or upgrade distribution packages.
  Missing prerequisites or dependencies stop visibly: use `omarchy update`,
  install the missing package, then retry. Never use `pacman -Sy` or bypass
  Omarchy's system-upgrade guard. No distribution refresh or upgrade is needed
  on a fresh 4.0.4 install. The maintained enroll-from-console lane uses the
  authenticated offline-installed golden without a rolling-mirror transaction.
  The agent reads `/var/lib/pacman/local` directly; the accounts provider drops
  exactly the missing-sync-database notices from `pacman -Qo`, and fails on other
  stderr. Lab read-only package queries use `--config /dev/null`.
- **Session file location.** `omarchy.desktop` (uwsm-managed Hyprland) is in
  `/usr/local/share/wayland-sessions/`, not `/usr/share/wayland-sessions/`.
- **Firewall.** `ufw` is active by default (deny incoming except LocalSend
  53317/tcp+udp); the vendor's unattended `authorized_keys` path opens 22/tcp.
- **Sysctl.** `/etc/sysctl.d/99-omarchy-sysctl.conf` tunes reclaim for zram
  (`vm.swappiness=150`, `vm.vfs_cache_pressure=50`, dirty limits,
  `fs.inotify.max_user_watches`). It sorts after lindm's stanza, so the sysctl
  provider refuses those keys (`later effective sysctl.d assignment`). The lab's
  resources lane manages `vm.overcommit_ratio` instead.
- **OpenSSH 10.5.** `sshd -T` prints keywords in canonical case (`Port 22`,
  `Banner none`), not the lowercase of OpenSSH 9.x. The SSH banner provider and
  lab oracles compare keywords case-insensitively; values stay exact.
- **Lock.** Omarchy 4 locks through its Quickshell shell (`WlSessionLock`,
  `shell/plugins/lock`), not hyprlock/hypridle. No logind `Lock` listener and no
  `SetLockedHint` caller exist in the v4.0.4 tree. Natively observed
  (`omarchy404-lock-quarantine-01`): after logind `LockSessions`, `LockedHint`
  stayed `no` and `omarchy-hyprland-session-locked` stayed unlocked, so the lock
  request has no effect. The registry records this as
  `Desktop.SessionLockUnsupported`. The server refuses a lock action that would
  only lock sessions (`device_action_session_lock_unsupported`). A lock action
  that also locks accounts or terminates sessions proceeds; its session part
  ends unverified with `session_lock_state_unreported`. Release, account lock and
  quarantine pass.
- **Assistance.** Gated in the registry (`notification_actions_unverified` and
  `session_lock_state_unreported`). The
  helper starts through `graphical-session.target` (uwsm) and sees
  `XDG_CURRENT_DESKTOP=Hyprland`. The earlier native record
  `omarchy404-assistance-03` observed VIEW `UNAVAILABLE`
  `session_lock_state_unreported` and CONTROL `portal_remote_desktop_unavailable`,
  both before any prompt. The current helper instead names an unverified fixed
  runtime `desktop_runtime_unqualified` after the portal/notification probes.
  xdg-desktop-portal 1.22.1 with
  xdg-desktop-portal-hyprland 1.4.1 exposes ScreenCast version 6 and no
  RemoteDesktop. `gst-plugins-good` is not installed. The lab runs only the
  refusal scenarios.
- **Lab name resolution.** Omarchy places NSS `resolve` before `files`, so rewriting `/etc/hosts` alone leaves synthetic `localhost` at `127.0.0.1`. Assistance fixtures move `files` first in the disposable guest (retaining the original configuration and module actions) before validating the existing `10.0.2.2` QEMU-host route. This is lab routing, not a desktop assistance qualification or a change to the golden.
- **TPM.** The busybox `encrypt` hook cannot consume systemd TPM2 tokens and the
  lab has no TPM early-boot variant; the device-action lane binds a real token and
  records the observed passphrase prompt as unsupported.

## Packaging

Signed `lindm-agent` pacman packages (`.pkg.tar.zst` with detached `.sig`) from
the [Arch](arch.md) path, installed through the lab's isolated pacman keyring and
a single `[lindm]` repository. Omarchy's own repositories are untouched; no
partial upgrade is performed.

Console enrollment uses the registry's explicit Omarchy identity and pacman
packaging prerequisites. Agent artifacts must come from the customer's own
`lindmd`; an absent signed repository is a visible setup gate, never permission
to substitute an external agent host or AUR package. Signer and server/bootstrap
trust must be authenticated before installation. See the
[install runbook](../security-and-operations.md#enrollment-installation-from-your-server).
Arch packaging alone is not native Omarchy qualification.

## Updates

Agent self-update uses the `pacman` native manager (the TUF-authenticated
package and its adjacent detached `.sig` target). OS updates are gated: the
`omarchy` package's ALPM pre-transaction hook
(`/usr/share/libalpm/hooks/00-omarchy-update-guard.hook`,
`omarchy-update-pacman-guard`) aborts any direct `pacman -Syu` that was not
started by `omarchy update` (bypass only with `OMARCHY_UPDATE_PACMAN=1` or
`OMARCHY_ALLOW_DIRECT_PACMAN=1`), and the vendor's stable mirrors
(`stable-mirror.omarchy.org`, `pkgs.omarchy.org/stable`) move with releases and
have no immutable dated snapshot for a pinned rolling update
([update process at v4.0.4](https://raw.githubusercontent.com/omacom/omarchy/c668141e9c42b13c80c9ca4ea108e11708c5e8a5/docs/update-process.md)).
The guard does not affect `pacman -S`, `-U` or `-Sw` of single packages.

## Encryption and recovery

LUKS2 root from the vendor installer. Escrow, reveal and rotation use the
generic LUKS provider; TPM2 unattended unlock is unsupported (see above).
Recovery sanitize is gated: the owned systemd-boot recovery fixture needs
`systemd-ukify`, `sbsigntools` and `busybox`, which are not on the authenticated
ISO, and the lab does not perform partial upgrades from rolling mirrors.

## Advisory feeds

Gated: no vendor advisory feed; the Arch ASA feed is not applied to Omarchy
packages (`feed_unavailable` stays visible).

## Remote assistance capability roadmap

Omarchy/Hyprland inherits no Arch or GNOME desktop evidence. The
[capability contract](../product-specification.md#remote-assistance-capabilities)
defines all tiers' consent, off/limited/on policy, role permissions and audit.
Require reliable local lock/stop observation and the actual selected portal backend
before enabling capture or input. Clipboard requires the existing RemoteDesktop
Clipboard interface; a private compositor command is not an authorized substitute.
File upload requires FileChooser. Clipboard, keys/layouts, two-head display
selection, messages, files, reconnect, recording and Tier 3 are
[not run](../verification.md#commercial-assistance-capability-qualification).
Missing portal/native mechanisms stay explicitly gated; native nonce/hash/guest
screenshots must qualify each capability. Unattended/KDE work awaits parent
confirmation.

### Experimental fixed Wayland tuple

The separate `hyprland_wayland` helper profile is admitted only after verifying
the reviewed deployed portal fork and Omarchy 4.0.4 locker tuple. Merely running
Hyprland, installing a new backend beside the active one, or retaining the stock
`omarchy=4.0.4-1` package metadata does not admit it. The verifier checks root-owned
artifact digests, the live portal implementation's executable mappings and
reviewed explicit-loader identity and invocation, root frontend selection, the
actual Quickshell configuration and locker source, and process start after
deployment. Ordinary reviewed executables must be the actual process image,
not merely mapped alongside an unreviewed loader. The reviewed locker is the
`lock-logind-4.0.4-native` port (`38a30a51`) with Quickshell `0.3.1-1`, not an
assumption that a newer Omarchy package fixes locking.

Quickshell's advertised `actions` capability is not consent proof. A fresh
normal signed-SDK run with the reviewed portal and locker reached the
notification, but the stock card rendered no Allow/Decline buttons, even when
physically hovered; the invitation timed out without sharing. Generic Quickshell
therefore refuses `notification_actions_unverified`, including on COSMIC and
other desktops. The fixed tuple additionally pins the explicit-action backport
from existing [Omarchy PR 9717](https://github.com/omacom/omarchy/pull/9717).
Under `/usr/share/omarchy/shell/plugins/notifications/`, the reviewed source is:

| File                              | SHA-256                                                            |
| --------------------------------- | ------------------------------------------------------------------ |
| `Service.qml`                     | `6bd0c86bcf814a23b578ae1e7be4b575151ce41a25350e686bd8fa544b239b97` |
| `NotificationLogic.js`            | `db0f4b680f6b40d8a54d300371765d9629df1f9f47c2925bceebe31494d91c9d` |
| `components/NotificationCard.qml` | `366a5aa93e3753dacaca5147239cd8abb29044e142dcb77be39aa03c3197041b` |

The actual native `/usr/share/omarchy/shell/Ui/` widgets are pinned too:

| File                | SHA-256                                                            |
| ------------------- | ------------------------------------------------------------------ |
| `Button.qml`        | `fda48672cc11dba109acea1cc98eb4b29746e5ce09f90a47f487b776ff99e799` |
| `BorderSurface.qml` | `e17d8150d0b0e60f431bd6df5e661f5d9fe1f5eec9c2e2420f6eff2179a45baf` |

The source checkout's newer Button is not substituted for the actual golden
file. Native `GetServerInformation` reports `quickshell` with an empty version;
neither inventing a version nor trusting its advertised capability qualifies it.
The root-owned, mode-0644 widget measurements and actual D-Bus reply are retained
in `~/.cache/lindm-upstream-prs/omarchy-qualified-20261015l/native-notification-widget-roots.json`
(SHA-256 `ec59a3146fa299a853095a111358f0eb524739a53d55c167718552e27abbc08a`).

These files participate in the shell's deployment-age fence. The notification
server must also be that reviewed Quickshell process, not another instance or
daemon borrowing its QML qualification. Only this runtime proof overrides the
generic unverified-action refusal.

The local native backport rendered actual Allow/Decline buttons, and a physical
Decline ended VIEW as `DECLINED` / `prompt_declined` without sharing. Evidence
under `~/.cache/lindm-upstream-prs/omarchy-qualified-20261015j/`:
`guest-respond-20261015T221641.427Z-screenshot.png` (SHA-256
`118af7e28c2e46fa3d6e2fb9e1908feeb4baa4cafcbccbc0ccb90b9b237aabf3`)
and `native-action-row-declined-helper-journal.txt` (SHA-256
`fc44939f67b62d5fbc294d5d9fc30b959949f625780ff0b5d195262e399ec7d4`).
This establishes native button rendering and denial, not a complete qualified
VIEW/CONTROL run with the final signed SDK.

On Btrfs, `stat` can identify a subvolume with a different device number from
the backing superblock reported in executable mappings. Such a mismatch is not
accepted on the strength of a pathname or inode alone: the kernel's
`/proc/PID/map_files` link must name the exact reviewed artifact, the helper and
target must share a mount namespace, and the artifact through the target's root
must retain the hashed file's identity and metadata. This needs only readlink
access, not privileged access to open the mapped file.

Only VIEW, CONTROL and keyboard are admitted; other optional tools remain
`desktop_capability_unqualified`. The native flow selects a screen and separately asks
whether to allow keyboard/pointer control, with no view-only downgrade choice.
The product consent therefore describes the selected screen and input together,
not GNOME's view-only choice or KDE's all-monitor behavior. Stock platform
support, the static desktop lock table and server-side pure-session lock-action
policy remain unchanged.
The live frontend must use the standard root-only search homes
`XDG_CONFIG_HOME=/etc/xdg`, `XDG_DATA_HOME=/usr/share`,
`XDG_CONFIG_DIRS=/etc/xdg` and `XDG_DATA_DIRS=/usr/share` through a root-installed
service drop-in. The first matching portal configuration must be the pinned
`/usr/share/xdg-desktop-portal/hyprland-portals.conf`, not a higher-priority override.

## Records

Private records under `~/.cache/lindm-desktopderiv-20261011/` (x86_64, KVM,
Ubuntu `ovmf` 2024.02-2ubuntu0.10, Secure Boot off), each cited by SHA-256:

| Lane                                  | Outcome | Record (SHA-256)                                                                                                                     |
| ------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| inspect (967 packages matched)        | pass    | `omarchy/omarchy-x86_64-inspect-s2.json` (`126b1c842857812121b897e61d9da0cf14151afe84e4ae9df3f8d9a1e36964f8`)                        |
| lifecycle (signed pacman 0.7.0→0.7.1) | pass    | `omarchy/omarchy-x86_64-lifecycle-s2b.json` (`552f689c0348ea9c48e57d7f06416652a05847dd59ffdca32cc757b42e1f61cd`)                     |
| encrypted smoke (2 prompted unlocks)  | pass    | `omarchy/omarchy-x86_64-encrypted-s5.json` (`adca53b03e8a71868e10eca298bf77b2d660aded7062e82d4620383f6c7d5e4e`)                      |
| dispatch (9 native scenarios)         | pass    | `omarchy/omarchy-x86_64-dispatch-s5.json` (`08fe06f8a3365a8be8438e039604c1a89b6edaf80aa9ebc6dfa8d24ae6b8f120`)                       |
| dispatch power actions                | pass    | `omarchy/omarchy-x86_64-power-s5.json` (`be843e9473b34ab486c4f05ad5c9e647ae8d1fb797c509432ffdbcd4d0ee6bef`)                          |
| device actions: encryption            | pass    | `omarchy/omarchy-x86_64-encryption-s8.json` (`972e18fed3a609c8e1b4ecb3869ab1604ed4dba9a6287bdfebe82c662079380b`)                     |
| lock-quarantine                       | pass    | `sessions/omarchy/omarchy404-lock-quarantine-01.json` (`c5933f0fcdd35f5e54fa899d984f7a0e39901873a62d3f017259bf92080fe060`)           |
| assistance refusals                   | pass    | `sessions/omarchy/omarchy404-assistance-03/assistance.json` (`68f21814beafbac0c9758b3f111378998ff51ef0ce23b461447de2ff5d2df2f0`)     |
| wipe live-erase                       | pass    | `omarchy/omarchy-x86_64-live-erase-fin3.json` (`f77e8c58e85f785246e25a72273e8d40a2d613d49576f9298888c3bb94935fbf`)                   |
| wipe live-report-loss                 | pass    | `omarchy/omarchy-x86_64-live-report-loss-fin3.json` (`cb029a617dfd1df7acf341a82c4723c5f73015a0f10df64b03f40c75f689a1aa`)             |
| agent self-update                     | pass    | `omarchy/omarchy-x86_64-updates-fin4.json` (`a27d1d74c73bc7d79760a81507c25d219214bfdd4672c445da25230a12ed4917`)                      |
| resources executor                    | pass    | `omarchy/omarchy-x86_64-resources-executor-fin3.json` (`c5838345f9b6fb51d4684f498872f9ef96b6ebc90f0ac2da11c48243bdd6c505`)           |
| resources connected (host kinds)      | pass    | `omarchy/omarchy-x86_64-resources-connected-host-fin7.json` (`374fc4e909cbdfc5bfbd59cb53ea0a3c881224604fdcec554320d2160d79eb32`)     |
| resources connected (secret, LAPS)    | pass    | `omarchy/omarchy-x86_64-resources-connected-pw-fin7.json` (`c66ec5595adb685b15432f23953b80cd7db43a81e5cbb52b67c060b17cad0ab0`)       |
| services (matrix run)                 | pass    | `omarchy/matrix-services-01/omarchy-4.0.4/services-x86_64.json` (`ba771c0d0d315711afa9ced3353ee6e4799f468f6500a5ecd9f5ba80a089b06d`) |

Console installation/enrollment also passed on a fresh clone of the authenticated
offline-installed 4.0.4 golden (2026-10-14, normal FIFO `lab matrix run`,
x86_64 KVM, the same package-pinned OVMF and Secure Boot off):
`~/.cache/lindm-omarchy-enroll-20261014/matrix-03/omarchy-4.0.4/enroll-from-console-x86_64.json`,
SHA-256 `17705591e7708e5847359d813a400db65ee99f4410c2d2e3a1a2f1952060e353`.
Before and after enrollment, the only non-lindm sync database was `offline.db`;
distribution package identities and database bytes were independently unchanged.
The production browser copied and executed the same install command, then
confirmed device `98d9472b-a5c4-46cf-b608-90b312359365` **Enrolled** before
owned guest cleanup. No `omarchy update`, direct system upgrade or partial
distribution refresh was performed. [Verification](../verification.md#fresh-pacman-console-enrollment-2026-10-14)
retains the Arch companion proof, web regression gate and root-cause details.

The encryption record covers escrow, server reveal, the retired key's rejected
boot, committed and interrupted rotation, a real TPM2 bind (`systemd-tpm2`
token) and the observed passphrase prompt that makes the unattended TPM boot
unsupported. Live erase: two distinct approvers, three destructive approval
denials, root and data escrow with a revealed-key data unlock and cold root
boot, then server `SUCCEEDED` attested before the forced power-off, both LUKS
headers absent and both post-erase credential boots rejected. Report loss: the
result channel was blocked, the server stayed `OUTCOME_UNKNOWN`, the timer powered
off the guest and both headers were absent. Self-update interrupts the pacman
unpack with a QEMU reset; the boot helper then completes the exact update and a
fresh catalog cannot downgrade it.

The connected phase runs as two records because all kinds together exceed the
lane's fixed 50-minute budget on the shared host. Host kinds: packages (10),
files (9), groups (7), users (11), sysctl (8, including reboot persistence) and
timers/drop-ins (10) scenarios pass. Secret delivery (hashed password create,
repeat, version rotation, release) and managed local admin (first rotation,
unapproved reveal denied, approved reveal with a real SSH password login,
post-reveal rotation, policy removal) pass.

Root causes fixed on the way (superseded failed records stay in the evidence
directory): relay credential retry e7f5ee6d (escrow start consumed after the 30 s
challenge), Btrfs root mapping fa75d78f (live erase refused before a challenge),
stale `db.lck` release b6753033 (self-update recovery), sync-database notices
82a58470 (accounts), `vm.overcommit_ratio` lab key 90a0fa80 (sysctl), `sshd -T`
keyword case 538c13cf and the Arch local-admin fixture group b6753033. The earlier `invalid_argument: constraint`
inventory rejection (`live-erase-s8`, base 6f06a3b6) did not recur in three
later runs; that run kept no server log, so its column is unidentified.

## Known gaps

- Password is gated: Omarchy 4.0.4 ships `pam` 1.7.2-2 (the Arch pins were
  measured on 1.7.3-1) and rewrites `system-auth` (`pam_faillock deny=10`), so its
  own PAM stack has no measured pins.
- Firewall is gated: the Arch provider manages firewalld zones; Omarchy runs `ufw`
  active by default and its ISO carries no `firewalld`.
- Kernel module blocklist is unsupported: the registry has initramfs tooling only
  for initramfs-tools and dracut, not Omarchy's mkinitcpio, and the lane refuses
  with `module blocklist platform has no qualified initramfs tooling`.
- SSH banner is unsupported: the registry declares no `SSHBannerUnit` for the
  Arch family, so the provider refuses `banner_only_native_capability_unavailable`
  (`omarchy/omarchy-x86_64-resources-connected-secrets-fin7.json`,
  `91a1ae55c1758c67bf28bc9217a63e8774d3d60331268a2a7963bbf205bffd37`).
- Recovery sanitize, assistance, advisories, OS update and release upgrade are
  gated with the reasons above.
- VM results are not physical qualification.
