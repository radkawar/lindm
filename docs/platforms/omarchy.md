# Omarchy

Tier 2: the current Omarchy release on a pinned Arch Linux snapshot, Hyprland,
x86_64 ([tiers](../product-specification.md#supported-os-tiers)). Omarchy is an
opinionated setup layered on Arch. **No [Arch](arch.md) evidence carries over** to
it.

## Supported versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability           | Omarchy 4.0.4                                                                                                                                                                                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| inventory            | implemented                                                                                                                                                                                                                                                 |
| lifecycle            | implemented                                                                                                                                                                                                                                                 |
| dispatch             | implemented                                                                                                                                                                                                                                                 |
| packages             | implemented                                                                                                                                                                                                                                                 |
| accounts             | implemented                                                                                                                                                                                                                                                 |
| sysctl               | implemented                                                                                                                                                                                                                                                 |
| definitions          | implemented                                                                                                                                                                                                                                                 |
| password             | gated: Omarchy 4.0.4 ships pam 1.7.2-2 (Arch pins measured 1.7.3-1) and rewrites system-auth (pam_faillock deny=10); its own PAM stack has no measured password pins                                                                                        |
| firewall             | gated: the Arch firewall provider manages firewalld zones; Omarchy 4.0.4 runs ufw active by default and its ISO carries no firewalld                                                                                                                        |
| encryption           | implemented                                                                                                                                                                                                                                                 |
| wipe                 | implemented                                                                                                                                                                                                                                                 |
| report-loss          | implemented                                                                                                                                                                                                                                                 |
| lock                 | implemented                                                                                                                                                                                                                                                 |
| recovery-sanitize    | gated: owned-boot recovery fixture packages (systemd-ukify, sbsigntools, busybox) are not on the authenticated Omarchy ISO and partial pacman upgrades are unsupported                                                                                      |
| self-update          | implemented                                                                                                                                                                                                                                                 |
| assistance           | gated: session_lock_state_unreported: Omarchy's Quickshell WlSessionLock bypasses logind (no Lock listener, no LockedHint) and Hyprland screencopy keeps streaming a locked screen; CONTROL additionally lacks RemoteDesktop in xdg-desktop-portal-hyprland |
| assistance-clipboard | gated: not implemented for Omarchy 4.0.4                                                                                                                                                                                                                    |
| assistance-keyboard  | gated: not implemented for Omarchy 4.0.4                                                                                                                                                                                                                    |
| assistance-displays  | gated: not implemented for Omarchy 4.0.4                                                                                                                                                                                                                    |
| assistance-messages  | gated: not implemented for Omarchy 4.0.4                                                                                                                                                                                                                    |
| advisories           | gated: no vendor advisory feed; the Arch feed does not cover Omarchy packages                                                                                                                                                                               |
| os-update            | gated: Omarchy 4.0.4's ALPM guard aborts direct pacman system upgrades (only `omarchy update` may run them), and its moving stable mirrors have no immutable snapshot for a pinned rolling update                                                           |
| release-upgrade      | gated: release upgrade is not implemented                                                                                                                                                                                                                   |

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

- **No sync databases after install.** The offline install leaves no
  `/var/lib/pacman/sync/*.db`, so any `pacman` query prints "database file for
  'core' does not exist" (also extra, multilib, omarchy) on stderr until the owner
  runs `omarchy-update`. The agent reads `/var/lib/pacman/local` directly and its
  updater accepts warnings with exit 0; the accounts provider's `pacman -Qo`
  shadow version lookup drops exactly these notices and fails on any other
  stderr. The lab's package oracle and probes use a repository-free
  `--config /dev/null` query.
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
- **Assistance.** Gated in the registry (`session_lock_state_unreported`). The
  helper starts through `graphical-session.target` (uwsm) and sees
  `XDG_CURRENT_DESKTOP=Hyprland`. VIEW ends `UNAVAILABLE`
  `session_lock_state_unreported` and CONTROL ends `UNAVAILABLE`
  `portal_remote_desktop_unavailable`, both before any prompt
  (`omarchy404-assistance-03`). xdg-desktop-portal 1.22.1 with
  xdg-desktop-portal-hyprland 1.4.1 exposes ScreenCast version 6 and no
  RemoteDesktop. `gst-plugins-good` is not installed. The lab runs only the
  refusal scenarios.
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

## Records

Private records under `~/.cache/lindm-desktopderiv-20261011/` (x86_64, KVM,
Ubuntu `ovmf` 2024.02-2ubuntu0.10, Secure Boot off), each cited by SHA-256:

| Lane                                  | Outcome | Record (SHA-256)                                                                                                                  |
| ------------------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------- |
| inspect (967 packages matched)        | pass    | `omarchy/omarchy-x86_64-inspect-s2.json` (`126b1c842857812121b897e61d9da0cf14151afe84e4ae9df3f8d9a1e36964f8`)                     |
| lifecycle (signed pacman 0.7.0→0.7.1) | pass    | `omarchy/omarchy-x86_64-lifecycle-s2b.json` (`552f689c0348ea9c48e57d7f06416652a05847dd59ffdca32cc757b42e1f61cd`)                  |
| encrypted smoke (2 prompted unlocks)  | pass    | `omarchy/omarchy-x86_64-encrypted-s5.json` (`adca53b03e8a71868e10eca298bf77b2d660aded7062e82d4620383f6c7d5e4e`)                   |
| dispatch (9 native scenarios)         | pass    | `omarchy/omarchy-x86_64-dispatch-s5.json` (`08fe06f8a3365a8be8438e039604c1a89b6edaf80aa9ebc6dfa8d24ae6b8f120`)                    |
| dispatch power actions                | pass    | `omarchy/omarchy-x86_64-power-s5.json` (`be843e9473b34ab486c4f05ad5c9e647ae8d1fb797c509432ffdbcd4d0ee6bef`)                       |
| device actions: encryption            | pass    | `omarchy/omarchy-x86_64-encryption-s8.json` (`972e18fed3a609c8e1b4ecb3869ab1604ed4dba9a6287bdfebe82c662079380b`)                  |
| lock-quarantine                       | pass    | `sessions/omarchy/omarchy404-lock-quarantine-01.json` (`c5933f0fcdd35f5e54fa899d984f7a0e39901873a62d3f017259bf92080fe060`)        |
| assistance refusals                   | pass    | `sessions/omarchy/omarchy404-assistance-03/assistance.json` (`68f21814beafbac0c9758b3f111378998ff51ef0ce23b461447de2ff5d2df2f0`)  |
| wipe live-erase                       | pass    | `omarchy/omarchy-x86_64-live-erase-fin3.json` (`f77e8c58e85f785246e25a72273e8d40a2d613d49576f9298888c3bb94935fbf`)                |
| wipe live-report-loss                 | pass    | `omarchy/omarchy-x86_64-live-report-loss-fin3.json` (`cb029a617dfd1df7acf341a82c4723c5f73015a0f10df64b03f40c75f689a1aa`)          |
| agent self-update                     | pass    | `omarchy/omarchy-x86_64-updates-fin4.json` (`a27d1d74c73bc7d79760a81507c25d219214bfdd4672c445da25230a12ed4917`)                   |
| resources executor                    | pass    | `omarchy/omarchy-x86_64-resources-executor-fin3.json` (`c5838345f9b6fb51d4684f498872f9ef96b6ebc90f0ac2da11c48243bdd6c505`)        |
| resources connected                   | partial | `omarchy/omarchy-x86_64-resources-connected-nomod-fin7.json` (`80abe02d25c3061db0cdcc66b4f2180af8e4cfe918b35233cb4e94302105fb02`) |

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

The connected record passed every scenario of packages (9), files (9), groups
(7), users (11), sysctl (8, including reboot persistence) and timers/drop-ins
(10), and the SSH banner's unowned-notice refusal. It failed only on the lane's
fixed 50-minute budget during SSH banner adoption, so the remaining banner
scenarios, secret-password and local-admin did not run in it.

Root causes fixed on the way (superseded failed records stay in the evidence
directory): relay credential retry e7f5ee6d (escrow start consumed after the 30 s
challenge), Btrfs root mapping fa75d78f (live erase refused before a challenge),
stale `db.lck` release b6753033 (self-update recovery), sync-database notices
82a58470 (accounts), `vm.overcommit_ratio` lab key 90a0fa80 (sysctl) and `sshd -T`
keyword case 538c13cf (SSH banner). The earlier `invalid_argument: constraint`
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
- SSH banner adoption onward, secret-password and local-admin have no completed
  Omarchy record yet (see the connected record above).
- Recovery sanitize, assistance, advisories, OS update and release upgrade are
  gated with the reasons above.
- VM results are not physical qualification.
