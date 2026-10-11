# Omarchy

Tier 2: the current Omarchy release on a pinned Arch Linux snapshot, Hyprland,
x86_64 ([tiers](../product-specification.md#supported-os-tiers)). Omarchy is an
opinionated setup layered on Arch. **No [Arch](arch.md) evidence carries over** to
it.

## Supported versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Omarchy 4.0.4                                                                                                                                                                                                                                               |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| inventory         | implemented                                                                                                                                                                                                                                                 |
| lifecycle         | implemented                                                                                                                                                                                                                                                 |
| dispatch          | implemented                                                                                                                                                                                                                                                 |
| packages          | gated: host resource providers have no pacman/Arch implementation or measured native quirks                                                                                                                                                                 |
| accounts          | gated: host resource providers have no pacman/Arch implementation or measured native quirks                                                                                                                                                                 |
| sysctl            | gated: host resource providers have no pacman/Arch implementation or measured native quirks                                                                                                                                                                 |
| definitions       | gated: host resource providers have no pacman/Arch implementation or measured native quirks                                                                                                                                                                 |
| password          | gated: host resource providers have no pacman/Arch implementation or measured native quirks                                                                                                                                                                 |
| firewall          | gated: host resource providers have no pacman/Arch implementation or measured native quirks                                                                                                                                                                 |
| encryption        | implemented                                                                                                                                                                                                                                                 |
| wipe              | implemented                                                                                                                                                                                                                                                 |
| report-loss       | implemented                                                                                                                                                                                                                                                 |
| lock              | implemented                                                                                                                                                                                                                                                 |
| recovery-sanitize | gated: owned-boot recovery fixture packages (systemd-ukify, sbsigntools, busybox) are not on the authenticated Omarchy ISO and partial pacman upgrades are unsupported                                                                                      |
| self-update       | implemented                                                                                                                                                                                                                                                 |
| assistance        | gated: session_lock_state_unreported: Omarchy's Quickshell WlSessionLock bypasses logind (no Lock listener, no LockedHint) and Hyprland screencopy keeps streaming a locked screen; CONTROL additionally lacks RemoteDesktop in xdg-desktop-portal-hyprland |
| advisories        | gated: no vendor advisory feed; the Arch feed does not cover Omarchy packages                                                                                                                                                                               |
| os-update         | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release                                                                                                                                                     |
| release-upgrade   | gated: release upgrade is not implemented                                                                                                                                                                                                                   |

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
  packages (`cloud-init`, and the device-action prerequisites `cryptsetup
nftables iproute2 iputils tpm2-tools bind curl`) come only from the ISO's
  offline repository with package signatures required; the encrypted golden adds
  `console=tty0 console=ttyS0,115200` and virtio/AHCI/NVMe modules through the
  vendor `limine-entry-tool.d` and `mkinitcpio.conf.d` drop-ins.

## Quirks observed

- **No sync databases after install.** The offline install leaves no
  `/var/lib/pacman/sync/*.db`, so any `pacman` query prints "database file for
  'core' does not exist" (also extra, multilib, omarchy) on stderr until the owner
  runs `omarchy-update`. The agent reads `/var/lib/pacman/local` directly and its
  updater accepts warnings with exit 0; the lab's package oracle and probes use a
  repository-free `--config /dev/null` query.
- **Session file location.** `omarchy.desktop` (uwsm-managed Hyprland) is in
  `/usr/local/share/wayland-sessions/`, not `/usr/share/wayland-sessions/`.
- **Firewall.** `ufw` is active by default (deny incoming except LocalSend
  53317/tcp+udp); the vendor's unattended `authorized_keys` path opens 22/tcp.
- **Lock.** Omarchy 4 locks through its Quickshell shell (`WlSessionLock`,
  `shell/plugins/lock`), not hyprlock/hypridle. No logind `Lock` listener and no
  `SetLockedHint` caller exist in the v4.0.4 tree, so `loginctl lock-session` is
  not expected to lock and `LockedHint` is not maintained.
- **Assistance.** Gated in the registry (`session_lock_state_unreported`): the lock
  state is not reported through logind, and `xdg-desktop-portal-hyprland` 1.4.1
  provides no RemoteDesktop, so CONTROL is unavailable. The lab runs only the
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

Agent self-update uses the `pacman` native manager (`pacman -U` of the
TUF-authenticated package). OS updates are the vendor's `omarchy-update`
(whole-system); the OS patch policy provider is not landed (gated).

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

None yet.

## Known gaps

- Host resource providers (packages, accounts, sysctl, definitions, password,
  firewall) have no pacman/Arch implementation (gated).
- Recovery sanitize, assistance, advisories, OS update and release upgrade are
  gated with the reasons above.
- VM results are not physical qualification.
