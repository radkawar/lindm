# Linux Mint

Tier 1, desktop-first: current Linux Mint release, Cinnamon edition, x86_64. Full
parity with Ubuntu 24.04 is required
([tiers](../product-specification.md#supported-os-tiers)). Mint is built on an Ubuntu
LTS base, but **no Ubuntu evidence carries over** to it.

## Supported versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability            | Linux Mint 22.3                                                                                                                            |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| inventory             | implemented                                                                                                                                |
| lifecycle             | implemented                                                                                                                                |
| dispatch              | implemented                                                                                                                                |
| packages              | implemented                                                                                                                                |
| accounts              | implemented                                                                                                                                |
| sysctl                | implemented                                                                                                                                |
| definitions           | implemented                                                                                                                                |
| password              | implemented                                                                                                                                |
| firewall              | implemented                                                                                                                                |
| encryption            | implemented                                                                                                                                |
| wipe                  | implemented                                                                                                                                |
| report-loss           | implemented                                                                                                                                |
| lock                  | implemented                                                                                                                                |
| recovery-sanitize     | implemented                                                                                                                                |
| self-update           | implemented                                                                                                                                |
| assistance            | gated: portal_screencast_unavailable: xdg-desktop-portal-xapp/-gtk implement no ScreenCast or RemoteDesktop; lindm has no X11 capture path |
| assistance-clipboard  | gated: not implemented for Linux Mint 22.3                                                                                                 |
| assistance-keyboard   | gated: not implemented for Linux Mint 22.3                                                                                                 |
| assistance-displays   | gated: not implemented for Linux Mint 22.3                                                                                                 |
| assistance-messages   | gated: not implemented for Linux Mint 22.3                                                                                                 |
| assistance-files      | gated: local FileChooser consent, input isolation and secure transfer are not qualified on this release                                    |
| assistance-reconnect  | gated: fresh consent after real logout/reboot and workflow expiry are not qualified on this release                                        |
| assistance-recording  | gated: recording disclosure, encrypted storage and retention are not qualified on this release                                             |
| assistance-unattended | gated: a compositor-supported persistent remote-desktop grant, banner/stop and lock refusal are not qualified on this release              |
| assistance-elevation  | gated: pausing all remote injection around a local privileged prompt is not qualified on this release                                      |
| assistance-annotation | gated: no qualified non-interactive compositor overlay exists on this release                                                              |
| assistance-audio      | gated: selected PipeWire output/microphone capture with local mute is not qualified on this release                                        |
| assistance-kde        | gated: kde_plasma_desktop_unqualified: no native KDE Plasma Wayland lane on this release; the helper admits no KDE capability              |
| assistance-x11        | gated: x11_desktop_unqualified: no native X11 session lane on this release; X11 sessions end UNAVAILABLE                                   |
| advisories            | partial: vendor feed unavailable for Linux Mint packages                                                                                   |
| os-update             | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release                                    |
| release-upgrade       | gated: release upgrade is not implemented                                                                                                  |

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
- Ubuntu's cloud-init apt module rewrites APT sources using os-release
  `VERSION_CODENAME`; on Mint that produced `archive.ubuntu.com … zena`,
  `zena-updates` and `zena-security` entries (404) and every `apt-get update`
  exited 100. The golden's `/etc/cloud/cloud.cfg.d/99-lindm-lab.cfg` therefore
  sets `apt: {preserve_sources_list: true}` (recipe `linuxmint-ubiquity-v3`), and
  Mint's own `official-package-repositories.list` stays authoritative. The
  encrypted golden has no cloud-init and keeps its own recipe identity.
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

Cinnamon 6.6.4+zena (X11, `XDG_CURRENT_DESKTOP=X-Cinnamon`) under LightDM
1.30.0-0ubuntu14 with slick-greeter. The lab autologin session reports logind
`Service=lightdm-autologin`, `Type=x11`, `Desktop=cinnamon` (observed by the
desktop-session lane).

- **Lock.** logind `LockSessions` engages `cinnamon-screensaver` 6.6.1+zena
  (`org.cinnamon.ScreenSaver.GetActive` returns true), but Cinnamon never sets
  logind `LockedHint`, which stays `no`. The product therefore reports the lock
  as `OUTCOME_UNKNOWN` with `session_lock_state_unreported` evidence rather than
  claiming a verified lock. Release succeeds and leaves the screensaver locked;
  account lock/restore and quarantine pass.
- **Assistance.** Gated `portal_screencast_unavailable`: xdg-desktop-portal
  1.20.0+ds-2ubuntu1 with `-xapp` 1.1.3+zena and `-gtk` 1.15.1-1build2 exposes no
  ScreenCast or RemoteDesktop portal, and lindm has no X11 capture path. VIEW and
  CONTROL end `UNAVAILABLE` before any consent prompt. Cinnamon 6.6.4 leaves
  `graphical-session.target` inactive; the agent package's
  `/etc/xdg/autostart/lindm-session.desktop` starts `lindm-session.service`
  through cinnamon-session's XDG autostart instead
  (`session_unit_activation=xdg-autostart`).

## Advisory feeds

Linux Mint publishes no machine-readable advisory feed, so exposure of Mint's own
packages is never known. Mint 22.3 (the exact `linuxmint-22.3` row, base
`ubuntu-24.04`, vendor origin `linuxmint`) is evaluated against the Ubuntu 24.04
feed only for packages whose every APT listing is a verified Ubuntu-archive index
of `noble`, `noble-security` or `noble-updates`; the evaluation is always
`partial` with reason `vendor_feed_unavailable_linuxmint` and an uncovered count
([architecture](../architecture.md#distro-advisory-findings)). Packages listed only
by `packages.linuxmint.com` are UNKNOWN `vendor_feed_unavailable`.

The `advisories` and `airgap` lab lanes have no Mint feed of their own: they
acquire (or bundle) Ubuntu 24.04's OSV export and require that verified-origin
`partial` evaluation with uncovered packages. The `advisories` lane also lists
every uncovered package and checks against the guest's own `apt-cache policy`
that a vendor-reason package's installed version comes from Release Origin
`linuxmint` and that each finding's package is listed only by Ubuntu's assessed
suites (`qualified_verified_origin_partial_matching`, never complete coverage).

## Lab records

All records are under `~/.cache/lindm-desktopderiv-20261011/linuxmint/` on the
local x86_64 KVM host (QEMU 8.2.2, OVMF `2024.02-2ubuntu0.10`), except the
desktop-session records under `…/sessions/mint/`. Each lane ran from an immutable
snapshot: `snap3` = DesktopDerivatives `9620057` plus the FIFO admission files
(lab `47d5761b…`), `snap5` = main `7876a674` plus the APT-sources fix that landed
as `464ad5cc` (lab `c944eb4b…`, lindmd `728fa7eb…`). Unencrypted lanes boot the
installed golden with Secure Boot off (`OVMF_VARS_4M.fd`); encrypted and action
lanes use `OVMF_VARS_4M.ms.fd` with Secure Boot enforced.

| Cell                                                                                 | Result                       | Record                                                            | SHA-256                                                            |
| ------------------------------------------------------------------------------------ | ---------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------ |
| Inventory (golden v3, 1905 packages, APT origins verified)                           | pass                         | `inspect-05.json`                                                 | `19ae97aa8fc414a5043e22ec99caac6ecde8c38c9d19f9b417c02005eaaa07ad` |
| Lifecycle (signed DEB 0.7.0→0.7.1, control-plane trust, local authority)             | pass                         | `lifecycle-05.json`                                               | `c48333450314570f24fbfe56791a8de6834ba676fc82c318664d51ce852b21e2` |
| Dispatch (service scenarios, clock skew, revocation)                                 | pass                         | `dispatch-03.json`                                                | `7169f45460f70f49dfe645d0bf4bf22f961c0c7aafe91930d393f59c27133721` |
| Power actions (restart, refresh inventory, shutdown)                                 | pass                         | `power-03.json`                                                   | `9593e9cafb9118e2a9b0aee037c0953ce8b2d1b56cc5ea34af9d642403316d5e` |
| Agent self-update                                                                    | pass                         | `updates-03.json`                                                 | `b4711034c9ead10d62cde03997d733aec7b553204f5679b554c20b6450657219` |
| Resources, executor phase (packages, files, accounts, sysctl, definitions, password) | pass                         | `resources-executor-05b.json`                                     | `bc3e79333a16a38b22deea5375474650af990f4c64c117da28c5ab8afbdce4ad` |
| Resources, connected phase (same + secret-password, local-admin)                     | pass                         | `resources-connected-05.json`                                     | `b33b84222eb7bf4bf89703604d69334c37f887895f8e1729f04ceae39b1651b0` |
| Resources, connected firewall (probe-peer guest)                                     | pass                         | `resources-connected-05fw.json`                                   | `ca8f29c0173fd03cbf73c2688dbc5be7e9f83731d7fb014c2b812c85e0f99d0c` |
| Encrypted installer golden (LUKS2, TPM2, Secure Boot, two cold boots, headers)       | pass                         | `encrypted-05.json`                                               | `27a32bf1ec385eaf0e535fc8ad00b2fab22af921d1389c67f7e6122a7e2b0931` |
| Device actions `-scenario all` (encryption, wipe, lock/quarantine, TPM)              | pass                         | `device-actions-all-all-05.json`                                  | `228af3db99b280d06a99e8bac155df00c702bb327be9018b8b53081388eadafd` |
| Lock/release/quarantine (desktop-session lane)                                       | pass, lock `OUTCOME_UNKNOWN` | `sessions/mint/mint223-lock-quarantine-01.json`                   | `dbba0024735008971ccfff6d2d9043ca31df42fcdc4b0d300e0b9249eb7f9f81` |
| Assistance VIEW/CONTROL                                                              | unavailable                  | `sessions/mint/mint223-assistance-02/assistance.json`             | `ab55da8ff567ac164ddd272238fe7564c7af8f7d49f8e2455cafe1cefcc26ad3` |
| Recovery sanitize, Mint original, measured GRUB, NVMe format                         | pass                         | `device-actions-mint-original-recovery-nvme-07.json`              | `2ba33c1dbc2d0a2fc0c121382fd98865824e2b8839b76063d2964f3134c81e89` |
| Recovery sanitize, Mint original, measured GRUB, SATA overwrite                      | pass                         | `device-actions-mint-original-recovery-sata-07b.json`             | `ed05a68121abdece41bba98713216868a569b59ac9db3454a434c7a32bf7e321` |
| 30 consecutive unattended TPM2 cold boots (main `8c6af7ff`, Secure Boot on)          | pass                         | `device-actions-tpm-unattended-boots-08.json`                     | `bf5869a0037cd3f29693b31562bddd2779d6b9a9e17cefac0907cfd38190fabf` |
| TPM reference repair (legacy agent 1 of 4 references → 4 of 4; 30 cold boots)        | pass                         | `device-actions-tpm-reference-repair-01.json`                     | `90822f9b6245ac019b3f180afed2fddd90f9828ca9bb1b01196cb4c9d9ed1c3e` |
| Services (systemd.service.v1 native provider, eleven scenarios)                      | pass                         | `matrix-deriv-03/linuxmint-22.3/services-x86_64.json`             | `ebab9e0dd0aaee6e570469c6f731d9503c13b79e8e68e97b9186b08fa486be66` |
| Advisories (verified-origin partial through Ubuntu 24.04 OSV)                        | pass, partial-feed matching  | `matrix-deriv-03/linuxmint-22.3/advisories-x86_64.json`           | `0a95850049c7d767591a0ede1c9a4559d940553722a52a4cfea8658c7c32c17d` |
| Air gap (B1/B2/B3/expired bundles, offline install, rollout 0.1.0→0.1.1, partial)    | pass                         | `matrix-airgap-05/linuxmint-22.3/airgap-x86_64.json`              | `f8ccf413ae10442f23776348936d00cd4dde8301287198176cecd3c0dbce8732` |
| Enroll from console (copied command, waits for APT locks)                            | pass                         | `matrix-enroll-05/linuxmint-22.3/enroll-from-console-x86_64.json` | `9fb6abec2a5d2fe02365224179e8a88b17811649bafbddde03d7adbb8cf29cbf` |

The TPM reference repair record ran from main `b6753033` (lab `-desktop cinnamon`,
Secure Boot enforced, `-legacy-agent-revision ced6d209…`): the legacy agent's
bind wrote one systemd-tpm2 token reference to keyslot 1 where the server
requires four; after the package upgrade the repair action wrote the missing
three (server 4 of 4) and all 30 unattended cold boots unsealed with no prompt
and no unseal failure. `lab matrix run` passed GNOME to the device-action lanes
of every release until the matrix learned to pass a release's sole lab desktop
(`TestMatrixDesktopCellsBootTheReleaseDesktop`); Mint's Ubiquity recipe refuses
any desktop but Cinnamon.

Services and advisories ran through `lab matrix run` from main `e399809a` (plus an
empty pin commit). The advisories record is `qualified_verified_origin_partial_matching`:
the server evaluated the enrolled Mint device through the Ubuntu 24.04 OSV feed as
`partial` `vendor_feed_unavailable_linuxmint` with 476 uncovered packages (123
`vendor_feed_unavailable`, 353 `origin_unlisted`) and 35,231 affected findings
over 1,906 native packages. The guest's own `apt-cache policy` placed every one of
the 123 vendor packages' installed versions in `linuxmint/zena` and each of the 200
checked finding packages only in Ubuntu's `noble`, `noble-security` or
`noble-updates`.

The air-gap cell passed from main `1ecd7588f`: the site imported B1 before serve,
the guest (no public route: DNS and TCP to 1.1.1.1 failed) installed agent 0.1.0
only from the site-served signed repository and enrolled, the identical B1 was a
no-op, the expired, one-byte-tampered, unsigned-edit and replayed bundles were
refused for their exact reasons, and the audited rollout of B3 installed 0.1.1 with
the enrollment preserved. Both the B1 and B3 evaluations of the bundled Ubuntu 24.04
OSV snapshot were `partial` `vendor_feed_unavailable_linuxmint` with 476 uncovered
packages (findings read to the lane's 20,000 bound). Three earlier attempts failed
before serve on product regressions that were not Mint-specific, each fixed with a
regression in `internal/offlinebundle`/`internal/releasebuild`: the bundle omitted a
server release's embedded agent repository (`matrix-airgap-01`, `d338b98d…`; fixed
`dc2ef9503`), import verified that repository with the bundle's private file modes
although the provenance digest binds its canonical ones (`matrix-airgap-03`,
`8edc0967…`, "canonical agent repository provenance mismatch"; fixed
`0de14df65`), and the bundle omitted the signed LICENSE/NOTICE/THIRD-PARTY-LICENSES
(`matrix-airgap-04`, `b6de6102…`; fixed `1ecd7588f`).

Enroll from console passed from main `dc2ef9503` (`matrix-enroll-04`,
`865a02d9ab2b7f5e70dde88c3c2acf66514be463ab998eb1702557e38563be49`) and again with
the lock-waiting APT command from main `57400ed5c` (the table's record). Two
attempts do not qualify the cell: `matrix-enroll-01` stopped before capture because
its browser configuration lacked `timeoutMs` (the runner's `invalid_deadline`;
operator input), and `matrix-enroll-03` was cancelled while queued for owner
priority.

The device-action record covers encryption inventory (LUKS2 UUID, TPM 2.0,
Secure Boot on, host oracle match), escrow (keyslot 1), audited reveal and custody
KEK, committed and interrupted rotation (keyslot 2, retired slot absent), TPM2
bind with an unattended cold boot, a mismatched PCR7 policy that falls back to the
passphrase prompt and revealed-key recovery, live-root crypto-erase (attested before
power-off, all headers absent) and report-loss (blocked report, outcome unknown by
design), lock/release and account locks, and quarantine (DNS preserved, host
endpoints verified, kernel expiry). Its original-device recovery sanitize sub-phase
uses the recovery manifest's Ubuntu 24.04 cloud image as the original device, so
it is not Mint evidence.

Mint-native recovery sanitize runs the measured shim+GRUB mode with the Mint golden
as the original device (`-recovery-manifest
lab/images/linuxmint-22.3-cinnamon-amd64.json -recovery-boot-mode measured-grub`).
The first attempt (`device-actions-mint-original-recovery-sata-05.json`,
`b1a6fcab4c8cdd9cbef78063262f963fcb829908acc6555fb1ebbf9d8d83abb3`) was refused
with `recovery_readiness_measured_grub_unsupported`: the agent's readiness reads
the GRUB chain from the os-release row's own quirks, and the Mint row had none.
The row now declares Ubuntu's stock chain (`Quirks.RecoveryGRUB`, landed as
`cc6a707e` with a regression in `TestDerivativeUsesBaseTooling`). The qualifying
NVMe and SATA reruns above ran from main `9b4e6f5f` (`snap7`, lab `5119bcfd…`,
lindmd `bad0b53e…`), which also carries the direct-ioctl NVMe sanitize. A SATA
attempt from that snapshot (`device-actions-mint-original-recovery-sata-07.json`,
`b7a98e67c1861de367ba39e25e1b17cdc2b5786a27430c5140093de2f447b7b5`) timed out
waiting for recovery SSH at host load average 43–57; that is a contention window,
not a product result, and the rerun passed.

Records that do not qualify a cell, kept for attribution:

- `lifecycle-03.log` (no record): the collection-denied phase timed out after
  seven minutes while the server rate-limited the agent's attempts; the rerun
  above passed every phase.
- `resources-executor-04-noegress.json` and `resources-executor-05.json`: the first
  ran without `-allow-network` (operator error); the second exposed the cloud-init
  APT-sources defect fixed in recipe v3.
- `device-actions-all-all-05-nosupermin.json`
  (`f945d20184d22dd12764d13d584c98294b87989c9b2736e17df6f5829764b7e3`): the host
  header read lacked `SUPERMIN_KERNEL`/`SUPERMIN_MODULES` on this root-only-`/boot`
  host (operator prerequisite).

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

## Capability policy facts (signed provider grants)

The default signed PACKAGES grant approves only the pinned Ubuntu 24.04 base
archive: `noble`, `noble-updates` and `noble-security`, with `main` and `universe`.
The registry uses Ubuntu's archive keyring digest and signing identity; the
device must have that exact vendor keyring. It does not import the machine's
global APT trust or implicitly approve `packages.linuxmint.com`.

Mint's own archive has no package-source key digest pin in the registry, so it
is deliberately excluded from this grant. Its presence in the OS's APT sources
does not grant lindm authority to use it. Managing Mint-only packages requires
an explicitly approved local source with independently pinned vendor key
material. Standard file roots and local-account defaults match the Ubuntu base.
This is a derivation contract, not an additional native qualification claim;
qualification evidence remains in the [verification ledger](../verification.md).
