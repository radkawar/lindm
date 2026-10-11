# Linux Mint

Tier 1, desktop-first: current Linux Mint release, Cinnamon edition, x86_64. Full
parity with Ubuntu 24.04 is required
([tiers](../product-specification.md#supported-os-tiers)). Mint is built on an Ubuntu
LTS base, but **no Ubuntu evidence carries over** to it.

## Supported versions, architectures and qualification

Current Mint release (Cinnamon) on x86_64 only. Mint publishes no arm64 build.
Nothing is recorded yet; see the
[tier capability matrix](../verification.md#tier-capability-matrix).

## Quirks to verify

- **Cinnamon session type.** Cinnamon defaults to X11, and its Wayland session is
  experimental. The assistance helper captures only through the XDG
  ScreenCast/RemoteDesktop portals. Check whether
  `xdg-desktop-portal-xapp` provides them on X11 and on Wayland. If not, the
  session must end `UNAVAILABLE` and must never fall back to raw X11 capture.
  Session lock goes through `cinnamon-screensaver`; check logind `LockedHint`.
- **Ubuntu base, Mint identity.** `os-release` reports `ID=linuxmint` and
  `ID_LIKE="ubuntu debian"` with `UBUNTU_CODENAME`. Detection must use the observed
  capabilities and the Ubuntu base version, not the Mint version number.
- **Repositories.** Mint adds `packages.linuxmint.com` with its own signing key,
  plus the Ubuntu archive (`official-package-repositories.list`). It also has APT
  pinning that blocks some packages (for example snapd via `nosnap.pref`). Inventory
  and package resources must report both sources and that pinning faithfully.
- **Updates.** Mint Update (`mintupdate`) and its automatic-update units overlap
  with OS patch policy. Ownership and conflict behavior must be specified.
- **Timeshift.** Timeshift snapshots (rsync or Btrfs) and their scheduled runs can
  affect wipe, recovery and update rollback claims. Escrowed or erased data must not
  survive in a snapshot.
- **Installer and encryption.** The Ubiquity-based installer's LUKS layout (LVM on
  LUKS) must be confirmed for escrow, TPM2 binding and crypto-erase.

## Packaging

The Ubuntu-base DEB is expected to apply. Install it only through authenticated APT
and record the Mint release it ran on.

## Services and sandbox

Root executor and network units as in the
[shared boundaries](README.md#shared-implementation-boundaries); not yet observed
on Mint.

## Updates

Not recorded; see the Mint Update quirk above.

## Inventory

Not recorded. The native oracle must observe this distribution's own `os-release`
identity and package sources; `ID_LIKE` never selects behavior on its own
([shared boundaries](README.md#shared-implementation-boundaries)).

## Encryption and recovery

Not recorded. Encryption inventory, escrow, reveal, rotation, TPM2 binding and
cold-boot recovery need this distribution's own installer-encrypted golden.

## Actions

Not recorded. Lock/release/quarantine, live-root crypto-erase, report-loss and
recovery sanitize each need native evidence here.

## Advisory feeds

Not recorded.

## Lab

x86_64 only, on the local KVM host under lease admission (no arm64 build is used
for this row). Acquire media only with vendor-authenticated checksums and build the
golden with a maintained recipe; ISO relabels are not allowed
([engineering](../engineering.md)). Record evidence paths with SHA-256 in
[verification](../verification.md#tier-capability-matrix).

## Known gaps

Every capability cell is empty. Nothing in this page is qualified.
