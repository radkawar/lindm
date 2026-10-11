# Omarchy

Tier 2: the current Omarchy release on a pinned Arch Linux snapshot, Hyprland,
x86_64 ([tiers](../product-specification.md#supported-os-tiers)). Omarchy is an
opinionated setup layered on Arch. **No [Arch](arch.md) evidence carries over** to
it.

## Supported versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Omarchy 4.0.4                                                                                           |
| ----------------- | ------------------------------------------------------------------------------------------------------- |
| inventory         | implemented                                                                                             |
| lifecycle         | implemented                                                                                             |
| dispatch          | implemented                                                                                             |
| packages          | gated: not implemented for Omarchy 4.0.4                                                                |
| accounts          | gated: not implemented for Omarchy 4.0.4                                                                |
| sysctl            | gated: not implemented for Omarchy 4.0.4                                                                |
| definitions       | gated: not implemented for Omarchy 4.0.4                                                                |
| password          | gated: not implemented for Omarchy 4.0.4                                                                |
| firewall          | gated: not implemented for Omarchy 4.0.4                                                                |
| encryption        | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| wipe              | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| report-loss       | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| lock              | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| recovery-sanitize | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| self-update       | implemented                                                                                             |
| assistance        | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| advisories        | gated: no vendor advisory feed; the Arch feed does not cover Omarchy packages                           |
| os-update         | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release |
| release-upgrade   | gated: release upgrade is not implemented                                                               |

<!-- END GENERATED platform-capabilities -->

The Omarchy release and the underlying Arch snapshot are both pinned in each
record. x86_64 only. Nothing is recorded yet; see the
[tier capability matrix](../verification.md#tier-capability-matrix).

## Quirks to verify

- **Arch rolling base.** Omarchy follows Arch's rolling repositories plus its own
  package sources and `omarchy-update` flow. Records pin the Arch Archive date and
  the Omarchy version. Whole-system upgrades are the only supported update shape
  (no partial upgrades), and OS patch policy must say which tool owns them.
- **Hyprland session.** Hyprland is a wlroots-independent Wayland compositor with
  `xdg-desktop-portal-hyprland`. Assistance needs ScreenCast plus RemoteDesktop
  input. Confirm whether the backend implements RemoteDesktop; if not, sessions end
  `UNAVAILABLE` and there is no fallback.
- **hypridle and hyprlock.** Locking goes through `hyprlock`, triggered by
  `hypridle`. Check that the logind lock request (`loginctl lock-session`) reaches
  it and that `LockedHint` is set, both for lock/release and for the assistance
  `SESSION_LOCKED` path.
- **Notifications.** Omarchy uses its own notification daemon (mako). Consent
  prompts need notification actions to be supported.
- **Installer and encryption.** The Omarchy installer sets up full-disk LUKS
  encryption, typically on Btrfs, and its own boot loader choice. Escrow, TPM2
  binding, crypto-erase and Btrfs snapshot handling all need to be observed.

## Packaging

The pacman package path from [Arch](arch.md) is expected to apply. It must be
verified with signed packages on the pinned Omarchy system.

## Services and sandbox

As in the [shared boundaries](README.md#shared-implementation-boundaries); not yet
observed on Omarchy.

## Updates

Not recorded; see the rolling-base quirk above.

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
