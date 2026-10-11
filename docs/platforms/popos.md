# Pop!\_OS

Tier 1, desktop-first: current Pop!\_OS LTS with the COSMIC desktop, x86_64. Full
parity with Ubuntu 24.04 is required
([tiers](../product-specification.md#supported-os-tiers)). Pop!\_OS is built on
Ubuntu, but **no Ubuntu evidence carries over** to it.

## Supported versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Pop!\_OS 24.04 LTS                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------- |
| inventory         | implemented                                                                                             |
| lifecycle         | implemented                                                                                             |
| dispatch          | implemented                                                                                             |
| packages          | implemented                                                                                             |
| accounts          | implemented                                                                                             |
| sysctl            | implemented                                                                                             |
| definitions       | implemented                                                                                             |
| password          | implemented                                                                                             |
| firewall          | implemented                                                                                             |
| encryption        | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| wipe              | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| report-loss       | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| lock              | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| recovery-sanitize | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| self-update       | implemented                                                                                             |
| assistance        | gated: no maintained encrypted installer, native action prerequisites or graphical golden               |
| advisories        | gated: no vendor advisory feed; the Ubuntu feed covers only verified Ubuntu-archive packages            |
| os-update         | gated: OS update policy (unattended-upgrades/dnf automatic runner) has no native record on this release |
| release-upgrade   | gated: release upgrade is not implemented                                                               |

<!-- END GENERATED platform-capabilities -->

Current LTS on x86_64. System76 arm64 images are not part of this row. Nothing is
recorded yet; see the
[tier capability matrix](../verification.md#tier-capability-matrix).

## Quirks to verify

- **COSMIC compositor.** COSMIC is a Rust Wayland compositor (`cosmic-comp`) with
  its own portal backend (`xdg-desktop-portal-cosmic`). Assistance needs that
  backend to support ScreenCast **and** RemoteDesktop input injection, plus
  notification actions. Lock goes through `cosmic-greeter`/logind; check that
  `LockedHint` and portal closure ordering are reported as on GNOME.
- **Own installer.** The System76 installer (`pop-installer`/distinst) creates its
  own partition and LUKS layout, including a recovery partition. Escrow, TPM2
  binding, crypto-erase and recovery sanitize must be checked against that layout.
- **systemd-boot and kernelstub.** Pop!\_OS boots with systemd-boot, not GRUB.
  `kernelstub` copies kernels and initrds to the ESP and manages the kernel command
  line. Reboot, TPM2 PCR policy, recovery boot entries and ESP capacity must be
  observed on this stack, and kernelstub must not be bypassed.
- **Repositories.** System76 `apt.pop-os.org` sources sit on top of the Ubuntu base.
  They have their own keys and Pop-specific package versions that inventory and
  package resources must report.
- **Identity.** `os-release` reports `ID=pop` with `ID_LIKE="ubuntu debian"`;
  select behavior by capability, not resemblance.

## Packaging

The Ubuntu-base DEB is expected to apply through authenticated APT. Record the
Pop!\_OS release it ran on.

## Services and sandbox

As in the [shared boundaries](README.md#shared-implementation-boundaries); not yet
observed on Pop!\_OS.

## Updates

Not recorded. Pop!\_OS ships its own update tooling (COSMIC Store, `pop-upgrade`),
and its ownership relative to OS patch policy must be specified.

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
