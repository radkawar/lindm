# Platform engineering guide

These pages explain how lindm implements each Linux family and which native details must survive refactoring.
They describe evidence limits, not production support.
Lindm remains a development preview.
The ledger qualifies Tier 1 x86_64 operations only within each recorded scope.
Arm64 release qualification awaits the lab, despite partial native passes.
A package installation, inventory comparison or service scenario does not qualify every resource on that family.

Use [verification](../verification.md#1-launch-platform-qualification) and the
[implementation plan](../implementation-plan.md) for authoritative gates and evidence.

**Evidence access:** `~/.cache` and `$HOME` evidence paths identify maintainer-local retained records with hash references.
The repository does not include these records or provide public downloads.

Connected turnkey advisory defaults activate only complete maintained exports for
actual enrolled inventory identities; registry support alone is not a promise of
automatic complete feed coverage. Unknown products, derivatives, partial rows and
rows without every maintained export remain unchecked unless explicit policy
supplies a valid source. All matching, rejection and origin rules remain in force.
See [installation guidance](../install.md#wait-for-the-first-vulnerability-assessment)
and each family's advisory section. There is no new qualification claim.

## Support status matrix

The table below is generated from the platform registry (`internal/platform`, run
`make generate`). New distribution facts go only into the registry; providers and the
lab ask it for capabilities instead of comparing os-release IDs. A row is required
launch scope or a recognized branch, not currently supported production use. Recorded
native evidence is in the [tier capability matrix](../verification.md#tier-capability-matrix),
generated from the lab matrix ledger; see each family page for exact records, hashes,
failures and later continuations. The
[resource-kind matrix](../verification.md#resource-kind-coverage) and
[customer-journey gate](../verification.md#customer-journey-release-acceptance)
must be checked before advertising a capability. Connected and air-gapped deployments,
desktop editions, CPU baselines and physical hardware qualify independently, and a
derivative never inherits its base's evidence.

Tiers come from the
[product specification](../product-specification.md#supported-os-tiers). Tier 1 is
desktop-first with full parity with Ubuntu 24.04. Tier 2 meets the same contract
through a rolling model. Future rows are design-only. Outside rows are recognized
branches the owner has not placed in a tier.

<!-- BEGIN GENERATED platform-support -->

| Tier    | Release                          | os-release match                                                            | Architectures   | Packages                    | systemd | Firewall (native)         | FDE                                                                                                     | Desktop                                                                                                                                                                                                                               | Advisory feed                                                | Provisioning formats    | Guide                           |
| ------- | -------------------------------- | --------------------------------------------------------------------------- | --------------- | --------------------------- | ------- | ------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------------------- | ------------------------------- |
| 1       | Ubuntu 22.04 LTS                 | ID=ubuntu VERSION_ID=22.04                                                  | x86_64, aarch64 | apt                         | 249     | nftables + ufw (inactive) | LUKS2 (subiquity LVM); TPM2 via systemd-cryptenroll (dracut 051 + TSS2 libraries)                       | GNOME; DM gdm3; lock GNOME Shell                                                                                                                                                                                                      | osv Ubuntu:22.04:LTS                                         | cloud-init, autoinstall | [ubuntu](ubuntu.md)             |
| 1       | Ubuntu 24.04 LTS                 | ID=ubuntu VERSION_ID=24.04                                                  | x86_64, aarch64 | apt                         | 255     | nftables + ufw (inactive) | LUKS2 (subiquity LVM); TPM2 via systemd-cryptenroll (dracut)                                            | GNOME (GNOME 46); DM gdm3; lock GNOME Shell                                                                                                                                                                                           | osv Ubuntu:24.04:LTS                                         | cloud-init, autoinstall | [ubuntu](ubuntu.md)             |
| 1       | Ubuntu 26.04 LTS                 | ID=ubuntu VERSION_ID=26.04                                                  | x86_64, aarch64 | apt                         | 259     | nftables + ufw (inactive) | —                                                                                                       | GNOME; DM gdm3; lock GNOME Shell                                                                                                                                                                                                      | osv Ubuntu:26.04:LTS                                         | cloud-init, autoinstall | [ubuntu](ubuntu.md)             |
| 1       | Debian 12                        | ID=debian VERSION_ID=12                                                     | x86_64, aarch64 | apt                         | 252     | nftables                  | LUKS2 (partman-crypto LVM); TPM2 via systemd-cryptenroll (dracut)                                       | GNOME/KDE; DM gdm3; lock GNOME Shell                                                                                                                                                                                                  | osv, debian-tracker Debian:12                                | cloud-init              | [debian](debian.md)             |
| 1       | Debian 13                        | ID=debian VERSION_ID=13                                                     | x86_64, aarch64 | apt                         | 257     | nftables                  | LUKS2 (partman-crypto LVM); TPM2 via systemd-cryptenroll (dracut)                                       | GNOME/KDE; DM gdm3; lock GNOME Shell                                                                                                                                                                                                  | osv, debian-tracker Debian:13                                | cloud-init              | [debian](debian.md)             |
| 1       | Fedora 43                        | ID=fedora VERSION_ID=43 VARIANT_ID=unset/workstation/server/cloud/container | x86_64, aarch64 | dnf5 ≥ 5.4.6.0              | 258     | nftables + firewalld      | LUKS2 (anaconda LVM); TPM2 via systemd-cryptenroll (dracut)                                             | Workstation GNOME; KDE edition (GNOME 49); DM gdm; lock GNOME Shell                                                                                                                                                                   | rpm-updateinfo Fedora 43                                     | cloud-init, kickstart   | [fedora](fedora.md)             |
| 1       | Fedora 44                        | ID=fedora VERSION_ID=44 VARIANT_ID=unset/workstation/server/cloud/container | x86_64, aarch64 | dnf5 ≥ 5.4.6.0              | 259     | nftables + firewalld      | LUKS2 (anaconda LVM); TPM2 via systemd-cryptenroll (dracut)                                             | Workstation GNOME; KDE edition (GNOME 50); DM gdm; lock GNOME Shell                                                                                                                                                                   | rpm-updateinfo Fedora 44                                     | cloud-init, kickstart   | [fedora](fedora.md)             |
| 1       | RHEL 9                           | ID=rhel VERSION_ID=9[.N]                                                    | x86_64, aarch64 | dnf4 ≥ 4.7.0                | 252     | nftables + firewalld      | —                                                                                                       | GNOME; DM gdm; lock GNOME Shell                                                                                                                                                                                                       | redhat-csaf cpe:/o:redhat:enterprise_linux:9                 | cloud-init, kickstart   | [rhel](rhel.md)                 |
| 1       | RHEL 10                          | ID=rhel VERSION_ID=10[.N]                                                   | x86_64, aarch64 | dnf4 ≥ 4.7.0                | 257     | nftables + firewalld      | —                                                                                                       | GNOME; DM gdm; lock GNOME Shell                                                                                                                                                                                                       | redhat-csaf cpe:/o:redhat:enterprise_linux:10                | cloud-init, kickstart   | [rhel](rhel.md)                 |
| 1       | Rocky Linux 9                    | ID=rocky VERSION_ID=9[.N]                                                   | x86_64, aarch64 | dnf4 ≥ 4.7.0                | 252     | nftables + firewalld      | —                                                                                                       | GNOME; DM gdm; lock GNOME Shell                                                                                                                                                                                                       | osv Rocky Linux:9                                            | cloud-init, kickstart   | [alma-rocky](alma-rocky.md)     |
| 1       | Rocky Linux 10                   | ID=rocky VERSION_ID=10[.N]                                                  | x86_64, aarch64 | dnf4 ≥ 4.7.0                | 257     | nftables + firewalld      | —                                                                                                       | GNOME; DM gdm; lock GNOME Shell                                                                                                                                                                                                       | osv Rocky Linux:10                                           | cloud-init, kickstart   | [alma-rocky](alma-rocky.md)     |
| 1       | AlmaLinux 9                      | ID=almalinux VERSION_ID=9[.N]                                               | x86_64, aarch64 | dnf4 ≥ 4.7.0                | 252     | nftables + firewalld      | —                                                                                                       | GNOME; DM gdm; lock GNOME Shell                                                                                                                                                                                                       | osv AlmaLinux:9                                              | cloud-init, kickstart   | [alma-rocky](alma-rocky.md)     |
| 1       | AlmaLinux 10                     | ID=almalinux VERSION_ID=10[.N]                                              | x86_64, aarch64 | dnf4 ≥ 4.7.0                | 257     | nftables + firewalld      | —                                                                                                       | GNOME; DM gdm; lock GNOME Shell                                                                                                                                                                                                       | osv AlmaLinux:10                                             | cloud-init, kickstart   | [alma-rocky](alma-rocky.md)     |
| 1       | Linux Mint 22.3                  | ID=linuxmint VERSION_ID=22.3                                                | x86_64          | apt (Ubuntu 24.04 LTS base) | 255     | nftables + ufw (inactive) | LVM on LUKS (Ubiquity)                                                                                  | Cinnamon; DM lightdm; lock cinnamon-screensaver (logind Lock; never sets LockedHint)                                                                                                                                                  | osv Ubuntu:24.04:LTS (verified Ubuntu-archive packages only) | —                       | [mint](mint.md)                 |
| 1       | Pop!\_OS 24.04 LTS               | ID=pop VERSION_ID=24.04                                                     | x86_64          | apt (Ubuntu 24.04 LTS base) | 255     | nftables + ufw (inactive) | LVM on LUKS (distinst)                                                                                  | COSMIC; DM cosmic-greeter; lock cosmic-greeter (logind)                                                                                                                                                                               | osv Ubuntu:24.04:LTS (verified Ubuntu-archive packages only) | —                       | [popos](popos.md)               |
| 2       | Arch Linux                       | ID=arch, no VERSION_ID                                                      | x86_64          | pacman                      | —       | —                         | LUKS2; systemd-cryptenroll with mkinitcpio sd-encrypt                                                   | GNOME Wayland (maintained); owner-chosen bootloader; DM gdm; lock GNOME Shell                                                                                                                                                         | arch-asa Arch Linux rolling                                  | cloud-init              | [arch](arch.md)                 |
| 2       | Omarchy 4.0.4                    | ID=omarchy VERSION_ID=4.0.4                                                 | x86_64          | pacman (Arch Linux base)    | —       | —                         | LUKS2 on Btrfs (archinstall via the Omarchy ISO); mkinitcpio busybox encrypt hook, no TPM2 token unlock | Hyprland (Hyprland 0.56.2); DM sddm; lock Quickshell WlSessionLock (Omarchy shell); session lock unsupported: logind LockSessions has no effect on Omarchy's Quickshell session lock (omarchy-hyprland-session-locked stays unlocked) | —                                                            | —                       | [omarchy](omarchy.md)           |
| 2       | openSUSE Tumbleweed              | ID=opensuse-tumbleweed VERSION_ID=YYYYMMDD                                  | x86_64, aarch64 | zypper                      | —       | —                         | LUKS2 (AutoYaST); systemd-cryptenroll with dracut                                                       | GNOME Wayland (maintained); KDE separately qualified; DM gdm; lock GNOME Shell                                                                                                                                                        | suse-oval, suse-csaf cpe:/o:opensuse:tumbleweed              | cloud-init, autoyast    | [opensuse](opensuse.md)         |
| Future  | Fedora Atomic Silverblue/Kinoite | ID=fedora VARIANT_ID=silverblue/kinoite                                     | —               | —                           | —       | —                         | —                                                                                                       | —                                                                                                                                                                                                                                     | —                                                            | —                       | [atomic-nixos](atomic-nixos.md) |
| Future  | NixOS                            | ID=nixos                                                                    | —               | —                           | —       | —                         | —                                                                                                       | —                                                                                                                                                                                                                                     | —                                                            | nixos                   | [atomic-nixos](atomic-nixos.md) |
| Outside | Debian 11                        | ID=debian VERSION_ID=11                                                     | x86_64, aarch64 | apt                         | 247     | —                         | —                                                                                                       | —                                                                                                                                                                                                                                     | osv, debian-tracker Debian:11                                | cloud-init              | [debian](debian.md)             |
| Outside | RHEL 8                           | ID=rhel VERSION_ID=8[.N]                                                    | x86_64, aarch64 | dnf4 ≥ 4.7.0                | 239     | —                         | —                                                                                                       | —                                                                                                                                                                                                                                     | redhat-csaf cpe:/o:redhat:enterprise_linux:8                 | cloud-init, kickstart   | [rhel](rhel.md)                 |
| Outside | Rocky Linux 8                    | ID=rocky VERSION_ID=8[.N]                                                   | x86_64, aarch64 | dnf4 ≥ 4.7.0                | 239     | nftables + firewalld      | —                                                                                                       | GNOME; DM gdm; lock GNOME Shell                                                                                                                                                                                                       | osv Rocky Linux:8                                            | cloud-init, kickstart   | [alma-rocky](alma-rocky.md)     |
| Outside | AlmaLinux 8                      | ID=almalinux VERSION_ID=8[.N]                                               | x86_64, aarch64 | dnf4 ≥ 4.7.0                | 239     | nftables + firewalld      | —                                                                                                       | GNOME; DM gdm; lock GNOME Shell                                                                                                                                                                                                       | osv AlmaLinux:8                                              | cloud-init, kickstart   | [alma-rocky](alma-rocky.md)     |
| Outside | CentOS Stream 9                  | ID=centos VERSION_ID=9                                                      | x86_64, aarch64 | dnf4 ≥ 4.7.0                | —       | —                         | —                                                                                                       | —                                                                                                                                                                                                                                     | —                                                            | cloud-init, kickstart   | [alma-rocky](alma-rocky.md)     |
| Outside | CentOS Stream 10                 | ID=centos VERSION_ID=10                                                     | x86_64, aarch64 | dnf4 ≥ 4.7.0                | —       | —                         | —                                                                                                       | —                                                                                                                                                                                                                                     | —                                                            | cloud-init, kickstart   | [alma-rocky](alma-rocky.md)     |
| Outside | openSUSE Leap 16.0               | ID=opensuse-leap VERSION_ID=16.0                                            | x86_64, aarch64 | zypper                      | —       | —                         | —                                                                                                       | —                                                                                                                                                                                                                                     | suse-csaf cpe:/o:opensuse:leap:16.0                          | cloud-init              | [opensuse](opensuse.md)         |
| Outside | SLES 15                          | ID=sles VERSION_ID=15[.N]                                                   | x86_64, aarch64 | zypper                      | —       | —                         | —                                                                                                       | —                                                                                                                                                                                                                                     | suse-csaf cpe:/o:suse:sles:15:spN                            | cloud-init, autoyast    | [opensuse](opensuse.md)         |
| Outside | SLED 15                          | ID=sled VERSION_ID=15[.N]                                                   | x86_64          | zypper                      | —       | —                         | —                                                                                                       | —                                                                                                                                                                                                                                     | —                                                            | autoyast                | [opensuse](opensuse.md)         |

<!-- END GENERATED platform-support -->

Branch architecture allocation is in
[branch allocation](../verification.md#branch-allocation); detailed native
continuations in that ledger take precedence over any older summary table.
Server-host qualification is a separate
[deployment matrix](../verification.md#control-plane-deployment-matrix).

## Shared implementation boundaries

- **Detect capabilities, not family resemblance.** Applicability depends on observed
  OS/version, architecture, tooling, session, topology and hardware, not `ID_LIKE`
  alone (`docs/architecture.md:461-472`). A canonical RPM package identity does not
  mean the machine runs DNF, and a DNF5 collector does not make DNF4 APIs equivalent.
- **Keep the root/network split.** The installed root executor runs
  `/usr/libexec/lindm/lindm-agent executor`, reads `/etc/lindm/executor.json`, and
  owns `/var/lib/lindm/executor`. The `lindm` network user runs the same binary's
  `run` command with `/etc/lindm/agent.json` and separate `/var/lib/lindm/agent` state.
  Both units use `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateDevices=yes`
  and `NoNewPrivileges=yes`; network capabilities are empty. Privileged action
  exceptions must be explicitly provisioned and qualified, not implemented by
  removing the persistent sandbox. Sources:
  [`lindm-executor.service`](../../internal/packaging/assets/lindm-executor.service):9-61,
  [`lindm-agent.service`](../../internal/packaging/assets/lindm-agent.service):9-50.
- **Do not collapse trust domains.** Native package/repository signing, vendor image
  signing, TUF agent-release metadata and signed execution authority solve different
  problems. Agent packages always come from the customer's own `lindmd`, at its
  configured HTTPS origin, never from an external agent repository or a URL guessed
  from browser headers. The console uses the registry's exact OS/architecture to
  select APT, DNF, zypper or available pacman packaging and gives an explicit remedy
  when artifacts are missing. Copied commands carry authenticated signer,
  execution-root and private-CA pins. See the
  [install runbook](../security-and-operations.md#enrollment-installation-from-your-server)
  and [bootstrap threat model](../architecture.md#trust-bootstrap-from-the-customers-server).
- **Equality is not health.** The native oracle rejects matching permission errors,
  timeouts, invalid output and command failures. An optional `UNAVAILABLE` field
  needs its exact capability-backed explanation: for example absent Flatpak requires
  a successful backend observation of `false`; missing DNF repositories on an RPM
  host are not excused as a family quirk. See
  `internal/vmlab/inventory_health_linux.go` and
  `internal/vmlab/inventory_unavailable_linux.go`, and
  `docs/engineering.md:397-412`.
- **Device identity is hardware-specific.** A stock virtio disk without a WWN is not
  evidence of a distribution defect or license to invent an identifier. Stable
  targeting, encryption slots, Secure Boot and TPM observations each need independent
  native evidence; see [stable storage selection](../verification.md#stable-storage-selection).
- **Desktop assistance needs a real session and the portal.** The session helper
  is a per-user systemd unit. It is authorized only by `SO_PEERCRED` plus a local,
  active, unlocked logind graphical session. It captures only through the XDG
  ScreenCast/RemoteDesktop portals with PipeWire and GStreamer. Each page lists its
  qualified desktop/portal versions and GStreamer package names. A desktop without
  the portal, notification actions or GStreamer elements ends sessions
  `UNAVAILABLE`; it is never a silent X11 capture. See
  [architecture](../architecture.md#implemented-assistance-path).
- **Recovery capacity is a prerequisite.** In-band recovery requires room for the
  qualified signed image. Do not resize an ESP, delete vendor boot files or replace
  the qualified kernel to turn an unsupported cell green; see
  `docs/product-specification.md:145-160` and the Fedora page.

## Remote assistance capability qualification

The [remote assistance capabilities](../product-specification.md#remote-assistance-capabilities)
contract defines each user story, consent model, off/limited/on policy, per-role
permission, audit event and native mechanism. Apply it separately to every platform
page; an `assistance` registry entry qualifies neither a clipboard interface nor
file transfer, recording, audio, unattended access, KDE or X11. The existing local
session/portal gate is mandatory for every extension, not a bypassable default.

GNOME 46 on Ubuntu 24.04 and GNOME 50 on Fedora 44 are the initial x86_64 Wayland
targets. Inspect exact portal frontend, backend and compositor sources and probe
the running interface before enabling a capability. Clipboard must use the existing
RemoteDesktop session; files use Downloads/FileChooser; messages use the bound
user's notification service. No `ID_LIKE`, desktop-name or version-only assumption
is sufficient. A missing native mechanism has an explicit registry refusal reason.

The [new qualification rows](../verification.md#commercial-assistance-capability-qualification)
are not run. Each platform needs its own clipboard nonce round-trip, guest shortcut
effects, two-head monitor/pointer checks, visible notification, transfer hashes,
reboot/logout re-consent and encrypted-recording/retention evidence as applicable.
Tier 3 unattended access, password guidance, the GNOME Shell pointer overlay and
sound are owner-approved and implemented, unqualified, on Ubuntu 24.04 and Fedora 44
GNOME Wayland only; every other platform gates them. Plasma and X11 keep their own
qualification rows.

## Maintaining these pages

Any change touching distro-specific behavior must update the matching page in the
same change, as required by [AGENTS.md](../../AGENTS.md). Keep these sections on each
page: supported versions/architectures and qualification; packaging; services and
sandbox; inventory; updates; encryption/recovery; actions; advisory feeds; lab;
known gaps. Cross-link shared behavior instead of inventing a second convention.

Ground implementation claims in repository paths and line ranges, upstream claims
in version-specific sources, and qualification claims in recorded evidence paths
with SHA-256 digests. State whether a claim is implemented, natively observed,
unqualified or blocked. Preserve failures and their scope when adding a later pass;
a component correction alone is not a rerun. Do not publish private inventory,
credentials, activation keys, enrollment grants or recovery material. The
[verification ledger](../verification.md) retains executable inputs and the boundary
between VM, emulated hardware and physical-machine evidence.
