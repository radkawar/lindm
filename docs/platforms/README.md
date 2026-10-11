# Platform engineering guide

These pages explain how lindm implements each Linux family, which native details
must survive refactoring, and where evidence stops. They are engineering references,
not a support announcement. **No complete release matrix cell is certified.** A
passing package install, inventory comparison or service scenario qualifies only
that recorded operation, image and architecture—not every resource on that family.
The authoritative gates and evidence ledger remain
[verification](../verification.md#1-launch-platform-qualification) and the
[implementation plan](../implementation-plan.md).

## Support status matrix

“Target” below means required launch scope, not currently supported production use.
“Recorded” summarizes bounded native evidence; see each family page for exact records,
hashes, failures and later continuations. The
[resource-kind matrix](../verification.md#resource-kind-coverage) and
[customer-journey gate](../verification.md#customer-journey-release-acceptance)
must be checked before advertising a capability. Connected and air-gapped deployments,
desktop editions, CPU baselines and physical hardware qualify independently.

Tiers come from the
[product specification](../product-specification.md#supported-os-tiers). Tier 1 is
desktop-first with full parity with Ubuntu 24.04. Tier 2 meets the same contract
through a rolling model. Future rows are design-only. Per-capability cells are in
the [tier capability matrix](../verification.md#tier-capability-matrix).

| Tier   | Family guide                                | Target branches and architecture                                     | Recorded status and boundary                                                                                                                                                                                                      |
| ------ | ------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1      | [Ubuntu](ubuntu.md)                         | 22.04/24.04/26.04 LTS; x86_64 desktop/server, aarch64 server         | Native x86_64 packaged/service/trust evidence, selected 24.04 encryption/actions and ARM inventory; not whole-family or physical certification.                                                                                   |
| 1      | [Debian](debian.md)                         | 13 and 12; x86_64 desktop/server, aarch64 server                     | Signed installer path; Debian 12/13 native ARM inventory, lifecycle/trust and dispatch records. Desktop, encryption and other cells remain separate.                                                                              |
| 1      | [Fedora](fedora.md)                         | Current two releases (43/44); x86_64 desktop/server, aarch64 server  | Fedora44 ARM DNF5 inventory, CPU/source and session applicability passed; selected lifecycle/service/encryption/action records. Other cells require separate evidence.                                                            |
| 1      | [RHEL](rhel.md)                             | 9/10 supported minors; x86_64 and vendor aarch64 server              | RHEL9.8 current DNF4 inventory passed; 9.8/10.2 x86_64 registered lifecycle/trust/dispatch recorded with SELinux enforcing; 9.8 aarch64 registered DNF4 package resources passed. Entitlement and architecture are not inherited. |
| 1      | [AlmaLinux and Rocky Linux](alma-rocky.md)  | Separate 9/10 current-minor rows; x86_64/aarch64                     | Signed image acquisition and selected native comparisons; AlmaLinux 9.8/10.2 aarch64 DNF4 package resources passed. Each distribution/version/lifecycle continuation stands alone.                                                |
| 1      | [Linux Mint](mint.md)                       | Current release, Cinnamon; x86_64 only                               | Nothing recorded. Ubuntu evidence does not carry over.                                                                                                                                                                            |
| 1      | [Pop!\_OS](popos.md)                        | Current LTS, COSMIC; x86_64                                          | Nothing recorded. Ubuntu evidence does not carry over.                                                                                                                                                                            |
| 2      | [Arch Linux](arch.md)                       | Pinned rolling snapshot, x86_64                                      | Native inventory and signed pacman lifecycle recorded; dispatch not qualified. Arch Linux ARM is a separate derivative.                                                                                                           |
| 2      | [openSUSE and SUSE boundaries](opensuse.md) | Pinned Tumbleweed, x86_64; Leap 16.0 and SLES/SLED outside the tiers | Tumbleweed aarch64 inventory, lifecycle and dispatch recorded; x86_64 and desktop cells remain separate.                                                                                                                          |
| 2      | [Omarchy](omarchy.md)                       | Current release on a pinned Arch snapshot, Hyprland; x86_64          | Nothing recorded. Arch evidence does not carry over.                                                                                                                                                                              |
| Future | [Fedora Atomic and NixOS](atomic-nixos.md)  | Silverblue/Kinoite and NixOS, x86_64                                 | Design-only until a separate declarative/image-based management model is specified; mutable RPM/DEB implementations do not qualify them.                                                                                          |

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
  problems. Enrollment repository instructions are deployment configuration, not a
  guessed URL derived from the console origin; see
  [enrollment instructions](../agent-enrollment.md) and
  [security and operations](../security-and-operations.md).
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
