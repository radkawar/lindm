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

| Family guide                                | Target branches and architecture                                                   | Recorded status and boundary                                                                                                                                                |
| ------------------------------------------- | ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Ubuntu](ubuntu.md)                         | 24.04/26.04 LTS; x86_64 desktop/server, aarch64 server; 22.04 legacy separately    | Native x86_64 packaged/service/trust evidence, selected 24.04 encryption/actions and ARM inventory; not whole-family or physical certification.                             |
| [Debian](debian.md)                         | 13 and 12 LTS; x86_64 desktop/server, aarch64 server                               | Signed installer path; Debian 12/13 native ARM inventory, lifecycle/trust and dispatch records. Desktop, encryption and other cells remain separate.                        |
| [Fedora](fedora.md)                         | 43/44 while upstream-supported; x86_64 desktop/server, aarch64 server              | Fedora44 ARM DNF5 inventory, CPU/source and session applicability passed; selected lifecycle/service/encryption/action records. Other cells require separate evidence.      |
| [RHEL](rhel.md)                             | 9/10 supported minors; x86_64 and vendor aarch64 server; 8 legacy separately       | RHEL9.8 current DNF4 inventory passed; 9.8/10.2 x86_64 registered lifecycle/trust/dispatch recorded with SELinux enforcing. Entitlement and architecture are not inherited. |
| [AlmaLinux and Rocky Linux](alma-rocky.md)  | Separate 9/10 current-minor rows; x86_64/aarch64 server; 8 legacy separately       | Signed image acquisition and selected native comparisons; each distribution/version/lifecycle continuation stands alone.                                                    |
| [openSUSE and SUSE boundaries](opensuse.md) | Leap 16.0 and pinned Tumbleweed, x86_64; SLES 15 SP7/16 and SLED 15 SP7 separately | Image acquisition and maintained zypper paths do not establish a passing complete lifecycle. ARM acquisition is not automatic expansion of the launch matrix.               |
| [Arch Linux](arch.md)                       | Pinned rolling snapshot, x86_64                                                    | Native inventory recorded; signed package installation reached but lifecycle/dispatch not qualified. Arch Linux ARM is a separate derivative.                               |
| [Fedora Atomic and NixOS](atomic-nixos.md)  | Silverblue/Kinoite and NixOS 26.05/successor, x86_64                               | Required native deployment/generation models; mutable RPM/DEB implementations do not qualify them.                                                                          |

The versions and architecture allocation above come from
`docs/verification.md:155-175`; detailed native continuations in that ledger take
precedence over any older summary table. Server-host qualification is a separate
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
