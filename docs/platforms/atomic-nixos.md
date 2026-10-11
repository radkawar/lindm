# Fedora Atomic and NixOS

## Versions, architectures and qualification

<!-- BEGIN GENERATED platform-capabilities -->

Generated from `internal/platform`; “implemented” is not qualification (see the
[verification ledger](../verification.md#tier-capability-matrix)).

| Capability        | Fedora Atomic Silverblue/Kinoite                                                  | NixOS                                                                             |
| ----------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| inventory         | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| lifecycle         | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| dispatch          | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| packages          | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| accounts          | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| sysctl            | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| definitions       | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| password          | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| firewall          | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| encryption        | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| wipe              | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| report-loss       | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| lock              | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| recovery-sanitize | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| self-update       | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| assistance        | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| advisories        | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| os-update         | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |
| release-upgrade   | gated: design-only: the declarative/image-based management model is not specified | gated: design-only: the declarative/image-based management model is not specified |

<!-- END GENERATED platform-capabilities -->

**Fedora Silverblue/Kinoite and NixOS are separate native management products, not
mutable RPM/DEB aliases.** Under the
[supported OS tiers](../product-specification.md#supported-os-tiers) they are a
**future management model**. They stay design-only, and no lane qualifies them,
until a separate declarative/image-based model is specified. The
[branch allocation](../verification.md#branch-allocation) names x86_64 Silverblue,
Kinoite and NixOS stable 26.05 and successor as the eventual targets. Those need
actual atomic installers/deployments and owner-approved NixOS configuration/closure
activation.

The [resource matrix](../verification.md#resource-kind-coverage) records atomic OS
deployment and NixOS generation activation as specified/planned, with no complete
qualified cell. Other resources marked `S*` must be implemented through that
product's own ownership model; they do not inherit mutable-provider support
(`docs/verification.md:770-821`). A Fedora 43/44 mutable cloud result does not
qualify a corresponding Silverblue/Kinoite release. NixOS version allocation is
not evidence that a native generation was built or booted.

| Product               | Native authority and evidence required                                                                                                        | Current qualification boundary                                                                          |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Silverblue/Kinoite    | Staged and booted rpm-ostree deployment checksums, explicit layering, reboot and rollback, preserved mutable state.                           | Required native product model; no complete platform cell or recorded native deployment lane cited here. |
| NixOS 26.05/successor | Owner-approved composition, pinned inputs, previewed configuration/closure digest, signed closure/cache, build/test/boot/activate generation. | Required native product model; no complete platform cell or recorded native generation lane cited here. |

These contracts are explicit in `docs/architecture.md:1286-1320`. Do not extend
scope to CoreOS, MicroOS, Aeon, Ubuntu Core, arbitrary transactional derivatives,
aarch64 or physical hardware by family resemblance
(`docs/verification.md:718-728`).

## Packaging, signing, repositories, paths and LSM

Mutable package builders are not an atomic deployment or Nix closure builder.
The current packaging package documents DEB/RPM and explicit Arch agent artifacts
([`internal/packaging/doc.go`](../../internal/packaging/doc.go):3-6,14-42).
The mutable VM family selector rejects unknown/immutable distributions instead
of choosing a package format from `ID_LIKE`
([`vm_distribution_linux.go`](../../internal/vmlab/vm_distribution_linux.go):20-50).

For Atomic, the required packaging model must explicitly place the agent in the
owned deployment/layering transaction. A signed RPM alone does not authenticate
the complete OS deployment or establish successful boot. For NixOS, required
packaging includes the selected closure dependencies, pinned inputs and binary
cache trust, with owner-approved composition rather than a second independent
updater (`docs/architecture.md:1301-1316`). Offline delivery must include that native
closure/deployment content, not merely an agent binary and a mutable repository.

The existing mutable layout is a reference, **not a prescribed Nix store or atomic
installation layout**: binary `/usr/libexec/lindm/lindm-agent`, configuration under
`/etc/lindm`, separated persistent state under `/var/lib/lindm`, and socket under
`/run/lindm` ([`layout.go`](../../internal/packaging/layout.go):15-46).
NixOS must compose configuration and services into the owner's declaration; it
must never overwrite generated `/etc` files behind Nix. Atomic writable `/etc`
controls and deployment/layering controls remain distinct
(`docs/verification.md:775-779`; `docs/architecture.md:1309-1317`).

Preserve distinct native-content, TUF-release, image and execution-authority trust
as described in the [shared guide](README.md#shared-implementation-boundaries).
Each installer/generation must record its actual kernel, CPU baseline and LSM mode;
no SELinux/AppArmor enforcement claim follows from the Fedora or NixOS name
(`docs/verification.md:171-175`). Neither an LSM exception nor disabling enforcement
is a substitute for native policy qualification.

## Agent services and sandbox

The shared identity/audit and root/network privilege separation are architectural
requirements, not evidence of working platform installation. Existing mutable
units run the executor as root and the transport as `lindm`; the transport has
empty capabilities, while both retain `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome` and private devices
([`lindm-executor.service`](../../internal/packaging/assets/lindm-executor.service):9-61;
[`lindm-agent.service`](../../internal/packaging/assets/lindm-agent.service):9-50).

Atomic needs these services qualified against deployment replacement and mutable
state preservation. NixOS needs services composed into the approved generation,
with runtime state distinct from declaratively owned files. Shared typed evidence
may be reused only where semantics match; there is no universal mutable-resource
provider promise (`docs/architecture.md:1304-1317`). The default executor cannot
be made an OS updater by removing its read-only filesystem protections. Per-target
storage exceptions remain explicit, bounded and separately qualified.

## Inventory and per-field quirks

The current mutable package collector deliberately refuses ostree and transactional
markers (`/run/ostree-booted`, `/ostree/repo`, `/sysroot/ostree/repo`,
`/etc/transactional-update.conf`). Fedora variants outside its explicit mutable
allowlist return unavailable. NixOS is not a selected native package backend
([`packages_linux.go`](../../internal/agent/inventory/packages_linux.go):51-101).
This fail-closed behavior must survive refactoring; an RPM database is not proof
that an immutable OS can be managed with DNF.

| Observation                                       | Required interpretation                                                                                                          |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Atomic RPM contents                               | Do not substitute a mutable RPM snapshot for staged/booted deployment identity, layering ownership or rollback evidence.         |
| Nix installed content                             | A closure/generation and its pinned configuration are native identities; a list of files or packages is not activation evidence. |
| rpm-ostree/nix executable presence                | A capability observation only, not an implemented transaction model.                                                             |
| Hardware, network, firmware, sessions and storage | Preserve individual collection statuses; generic Linux probes do not qualify their behavior under a native platform sandbox.     |
| Flatpak/user applications                         | Independently owned inventory/state, not implicitly part of OS deployment or generation rollback.                                |

Native identity/rollback requirements are in `docs/architecture.md:1301-1320`.
The existing generic collector assembles independently bounded CPU, memory,
network/default-route, firmware, TPM, storage, session, user and application
categories ([`details_linux.go`](../../internal/agent/inventory/details_linux.go):135-165).
Those code paths establish implementation availability, not a native Atomic/NixOS
pass. Do not import the mutable lab's optional-field exceptions wholesale: its
explicit distro list excludes these products
([`inventory_unavailable_linux.go`](../../internal/vmlab/inventory_unavailable_linux.go):55-56).
Missing capabilities stay unavailable; errors do not become empty healthy lists.

## Updates and native activation boundaries

### Fedora Atomic

The required transaction stages a native rpm-ostree deployment, records its
identity, handles explicit layering, reboots, verifies the **booted checksum**, and
supports qualified rollback. Mutable state must be preserved across those events.
Installing an RPM with DNF/zypper is not this transaction and must not mutate the
immutable base (`docs/architecture.md:1294-1317`). A staged deployment is not yet
an observed boot, and an old deployment's availability is not proof of rollback.

### NixOS

The required flow composes only owner-approved configuration with pinned inputs,
previews the configuration/closure digest, and executes a build/test/boot/activation
transaction. Low-privilege arbitrary Nix expressions and an independent updater
that overwrites the owner's generation are forbidden. Offline operation requires
closure dependencies and binary-cache trust (`docs/architecture.md:1309-1313`).
Observe the activated generation independently; a successful build alone is not
activation or reboot evidence.

### Shared rollback limits

The existing helper's apt/dnf/zypper/pacman package effects are explicitly a
**mutable agent self-update path**, not an atomic/Nix generation updater
(`docs/architecture.md:968-978`). Native deployment rollback does not roll back
Flatpak applications, user data or database migrations automatically. Each product
needs its own interruption, startup/recovery and compatibility evidence
(`docs/architecture.md:1315-1320`).

## Encryption and recovery

No encrypted-installer, recovery-escrow, TPM-binding or recovery-boot qualification
for these product rows is asserted here. The resource matrix explicitly retains
native recovery requirements rather than importing mutable results
(`docs/verification.md:792-811`). The required native model must preserve ownership
of boot configuration, encryption metadata and independent owner recovery across
deployment/generation activation and rollback.

Shared action code checks target and operation qualification, preserves an
independent owner recovery slot, and requires free keyslot/token capacity for
rotation ([`provider_linux.go`](../../internal/agent/actionprovider/provider_linux.go):209-258).
Current in-band readiness requires measured writable FAT ESP capacity, Secure Boot
with SetupMode disabled and a matching running systemd-boot ESP
([`readiness_linux.go`](../../internal/agent/recoveryboot/readiness_linux.go):28-105).
Do not infer those prerequisites from either distribution name or install another
bootloader merely to pass them. A native product needs an explicitly compatible,
qualified recovery path; OS rollback does not restore erased key material by
implication.

## Device actions

Generic root action code is not permission to mutate declaratively owned state.
NixOS configuration changes must follow approved generation composition; Atomic
controls must respect the distinction between writable state and immutable
deployment ownership (`docs/architecture.md:1301-1317`). Only runtime state is
changed outside the NixOS generation model (`docs/verification.md:775-779`).

Lock/quarantine, power operations, recovery and sanitization still need their own
session, stable target identity, authority and sandbox evidence. The shared provider
requires root and explicit bounded configuration; an unqualified operation returns
unsupported ([`provider_linux.go`](../../internal/agent/actionprovider/provider_linux.go):69-88,205-222).
No Atomic/NixOS action parity, physical-media erasure or unattended desktop access
is implied by shared APIs. Desktop consent and headless maintenance are separate
qualification gates (`docs/verification.md:718-728`).

## Advisory feeds

Do not inherit mutable Fedora coverage for a deployment or treat a Nix closure as
an RPM ecosystem. Feed matching binds explicit distribution, release, architecture
and native package identities; the existing architecture describes native mutable
vendor feeds, not a qualified Atomic deployment or Nix closure advisory model
(`docs/architecture.md:1151-1178`). Native content identity and coverage need their
own implementation/evidence before these product rows can claim complete exposure
reporting.

Partial, missing or stale feeds cannot establish clean state; freshness is bounded
by authenticated snapshot signing time, and offline imports do not establish
current complete coverage (`docs/architecture.md:1180-1196`). The existence of an
advisory UI or a common CVE identifier does not fill the native inventory/identity
gap.

## Lab inputs and recorded evidence

There is no Atomic/NixOS image/generation execution record with a SHA-256 cited
for these rows in the current [resource ledger](../verification.md#resource-kind-coverage).
Do not fabricate an evidence hash or borrow a mutable Fedora record. The planned
qualification must retain native installer/deployment or configuration/closure
pins, build and signature provenance, actual architecture/firmware/LSM/session,
staged and booted/activated identity, and interruption/rollback observations.
These requirements derive from `docs/architecture.md:1286-1320` and
`docs/verification.md:155-175,718-728,770-821`.

The current mutable lab family selector is deliberately not an Atomic/NixOS
installation path ([`vm_distribution_linux.go`](../../internal/vmlab/vm_distribution_linux.go):20-50).
Creating a mutable Fedora guest and adding a graphical desktop, or copying an
agent into a NixOS system, cannot satisfy the required native lane. Physical and
connected/air-gap evidence remain independent. No tests or native runs were
performed to create this page.

## Known gaps

Both products still need their native packaging/content trust, ownership and
activation implementation plus end-to-end qualification. Open work includes
installer or owner-composition input pins, staged/booted deployment or activated
generation evidence, native inventory/advisory mapping, service and sandbox
integration, updates/interruption/rollback, encryption/recovery, actions,
desktop consent and both connectivity modes. These are required release gates,
not reduced scope or deferred parity promises. Keep the
[authoritative verification matrix](../verification.md#resource-kind-coverage)
and this page explicit when any native subset becomes implemented or measured.
