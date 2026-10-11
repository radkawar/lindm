# Linux MDM product specification

Status: release-scoped implementation contract. Enrollment, inventory, profile catalog
and signed local service execution have exercised implementations; production
dispatch and the revised authentication modes are not yet qualified. No release is
certified. See the [evidence ledger](implementation-plan.md#2-evidence-ledger).
Research baseline: 2026-10-08. Working name: `lindm`.

## 1. Product outcome

A self-hosted, single-tenant Linux device-management product with the usability of
SimpleMDM: enroll a device, assign understandable policies and software, see whether
those policies actually took effect, and safely manage the device through retirement.
Desktop experience is the priority. Company-owned servers are also in the commercial
launch scope and share the management core, not the desktop assumptions.

The commercial launch contract is the **entire** requirement set below (P01–P21) on
every Tier 1 and Tier 2 distribution in [supported OS tiers](#supported-os-tiers),
plus the other branches allocated in [verification](verification.md).
Nothing in this specification is optional roadmap. Implementation milestones (G0–G8)
only order the work; they are not permission to ship a reduced product as
production-ready. No resource, derivative, architecture or desktop workflow inherits
support from a neighboring cell.

The build order started with one systemd service resource proven end to end
(console intent → server work → installed agent → native effect → device-signed
result → console), so that every later resource kind and imperative action reuses a
proven authority, dispatch and evidence spine. The highest-priority capabilities after
that spine are: agents qualified on the major releases (Ubuntu, Fedora, RHEL), disk
encryption management (inventory, recovery-key escrow and rotation, TPM2 binding and
cold-boot recovery), and remote lock, quarantine and wipe with two-person approval.

QEMU/KVM emulation (UEFI Secure Boot, swtpm TPM 2.0, NVMe/SATA/virtio disks,
aarch64, desktop sessions, network faults) is used to build and verify behavior as far
as emulation allows. Evidence records whether each property was emulated or physical.
Destructive and hardware-attestation capabilities still require their recorded
physical-hardware gate before they are advertised; a missing machine never leaves the
behavior unbuilt.

### Confirmed product decisions

- Greenfield implementation; Fleet is a research reference, not the base product.
- Go backend, PostgreSQL with sqlc, versioned protobuf RPC, and a separate Go agent.
- One organization per installation; single-host deployment must be first-class.
- Desktop-first, with company-owned servers included. No graphical dependencies in
  the server agent. Desktop integrations are an unprivileged presentation layer.
- Connected and genuinely air-gapped installations are both launch requirements.
- Remote lock, quarantine and wipe are launch requirements. They are
  capability-gated, audited and two-person approved; advertised destructive
  capabilities also require physical-hardware validation.
- Production security, scaling, repeatable lifecycle testing, maintainable automation,
  code review, linting, and Git hooks are requirements from the start.
- Launch distributions follow the [supported OS tiers](#supported-os-tiers). Each
  native management model gets its own qualification. Rolling systems use pinned
  snapshots and whole-system upgrades. NixOS and Fedora Atomic need a separately
  specified declarative/image-based model, not DEB/RPM aliases.
- Employee entitlements support both device and person assignments, with explicit
  organizational-identity/local-account bindings and no cross-user secret inheritance.
- Built-in local admin accounts use Postgres, Argon2id and mandatory WebAuthn.
  Keycloak (including offline and SAML brokerage), Entra ID, Okta and Google Workspace
  are certified directory integrations with actual lifecycle sync, plus SCIM. Keycloak
  is optional, not mandatory.
- Lindm authenticates its own administrators only. It does not become an IdP or
  issue identity tokens for other applications.
- Graphical remote assistance is built into the product with explicit user consent;
  it is not outsourced to a third-party support product or an unattended root shell.

### Supported OS tiers

The owner set these tiers on 2026-10-11. The live per-capability matrix is in
[verification](verification.md#platform-support-tiers).

- **Tier 1, desktop-first, full parity with Ubuntu 24.04:** Ubuntu 22.04/24.04/26.04
  LTS, Debian 12/13, Fedora (current two releases), RHEL 9/10, Rocky Linux and
  AlmaLinux 9/10, Linux Mint (current, Cinnamon) and Pop!\_OS (current LTS, COSMIC).
- **Tier 2:** Arch Linux, openSUSE Tumbleweed and Omarchy (Arch-based, Hyprland).
- **Future management model, design-only:** NixOS and Fedora Atomic
  (Silverblue/Kinoite). Their declarative and image-based models stay unadvertised
  and unbuilt beyond design until a separate model is specified.

Full parity means the agent lifecycle works: signed install, enrollment, upgrade,
reboot, purge/reinstall and revocation. It also needs connected dispatch, strict
inventory health and all eight configuration kinds. Encryption covers inventory,
escrow, reveal, rotation, TPM2 binding and cold-boot recovery. Wipe covers live-root
crypto-erase, report-loss and recovery sanitize. It also needs lock, release and
quarantine, agent self-update, OS patch policy and remote assistance. Each
distribution, version, architecture and desktop edition qualifies on its own; a
derivative never inherits its base's evidence.

### Definitions

- **Managed** means an enrolled agent has a valid identity and an assigned lifecycle.
  It does not mean its last report is current or every policy is enforced.
- **Compliant** means all required controls have fresh, applicable, successful evidence.
  Unknown, unsupported, stale, conflicting, and not applicable are distinct states.
- **Supported** means a published distro/version/architecture/capability combination
  passed its release gates. A package that installs is not sufficient evidence.
- **Air-gapped** means installation and operation without public DNS, Internet egress,
  public identity providers, public registries, or license/telemetry phone-home.
- **Lock** means the named, tested lock mechanism. It never implicitly means Apple
  Activation Lock, boot prevention, or resistance to a hostile root user.
- **Wipe** means a named sanitization workflow and its evidence, not "device stopped
  checking in." A lost acknowledgment is an unknown outcome.

## 2. Users and critical journeys

| User              | Required journey                                                                         | Observable success                                                                              |
| ----------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| IT administrator  | Configure identity, enroll machines, assign baseline/apps                                | Devices become ready with independently observed policy and software state                      |
| Employee          | See management disclosure, install approved apps, defer a restart, request help          | No administrator password or arbitrary root execution; accessible UI and clear reasons          |
| Server operator   | Schedule patches and reboot coordinated hosts                                            | Explicit headless policy, bounded concurrency, availability prerequisites and no desktop prompt |
| Security operator | Investigate stale/vulnerable devices, rotate recovery access, isolate or retire a device | Scope-limited, fresh evidence and attributable approved actions                                 |
| Auditor           | Export configuration history, access, approvals, and execution evidence                  | Complete time-bounded records with actor, reason, revision, outcome, and redaction              |
| Platform operator | Install offline, upgrade, restore, rotate keys, scale workers                            | Documented reproducible operations without bypassing integrity or authentication                |

### Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Discovered
    Discovered --> PendingEnrollment
    PendingEnrollment --> Managed: identity issued and acknowledged
    Managed --> Quarantined: explicit access restriction
    Quarantined --> Managed: authorized recovery
    Managed --> Retiring: approved deprovision plan
    Quarantined --> Retiring
    Retiring --> Retired: observed cleanup or recorded exception
    Retired --> PendingEnrollment: explicit new enrollment generation
    Retired --> [*]: retention permits deletion
```

Connectivity is orthogonal: online, delayed, offline, or stale must not overwrite
lifecycle. Deleting a record is not unenrollment. Revoking an identity does not erase
local data. Uninstall and retirement are separately tracked operations.

## 3. Commercial launch requirements

All rows are launch requirements for their certified capability combinations. A
capability limitation must have a visible reason and remediation, not a green check.
The test references are scenario families in [verification](verification.md).

| ID  | Capability and required behavior                                                                                                                                                                                                                                                                     | Acceptance evidence                                                                                                                                                                                       |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P01 | Install and bootstrap a single host using signed artifacts, external hostname/TLS, PostgreSQL, durable artifact storage, and first-owner setup                                                                                                                                                       | Fresh connected and offline installs; restart survives; bootstrap cannot be claimed a second time (L01, L14)                                                                                              |
| P02 | Built-in local admin accounts (Argon2id, mandatory WebAuthn), CLI loopback PKCE sessions; certified Keycloak (incl. SAML broker), Entra, Okta and Google Workspace directory lifecycles; SCIM provisioning; opaque sessions, roles, CSRF, authorization fencing, MFA/step-up and audited break-glass | Actual local/external login, immediate local disable, bounded external revocation/outage denial, WebAuthn enrollment and replay rejection, restricted break-glass, broker flow and SCIM correlation (L02) |
| P03 | Owner/admin/operator/helpdesk/auditor roles and group-scoped custom roles; separate recovery-key, remote-execution, destructive-action, approval, and infrastructure permissions                                                                                                                     | Every RPC denies unauthorized and out-of-scope identities; no self-approval; no scope leakage in counts/exports (L02, L13)                                                                                |
| P04 | Interactive and unattended enrollment, short-lived one-use grants, approval flows, offline-site enrollment, reinstall and identity recovery                                                                                                                                                          | Token races, expiration, cloned image, interrupted enrollment, identity renewal/revocation, and re-enrollment (L03)                                                                                       |
| P05 | Hardware/OS/software inventory, ownership, labels, custom typed attributes, last-seen and data freshness, searchable pagination and export                                                                                                                                                           | Real machines and packages; architecture, package epochs, serial absence, changed boot IDs and stale records handled (L04)                                                                                |
| P06 | Static/dynamic groups, assignments, exclusions, immutable profile revisions, previews, staged rollout, drift detection and remediation                                                                                                                                                               | Target preview matches execution snapshot; conflicting resources rejected; obsolete revisions do not execute (L05)                                                                                        |
| P07 | Native security/configuration controls: local accounts/groups and sudo, SSH, session/password settings, service state, firewall, time, trust stores, Wi-Fi/Ethernet/VPN and DNS/proxy                                                                                                                | Per-backend enforcement plus fresh observation, reboot persistence, drift repair, safe network rollback and uninstall ownership (L05, L10)                                                                |
| P08 | Repository/software management across DEB/RPM/Arch packages and atomic/Nix deployments, Flatpak/Snap capability providers, device/person self-service assignments                                                                                                                                    | Native dependencies/signatures/transaction ownership, source failure, offline mirrors and per-person authorization; no unsafe partial upgrades (L06)                                                      |
| P09 | OS/security update policies, advisory reporting, rings/canaries, maintenance windows, restart deadlines/deferrals, exclusions and server availability budgets                                                                                                                                        | Real kernel/package updates and reboot; interrupted transactions; DST/timezone changes; rollout automatically pauses on threshold (L07)                                                                   |
| P10 | Encryption inventory, supported LUKS recovery escrow and rotation, TPM/Secure Boot posture, controlled recovery access                                                                                                                                                                               | Recovery unlock after cold boot, key rotation and escrow failure recovery on qualified configurations; never generic live encryption (L10, L15)                                                           |
| P11 | Certificates and identity: trust roots, device/user certificate enrollment and rotation, revocation, enterprise EAP-TLS/VPN credentials, SSSD/realmd directory configuration where certified                                                                                                         | Certificate renewal, removal, wrong EKU/name rejection, network authentication, directory outage and offline-login policy (L10)                                                                           |
| P12 | Compliance rules, exceptions with expiry, vulnerability findings using distro advisories, remediation workflows and evidence exports                                                                                                                                                                 | Backported fixes and package epochs correctly classified; stale feeds/observations are unknown; expired exception resurfaces (L11)                                                                        |
| P13 | Desktop status/disclosure, approved self-service apps, reboot notices/deferrals, recovery interaction and support requests; GNOME and KDE paths                                                                                                                                                      | Actual visible Wayland and applicable X11 sessions, accessibility and multi-user isolation; no dependency on a tray extension (L09)                                                                       |
| P14 | Audited diagnostics, reboot/shutdown, support bundles, built-in consent-controlled graphical assistance and restricted script escape hatch                                                                                                                                                           | Actual console/employee screen-share/control UX, local/remote termination, session isolation and local TURN under air-gap; scripts remain distinct (L09, L12, L16)                                        |
| P15 | Capability-gated session lock, access restriction/quarantine and sanitization plans with two-person approval, target preview and physical validation                                                                                                                                                 | Unsupported plans refused; approvals bind exact targets/action/revision/expiry; ambiguous result stays unknown; qualified physical evidence (L13, L15)                                                    |
| P16 | Safe offboarding: remove owned profiles/apps/credentials by policy, revoke device/user access, transfer ownership, retain audit and re-enroll deliberately                                                                                                                                           | No unrelated configuration/data removal; cancellation/partial cleanup visible; server reboots not implied by retirement (L08)                                                                             |
| P17 | Full admin API/CLI parity, versioned RPC, stable cursors, idempotent mutations, signed webhooks, scheduled reports, SIEM/CMDB export and Git-managed policy import                                                                                                                                   | Retry/deduplication, ordering and delivery failure visible; secrets excluded; preview/change authorization same as UI (L12)                                                                               |
| P18 | Tamper-evident audit export, configurable retention/legal holds, privacy controls, event alerts, backup/restore, key rotation, upgrade/rollback operations and metrics                                                                                                                               | Restore drills, audit continuity, retention boundary tests, external archive verification and failure alerts (L14)                                                                                        |
| P19 | Offline install/update/software/advisory distribution, local IdP and PKI, site mirrors, signed import/export bundles and explicit freshness                                                                                                                                                          | Full isolated lifecycle with egress denied, expired/replayed/corrupt bundles refused; local management continues (L16)                                                                                    |
| P20 | Native package/image/generation delivery, unattended agent updates, compatibility, reproducible releases, SBOM/provenance/signatures and distro certification                                                                                                                                        | Full matrix install/update/recovery and two clean builds with matching unsigned payload digests; old-agent/new-server and rejection attacks (L08, L17)                                                    |
| P21 | Horizontal control-plane/worker operation with durable jobs, isolation/backpressure, predictable capacity and no mandatory message broker                                                                                                                                                            | Sustained load and failover gates in operations; no duplicate destructive effects or lost accepted work (L18)                                                                                             |

### Original-device sanitize capability

Original-device SATA/NVMe sanitize requires the approved signed recovery image to
fit the existing EFI system partition, including allocation-unit rounding. A
fresh authenticated inventory observation reports the image, needed and available
bytes before approval. Insufficient capacity is **unsupported: ESP capacity**, not
an approval warning or a sanitization failure after erasure begins. The console
shows those bytes and the external-recovery alternative. Execution rechecks space;
inventory readiness is neither authority nor a reservation.

Do not resize the ESP, remove or compact ordinary boot images, replace the
distribution kernel with an unqualified kernel, or weaken image trust to turn a
gated cell green. The pinned Fedora 44 stock fixture is such a gated cell: its
unchanged ESP has 14,888,960 bytes available, while its vendor-signed kernel alone
is 18,479,464 bytes before the recovery stub and initramfs. Component digests and
native records are retained in [verification](verification.md).

An on-site operator may instead use separately qualified external recovery media
with the same exact target validation, fresh two-person authorization and
protected off-target state described in
[dangerous-action operations](security-and-operations.md#3-dangerous-actions).
That mode is not remote wipe of a lost or stolen device and does not certify
original-device sanitize for the capacity-gated configuration.

### Management, not a script runner

Policies describe desired resources with schemas, applicability, dependencies,
conflict rules, observation, planning, application, and verification. Routine package,
account, firewall, certificate, and configuration operations use typed providers.
A provider may invoke a documented system utility with explicit arguments when it
is the correct interface. That is not equivalent to distributing arbitrary shell.

The shared resource vocabulary is closed and versioned: twenty kinds cover the
P07/P08/P09/P11 configuration scope. Profiles are heterogeneous and canonical
resource identities are derived from typed fields. Static/dynamic targeting,
exclusions, priority, pinned previews and staged rings do not weaken native
ownership or fresh execution authority. A declared kind without a qualified
executor remains visibly unsupported and is still a launch blocker. Unassignment
requests ownership-safe release, never invents a previous value and never treats
missing ownership evidence as successful cleanup.

A script is a separately authorized, immutable, hashed artifact with an explicit
interpreter, target identity, deadline, runtime/output bounds, audit, and results.
It is disabled by default, cannot be a hidden fallback for an unsupported provider,
and cannot silently upgrade a device's compliance state. Package maintainer scripts
are also privileged code; publisher approval and source integrity are required.

### Software and OS distinctions

- Package updates and release upgrades are different operations. Release upgrades
  need their own supported source/target pair, preflight, backup, recovery and gate.
- Generic package downgrade is not promised to undo schema/data migrations.
  Rollback eligibility is per application/provider, displayed before approval.
- Repositories carry distro/architecture, signing identity, provenance, entitlement
  and snapshot/freshness metadata. Do not mix incompatible distribution packages.
- Flatpak and Snap are app distribution capabilities, not assumptions about every
  server. Offline support requires a tested approved mirror/import workflow and
  permitted redistribution; missing content blocks the plan rather than fetching
  from the Internet. User-scoped installs run as the intended local user.

## 4. UI and operator semantics

Required console areas: overview, devices/device detail, groups, profiles, software,
patch campaigns, compliance/vulnerabilities, jobs/approvals, people/access, audit,
reports/integrations, and infrastructure health. Device detail includes inventory,
capabilities, policy diff, execution timeline, user, recovery access, and retirement.

Every operation shows intent, target count, exclusions, applicability, risk,
maintenance impact, revision, author, approval state, and progress. Bulk actions
require a concrete preview; destructive actions freeze the target set. Dynamic-group
membership changing later cannot silently add wipe targets.

Do not collapse accepted, delivered, running, reboot-required, verified, failed,
cancel-requested, cancelled-before-start, expired, superseded, unsupported, conflict,
and outcome-unknown into success/failure. Cancellation is not undo. Recovery UI must
explain whether a retry is safe. See architecture for execution invariants.

Target WCAG 2.2 AA for console and self-service. Keyboard use, screen readers,
contrast, reduced motion and non-color-only status need real surface tests. GNOME
and KDE integration must not assume a particular panel/tray implementation.

## 5. Safety and ownership boundaries

- An administrator/root attacker on a device can stop or falsify a software-only
  agent. Report tamper signals; do not advertise tamper-proof control.
- A powered-off or disconnected machine cannot receive immediate actions. Show last
  contact and expiry. Never queue indefinite destructive actions for a future owner.
- SSO for console access, workstation directory login, and enrollment authentication
  are distinct integrations and must be tested independently.
- No silent employee surveillance: no browsing history, keystrokes, screen capture,
  personal files or continuous location collection in baseline inventory. Remote
  assistance requires explicit visible session consent and recording disclosure.
- Multiple managers may coexist only with explicit resource ownership. Conflicts
  block enforcement rather than alternating values. Removal restores only values
  still owned by this product; administrator changes are not blindly overwritten.
- Unencrypted machines are not encrypted in place by a generic policy. Provisioning
  or a qualified migration procedure must establish encryption with recovery proof.
- Server patches/restarts require operator-controlled availability prerequisites.
  Desktop deferrals never substitute for server drain or quorum checks.

## 6. Boundaries and release contract

This product is not an EDR/antivirus engine, a general provisioning/IaC platform, a
backup product, or a replacement identity provider. It integrates with those systems.
No universal Linux zero-touch hardware enrollment, Activation Lock, non-removable
agent, secure wipe on arbitrary hardware, or universal live disk encryption is
claimed. Automated enrollment is achievable through trusted installer/image and
provisioning integrations, not a nonexistent cross-vendor hardware registry.

Commercial launch requires every P requirement and applicable lifecycle gate, a
published feature-level support matrix, security review, support/incident runbooks,
measured capacity and an independently reviewable evidence bundle. Unqualified cells
cannot be labeled "supported". See the [implementation sequence](implementation-plan.md)
for build order and [research](research.md) for evidence versus design decisions.
