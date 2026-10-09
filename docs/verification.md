# Distro support and lifecycle verification

Status: qualification plan. **No matrix cell is certified.** Installation, unit tests,
containers, simulations and a source-code review cannot substitute for the required
machine evidence. All supported claims are capability-specific.

## 1. Release-scoped platform qualification

R1 targets connected Ubuntu LTS and Fedora/RHEL on x86_64. The remaining mutable
families, aarch64, employee desktop integrations and full air-gap are later gates.
Atomic Linux and NixOS have separately approved product scopes, not inherited
mutable-provider requirements. The table allocates qualification work; it does not
declare support.

Versions are branches, not mutable download URLs. Pin exact vendor/minor/snapshot,
verified image digest, repositories, architecture and installer recipe in executable
evidence. Upstream maintenance does not prove product support. A branch reaching EOL
before its release must be explicitly replaced or supported with entitled content.

| Family / branch                           | Release allocation           | Native host acceptance                                                               | Architecture scope                       |
| ----------------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------- |
| Ubuntu 24.04 and 26.04 LTS                | R1                           | Official GNOME Desktop and Server/minimal; no employee UI or Kubuntu parity inferred | x86_64; aarch64 server later             |
| Fedora 43 and 44 while upstream-supported | R1                           | Workstation/Server/minimal; KDE edition qualified separately                         | x86_64; aarch64 server later             |
| RHEL 9 and 10, supported minor            | R1                           | Vendor GNOME-capable and minimal/server installations                                | x86_64; entitled images/content required |
| Rocky Linux 9 and 10, current minor       | Later mutable release        | Separate derivative lifecycle, not RHEL evidence                                     | x86_64; aarch64 server separately        |
| AlmaLinux 9 and 10, current minor         | Later mutable release        | Separate derivative lifecycle, not Rocky evidence                                    | x86_64; aarch64 server separately        |
| Debian 13                                 | Later mutable release        | GNOME/KDE and minimal separately                                                     | x86_64; aarch64 server separately        |
| openSUSE Leap 16.0                        | Later mutable release        | GNOME/KDE and headless separately                                                    | x86_64                                   |
| Ubuntu 22.04 LTS; Debian 12 LTS           | Later legacy release         | Separate branch/content/runtime evidence                                             | x86_64; aarch64 server separately        |
| RHEL 8, Rocky 8, AlmaLinux 8              | Later legacy release         | Independent vendor rows and maintained security content                              | x86_64                                   |
| SLES 15 SP7 and 16; SLED 15 SP7           | Later SUSE release           | Each vendor product/desktop/server installation separately                           | x86_64                                   |
| Arch Linux; openSUSE Tumbleweed           | Later rolling release        | Separate pinned snapshots, whole-system update and rollback semantics                | x86_64                                   |
| Fedora Silverblue and Kinoite             | Separate atomic product      | Actual atomic installer, deployment/layering, booted checksum and rollback           | Independently scoped                     |
| NixOS stable branch                       | Separate declarative product | Owner-approved configuration/closure and system-generation activation                | Independently scoped                     |

RHEL is not certified by testing Rocky; Alma is not certified by testing Rocky; a GUI
installed on a server is not proof of a vendor's separate desktop product. RPM format
alone is not a shared OS contract. Record CPU baselines (including x86-64-v2/v3), DNF
major version, SELinux/AppArmor mode and kernel. Emulation alone does not establish
native aarch64 performance/hardware support.

Alpine/OpenRC, Ubuntu Core, Amazon Linux, unrelated transactional products, containers
as devices, WSL and arbitrary derivatives are not implicitly included. Unsupported
resources report limitations instead of guessing a provider. R1 qualification includes
connected install/enroll/renew/revoke, actual inventory, server-dispatched service
state and authenticated results, interruption/reboot, agent upgrade/recovery and
explicit identity revocation/re-enrollment. It does not claim package/OS management,
profile-removal restoration, employee UI, remote assistance or offline operation.
Those capabilities add their own native lifecycle gates when advertised. Neither a
rolling/atomic/Nix product nor a new mutable distribution is certified by inventory
or package installation alone.

Support follows published vendor maintenance and security-content availability.
Fedora moving-window changes trigger qualification and a communicated transition;
never substitute a prerelease for a GA image. Publish EOL warnings at least 90 days
in advance when vendor schedules permit; continued inventory must not imply continued
security coverage. Entitlement-gated/EUS/ESM branches have explicit rows.

### Resource-kind coverage

Coverage is per resource **and** platform; a shared protobuf vocabulary does not
create native implementations. `S` means specified/planned only; `I` means code
exists but the end-to-end platform contract is unqualified; `N` means a named native
subset was exercised; `Q` would mean full release qualification. `S*` means planned
through that platform's own native model rather than a mutable-distro provider:
writable `/etc` and rpm-ostree layering/deployments on Atomic; configuration
composed into the owner's declaration and activated as a generation on NixOS (only
runtime state is changed outside the generation). `—` means not applicable.
There are currently **no Q cells**.

The code column separates implementation from platform evidence. `N24` is Ubuntu
24.04 and `N44` is Fedora 44 x86_64 only; it does not cover Ubuntu 26.04, other Fedora
branches, RHEL/derivatives, aarch64 or desktop workflows. For service state, these
are the existing provider and packaged **local-command** execution/history lanes,
not the still-missing production server dispatch loop. Exact builds and observed
limits are in the [evidence ledger](implementation-plan.md#2-evidence-ledger).

| Resource kind                                     | Code | Ubuntu LTS | Fedora | RHEL | Debian/SUSE | Arch/Tumbleweed | Atomic product | NixOS product |
| ------------------------------------------------- | ---- | ---------- | ------ | ---- | ----------- | --------------- | -------------- | ------------- |
| Host and native package inventory                 | I    | N24        | N44    | S    | S           | S               | S              | S             |
| Systemd service state                             | I    | N24        | N44    | S    | S           | S               | S*             | S*            |
| Device local accounts/groups                      | S    | S          | S      | S    | S           | S               | S*             | S*            |
| Sudo policy                                       | S    | S          | S      | S    | S           | S               | S*             | S*            |
| SSH configuration                                 | S    | S          | S      | S    | S           | S               | S*             | S*            |
| Session/password settings                         | S    | S          | S      | S    | S           | S               | S*             | S*            |
| Firewall                                          | S    | S          | S      | S    | S           | S               | S*             | S*            |
| Time synchronization                              | S    | S          | S      | S    | S           | S               | S*             | S*            |
| Trust stores                                      | S    | S          | S      | S    | S           | S               | S*             | S*            |
| Wi-Fi/Ethernet                                    | S    | S          | S      | S    | S           | S               | S*             | S*            |
| VPN                                               | S    | S          | S      | S    | S           | S               | S*             | S*            |
| DNS/proxy                                         | S    | S          | S      | S    | S           | S               | S*             | S*            |
| Native repositories/packages                      | S    | S          | S      | S    | S           | S               | S*             | S*            |
| OS/security-update lifecycle                      | S    | S          | S      | S    | S           | S               | S*             | S*            |
| Device/user certificates and directory client     | S    | S          | S      | S    | S           | S               | S*             | S*            |
| Recovery escrow, lock/quarantine and sanitization | S    | S          | S      | S    | S           | S               | S*             | S*            |
| Atomic OS deployment/boot/rollback                | S    | —          | —      | —    | —           | —               | S              | —             |
| Declarative system generation/activation          | S    | —          | —      | —    | —           | —               | —              | S             |

Only inventory and service state are R1 managed-device resources. Additional rows
remain independent later resource releases; `S` is not a delivery promise for every
combination. Debian/SUSE and Arch/Tumbleweed are compact planning columns, **not**
shared qualification: each native backend, vendor, version and snapshot needs its
own executable evidence row. Atomic/NixOS cells reuse the shared typed vocabulary
only where native semantics match; their provider must say how it persists through
deployments or generations before a control is claimed. Bind identity, audit and
evidence metadata across products; do not force package transactions or generated
configuration into a universal mutable-resource API.

### Capability matrix dimensions

The executable manifest must express distro/vendor/minor, architecture/CPU baseline,
image source/digest/signature, desktop edition/session or headless, provider versions,
network backend, package backend, boot/firmware/Secure Boot, encryption layout/owner,
TPM type, connected/air-gapped mode and scenario selection. A row has owner, evidence
URL/digest, tested product release and status: planned, qualifying, passed, blocked,
failed or retired. Skipped is not passed.

Lock/wipe, encryption recovery and hardware-attestation claims additionally require
hardware model/firmware/media/controller/TPM records. GNOME/KDE tests include logged
in, locked, logged out and multi-user sessions; Wayland and X11 are separate where
actually shipped and claimed. Headless tests have no user bus, display manager or
polkit prompt agent. No graphical-lock requirement applies to a headless system.

### Control-plane deployment matrix

Managed endpoint support does not establish server-host support. Initial certified
server hosts are Ubuntu Server 24.04/26.04 x86_64; native package/systemd and OCI/Docker
Compose are independent rows. Pin supported Docker Engine/Compose, PostgreSQL and
host prerequisites in each manifest. Other endpoint platforms do not implicitly
become supported server installation hosts.

| Deployment                                                | Mandatory coverage                                                                                                                                     |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Native server package/systemd                             | R1 connected L01 installation/permissions/restart; L14 migration/upgrade/backup/restore/rotation; measured single-host L18 capacity; later L16 air-gap |
| OCI/Docker Compose single host                            | Same R1 connected gates, with container volume ownership and image rollback independently observed; later L16                                          |
| Replicated API/workers + HA PostgreSQL + shared artifacts | Later G8: rolling upgrade, restore/failover fences, replicated capacity and artifact availability; isolated HA separately when offered                 |
| Built-in assistance relay                                 | Later G5/G6: TURN/direct variants, rotation/bandwidth and consent/termination, including isolated relay-only behavior when offered                     |

Both R1 single-host rows need connected acceptance. Full air-gap is a separate
release gate, not a hidden prerequisite of R1. Native dependencies/hardening/migration
invocation cannot be inferred from container success. R1 capacity is a measured
published limit, not the roadmap's 100k/HA target. Future relay media bandwidth has
its own measured concurrent-session and bitrate gate.

## 2. Repeatable laboratory

Use QEMU/KVM with libvirt-managed isolated networks and immutable signature-verified
base images. Each test receives a disposable qcow2 overlay, unique instance/device
identity, fresh secrets, and its own UEFI/NVRAM/swtpm state. Snapshot/restore covers the
whole machine state; a disk-only rollback is not a TPM reset. Tests never enroll the
developer's host, use a production grant, or mutate host networking/disks.

Two image routes are required:

1. Cached official cloud images plus cloud-init/NoCloud for fast agent regression.
2. Actual Desktop/Server installation ISOs for release acceptance: Ubuntu autoinstall,
   Debian preseed, Fedora/RHEL Kickstart, SUSE AutoYaST/Agama as appropriate, Arch's
   pinned installation recipe and NixOS's declarative installer closure. Atomic
   desktops use their actual installer/deployment. Include encrypted install, first
   boot, desktop login, native update/rollback and default security policy.

Use openQA for installer/desktop/boot visual flows instead of maintaining a custom
screen-clicking framework. A Go lifecycle runner owns API assertions, scenario state,
artifacts, deterministic fault injection and libvirt orchestration. Declarative image
manifests and shared providers replace distro-specific ad hoc shell scripts. Thin
installer/package lifecycle glue is versioned and checked where native formats need
it. Tools are pinned; fixtures and license notices accompany redistributed images.

Test packages are built DEB/RPM artifacts from the release pipeline, not `go run` in
a VM. Production TLS/mTLS, migrations and local IdP are exercised. Harness-only
credentials/certificates are clearly isolated; no insecure production mode is used.
The scenario driver may use SSH/serial for out-of-band observation but must not use
that channel to fake a policy result the agent was supposed to produce.

## 3. Acceptance scenario families

Each family maps to product requirement IDs. Individual deterministic tests must
assert externally meaningful results, not merely process existence or successful RPC.

| ID  | Scenarios and required result                                                                                                                                                                                                                       | Evidence surface                                                                                                                                                                         |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| L01 | Fresh single-host server installation, first-owner binding, restart and invalid configuration                                                                                                                                                       | Actual installer/console/CLI; same pinned owner bootstrap is idempotent, replacement owner denied; persisted state recovered                                                             |
| L02 | Real Keycloak/Entra/Okta/Google and SAML broker login, MFA/step-up, SCIM correlation, upstream disable/group removal during direct and brokered sessions without re-login, healthy broker with stale upstream, source outage, rename/recycled email | Original-directory propagation and local enforcement measured separately; no freshness reset from broker imports, stale-claim resurrection, source ambiguity or permissions beyond bound |
| L03 | Package enrollment, lost secret-issuance response, redaction/hash-only persistence, grant race, lost cert response, TPM/software key, renewal/revocation, cloned image and reinstall                                                                | Retry never recovers a bearer secret or creates a second credential; distinct device generation, correct denial and no secret in database/audit/outbox                                   |
| L04 | Native hardware/OS/package collection, absent serial, package epochs, pagination/filters, delta duplicate/out-of-order ingestion, stale/offline device                                                                                              | Guest truth compared with API/export; stale evidence never compliant                                                                                                                     |
| L05 | Profile preview/conflict/drift, trust bootstrap and quorum rotation, tampered/stale trust and plans, missing/corrupt executor journal, compromised network-process replay and restart during apply                                                  | Actual state/revision, root-only replay fences and fail-closed recovery; unknown capability or trust never becomes privileged execution                                                  |
| L06 | Native package/image/generation and repository transactions, invalid signatures, dependencies/locks/interruption, device/person catalog entitlements and UID/account reuse                                                                          | Native package database or booted generation and application health; no partial Arch upgrade, mutable-image overwrite, unapproved source or cross-person install                         |
| L07 | Patch/advisory rings, canary pause, maintenance window/DST, desktop deferral/deadline, server availability budget, kernel update and reboot inhibitor                                                                                               | New boot/kernel and workload health, not just agent reconnect; no reboot outside policy                                                                                                  |
| L08 | Agent install/upgrade/failed-upgrade recovery, purge/reinstall, journal migration, owner-safe config removal, supported OS upgrade or reinstall migration                                                                                           | Package/service/filesystem state and preserved/rotated identities as specified                                                                                                           |
| L09 | GNOME/KDE sessions, built-in support consent/indicator/local stop/input, self-service/notices, Wayland/X11 as claimed, UID reuse/shared-device/ownership transfer, suspend/resume and accessibility                                                 | Actual session evidence and isolated person binding; lock/logout/revocation terminates support; no tray or unattended-control dependency                                                 |
| L10 | Network rollback, EAP-TLS/VPN, firewall, certificates/trust/SSSD, account controls, encryption escrow and person-certificate binding/deprovisioning                                                                                                 | Real credential/network behavior and cold-boot recovery; no cross-person secret or competing native owner                                                                                |
| L11 | Compliance pass/fail/error/unknown/N/A, expiring exceptions, SCAP tailoring/content, distro backports/epochs, stale or conflicting advisories                                                                                                       | Native findings linked to content/version/freshness; no false healthy status                                                                                                             |
| L12 | CLI/UI parity, idempotency, webhooks retry/signature/dedup, export access, typed diagnostics, bounded scripts and consent-controlled remote support                                                                                                 | Receiver/user-visible outcomes, consent termination, redacted support bundle and action audit                                                                                            |
| L13 | Approval separation, changed targets/authority, executor challenge replay/expiry/restart, restore epoch and actual lock/quarantine effects                                                                                                          | No high-risk start without a fresh verified one-use grant; the bounded residual authorization window is measured                                                                         |
| L14 | Migration under traffic, DB/worker crash, both server installation modes, restore hold/epoch, revoked identity, key rotation/loss, audit/retention                                                                                                  | Usable restored system with fresh authority; no stale destructive replay or revived directory access                                                                                     |
| L15 | Real TPM/Secure Boot/recovery, lock boundaries, authenticated recovery-media handoff, wrong target/expiry/power loss, off-target state, sanitize/reinstall and key-copy implications                                                                | Physical signed evidence and separate verification/validation; lost state/report stays unknown rather than restarting wipe                                                               |
| L16 | Full isolated management LAN with public egress blocked, local IdP/DNS/time/PKI, signed content import, expiry/replay/corruption and missed key rotation                                                                                            | Network capture/deny counters and successful offline lifecycle; no disabled integrity checks                                                                                             |
| L17 | Cross-version contracts, generated code and two-clean-builder unsigned release-payload digest equality, TUF/freeze/rollback, native package/image trust, provenance/SBOM/licenses                                                                   | Both build manifests and comparisons plus actual installed release artifacts; signatures/attestations verified separately from deterministic payload equality                            |
| L18 | Single-host and replicated load/soak, reconnect storm, storage full, queue fairness and worker/DB failover                                                                                                                                          | Workload manifest and measured budgets from security/operations; accepted work preserved                                                                                                 |

### Fault injection and oracle requirements

Inject actual process kills, VM power cuts, network partitions, DNS failure, proxy
failure, TLS expiry, clock skew, exhausted disk/inodes, database disconnects and
package-manager locks. Inject at durable state transitions, not only between happy
path steps. Report whether a transaction can be retried, needs reconciliation, or
requires human recovery. Exercise schema incompatibility and rollback without
silently resetting the database/journal to make a test pass.

Native truth is the oracle: package database/application health, service readiness,
boot ID, network reachability, actual credential acceptance, unlocked data and desktop
effect. The API must report those observations correctly. A mocked agent echoing its
requested values proves nothing about Linux enforcement.

## 4. Scheduling and release gates

| Lane              | Trigger                           | Scope                                                                                                                             |
| ----------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Local inner loop  | Each relevant edit                | Focused Go tests/real PostgreSQL integration as needed; cached representative VM for changed provider                             |
| Pull request      | Every change                      | Formatting/lint/generation/breaking/schema/auth tests; representative Debian-family and RPM-family lifecycle; affected UI surface |
| Nightly           | Main and dependency/image changes | Entire VM matrix and interrupted operations; isolated-network subset, cross-version and graphical sessions                        |
| Release candidate | Every signed release              | Full applicable connected and air-gapped suite, actual ISO installs, physical capability gates, security/load/restore evidence    |

PR reduction is a feedback optimization, not a waiver of launch certification. An
unavailable licensed image, unavailable KVM, unavailable physical machine or skipped
scenario blocks the corresponding claim. Every matrix cell must list required vs
not-applicable scenarios with reasons; a missing capability is not a passing test.

Store run ID, commit/build IDs, image and repository digests, toolchain/firmware/CPU,
configuration, operation IDs, structured assertions, native observations, serial
console, redacted journals, screenshots and fault timing. Failed-run artifacts have
retention/access controls; never archive grant values or encryption keys. Results
are machine-readable JSON/JUnit plus a concise human report. Preserve reproducible
seeds. Automatic reruns retain the first failure and cannot turn an unexplained
flaky security/destructive scenario into a passing release gate.

## 5. Physical qualification prerequisites

Before implementing a supported sanitize method, select actual sacrificial company-
owned devices with explicit destructive-test authorization, firmware and media
inventories, out-of-band power/recovery access, and a retention/disposal policy. At
least each advertised hardware/storage/encryption tuple must be represented. A generic
"one laptop passed" is not coverage. Local workstation resources currently do not
establish availability of this laboratory; this remains a procurement/access gate.

Validate real TPM and software-key paths, NVMe/SATA as advertised, interrupted erase,
alternate boot and recovery media, lost network/ack, multi-disk/swap, escrow/header
backup implications and fresh OS installation afterward. Where firmware behavior or
full key destruction cannot be verified, report unsupported or require physical
destruction; do not redefine the acceptance test to obtain a green result.
