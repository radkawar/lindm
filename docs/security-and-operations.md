# Security, deployment and operations

Status: required design and acceptance targets, not measured service guarantees.
See [architecture](architecture.md) for identity, authorization, protocol and journal
invariants, and [verification](verification.md) for the required evidence.

## 1. Threat model

| Threat                              | Required controls                                                                                               | Residual limitation / test                                                                                 |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Network attacker or hostile mirror  | TLS/mTLS, pinned bootstrap trust, signed update metadata/content, anti-rollback/freeze checks                   | Availability can be denied; corruption/replay/expiry tests must fail safely                                |
| Leaked grant or copied golden image | One-use bounded grant, CSR proof, separate enrollment generation, no keys in images                             | A stolen unused bearer grant may race its owner; approval/hardware binding where required                  |
| Compromised device                  | Device-scoped auth, bounded untrusted input, observation freshness, no fleet/admin privileges                   | Root may fabricate its own posture; software evidence is not hardware attestation                          |
| Compromised desktop/network process | Separate privileged executor, peer identity, signed typed plans, UID-bound session actions                      | Root executor/kernel compromise is outside this isolation boundary                                         |
| Malicious or phished admin          | MFA/step-up, scoped RBAC, two-person approvals, target binding, external audit                                  | Colluding authorized admins can damage managed devices; minimize blast radius                              |
| Compromised control plane           | Restricted service identity, key separation, hardened host, segmented DB/storage, approval and release controls | Execution signing alone does not make a compromised server safe                                            |
| Malicious package or updater        | Publisher approval, repository signature verification, TUF, bounded staging, SBOM/provenance                    | Approved packages can execute privileged maintainer scripts; scanning is not a proof of safety             |
| SSRF or content import exploit      | Explicit egress destination policy, DNS/IP revalidation, redirect restrictions, archive/path/size limits        | Local mirrors need administrator-configured private-address allowlists, not blanket private-network access |
| Backup/database theft               | Envelope-encrypted secrets, separate key custody, encrypted backups and least-privilege access                  | A live host holding usable keys is not protected by at-rest encryption alone                               |
| Restored stale database             | Restore hold, recovery epoch, device journal reconciliation, revoke/reapprove high-risk work                    | Never silently replay stale destructive actions or resurrect revoked credentials                           |
| Capacity exhaustion                 | Per-principal limits, bounded concurrency/queues/batches, backpressure and disk budgets                         | Failed admission is visible; accepted durable work is not silently discarded                               |

Security review must cover every trust transition, a malicious enrolled device,
cross-group authorization, package/config injection, local privilege escalation,
key custody, update compromise and recovery. Fuzz parsers, protocol bounds, filters,
archive extraction and provider plans. Release requires an independent penetration
assessment and closure of critical/high findings, not just a linter report.

## 2. Key and secret custody

Separate keys for deployment CA, device identity, execution authorization, release
update signing, webhook signing, recovery-data wrapping, backup encryption and audit
checkpoints. Use maintained crypto/PKI libraries and OS CSPRNG; never implement custom
cryptographic primitives. Log identifiers, not token values, CSR private keys,
passwords, recovery material, session cookies or secret-bearing policy fields.

The default single-host deployment uses root-protected key files mounted read-only
into the relevant process and documents its host-compromise risk. An external KMS or
PKCS#11/HSM integration is required for higher-assurance deployments, including a
local offline-compatible option. Offline release root/targets signing custody is
never bundled into the online server image. Provide rotation/revocation drills with
overlap, missed rotations, old agents, expired certs and lost keys.

Recovery secrets use envelope encryption with per-record data keys and a separately
protected wrapping key. The API never returns them in inventory, exports or routine
logs. Reveal requires a dedicated permission, recent step-up, reason, and audit;
policy may require a second approver. Responses are no-store and auto-dismiss in UI.
Rotation establishes and verifies the replacement recovery path before retiring the
old one. A failed escrow cannot remove the only working unlock key.

Inventory, recovery escrow, LUKS validity and an actual cold-boot unlock are different
facts. Track all four. Qualify each encryption owner independently, including ordinary
LUKS2 versus vendor-managed TPM encryption. Never modify slots behind the owning
vendor interface. A valid recovery key retained in escrow/backups or a recoverable
LUKS header invalidates a simplistic "delete the local keyslot = secure erase" claim.

## 3. Dangerous actions

Destructive plans freeze exact device identities/generations, media identities,
method, prerequisites, artifacts, rollback limitations and expiry. Two distinct
humans authorize the digest with fresh step-up. Changes invalidate approvals. Before
execution recheck current authorization, target ownership, device/hardware capability,
maintenance policy, recovery state and online authorization. Unused plan approval
expires after 15 minutes by default; the executor-verifiable one-use start authority
expires within 30 seconds as specified in architecture. No offline destructive start.

Expose distinct operations and results:

- Session lock: the supported session interface; local recovery and alternate boot
  may bypass it. It is not boot lock or theft protection.
- Quarantine: the tested network/access policy with an explicit management/recovery
  channel. Validate reachability and automatically restore on a failed checkpoint.
- Retire: cleanup/revocation according to resource ownership, not storage sanitization.
- Sanitize: a qualified firmware/recovery-environment workflow for exact media and
  hardware. Plan multi-disk, RAID, removable storage, swap, headers, escrow, caches,
  snapshots and previously unencrypted areas. Reject an incomplete target scope.

Do not sanitize the live root filesystem as a generic command. A dedicated signed
recovery environment or documented external process must own the execution and
verification path. Secure Boot trust, boot configuration, power failure, firmware
behavior and reinstallation are physical qualification inputs. Record method,
manufacturer/model/firmware, serials, evidence and anomalies; separately record
operational verification and organizational validation following NIST SP 800-88r2.
A missing post-action report remains `outcome_unknown`, not `verified_sanitized`.
Physical operators can submit signed/attributable verification through the approved
workflow; disappearance from the fleet is never sanitization evidence.

Automated recovery-media handoff has a separate least-privilege protocol. Before
reboot, register a one-action recovery key generated in a qualified TPM or protected
off-target medium, and an expiring recovery credential bound to enrollment generation,
action/plan/media identities and the signed recovery-image digest. It can only fetch
that plan, request its fresh start authorization and submit its checkpoints/evidence;
it cannot act as a general device or admin credential. Boot image authenticity is
necessary but not authorization. Establish protected proof of the handoff key,
revalidate actual storage/controller identity and eligibility after boot, and obtain
a new executor-verifiable online start challenge before erasure begins.

The recovery environment writes authoritative execution checkpoints to protected
off-target storage and the server before destructive transitions. Credentials, journal
and sole evidence copy cannot reside only on media being erased. On restart, reconcile
with both stores and the device's reported sanitize status; never blindly restart an
ambiguous sanitize operation. A firmware operation may continue after network loss;
keep the outcome unknown until evidence arrives, rather than retrying it. If a target
has no qualified off-target durable state/identity path, automated wipe is unsupported
and the separately attributable external-operator method is required. Physical gates
exercise compromised/replayed handoff, wrong media, power loss, expired authority,
recovery-image changes and return to a clean installed state.

Deleting escrow now does not remove historical key copies from immutable backups.
A crypto-erase claim requires a demonstrated key hierarchy and retention design that
renders every recovery path unusable; otherwise choose qualified media sanitization
or destruction. Legal hold blocks conflicting destruction and is visible at approval.
Physical test evidence cannot establish behavior for untested SSD firmware/models.

## 4. Connected and air-gapped deployment

Single host: signed OCI server image, PostgreSQL, durable local artifact volume,
configured TLS and explicit secrets, health/readiness checks, resource limits and
systemd-managed Compose deployment. The IdP may be external or a local OIDC service.
No Redis, public object store or Internet call is necessary for normal operation.
Provide a native server package/service installation for operators who do not run
containers, using the same binary/config/migration contract. Root is required for
installation, not routine server execution.

Replicated topology: L4/TLS-aware load balancer, at least two API instances, separately
scalable workers from the same binary, supported PostgreSQL HA and shared S3-compatible
storage. No in-memory session/job ownership or local artifact assumptions. Kubernetes
packaging may use this topology, but is not the definition of scalability. A single
physical host is an availability single point of failure; never market it as HA.

Configuration is typed, validated and documented. Secrets may come from protected
files or approved secret managers, not command-line flags. Startup refuses ambiguous
listener trust, default credentials, unsupported schemas and unsafe production TLS.
Readiness covers DB/migration/key/artifact availability; liveness does not depend on
a remote IdP being online. Metrics/admin diagnostics are private and authenticated.

### Air-gap distribution contract

- Ship a complete manifest-addressed bundle: server/agent binaries and OCI images,
  installer packages, migrations, frontend assets, charts/configuration templates,
  trust metadata, dependency/license/SBOM/provenance data and supported recovery media.
- Mirror required OS/application repositories and vendor advisories legally. Track
  origin, snapshot digest, signing identity, acquisition time, expiry and entitlement.
  Do not promise redistribution rights for RHEL/SUSE or commercial applications.
- Import via a local operator workflow that validates signatures, size, digests,
  supported versions, provenance, monotonic metadata versions and expiration before
  atomic publication. Reject partial/corrupt/replayed imports; preserve old valid data.
- TUF root rotation and timestamp/snapshot renewal follow the same verifier online and
  offline. Expired metadata fails closed for new installs/updates. Existing valid
  agent operation continues; do not disable expiry checks to accommodate the air gap.
- A designated offline signing/mirror process refreshes metadata on schedule. Provide
  an expiry forecast and documented secure recovery if the site misses the window.
  Time is supplied by trusted local NTP; clock anomalies block high-risk actions.
- Include local DNS, CA/PKI, IdP, notification relay and repository configuration in
  the reference topology. All assets/fonts are local; no SaaS telemetry or public
  OCSP/JWKS discovery dependency may silently prevent local operation.
- Deny all external egress during acceptance. Prove provisioning, renewal, policies,
  software/advisory import, updates, backup/restore and audit export inside the site.
- Distinguish an air-gapped site with internal networking from a device disconnected
  from that site. The latter cannot receive fresh policies or destructive authority.

## 5. Release, update and recovery

Release artifacts are immutable, content-addressed, signed and accompanied by SBOM,
license notices, build provenance and vulnerability disposition. Pin toolchains,
container digests, generators and dependencies; review updates and verify reproducible
build inputs. Signed checksums alone are not a freshness/rollback protocol.

Reproducibility means output equality, not just pinned inputs: two isolated clean
builders with the same reviewed source, dependency lock, toolchain, locale and
`SOURCE_DATE_EPOCH` must produce matching unsigned executable/UI assets, DEB/RPM/Arch
payloads, Nix/OSTree payloads where shipped, and OCI layer/config/index digests.
Normalize archive ordering, ownership and timestamps by construction. Separate
signatures, timestamped attestations and transparency-log receipts from this equality
boundary; verify them independently and publish both payload digests and provenance.
L17/release-check retains the two manifests and comparisons. A nondeterministic
required payload fails the gate rather than being excluded after the comparison.

TUF verifies update metadata and targets with an embedded trusted root, threshold
root keys, delegated release channels, bounded metadata/content and anti-rollback/
freeze checks. Execution signing and package-repository trust remain separate. Canary
rings pause on health failure before fleet expansion. On mutable hosts agent packages
use the native package manager; on atomic/declarative hosts agent changes join the
native deployment/generation transaction. One updater owns the files. Never combine
uncoordinated self-overwrite with platform package/image ownership. A root-owned
supervised update job survives the agent restart and records version/booted health.

A known-good agent downgrade requires a newly authorized release policy and compatible
local journal schema; it does not bypass TUF rollback protection. Server migration
uses reviewed expand/contract changes and a serialized migration command. Normal API
startup does not race migrations across replicas. Backups and rehearsal are required
before irreversible changes. An application rollback never implies a safe schema
rollback. Define forward recovery for migrations that cannot be undone.

Backup covers PostgreSQL/WAL, immutable artifacts, configuration, trust material and
encrypted secret material with keys held separately. Restore to a fenced environment,
verify integrity, enter global dispatch hold, change recovery epoch, reconcile device
journals and revocation state, and require new approval for high-risk outstanding work.
A restored IdP/session table must not resurrect access: invalidate restored sessions
and reconcile directory deactivations before reopening admin access. Restore procedures
must account for key revocations newer than the backup through separately retained
security-event records. Fail closed if those records cannot establish safety.

## 6. Capacity, reliability and resource targets

These are proposed release-test budgets, not benchmark results or paid SLAs. Record
hardware, database/storage configuration, dataset, payload distribution, binaries and
traffic generator with every result; change budgets only by an explicit spec revision.

| Profile       | Initial release gate                                                                                                                                                               |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Single host   | 10,000 enrolled devices, 8 vCPU, 32 GiB RAM, SSD-backed storage; co-located server/DB, no load generator on the target                                                             |
| Replicated    | 100,000 devices with disclosed sizing, at least two API replicas and independent workers, PostgreSQL HA and shared artifacts                                                       |
| Traffic model | 60-second jittered heartbeat, 30-second long-poll, daily full inventory up to 5,000 packages/device with deltas, 100 concurrent console users, 5% fleet rollout                    |
| Latency       | p95 ordinary admin reads under 500 ms, durable mutation acceptance under 1 s, available online work delivered within 60 s; exclude package transfer and explicit long-poll waiting |
| Stability     | 24-hour representative soak; no lost accepted jobs, unbounded memory/queue growth or unauthorized duplicate effects; 10x heartbeat arrival burst drains within 15 minutes          |
| Agent idle    | Under 80 MiB RSS and 0.5% of one CPU core averaged over 15 minutes; provider scans/installers/desktop processes reported separately, never hidden                                  |
| Recovery      | Reference backup schedule targets RPO at most 15 minutes and RTO at most 4 hours at 10,000-device profile, proven by restore rehearsal                                             |
| HA failover   | Kill one API/worker and fail primary DB during load; preserve durable work/authorization and recover within documented 5-minute target                                             |

Observability: request/error/latency, job age and lease churn, enrollment/auth denials,
renewal failures, last-seen/freshness, provider outcomes, rollout error rate, database
pool/query/lock pressure, disk/artifact growth, backup lag, certificate/TUF/feed expiry,
and offline-import status. Use structured redacted logs and OpenTelemetry. Device IDs
belong in logs/traces, not unbounded metric label cardinality.

Default retention proposal: 30 days detailed observations, 90 days action outputs,
365 days security audit, and configurable device-record retention after retirement.
Recovery secrets live only while required by approved policy. Audit/legal hold takes
precedence over ordinary purge, with encryption and restricted access. Capacity sizing
must use these retention settings, not a nearly empty demonstration database.

Incident runbooks are release artifacts: credential/release-key compromise, malicious
package/policy, lost recovery key, mass lockout, failed migration, ransomware/restore,
expired offline trust, package-manager failure and overloaded reconnect storms. Each
has detection, blast-radius containment, break-glass, recovery and evidence preservation.
