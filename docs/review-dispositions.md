# Independent specification and implementation review

Review date: 2026-10-08. Scope: the product specification, architecture, operations,
verification, engineering, implementation plan and research. Three independent
read-only reviewers examined product completeness, security/protocol correctness and
operations/testing. They did not implement code, run product tests or certify safety.

Initial verdict: not ready to implement without correcting the ten initial findings.
All were accepted and amended in the main contracts and acceptance scenarios.
Three fresh reviewers then checked the corrections and expanded owner selections.
Security confirmed R03-R08 closed at design level; product confirmed R02; operations
confirmed R09-R10. Product and operations independently identified the same residual
R01 broker-freshness gap, recorded as R11 and corrected by the integration owner.
The R11 amendment is not represented as a third independent sign-off. "Resolved"
means resolved in the specification, not verified product code.

## Accepted findings

| ID  | Reviewer / priority                   | Concrete risk                                                                                                    | Design resolution and required evidence                                                                                                                                                                                                                                                                                 |
| --- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R01 | Product / high                        | OIDC-only login cannot signal upstream disable/group removal; a 12-hour session could retain access              | Architecture identity section now requires authoritative provider lifecycle adapters, bounded fresh snapshots and fail-closed access. G1 includes Keycloak lifecycle, not login alone. L02 disables accounts/groups during active sessions and measures source propagation separately                                   |
| R02 | Product / medium                      | Local UID, device owner and organizational person had no entitlement join                                        | Owner chose both device/person assignments. Architecture binds immutable principal to device generation and local-account incarnation; shared/unbound/recreated/transferred accounts are explicit. L06/L09/L10 exercise isolation and deprovisioning                                                                    |
| R03 | Security / high                       | Generic persisted idempotency responses would retain supposedly hash-only bearer grants                          | Secret issuance returns a secret once; retry exposes only ID/unknown-delivery state and revoke/reissue path. No plaintext in idempotency/audit/outbox. L03 covers lost responses and persistence inspection                                                                                                             |
| R04 | Security / high                       | Compromised network process could delete the dedup journal and replay privileged work                            | Root executor exclusively owns execution/trust/replay state; transport spool is separate; missing/corrupt journal enters recovery hold. L05 tests replay/tampering/reinstall                                                                                                                                            |
| R05 | Security / high                       | SCIM deactivation could not reliably join an issuer/subject principal; stale login claims could resurrect it     | Immutable provider-authorized correlation, uniqueness, authoritative membership source and persistent deactivation/tombstone precedence. L02 tests recycled email, conflict and subsequent login                                                                                                                        |
| R06 | Security / high                       | DSSE envelope format did not establish initial or rotated execution trust                                        | Bootstrap pins execution root; executor stores versioned root/delegation chain, quorum rotation and rollback fences; ordinary TLS/plan authority cannot replace roots. L05/L16 test tampering/missed rotation/expiry                                                                                                    |
| R07 | Security / high                       | Compromised relay process could fake or replay fresh destructive authorization                                   | Executor-generated challenge, signed device/action/digest/epoch-bound start grant, 30-second limit and durable single use; reboot invalidates it, restore fences the residual window. L13 covers replay/restart/revocation                                                                                              |
| R08 | Security / medium                     | Recovery media would erase its own sole identity/journal or treat signed boot as wipe approval                   | One-action recovery credential and key handoff, post-boot media revalidation, fresh start grant, protected off-target/server checkpoints; absent qualified storage forces external operator workflow. L15 tests handoff/power loss/wrong media                                                                          |
| R09 | Operations / medium                   | Native server deployment could avoid all acceptance while Compose alone passed                                   | Verification now has independent native, OCI/Compose, replicated and assistance-relay topology rows with installation/upgrade/restore/air-gap/load obligations                                                                                                                                                          |
| R10 | Operations / medium                   | Reproducible generated code did not prove reproducible binaries/packages/images                                  | Two isolated clean builds compare unsigned release payload digests; signatures/attestations form a separate verified boundary. L17 and release-check retain comparison manifests                                                                                                                                        |
| R11 | Product + operations follow-up / high | Polling the broker's imported account falsely resets freshness while the original SAML source has revoked access | Persist immutable upstream-to-broker lineage; query the original authoritative directory and intersect broker restrictions. Offline reference has separate upstream/broker realms. No qualified connector means no bounded-revocation certification. L02 explicitly mutates upstream state without another broker login |

R01/R03/R05 affect G1 identity/API contracts. R04/R06 affect G2 process/trust boundaries.
R07 is required before G3 execution and G7 destructive work. R02 blocks G4 entitlement
features. R08 blocks G7 automation/physical qualification. R09/R10 must be designed
into deployment/release pipelines and pass before commercial release. None is waived.
R11's lineage contract affects G1 identity schema and G5 broker certification; it is
an engineering correction, not a request to remove SAML or weaken revocation.

## Owner clarifications incorporated

- Desktop-first and company-owned servers share the core but have distinct acceptance.
- Connected and air-gapped both ship; lock/wipe remain capability-gated with mandatory
  physical evidence and two-person approvals.
- Device-wide and person-bound assignments both ship, with explicit binding rules.
- Core, SUSE enterprise, maintained legacy and rolling/immutable families all remain
  launch scope. Verification names branches and architectures; rolling/atomic/Nix
  providers have distinct transaction/ownership contracts.
- Keycloak with broker/standards paths, Entra ID, Okta and Google Workspace are named
  launch integrations. OIDC support alone is not certification of directory freshness.
- Remote assistance is built into the console/session experience. Portal/PipeWire,
  WebRTC and local TURN are the proposed implementation, with visible per-session
  consent and no default recording/unattended-access promise.

## Initial control-plane implementation reviews

Independent read-only reviews covered identity/device authority, configuration and
transport, operational composition, and frontend lifetimes. Parent-owned verification
used real PostgreSQL/Keycloak, the running Go server and Chromium, not reviewer claims
that source inspection proves runtime behavior.

| Finding                                                                                                             | Correction and exercised evidence                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Grant secret shadowing; overlapping certificate could mint new authority                                            | Corrected issuance assignment and active-certificate fence; real PostgreSQL replay/concurrent-renewal regressions pass                                                    |
| Older directory result could overwrite newer disable; authorization changes lacked audit                            | Database-clock observation fence and transactional effective-role auditing; real database ordering/rollback regressions pass                                              |
| Old disable could revoke a newer login; logout/session updates inverted principal lock order                        | Recheck authority under principal lock and lock principal before sessions; newer-session survival and actual concurrent logout/disable database regressions pass          |
| Enrollment replay returned a later renewal certificate                                                              | New migration binds grant consumption to the original issuance; same/different-key renewal replay and terminal rejection regressions pass                                 |
| PostgreSQL indirect file reads bypassed protected-resource checks; wrong CA EKU accepted                            | Checked in-memory TLS resource loading, no implicit credential sources, and intended-usage checks; file-permission/CA regressions and actual lab TLS startup pass         |
| Session transitions retained caches/observers or accepted late secrets                                              | Cancellable authentication generations, scoped queries and remounted feature state; real delayed grant response across logout/new session was aborted and not displayed   |
| Ambiguous revoke retry changed its payload; initial list failure bypassed recovery; browser back escaped lists      | Frozen submissions, recoverable prefetch and list-local cursor navigation; actual lost-response retry and invalid-cursor recovery exercised                               |
| Embedded lazy chunks, stale heading, table overflow, blocked theme initializer and mobile menu obscured destination | Correct embed inclusion, reactive heading, flex width constraint, bundled theme initialization and close-on-navigation; desktop/mobile/light/dark browser paths exercised |

These are verified corrections in an internal integration milestone, not a claim
that all commercial features are implemented or an independent sign-off of every
corrected line.

### Review of implementation commit `19dce6d`

Three further independent reviewers examined console request lifetimes, transport
configuration and identity/device authority. Four concrete findings were accepted:

| Finding                                                                                       | Correction and exercised evidence                                                                                                                                                                                                                                                                                    |
| --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A retry could remain in flight while “Start a different request” discarded its frozen payload | Disable replacement during pending mutations and synchronously guard reset handlers. Reproduced against the running server before correction. After correction, real issuance, grant-revoke and device-revoke requests each retained identical payloads through two dropped responses and a successful third attempt |
| Active certificate could expire while renewal waited for its device row lock                  | Recheck expiration after acquiring the lock, before any certificate mutation. Real PostgreSQL lock-wait regressions advance the service clock across active and overlap boundaries and verify rejected requests leave certificates and audit unchanged                                                               |
| Allowed `load_balance_hosts` was unsupported by the pinned driver                             | Reject the option rather than forwarding an invalid PostgreSQL startup parameter; configuration regression covers rejection                                                                                                                                                                                          |
| Generic URL authority parsing rejected valid PostgreSQL failover lists                        | Preserve PostgreSQL host-list syntax while checking explicit identity/options and protected TLS resources. Mixed-port/IPv6 and unsafe-input regressions pass; actual `check-config` and `migrate` succeed with an unavailable first endpoint and the verified-TLS PostgreSQL fallback                                |

The corrective quality run passed `make check test-integration build` and separate
integration-tagged Go lint. Actual device-listener verification also enrolled a
software key, reported native host OS metadata, renewed with a new key, replayed
the original enrollment issuance, and rejected inventory on an existing TLS
connection immediately after console revocation. This was a temporary protocol
smoke client, not a packaged agent, complete inventory collector or VM qualification.

Three independent follow-up reviews of corrective commit `2a33788` found no further
actionable defects in the examined database parser, renewal-expiry boundary and
console exact-retry lifecycles. They were read-only reviews; runtime evidence remains
the parent-owned checks above, not a blanket production certification.

### G2 agent contract review

Two independent design reviewers identified eleven concrete gaps before native-agent
implementation. [The refined contract](agent-enrollment.md) now specifies:

- Message-aware TLS signing, executor-derived renewal intent and separate retrieval
  of an existing issuance after prolonged interruption.
- Root-only pending enrollment credentials, marker/journal crash ordering and a
  reboot-safe session fence with explicit software-clone assurance limits.
- Independent observation/package sequences, typed failure/freshness evidence,
  durable replay receipts and immutable snapshot-bound pagination.
- Aggregate server/spool admission bounds, exact batch-byte hashing and atomic
  cleanup, plus enforced APT/RPM signer verification before package scripts run.

These are design dispositions, not implemented or certified G2 behavior.

### G2 prerequisite implementation review

Implementation commit `051d213` contains native observation collection, DSSE/TUF
bootstrap verification, restricted TLS message signing and verified vendor-image
acquisition—not the complete enrolled agent. Three independent code reviewers
examined native collection, trust/PKI and image acquisition. The trust/PKI reviewer
reported no actionable defect in its assigned scope. Two findings were corrected:

| Finding                                                                                          | Correction and exercised evidence                                                                                                                                                                                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RPM 4.x imported signing-key records lack an architecture tag and invalidated the whole snapshot | Reproduced native `gpg-pubkey` output using an isolated RPM database and vendor key; the regression failed before correction. Interpret RPM's documented absent-tag sentinel as an absent architecture, preserving key/version identity without a package-name exception. Empty/malformed native fields remain rejected; focused race regressions pass      |
| First-time image-cache creation synced contents but not newly created ancestor entries           | Sync the parent hierarchy under the initialization lock before publishing the marker, then sync the marker's directory. Existing marked caches avoid repeated ancestor syncs. Concurrency/offline/cache race tests pass; the built CLI acquired and reverified the full Ubuntu image in a new nested cache. Physical power-loss injection was not performed |

Corrective Go lint reports zero issues. Native inventory, image-cache and trust race
tests pass; the corrected built inspector still matches all 2,440 native host package
records. The temporary duplicate image cache and isolated RPM database were removed.
These checks do not qualify RPM VM installation or physical crash durability.

Corrective commit `016cf38` received two independent follow-up reviews of the RPM
sentinel and first-cache durability changes; neither found an actionable defect.

### Native VM and protected-authority implementation checks

The maintained VM lane exercised Ubuntu 24.04 and Fedora 44 native observations.
A Fedora run exposed cloud-init's attempted hostname change as a degraded result.
The inspection scenario does not need to rename the guest: it now preserves the
vendor hostname and still compares that actual value independently. Degraded
cloud-init remains a failure; it is not ignored or marked successful. Both guests
passed after the correction and private VM resources were removed.

A failing-before PostgreSQL regression exposed a session-fencing error: reformatting
the unsigned outer DSSE JSON changed its byte digest and could create a clone hold.
Changed reuse of an existing acquisition UUID now returns an idempotency conflict
before clone detection; a different protected request consuming the same predecessor
still creates a durable hold. The regression and the complete integration/race suite
pass. HTTPS issuance retrieval also preserves the original certificate after overlap
expiry and denies wrong-key, expired, held and revoked requests.

After the provider's usage limit reset, independent protected-authority review found
no actionable defect in session fencing, renewal/retrieval, certificate policy,
typed admin state and their persistence/callers. Live mTLS and browser verification
also exercised acquisition replay, unsigned-wrapper conflict without hold, successor
fencing, durable clone hold, the console's recovery-hold badge and revocation.

Independent review of VM implementation commit `219f676` found a cancellation/privacy
defect: `cloud-localds` copied private seed material into inherited `TMPDIR`; killing
its shell bypassed the cleanup trap and left the ISO-builder descendant running.
A real-tool regression reproduced both failures. Host helpers now set `TMPDIR` to
the owned private run directory and cancellation kills their process group.
The regression passed ten repetitions; the corrected maintained runner then matched
all 427 Fedora package records and native host facts and completed owned cleanup.
That run used agent SHA-256
`981ce2e080ac17e30747fc023e84ca03a7869e0f36d8dc40bb091b0acc4156fe`.
Independent follow-up review found no additional actionable defect in the staging
containment/process-group correction or its real-tool regression.

### Protected journal storage review

The SQLite/sqlc journal library now persists closed protobuf authority state with
full-synchronous WAL, a separately synced installation marker, exclusive directory
ownership and revision CAS. A separate-process smoke recovered acknowledged revision
2 after the writer exited without closing its database. This is not a physical
power-loss test or a completed privileged executor.

Two independent reviewers found and reviewed corrections to:

- SQLite canonicalizes proc-fd paths, so final-directory checks alone accepted an
  attacker-replaceable ancestor. A regression failed before correction. The library
  now walks directory descriptors from the root, checking ownership, non-sticky
  writability and symlink exclusion before any provisioning write.
- Cancelled/deadline-expired reads, integrity checks and opens were incorrectly
  reported as corrupt-state recovery hold. Both interruption modes failed before
  correction; context errors now remain distinct and a healthy reopen still works.

Focused race and lint checks pass; both reviewers' correction follow-ups found no
additional actionable defect. Cryptographic state admission and lifecycle transition
authorization remain responsibilities of the executor caller, not claims made by the
storage library. Distinct-UID VM process isolation is still an integration gate.

### Packaged executor, inventory and native lifecycle reviews

Independent implementation reviews found boundary defects before native
qualification. Corrections were exercised against the actual failing paths:

- Executor startup reacquired its own directory lock; socket permission changes
  targeted the socket descriptor instead of its filesystem inode; expired prior
  private credentials remained in the journal. Shared lock ownership, pinned
  pathname-inode operations and durable key retirement replaced those paths.
- Spool recovery lost valid queued empty inventories, mishandled orphan ownership
  rows, underestimated allocated blocks, retained cancelled payloads and classified
  cancellation as corruption. Regression failures preceded the fixes; the
  corrected spool suite passed under the race detector.
- Snapshot admission had PostgreSQL timestamp-type inference errors; pagination
  exceeded encoded response bounds, mishandled literal prefixes and could admit a
  cursor that expired while waiting for its lock. Device detail could mix database
  snapshots, and a maximum-size valid JSON batch exceeded the transport allowance.
  Real PostgreSQL and Connect regressions reproduced these failures and passed
  after correction.
- Packaging truncated large tool output, mishandled RPM payload paths, overwrote
  dynamic account IDs in shell helpers and let a contending signer terminate the
  lock owner's GnuPG agent. Actual package/signing checks cover streaming,
  authenticated payloads, retained ownership and exclusive signing cleanup.
  Duplicate packaging assets and source-text assertions were removed.
- Chromium reproduced cached “Latest snapshot” selection, lost backward navigation
  after a page-size change and incorrect “newer snapshot” notices when the table
  preceded the detail refresh. Corrected navigation was exercised on published VM
  inventory. Desktop/mobile views retained 665 package records and their original
  freshness after a permission-denied attempt, then displayed revocation.

Both Ubuntu 24.04 and Fedora 44 subsequently completed the full corrected
`/usr/libexec/lindm` packaged-agent lifecycle: native signature rejection,
installation, upgrade, reboot, removal/reinstall, interrupted-enrollment recovery,
distinct-UID privilege probes, spool recovery, failed collection preserving the
last snapshot, revocation and missing-journal recovery hold. Exact package hashes
and run identities are recorded in the implementation evidence ledger.

Fedora enforcing-policy execution exposed two independent defects. The old
`/usr/lib/lindm` executable received `lib_t`, leaving services in `init_t` and
denying network access. The standard libexec location now passes vendor-label,
Enforcing and non-`init_t` process assertions and published 429 native package
records through mTLS. Separately, `RestrictSUIDSGID=yes` denied `openat2` for
transport diagnostics. Descriptor-relative `openat` preserves no-symlink and
inode validation without weakening the unit. Root diagnostics accept only the
configured final spool owner; mutable-state and ancestor ownership remain strict.
Root and ordinary-user filesystem regressions passed; independent supplemental
reviews found no additional actionable defect in these two corrections.

That Fedora run then reported a native RPM collection failure during upgrade,
preserving its previous snapshot. The laboratory's seven-minute wait was shorter
than the agent's normal ten-minute recollection interval. The bounded oracle now
allows recollection, server admission and heartbeat jitter without changing product
timers or treating a failed attempt as success. The corrected Fedora run observed
successful recollection and completed the remaining lifecycle.

The integration suite also exposed a test observation race: `/proc/PID/status`
returned ESRCH when an already-killed ISO helper was reaped. The seed-cancellation
regression now pins the paused helper with a pidfd, observes actual exit with
bounded polling and avoids signalling a reused PID during cleanup. Its real-tool
focused run passed; private-staging and descendant-exit assertions remain intact.

Review also found that observation pauses could age the original comparison
cursor out before upgrade. The lab now selects and records a fully compared
current baseline immediately before upgrade, refreshes its comparison cursor only
while that snapshot remains current and preserves the fixed cursor after
supersession. Independent corrective review found no remaining defect in this
change; Fedora's full lifecycle then passed with the maximum ten-minute observation
pauses. Executor, spool, snapshot, console and native-signing corrective reviews returned no
additional actionable findings in their assigned scopes. These are scoped reviews,
not whole-product security certification.

### Signed execution-trust integration reviews

Independent reviews covered dual-quorum cryptography, journal migration, executor
acceptance and native proof. Corrections addressed the following observed failures:

- Journal migration assertions initially unpacked the stored revision/blob in the
  wrong order. The integration run also exposed invalid unsigned/integer CEL
  comparisons in the new trust-state completeness rule. Corrected generation and
  journal/executor race suites pass.
- Schema-valid damage to a stored delegation counter was detected only on trust
  update. A failing-before regression showed live/offline status and restarted
  credential access incorrectly returning to enrolled state. Shared historical
  reconstruction now runs before status, credential access and mutations, including
  startup and offline inspection. The corrected regression also preserves ordinary
  expired-trust status without treating expiry as corruption.
- Native negatives now isolate delegation-version and recovery-epoch fences using
  current-root signatures, rather than failing old-root authentication first.
  Retention checks also reject the exact preceding accepted rotation before
  replaying the final revocation receipt, preventing silent repair from passing as
  persistence. Public TLS identity and transport pins are compared independently.
- Both initial native runs rejected the positive trust fixture. A real-fixture
  verifier smoke reproduced rejection when the checking clock lagged generation
  by one second. Fixture signatures now deliberately overlap by one minute within
  root validity; executor time checks are unchanged. Earlier guest clocks were not
  recorded, so clock skew is not retrospectively proven as their cause. The
  corrected Ubuntu and Fedora runs passed the complete lifecycle and record
  guest/host UTC. Both retained the final trust revocation and unchanged TLS pins
  across reboot and reinstall.

The four scoped reviews, including corrective follow-ups, returned no remaining
actionable findings. `make check` and `make test-integration build` passed.
Both native execution-trust lanes passed; broader G3 policy execution remains open.

### Native service-provider integration reviews

The provider and maintained VM proof received separate read-only reviews. The
provider review found that job-match cleanup could turn a known pre-submission
cancellation into an unknown service effect. Cleanup now tracks the actual runtime
submission boundary; earlier enablement effects retain their separate uncertain
outcome handling. Corrective review found no remaining actionable issue.

Native Ubuntu and Fedora runs exposed two integration errors:

- Persistent enablement leaves `NeedDaemonReload` set. The provider now performs
  bounded native manager reload, then rechecks definition/state before runtime
  effects. It does not ignore the condition or claim reload is per-unit isolated.
- `LoadUnit` can return a cached not-found object. Load-state admission now precedes
  service-specific and persistent-file queries, preserving unsupported-state
  classification without confusing an absent unit with transport failure.

The parent also corrected the alias fixture: native disable removes aliases, so
the negative now creates the alias afterward and proves its loaded canonical ID.
Both corrected native lanes passed all nine phases, including independent native
state checks and teardown. Root-isolated filesystem-boundary tests and scoped race
tests passed. The exact cancellation-between-match-and-submit interleaving was
reviewed statically; the native lane exercises cancellation before `Apply`.
`make fmt check test-integration build` passed, followed by both final native
lanes on the same recorded lab build. These scoped reviews do not qualify signed
remote policy execution or whole-product security.

### Signed durable service-execution reviews

Four independent read-only reviews covered the action journal, cryptographic/native
authority boundary, executor/local RPC lifecycle, and maintained packaged proof.
The journal review found that accounting only for a pending record's current size
could admit an effect but reject its later completion at capacity. Unfinished
records now reserve their full 128 KiB allowance; terminal transitions release
unused space. The actual 2,048-record saturation regression covers rejection and
rollback of new work, queue/start/completion, expiry, supersession and reopen.
Logical reservations do not promise physical disk availability.

The laboratory review identified two proof defects before native execution:

- An empty JSON envelope was a malformed request, not the claimed signature denial.
  The negative now uses a well-formed intent with a fresh action ID, higher sequence
  and forged signature. Each negative requires its explicit Connect denial code;
  transport errors cannot count as authority rejection.
- An inactive unit can lack an invocation ID while asynchronous work is still
  queued. Bounded polling now permits that state and requires a valid nonzero ID
  when native activation is observed.

Corrective reviews found no remaining actionable defects in their assigned scopes.
The quality run also required an explicit protobuf `UNSPECIFIED` zero failure value
with nonzero `NONE`, and deferred row cleanup in migration fixtures. Native preflight
unsupported/conflict outcomes now return stable failed-precondition codes rather
than accidental internal errors. `make fmt check test-integration build` passed,
including race tests and real PostgreSQL/Keycloak integration. The dependency scan
reported no reachable Go vulnerabilities, not absence of every required-module
advisory.

Both maintained packaged lanes then passed with the same lab build: Ubuntu
upgraded genuine schema 1 and Fedora genuine schema 2 to schema 3. The sandboxed
executor performed native effects through network-UID RPC relay; independent native
observations verified the positive and denial cases. Each run recorded ten terminal
actions, including actual persistent `OUTCOME_UNKNOWN` after executor SIGKILL.
The native service invocation survived and was not repeated by an exact grant retry.
Terminal evidence stayed identical after revocation, reboot and remove/reinstall.
The full lifecycle also retained inventory, identity and trust fences, rejected
revoked device access, and held a missing journal. Build/run identifiers are in the
implementation evidence ledger. No product timers or Fedora enforcement policy
were relaxed.

The first-effect callback verifies current authority and consumes the challenge
durably, then rechecks expiry after the commit. Wall-clock completion timestamps
remain actual observations even after clock rollback; `CLOCK_BOOTTIME` separately
bounds start authority. Restart reconciliation never reapplies a running action.
These are scoped reviews, not whole-product certification; production dispatch,
fresh directory reauthorization and root-authenticated remote result reporting
remain required integrations.

## Remaining external gates

No product-owner ambiguity remains in the first-slice scope after these decisions.
The internal G2 slice is verified and committed as `cb97712`. Named IdP test tenants/permissions,
licensed enterprise content, physical sacrificial machines/destructive consent,
distribution license/public namespace and production signing custody must exist
before their corresponding integration, publication or hardware gates. They are not
grounds to claim unsupported features complete. Old desktop portal compatibility,
immutable-provider behavior, air-gap trust renewal and capacity remain explicit
technical qualification work.
