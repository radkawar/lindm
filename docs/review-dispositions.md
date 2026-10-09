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

### Legacy include definition-binding correction

Upstream systemd v239's
[configuration parser](https://github.com/systemd/systemd/blob/v239/src/shared/conf-parser.c#L180-L206)
can open `.include` files outside the fragment/drop-in paths hashed by the
provider. Its
[line reader](https://github.com/systemd/systemd/blob/v239/src/basic/fileio.c#L1586-L1653)
also treats NUL as a physical-line delimiter. Six regressions failed before the
correction: plain, whitespace, BOM, NUL and two continuation forms were accepted.
The streaming definition reader now refuses legacy include prefixes as unsupported
without normalizing accepted bytes. It does not attempt to reproduce native INI
or install semantics; ordinary comment/value mentions remain accepted.

Independent stateless source review found no actionable guard defect within that
scope. A separate fixture review found that the host accepted only capability and
record count, not the required scenarios. The host now verifies ordered scenario
names, targets, rejection values, canonical IDs and native state bindings, including
the loaded/inactive/disabled legacy fixture. Empty records are rejected. Replay of
both real native evidence records rejected duplicate scenarios, changed state,
substituted canonical IDs and falsely absent legacy targets; the throwaway replay
code was removed. Corrective source review found no further actionable issue.
These source reviews did not execute checks. The caller-selected lab executable
remains trusted; structural validation does not authenticate an arbitrary program.

The corrected ten-scenario native lane passed on Ubuntu 24.04 and Fedora 44.
Fedora's enforcement checks were Enforcing before and after. Evidence:
`/home/r/.cache/lindm-services-ubuntu-legacy-include-v2.json` and
`/home/r/.cache/lindm-services-fedora-legacy-include-v2.json`; both used lab SHA-256
`342e5c0efdac76724ecc8654e0dea5dba30aa80c7f81c4bfa67480fb596bff88`.
Focused provider/executor/lab race checks and lint passed. This qualifies the
refusal and existing provider scenarios, not profile ownership or full G3.

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

### Fresh actor-authorization reviews

Independent reviews covered the authority/version/transaction boundary and the
isolated live-Keycloak proof with its shared schema-lifecycle extraction. Neither
found remaining actionable defects in its assigned scope. The regression author
identified that browser future-clock tolerance must not apply to the current
snapshot in a dispatch fence: an actual PostgreSQL test first committed the gated
effect incorrectly, then passed after explicit future-observation rejection.
Opaque approvals also bind the required operation permission and retain a
process-monotonic deadline; wall-clock rollback cannot extend a signed start window.

The maintained real-Keycloak check passed through both `cmd/dev test-integration`
and `lab auth check-fresh`. Unchanged/display-only observations retained authority
version 2; observed group removal, regrant, disable and re-enable advanced it through
versions 3–6. Old approvals remained rejected after restored membership, and only
the two allowed private-schema writes persisted. Temporary users, groups and
database schemas were removed without changing shared fixture identities or
application tables. These observations qualify this actor API, not job dispatch
or device compliance.

Formatting, protobuf/web checks, full Go lint/race tests, dependency checks, real
PostgreSQL integration tests and builds passed. The quality run also corrected
unchecked response-body closure in the fixture adapter using the existing joined
error-handling convention. Production dispatch must still combine this API with
current desired-head, device/generation, recovery and lease fences, and clip signed
start expiry to the actor approval deadline. This is not whole-product certification.

### Service-history attestation reviews

Independent reviews covered the root signing/current-identity boundary and the
maintained native proof. The first found a certificate-encoding mismatch: enrollment
accepts an issuer preamble, whereas the attestation verifier requires exactly one
canonical PEM leaf. A renewal regression failed before the correction and passed
after root emitted PEM from its already authenticated parsed certificate. Stored
enrollment and original execution evidence are unchanged.

The proof review found that a one-minute readiness deadline could be shorter than
legitimate transport recovery. It is now ten minutes, without accelerating product
timers. The first native reboot run then failed with `session_required`: the lab
had treated a usable committed epoch as proof of a current-boot session. Readiness
now independently reads the guest boot ID and requires it to match the committed
executor boot. Root's rejection was correct; no authority fence was weakened.
Corrective reviews found no remaining actionable defects in their assigned scopes.

Both corrected packaged lifecycles passed. Ubuntu and Fedora each verified ten
device-signed retained actions in four phases: terminal, execution-trust revocation,
reboot and reinstall. Every positive had schema-valid payload-tampering and
wrong-nonce replay negatives. The reboot acquired epoch 2 on a distinct boot;
terminal status and action revision remained identical in all later phases,
including the actual SIGKILL outcome-unknown record. The schema-3→3 packages add
attestation, not a new journal migration. Immutable build/run references are in
the implementation evidence ledger.

Protobuf generation, formatting/web checks, full Go lint/race tests, integration
checks, dependency scans and builds passed, followed by the corrected native runs.
Focused regressions also cover historical timestamps after clock rollback, no
native reads/effects or journal mutation during attestation, certificate-expiry
clipping, renewed-key signing, and pending/other-boot identity rejection. Current
certificate/device revocation, desired-head/recovery policy and production receipt
ingestion remain consumer responsibilities; this is not a compliance or release
certification.

### Control-plane authority and automatic relay reviews

Independent source reviews covered public-bootstrap configuration and RPC fences,
durable authority history, root/transport synchronization, and private native proof.
The following failures were reproduced and corrected before qualification:

| Finding                                                                                | Correction and exercised evidence                                                                                                                                                                                                                                                                                                |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Concurrent relay loops could interleave renewal with session establishment             | A shared cancellable gate spans the complete transition sequence, including inventory `GetSyncState`, but not collection/upload or trust delivery. The deterministic regression failed with `renewal_pending` before the correction and passes under the race detector; cancellation of a waiting loop leaves inventory usable   |
| A restored singleton delegation could lower live floors beneath newer retained history | Real PostgreSQL admitted D15 after D20 when only the singleton envelope was restored to D10. Live snapshots now bind their captured revision to immutable admission bytes, digest, receipt, time and retained root. The reproduced case, metadata corruption, historical retry and concurrent captured-snapshot regressions pass |
| Root-only initial state bypassed retained-root binding                                 | Real PostgreSQL accepted an attacker-quorum first delegation after replacement of only the initial root document. Root identity/position checks now precede both snapshot branches; initial acceptance metadata must match initialization. The same attack and seed-metadata regressions pass                                    |
| systemd garbage collection erased the no-effect probe's start timestamp                | An actual owned user-service start/stop/reload returned timestamp zero while a persistent marker remained. The VM probe uses its own persistent marker and positively tests it before the synchronization observation window                                                                                                     |
| The isolated server fixture supplied a forbidden `search_path` option                  | Native startup failed, and the production resource loader reproduced the rejection. The fixture now owns a separate database rather than weakening configuration validation. Real server migration, owner login/admission, restart/exact retry, session revocation and confirmed database cleanup passed                         |

The database cutover also corrected a missing optional migration URL reference.
It uses the owned non-superuser migrator URL for both migration and runtime; cluster
administration remains confined to laboratory code. Final source re-reviews reported
no remaining actionable findings in their assigned scopes. Full generation,
formatting, lint/race and PostgreSQL/Keycloak integration checks passed; the corrected
fixture additionally passed its real-process smoke and focused checks. Packaged
Ubuntu 24.04 and Fedora 44 authority synchronization lifecycles passed owner admission,
automatic relay, rotation/revocation, quorum and rollback denials, exact historical
retry after server restart, unchanged TLS identity, positively witnessed no-effect
checks and trust retention after reboot/reinstall. Both isolated databases were
confirmed absent after teardown. Artifact identities and device IDs are recorded
in the implementation ledger. These reviews do not qualify profile dispatch or
whole-product security.

### Profile catalog and online signing-resource review

The current integration has source-reviewed immutable catalog persistence and
optional online signing-resource loading. A reviewer found that Go's PEM decoder
could skip a malformed first section and load a later valid private key. A protected
configuration-file regression reproduced acceptance before the correction. The
loader now requires exactly one BEGIN and END marker as well as the existing
type, header, remainder, PKCS#8 and Ed25519 checks. The signing-resource race suite
passed, and focused source re-review found no remaining actionable issue.

Parent verification also reproduced a dependency-graph defect: with `a -> {b,c}`,
`b -> a`, and `c -> b`, DFS back-edge marking classified `c` as merely blocked
rather than a cycle member. Strongly connected components now classify all cycle
members, and reverse-edge propagation blocks their transitive dependents. The
failing-before regression and resolver race suite pass.

Real PostgreSQL checks passed canonical immutable history, exact retries,
concurrent expected-head publication, rollback and corrupted-resource rejection.
The maintained real-server catalog command passed under actual owner login,
including restart/retry and typed dependency retention; run profile
`8adb88c7-d5a6-4157-b35d-e295166b0373`. Integration-tagged Go lint and focused
race checks passed after correcting unchecked assertions in test helpers.
The extended command also passed real server startup with two distinct protected
online-key files before repeating the full catalog scenario; run profile
`53aad558-d4b2-4686-890e-fd0e7646ace5`. Focused source re-review confirmed private
key/config ownership and cleanup, without treating loaded keys as delegated authority.
A separate scoped review found no actionable defect in the maintained command's
real-process isolation, cleanup ordering or RPC pagination budget. The pagination
regression covers control-character-heavy JSON metadata against real PostgreSQL;
the maintained command and browser exercise the actual HTTP service.

The independent console review found two reachable lifecycle bugs: failed revision
refreshes unmounted and discarded unsent drafts, and finishing creation from the
detail page left the create route holding a consumed profile UUID. Both were
reproduced in the real browser before correction. A pinned editor source now
survives read failures, recovery and exact-revision navigation. Clearing a published
attempt retires its matching creation reservation without retiring pending or
ambiguous attempts. Source re-review and browser after-checks passed.

Browser verification additionally replaced duplicate handwritten schema checks with
generated protobuf validation, corrected non-BMP input truncation, cleared stale
pre-publication notices on send, and corrected the narrow-screen revision lookup.
Real owner SSO, a successfully committed reply dropped before delivery, byte-identical
retry after route navigation, a genuinely competing revision, explicit refresh/rebase
without implicit publication, immutable history and sign-out with a held successful
reply all passed. The accepted-before-sign-out mutation remained accepted; its late
reply did not restore the old authenticated surface. Browser evidence is retained at
`.cache/g3-profiles-browser-evidence-v1.json`.

Full quality gates, integration-tagged lint and the production console build passed.
The full PostgreSQL/Keycloak integration run also passed. These reviews do not qualify
online issuance, profile activation, native ownership, fleet capacity or whole-product
security. Full G3 remains open.

### Isolated native install and custody checks

Independent stateless source reviews examined native command isolation, retained
symlink identity, replacement preservation, bounded output and evidence publication.
They did not execute the native scenario or certify production ownership.

An actual failing-before regression showed that the initial lab command accepted a
replaceable `0777` work parent. Corrective review then found that validating ancestry
only after creation still left recursive cleanup exposed to directory substitution.
The maintained command now validates and retains the work-parent boundary before
creating its fixture. Shared `statefs` traversal retains the distinct diagnostic
final-owner rule; it does not trust that foreign owner for ancestor directories.
Source re-review found no additional actionable issue within the stated UID/root
and trusted-filesystem assumptions. No adversarial cross-UID rename schedule was run.

The corrected native CLI passed on systemd `255.4-1ubuntu8.17` with evidence
`/home/r/.cache/lindm-native-install-projection-v3.json`. Focused lint and all agent,
VM-lab and lab-command race checks passed. The existing foreign-final-owner
regression and new temporary-parent checks also passed as actual UID 0 in an
isolated, network-disabled, read-only container with only temporary filesystem
writes. This verifies filesystem permission boundaries, not a native distro lane.
Profile ownership, crash/power-loss recovery, runtime restoration and full G3 remain
unqualified.

A follow-on actual native run, recorded as
`/home/r/.cache/lindm-native-install-projection-v4.json`, started with both declared
and undeclared aliases plus an already-enabled `Also` instance. Direct enable
preserved all three; disable removed them; re-enable recovered the declared alias
and `Also` link but not the undeclared alias. Focused lab race checks and lint
passed. This establishes the counterfactual footprint only for the controlled
fixture; it does not establish a general snapshot algorithm, shared ownership or
production release semantics. The earlier independent reviews did not review this
follow-on extension.

The root-boundary extension passed on both systemd `255.4-1ubuntu8.17` (host UID
1000; record `/home/r/.cache/lindm-native-install-projection-v5.json`) and
`239-78.el8` (UID 0 in the same pinned, capability-free Rocky 8 container).
An absolute directory symlink caused native `--root` to read a different
fixture-owned definition outside the staged root. A relative directory rewrite
selected the staged definition without changing the logical install-link targets.
An unchanged absolute final-file link selected the staged bytes through native
root-aware lookup, including the extra linked-unit configuration link. Every
result was checked against the exact observed filesystem link set.

An independent stateless source review found no actionable issue in this extension
under the existing fixture ownership/parent-trust assumptions. It did not run the
scenario, inspect the trust/output-limit helpers or authenticate caller-selected
native executables. Focused VM-lab/lab-command race checks and lint passed. This
does not establish general alias classification, symlink-limit equivalence,
complete lookup snapshots, a production helper sandbox or distro certification.

## Remaining external gates

No product-owner ambiguity remains in the first-slice scope after these decisions.
The internal G2 slice is verified and committed as `cb97712`. Named IdP test tenants/permissions,
licensed enterprise content, physical sacrificial machines/destructive consent,
distribution license/public namespace and production signing custody must exist
before their corresponding integration, publication or hardware gates. They are not
grounds to claim unsupported features complete. Old desktop portal compatibility,
immutable-provider behavior, air-gap trust renewal and capacity remain explicit
technical qualification work.
