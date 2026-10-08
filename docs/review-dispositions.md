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

## Remaining external gates

No product-owner ambiguity remains in the first-slice scope after these decisions.
Engineering must still finish G2 qualification. Named IdP test tenants/permissions,
licensed enterprise content, physical sacrificial machines/destructive consent,
distribution license/public namespace and production signing custody must exist
before their corresponding integration, publication or hardware gates. They are not
grounds to claim unsupported features complete. Old desktop portal compatibility,
immutable-provider behavior, air-gap trust renewal and capacity remain explicit
technical qualification work.
