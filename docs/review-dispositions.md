# Independent specification review

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

## Remaining external gates

No product-owner ambiguity remains in the first-slice scope after these decisions.
Engineering must still prove the design in G1/G2; reviewers have not audited an
implementation. Named IdP test tenants/permissions, licensed enterprise content,
physical sacrificial machines/destructive consent, distribution license/public
namespace and production signing custody must exist before their corresponding
integration, publication or hardware gates. They are not grounds to claim unsupported
features complete. Old desktop portal compatibility, immutable-provider behavior,
air-gap trust renewal and capacity are explicit technical qualification work.
