# Implementation sequence and decision gates

Status: planning, before product implementation. The specification is not a built
MDM, and this repository does not yet contain a backend, agent, UI or certified distro.
Each gate below requires working behavior and evidence, not empty package trees or
passing tests around mocks. The whole commercial contract remains in scope.

## 1. Delivery sequence

| Gate                             | Working deliverable                                                                                                                                 | Prerequisites                                                                                           | Exit evidence                                                                                                                                 |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| G0: reviewed contract            | Product requirements, architecture, threat model, distro/capability matrix, test/operations plan and reproducible spec checks                       | User intent and primary-source research                                                                 | Independent reviews reconciled; blocking decisions recorded; initial docs/tooling commit                                                      |
| G1: secure control plane         | Go executable, real PostgreSQL/sqlc/migrations, Keycloak OIDC plus authoritative directory freshness, sessions/RBAC/audit and protobuf console      | G0; private local module initially, real test IdP and immutable identity contract                       | Actual login/disable/group-removal/source-outage denial, hash-only secret issuance, durable restart/migration; Go/proto/SQL lint/hooks active |
| G2: real enrollment              | Signed native agent, separate executor with protected journal/trust bootstrap, grants/mTLS/renewal/inventory                                        | G1; representative images and authenticated development trust bundle                                    | Debian/RPM VM enrollment/restart/revocation, lost secret/certificate responses and root-state isolation; L03-L04                              |
| G3: declarative control          | Typed immutable profiles, targeting, native provider contracts including rolling/atomic/Nix ownership, signed execution/trust rotation and recovery | G2; protected journal and challenge-bound authority contracts                                           | Real drift, interrupted/duplicate delivery, native transactions, corrupt state, key rotation and safe rejection; L05-L08                      |
| G4: desktop and server workflows | GNOME/KDE self-service/notices, accounts/network/certificates/directory providers, patch campaigns, headless workload-safe maintenance              | G3; concrete desktop/remote-support design and server availability policy                               | Actual sessions and workload recovery; accessibility, reboot deferral, no-user-bus behavior, network rollback; L07/L09/L10                    |
| G5: commercial operations        | All named IdP lifecycles/SCIM/broker, software/compliance/reports, integrations and built-in graphical assistance with local TURN                   | G4; actual provider test tenants, feed/content rights and qualified portal/backend integration          | Real IdP/software/receiver and visible screen/input/consent/termination paths; L02/L06/L11/L12                                                |
| G6: offline and recovery         | Complete signed offline distribution, local services/mirrors, agent/server update and migration recovery, backup/restore and key rotation           | Offline constraints apply from G1, not retrofitted here; complete components from G1-G5                 | External egress denied throughout actual install/manage/update/restore; expired/replayed imports rejected; L14/L16/L17                        |
| G7: high-risk capabilities       | Qualified recovery escrow, session lock/quarantine, retirement and media sanitization with immutable approvals and physical evidence                | Auth/journal/recovery design plus selected sacrificial hardware, consent and media/key lifecycle policy | Real recovery boot and sanitization interruption/verification/validation on every advertised tuple; L10/L13/L15                               |
| G8: commercial launch            | Entire supported matrix, packaging/docs/runbooks, capacity/HA/security release gates, support policy and signed release evidence                    | G1-G7 and every required P/L mapping                                                                    | All applicable gates passed; no skipped required capabilities, unresolved critical/high findings or unsupported claims                        |

Build order is not a "minimal production" release. G1-G7 are internal integration
milestones. Revisit estimates only after actual vertical slices and lab throughput
exist; there is no evidence-based delivery-date claim yet.

### First end-to-end implementation slice

G1 and G2 establish one narrow but real path: start the single-host server with real
PostgreSQL and an OIDC IdP; authenticate an admin; issue one-use enrollment authority;
install the built agent package in a disposable VM; establish mTLS; collect actual
inventory; show it in the console; revoke identity and prove subsequent sync denied.
Add the RPM-family execution before calling this slice cross-distro. Do not implement
high-risk provider actions before the identity/audit/durability invariants work.

No demo-only no-auth mode, token in a shell history, fake SSO provider, in-memory
production store, generic shell executor, or hardcoded inventory is an acceptable
shortcut. Test credentials are legitimate isolated IdP/PKI fixtures, not production
fallbacks. The same migrations, generated clients and domain authorization serve UI,
CLI and worker paths.

## 2. Evidence ledger

| Deliverable                                | Current evidence/status                                                                                                                                                                                   |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirements/research/design               | Primary-source specification, three independent initial reviews plus three follow-up reviews; eleven design findings incorporated in the disposition ledger                                               |
| Documentation automation                   | Bootstrap/hook install and full lint exercised on pinned Node; two real-hook regression scenarios passed; dependency audit reported zero vulnerabilities. CI workflow configured but not run on hosted CI |
| Go server, agent and console               | Not implemented or tested                                                                                                                                                                                 |
| Protobuf/sqlc generation and Go lint gates | Specified; not configured against nonexistent application sources                                                                                                                                         |
| OIDC/mTLS/device enrollment                | Specified; no exercised product flow                                                                                                                                                                      |
| Distro/desktop/server lifecycle            | Planned matrix and scenarios; no certified cells                                                                                                                                                          |
| Air-gapped deployment                      | Required architecture and gates; not exercised                                                                                                                                                            |
| Physical recovery/lock/wipe                | Required; no laboratory/hardware evidence available                                                                                                                                                       |
| Capacity/security/production readiness     | Targets and release criteria only; no benchmark, audit or production claim                                                                                                                                |

When a gate completes, replace its status with immutable build/run references and
observed outcomes. Never mark a requirement implemented because its documentation,
interface, generated schema or unit-test fixture exists.

## 3. Decision ownership and readiness

Confirmed user decisions: greenfield; Go/protobuf/sqlc; separate agent; single-tenant
single-host-capable backend; desktop-first plus servers; connected plus air-gapped;
capability-gated destructive actions plus physical qualification; maintained automation,
hooks and production-quality engineering; independent specification review before
product implementation.
The review clarification also confirmed both device/person entitlements; all proposed
core, SUSE enterprise, legacy and rolling/immutable families; Keycloak/Entra/Okta/Google;
and built-in graphical remote assistance. These are launch requirements, not optional
expansion ideas. Their wider provider and qualification cost cannot be replaced with
inventory-only support or a generic mutable-package adapter.

Engineering defaults selected for review: modular monolith; PostgreSQL/pgx/sqlc;
Connect; OIDC with SCIM and brokered SAML; native providers; SQLite agent journal;
separated executor/session processes; TUF updates; QEMU/libvirt/openQA laboratory;
no mandatory broker/cache or Kubernetes. Security findings may change these choices
before implementation. Package/library versions are pinned at G1 after compatibility
and maintenance checks, not invented here.

### Decisions needed before affected gates

| Decision                                              | Proposed default                                                                                                              | Gate / owner                                                                         |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Distro image/snapshot selection                       | Launch families confirmed in verification; acquire/pin each exact licensed image and native-management recipe                 | Before its G2/G3 adapter and release claim; engineering/lab owner                    |
| Hardware qualification and destructive-test consent   | Named sacrificial x86_64 and applicable aarch64 TPM/storage machines, firmware/media inventory, out-of-band recovery          | Before high-risk implementation/claims in G7; product/security/lab owner             |
| Identity integration access and mappings              | Keycloak/Entra/Okta/Google confirmed; immutable correlation, authoritative-directory freshness and least-privilege API access | Keycloak in G1; actual external tenants before G5 certification; security/operations |
| Remote-assistance feasibility                         | Built-in confirmed; portal/PipeWire/WebRTC and local TURN, visible consent, no default recording or unattended access         | Prove oldest supported sessions before G4/G5; engineering/security                   |
| Server workload safety                                | Typed health/inhibitor checks, maintenance groups and availability budgets; external orchestrator approval when required      | Before G4; product/operations                                                        |
| Distribution license, namespace and signing ownership | Private `lindm` Go module until owner-controlled public namespace is assigned; no public license assumed                      | Before publication/redistribution, not local G1 development; product/legal           |
| Retention, recovery key custody and capacity          | Proposed budgets in operations; external/offline-compatible key custody where required                                        | Before schema retention/recovery design and G6/G8; product/security/operations       |

Questions answerable from a repository, standard or experiment are engineering work,
not requests for the owner to research. Product tradeoffs are raised with concrete
options. Independent reviewers identify missing decisions and contradictions; their
findings are resolved into the main documents rather than left as parallel plans.

## 4. Review and acceptance protocol

Independent reviewers cover (1) commercial product scope and ambiguity, (2) protocol,
authorization, endpoint/security and destructive safety, and (3) deployment/air-gap,
scaling, distro/lifecycle testing and developer automation. Reviewers work read-only;
one integration owner edits the specifications to prevent conflicting fixes.

A finding records severity, exact location, failure scenario, proposed correction,
whether it blocks implementation or only its later gate, and who owns the decision.
Resolve factual/design gaps directly. Ask the owner only for materially different
product tradeoffs. Preserve a concise disposition ledger and amend requirements/tests
for accepted findings. Do not treat lack of reviewer feedback as proof of correctness.

The first three independent reviews produced ten accepted findings: two product,
six security/protocol and two operations/testing gaps. Three follow-up reviews
confirmed the main corrections and found one shared residual broker-freshness gap,
also corrected. All eleven corrections and their evidence obligations are tracked
in [review dispositions](review-dispositions.md).

G0 is ready only when the independent review has been reconciled and the first-slice
contract has no unresolved correctness/security ambiguity. Hardware/enterprise access
may remain a clearly named later gate, but cannot be silently waived at launch.
