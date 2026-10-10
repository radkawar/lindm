# Resource core: Phase 2 cutover handoff

## Boundary established by Phase 1

The catalog and control plane use `lindm.resource.v1` closed kinds, canonical
`ResourceRef` identities, heterogeneous `lindm.policy.v1.ResourceProfile` revisions,
typed dependencies and resource ownership/verification metadata. Admin publication,
assignment and state methods are generic. Device-targeted/group-targeted assignment
resolution and rollout snapshots are retained independently of catalog publication.
The exact resolved resource bytes and provenance are part of the retained preview.

Phase 1 intentionally retains the existing signed service intent, challenge, start
grant, attestation and protected agent journal. It does not change executor,
journal or service-provider behavior. `internal/device/resource_rows.go` contains
the explicit service-only execution translation. Other kinds, unsupported
verification requests, adoption/restoration operations and missing capability
qualification are visible unsupported states; they cannot fall through to systemd.

## Files and contracts to consume

- `api/lindm/resource/v1/`: twenty-kind registry; typed desired, observation, plan,
  checks, artifact manifests, canonical references and ownership metadata.
- `internal/resource`: capability derivation, canonical identity and closed
  validation, typed cross-kind claims and domain-separated resource digests.
- `api/lindm/policy/v1/profile.proto`, `internal/policy`: immutable profiles,
  canonical set handling, priority/merge/conflict and dependency resolution.
- `api/lindm/admin/v1/assignments.proto`: generic assignment/resource state,
  service-specific signed history retained only for this phase, and release rows.
- `db/migrations/00004_profiles.sql`, `00005_resource_dispatch.sql`:
  `profiles`, `profile_revisions`, `profile_resources`, `profile_dependencies`,
  `profile_requests`; `resource_assignments`, `resource_assignment_heads`,
  `resource_assignment_resources`, `resource_sequences`, `resource_actions`,
  `resource_releases`. Sequence keys are generation, resource kind and canonical
  key. Source-profile resource UUIDs are not cross-profile identity.
- `db/migrations/00010_targeting.sql`, `internal/targeting`: dynamic typed AST,
  pinned membership/preview snapshots, target assignments and ring cohorts.
  Static groups/labels remain the existing RBAC-owned concepts.
- `internal/device/resource_targeting.go`: generic resolution projection and
  atomic activation of exact preview bytes. Effective snapshot resource UUIDs
  are deterministically derived from canonical resource-ref digests.
- `internal/device/service_dispatch.go`, `service_start.go`, `service_result.go`:
  retained service-wire dispatch over generic rows. Preserve the one-open-effect
  rule, exact grant replay and fresh native compliance when replacing this wire.

## Authority and transaction invariants

`resources.assign` replaces the old service-only permission. Direct assignment and
preview activation both honor configured two-human approval policy. Preview
activation binds device ID, preview ID/digest and mutation ID; the approval ID is
excluded from its canonical request digest. The activating human adopts the exact
resolved snapshot, and their fresh authorization/version/scope fences remain
mandatory at dispatch/start. Publishing a profile or editing a target definition
is not device activation.

Lock fresh principals before the targeting serialization fence, then device/head
and action rows. Preview/cohort evaluation uses a repeatable-read database
snapshot. New effect authority rechecks current targeting, exclusions, generation,
head and rollout pause; a previously granted unknown effect is not replaced.
Automatic pause updates must commit even when execution is withheld. Authenticated
resource results update rollout health only for the current generation/head;
uncertain outcomes and expired verification remain unknown rather than healthy.

Resource verification freshness is bounded by both assignment recheck policy and
the resource's `verification.max_age_seconds`. SQL projections, dispatch scheduling,
console state and rollout health must continue to agree on that boundary.

## Required atomic agent cutover

Once DeviceActions has landed, replace service-specialized signed execution,
transport, trust validation, provider dispatch and journal records as one compiling
set. The generic target must bind kind/ref, operation, exact desired/plan digests,
capability, generation, boot/incarnation, trust/authorization versions and a fresh
one-use start challenge. Derive capability from the kind registry; no arbitrary
capability string, command, path or plugin fallback is admitted.

Remove the Phase 1 service translation rather than retaining dual execution
aliases. Migrate every agent/server/lab caller and generated descriptor together.
Historical signed service bytes must not be rewritten as though signed under a
new generic envelope domain. Retained initialized state needs an explicit stopped,
fenced, integrity-checked migration; a new disposable fixture may be enrolled
cleanly but an enrolled journal must never be reset silently.

## Ownership-safe release

Phase 1 records release requests when a resource disappears from a desired head.
Existing service effects lack a pre-management ownership baseline and remain
`baseline_unknown` with `ownership_baseline_unavailable`; no inverse value or
native cleanup is invented. Restoration must bind the protected executor ledger,
first observed baseline, every affected dimension and proof that no foreign actor
subsequently changed it. Ambiguous custody remains a visible release conflict.
The server never supplies purported old native values as authority to restore.

Implement operation-specific capability reporting and actual ownership evidence
before enabling release/adoption. Preserve unrelated units, links, memberships,
configuration and application data. A provider's process exit is not verification.

## Qualification boundary

Phase 1 schema coverage is not native-provider qualification. Preserve all
per-kind/per-platform launch gates in `docs/verification.md`, including Atomic/Nix
transaction semantics, independent native oracles, network rollback, secret custody
and physical safety evidence. The existing Ubuntu 24.04 signed-service dispatch
lane remains the Phase 1 end-to-end regression; Phase 2 requires separate generic
protocol/journal migration and ownership-release qualification.

## Asynchronous native package preparation

Package intent acceptance is durable before native staging starts. The executor
reserves the action lifecycle, binds the signed ownership and sequence floor, and
records `PREPARING` without a native plan, observation, challenge or start grant.
The independent native staging unit owns its signed immutable deadline, disk
quota, exact request digest and per-action protected cache. Executor restart does
not extend those limits or restart consumed native effects.

An exact later `PrepareResourceExecution` call performs one bounded readiness
poll. Only a validated ready plan is journaled with a fresh challenge of at most
thirty seconds; original acceptance, ownership and intent expiry remain unchanged.
Ordinary RPC deadlines and the executor sandbox remain unchanged. Systemd
preparation retains its immediate lifecycle.

Cancellation, expiry and invalid authority stop only owned staging. A terminal
`ResourcePreparationOutcome` explicitly distinguishes a preparation failure with
no native observation from native execution evidence. Cancellation before delivery
persists a generation-bound action/digest denial tombstone, returning
`never_prepared` rather than fabricating historical acceptance or a native result.
Late preparation cannot bypass that tombstone. Queued or running effects cannot be
canceled through this preparation-only API, and `RUNNING` recovery is read-only.

The wire contract is in `api/lindm/agent/v1/service_execution.proto`; executor
admission/polling is in `internal/agent/executor/service_preparation.go`; durable
fences and reservations are in `internal/agent/journal/resource_actions_linux.go`
and `resource_preparation_linux.go`. Their deterministic regression tests cover
restart, cancellation, expiry, evidence shape and digest corruption. These tests
are authored contract coverage, not evidence that a native distro lane passed.

## Read-only resource findings

A validated no-effect plan completes without a challenge, start grant, worker
mutation or `started_at`. Its authenticated status explicitly sets `read_only`.
`CONVERGED` is successful verification. `DRIFTED` and `UNKNOWN` remain durable
`FAILED` findings with `POSTCONDITION`; a provider's typed nonconvergence error
does not discard valid evidence or turn it into success. Unrelated native errors,
missing observations and mismatched plan digests cannot produce accepted findings.

Read-only release may finish successfully as `NOT_APPLICABLE`, which is not a
claim that the removed requirement converged. Encryption compliance release does
not construct an ownership inverse or change storage. Server interpretation still
binds the original signed release operation and distinguishes this evidence from
compliance success.

The journal's `read_only_terminal` marker covers both successful and unsuccessful
no-effect findings. Their bounded historical retention preserves current sequence
floors and does not turn them into ownership mutation history. Native effect
failures retain their existing protected-history rules. Validation is shared in
`internal/resource/readonly.go`; executor and journal regression tests cover signed
read-only outcomes, restart, bad evidence, retention and clock rollback.
