# Rollout flow: one reviewed "Roll out" action

Status: implemented design note (owner pass 2, 2026-10-12). It records why the
console's rollout journey changed and which guarantees it keeps.

## Problem

Before this change, rolling a profile version out took four separate jobs:

1. plan a staged rollout (`PutRollout`), which only froze cohort membership;
2. save a reviewed assignment (`SaveTargetAssignmentImpact`), which only changed
   the catalog ("Saving records this assignment only");
3. inspect every device's saved settings (`PreviewTargetAssignments`);
4. activate each device's exact preview (`ActivateTargetPreview`), plus one
   independent approval per device whenever a resource adopts existing native
   state (`OWNERSHIP_MODE_APPROVED_ADOPTION`, the only mode qualified for
   `SYSCTL` and `PASSWORD_POLICY`).

Promotion froze the next stage but activated nothing, so staged rollouts never
reached a device on their own. `lindmctl apply` could not apply adoption-only
kinds declaratively, because each device's activation needed a separate approval
that drifted on every promotion.

## Model

An administrator picks a profile version and a target, optionally adds stages,
reviews the impact, and presses **Roll out**. That single request
(`StartRollout`) binds:

- the exact reviewed impact report (`preview_id`, `review_sha256`) and assignment
  proposal with its expected catalog revision;
- the rollout plan (`RolloutSpec`: name, salt and stages; every stage cohort is
  the assignment target);
- a **per-device plan**: for every device included by the review (and every
  device whose settings the proposal removes), its enrollment generation, the
  digest of its reviewed proposed resolution (the same `resolution_sha256` a
  per-device preview computes), and whether that change adopts existing native
  state. The review names which profile currently manages each replaced setting,
  including a direct per-device assignment, so nothing is removed silently.

If approval is needed (a planned device adopts existing state, or authorization
policy requires approval for `resources.assign`), the rollout is stored as
**awaiting approval**. Neither the assignment nor any stage membership exists
yet, so no device's resolution or dispatch changes. The requester creates one
ordinary approval request whose payload is the exact `StartRolloutRequest`
(action `resources.rollout`). The approver sees the rollout's name, version,
target, device counts and every adoption ("adopts existing kernel.kptr_restrict"),
and approves once.

The exclusive `rollout-promoter` job then performs the rollout under the
creator's fresh, unrestricted `resources.assign` authority:

1. **Start.** Approved: it consumes the approval (two distinct humans, versions
   unchanged, unexpired), saves the reviewed assignment (with `rollout_id`) under
   the reviewed expected revision, and freezes stage 1. A changed assignment
   revision ends the rollout as `assignment_changed`; it is never merged.
   Rejected or expired approvals end the rollout visibly; nothing was applied.
2. **Activate per stage.** For each admitted, still-pending planned device (at
   most 50 per tick), it creates a fresh creator-bound per-device preview through
   the normal `Preview` path and checks:
   - same enrollment generation as planned;
   - `resolution_sha256` equal to the reviewed per-device digest.

   On a match it activates **that exact preview** through the normal `Activate`
   path (input-digest, expiry and unknown-membership fences unchanged). Adoption
   heads record the rollout's consumed approval as `adoption_approval_id`, which
   is only possible because the approved plan contained this exact adoption for
   this device.

3. **Promote.** Existing health/soak gates, failure budgets and creator
   re-authorization are unchanged. A promotion freezes the next stage, whose
   devices are then activated by step 2.

## Binding guarantees kept

- Every device head is still exactly one immutable per-device preview,
  re-evaluated against the same fences as a manual activation.
- A device whose preview no longer equals its reviewed change (another
  assignment, profile, group or rollout changed, the device re-enrolled, a
  profile was assigned directly on the device after the review, or a
  resolution became blocked) is **paused for re-review**: the device is marked
  `needs review` with the reason, and it is never silently applied. Other devices
  continue. Rolling out again (a new review) supersedes the remaining devices.
- A review says which devices' direct per-device assignments the change
  replaces. A declarative `apply` whose definition is unchanged never replaces
  them; changing the declaration does, after review.
- A device whose settings came from a rollout names those profile versions and
  the rollout's reason ("From rollouts: …"), never "profile removed".
- Declarative single-stage rollouts do not pause on device failures: a pause
  would withhold remediation from every device of a baseline, and one stage has
  no successor to protect. Failures are reported per device.
- Devices that join the target after the review are not in the plan; they are
  reported as not planned, never activated by this rollout.
- An adoption is applied only to devices whose reviewed plan contained it, under
  an approval that bound the whole plan digest.
- Lost creator authority pauses the rollout (`rollout_authorization_denied`);
  health budgets pause it as before. Pause is a secondary action; Resume requires
  passing gates.

## Progress

`RolloutState` reports live per-device results: applied (verified healthy on the
current head), failed, in progress (activated or admitted but not yet verified),
waiting for a later stage, and needs review, from rollout member health and the
per-device plan, not from saved counts. `ListRolloutDevices` pages the rows.

## Declarative apply

`lindmctl apply` reviews each declared assignment's impact and starts a rollout
when the definition changed or any device would change. When approval is required
it creates the rollout approval and reports the assignment as `pending` with the
approval id; it never fails for it. An unchanged declaration whose rollout is still
admitting devices is `unchanged` (with its progress), and one awaiting approval or
paused stays `pending`; neither forks a second rollout. A declared assignment that
no enrolled device matches is saved without a rollout; a later apply rolls out the
devices that come to match it, after reviewing them.

## Known costs

- One rollout per assignment: an organization with four adoption assignments
  produces four approvals.
- Rollout-bound dispatch takes the exclusive targeting fence (see architecture
  §targeting). Every console rollout is rollout-bound, so large single-stage
  rollouts are serialized at dispatch until that fence is qualified at fleet scale.
- The current value of an adopted setting is shown only when the device has
  already reported it; the server never invents it.
