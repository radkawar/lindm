# Linux fleet interface ideas

Status: **DRAFT, owner selection only**. These are four alternative interaction
mechanisms, not an implementation commitment or new production routes. All names,
counts, times and outcomes in the linked drawings are illustrative specimens,
not observations from the fleet. Each SVG is a static, non-interactive image with
an accessible title and description, no scripts and no remote assets.

The [product specification](product-specification.md) supplies the problems;
[engineering](engineering.md) supplies current console boundaries. “Existing” below
means a documented interface or source contract, not release qualification. None
of the proposed cross-resource projections, reservations or new records should be
assumed available from an API. Preserve scoped authorization, exact targets,
independent approval, freshness and same-request recovery for ambiguous mutations.

## 1. Evidence fork: choose the observation before the repair

[Evidence fork mockup](design-concepts/evidence-fork.svg)

Instead of presenting a red device and a repair button, let an operator place one
unresolved question between two distinguishable explanations: “the service changed”
or “our evidence stopped arriving.” Each branch names the observation that would
support it, and the operator chooses the least disruptive available evidence action.
This is a diagnostic decision instrument, not a device timeline or an inferred root
cause: no probability, automated diagnosis or green status is fabricated. The
specimen selects one inventory refresh for one workstation; acceptance leaves the
question unresolved until a matching new report arrives, and a collection error
remains an error. Existing inventory collection states, service status and
[refresh-inventory action](../web/src/features/devices/action-form.tsx) ground this
idea (P05/P07/P14). **Proposed:** saved investigation questions, operator-authored
branches and explicit links between a requested observation and the evidence that
can resolve it; no arbitrary diagnostic command or automatic repair is introduced.
**Owner question:** is choosing the next observation valuable enough for a separate
workspace, or should this be a small investigation mode on device detail?

## 2. Custody seam: negotiate a boundary between managers

[Custody seam mockup](design-concepts/custody-seam.svg)

Expose the precise seam where lindm's policy stops and a local administrator or
another manager takes over. The operator pairs a conflicting native resource with
its last lindm-applied value and its current observation, then chooses to leave it
external or begin an explicitly approved adoption review. The useful mechanism is
a field/resource custody negotiation, not a profile diff or a prediction of impact:
it separates who may write next from what value looks desirable. Unknown authors
stay unknown; a changed value never proves which other manager wrote it. Existing
[ownership policy](../api/lindm/resource/v1/common.proto) and
[inverse bindings](../api/lindm/resource/v1/plans.proto) distinguish approved
adoption, retaining configuration and restoring only owned changes (P06/P07/P16).
**Proposed:** a scoped, readable custody projection and a persisted boundary proposal;
these agent/provider contracts are not a claim that a console can currently fetch
all ownership history. Opening review changes nothing, and declining adoption does
not silently unassign policy. **Owner question:** should this primarily serve
coexistence during enrollment, or contested cleanup during offboarding?

## 3. Courier return ticket: close an air-gap exchange from both sides

[Courier return ticket mockup](design-concepts/courier-return.svg)

Treat removable-media delivery as a two-sided exchange with an explicit missing
return half, rather than a download marked complete. The sending station knows what
it exported; the isolated site knows what it verified and imported. A return ticket
would let the operator reconcile those claims without suggesting a live connection,
and choose whether to carry back confirmation or prepare a replacement delivery.
The existing [signed bundle contract](../api/lindm/bundle/v1/bundle.proto) and
[offline implementation](engineering.md#offline-bundles-g6p20) already provide
expiry, replay fencing, acquired-at advisory freshness and imports with paused
rollout proposals (P19/P20); offline enrollment also has separate import/export
steps. **Proposed:** a signed, privacy-minimized site return artifact, its trust and
replay rules, and the console exchange record. They do not exist merely because
local import audit exists. A valid import is not deployment, a returned ticket is
not fresh device evidence, and importing old advisory content never resets its age.
**Owner question:** is transport closure the missing operator decision, and what
site information may be carried back across the boundary at all?

## 4. Restart seat exchange: allocate disruption, not just time

[Restart seat exchange mockup](design-concepts/restart-seats.svg)

Represent a maintenance window as a small number of explicitly occupied disruption
seats. Operators can propose exchanging a desktop's reserved turn for another
eligible device rather than widening a deadline or restarting a whole group. Keep
server seats separate: a human preference cannot substitute for drain, health or
availability prerequisites. This is a constrained negotiation mechanism, not a
calendar or rollout progress chart. Existing
[maintenance and reboot policy fields](../api/lindm/resource/v1/software.proto)
define windows, time zones, DST handling, deferrals, inhibitors, drain policy and
availability budgets (P09/P13); these fields are not proof of an atomic reservation
service. **Proposed:** expiring server-authoritative seat reservations, a negotiated
employee preference and a revalidated exchange operation. The specimen previews a
one-for-one swap without sending a reboot; approval and fresh execution-time gates
still apply. Unknown drain or health keeps a server blocked, not tentatively safe.
**Owner question:** does negotiated desktop disruption warrant this extra mechanism,
or is a policy-defined deadline with ordinary deferrals sufficient?

## Selection and implementation boundary

Choose **one** mechanism to explore first, or reject all four. Suggested selection
criterion: name a recurring operator decision that current pages cannot resolve
without side-channel notes. Evidence fork is closest to existing console actions;
Courier return ticket addresses a distinctly disconnected workflow; Custody seam
needs trustworthy provider evidence; Restart seat exchange needs new coordination
semantics and should not be chosen for visual novelty alone.

Before implementation, the owner should identify the primary operator, one real
scenario, acceptable retained data and the backend owner for the proposed records.
A selected design must specify missing/stale/error/unauthorized states, consume-time
revalidation, approval and ambiguity recovery before any production control ships.
No diagram grants new authority or turns an unknown outcome into success.

These rough desktop compositions use the existing zero-radius visual vocabulary,
IBM Plex Sans when locally installed (otherwise a local sans-serif fallback), and
24/16/14/12 title/section/body/metadata sizing. Color is redundant with text. They
are not claims of mobile, dark-theme, keyboard or screen-reader acceptance for an
implemented UI. A selected implementation must linearize the decision before the
evidence on mobile, use semantic theme tokens, expose native keyboard controls and
focus order, and honor reduced motion. The linked descriptions provide a textual
reading of each drawing; the drawn buttons are not operable.
