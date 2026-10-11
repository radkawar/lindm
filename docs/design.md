# lindm design point of view

**DRAFT. Owner to edit.** This is the working design contract, not a claim that
current screens meet it. [Engineering](engineering.md#frontend-structure-and-framework)
remains binding for security, accessibility and implementation.

## An operator's workbench, not a fleet scoreboard

We build for the IT administrator keeping Linux laptops usable and company servers
predictable: interrupted by a locked-out employee, responsible for a patch window,
and accountable for what actually happened. They may have mixed distributions,
spotty connectivity or no Internet. They need an answer they can defend, not another
place to watch numbers. The employee on the other end is a person, not a remote target.

lindm should feel like a calm, well-kept maintenance bench: precise, compact,
legible, and ready for the next job. Put the exception and its evidence together.
Let an administrator finish a decision and leave. A green enrollment badge is not
a healthy machine; an accepted command is not a completed change.

Every screen must answer, in this order:

1. **What changed?** Show the latest observation or recorded action and when it was
   received. Say when history is unavailable; never manufacture a trend.
2. **What needs me?** Name the decision and its target. If nothing in this view
   needs action, say so with the scope and freshness of that statement.
3. **What happens if I act?** Name the effect, timing, consent or approval, and
   what remains uncertain. Link directly to the relevant device, review or action.

## Refusals

- No generic card grids where unrelated numbers compete equally. Group by the
  operator's job; use rows for comparable records and a clear reading order.
- No metric without a decision and a route to its evidence or action. OS mix is
  supporting context, not the headline. No dashboard nobody acts on.
- No “how this works” essays on working screens. One necessary helper sentence;
  optional explanation in a disclosure. Safety warnings remain visible.
- No raw IDs, enum names or protocol language in primary text. Hostnames, people,
  observed effects and times first; copyable diagnostics in Details.
- No “Manage your…”, “Welcome to…”, “Lorem” or “Click here”. No congratulatory
  health claims, decorative urgency, or reassuring zeros after a failed read.

## Evidence and interaction

Write “Inventory received 12 minutes ago. Request fresh inventory” rather than
“Device healthy.” Write “Request accepted. Waiting for the device” rather than
“Fixed.” Unknown, unsupported, stale, failed and empty are different states.
Every state names the reported cause and the remedy; when the cause is not known,
say that and give a useful next investigation instead of inventing one.

There is always an obvious next action, or an explicit reason to wait. Give the
current decision visual priority, not every available command. Keep secondary
operations reachable. A disabled control explains its prerequisite. Preserve
keyboard operation, visible focus, and context after a dialog closes.

Before destructive confirmation, show **blast radius**: named device(s) or count,
exact selected storage target when relevant, affected users/data/access, whether
reversible, and approval/consent requirements. A generic “Are you sure?” fails.
Do not hide scope in Details. Preserve typed confirmation and exact-request recovery;
never invite a new request when the previous outcome is uncertain.

Remote assistance starts with the person, their consent and the support reason.
Waiting, viewing, controlling and ended are unmistakably different. Ending must
be easier to find than advanced controls. An ended session is a record, not a live
control panel; never imply an old permission still grants access.

## Visual editing, beyond the component preset

- **Type:** bundled IBM Plex Sans; page title 24px desktop / 20px mobile, section
  title 16px semibold, body and controls 14px, supporting metadata 12px minimum.
  Sentence case. Tabular numerals for comparisons; monospace only for technical
  values. Long hostnames wrap, never displace the action.
- **Density:** one clear decision band, then evidence, then optional detail.
  Compact rows and 16–24px section spacing beat repeated padded boxes. On 390px,
  stack in decision order; do not shrink type or hide consequences to fit.
- **Colour:** blue means action or selection; green means the named condition is
  confirmed; amber means attention/uncertainty; red means failure or destructive
  effect; neutral means inactive/unknown. Always pair colour with words. Charts
  stay neutral and retain exact text. Light and dark are equally designed.
- **Motion:** only explain a transition or pending work; keep it brief (roughly
  100–200ms), respect reduced motion, and never animate counts into apparent facts.
  No decorative chart entrances, pulsing urgency, or moving targets under a pointer.
- **Empty/error:** name what is absent and why, with a scoped next step. “No
  devices matched this filter. Clear filters” is useful. “No data” is not.
  Failed reads retain their error and retry action, never a happy empty state.

## Current-console editing examples

These observations come from the synthetic **ui-review fixture**, not live fleet
or native-machine evidence. Baseline: `/tmp/uireview-full-8/index.html`; screenshots
below are in its `screenshots/` directory. Retain them with the before/after review.

| Surface and screenshot                                                   | Keep                                                                            | Edit, not just polish                                                                                                                                                                                                     |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dashboard, `dashboard-light-desktop-full.png`                            | Timestamped totals, linked approval review, separate unchecked-device count.    | Four equal metric cards and three equal charts bury the approval decision. “No findings” beside seven unchecked devices invites false reassurance. Lead with reviewable work; put coverage uncertainty beside findings.   |
| Device, `devices-deviceid-overview-light-desktop-full.png`               | Hostname first; observed inventory time; explicit lock warning and undo advice. | A long uniform field grid repeats hostname/compliance and gives missing CPU the same weight as contact and encryption. Lead with the device's present situation and next investigation; keep full inventory in Inventory. |
| Assistance, `devices-deviceid-assistance-sessionid-dark-mobile-full.png` | Named device, support reason, end cause, visible state independent of colour.   | Ended session still says “Leaving this page ends the session” and “Control: Granted”. Lead with who stopped it and when; label historical consent as historical; offer return to device.                                  |

## Required design review in every console landing note

Report **pass / needs owner decision / not applicable (why)** for each item:

- Decision: what changed, what needs me, and consequences of the primary action.
- Evidence: scope/freshness, unknown/error states, no fabricated health or success.
- Restraint: no inert metrics, generic card wall, essay, jargon or exposed raw IDs.
- Safety: visible blast radius; consent, authorization and ambiguous outcomes intact.
- Craft: typography/density, semantic colour, reduced motion, keyboard, narrow screen,
  light/dark, empty/error and long-content states.
- Editing: before/after screenshot links, automated ui-review evidence, and owner
  edit-sheet annotations translated into named tasks with acceptance criteria.

Automation checks structure and obvious regressions, not taste or operator value.
A green report is the start of the **human editing pass**, not design approval.
Review the contact sheet and per-screen questions; the owner marks what to remove,
reorder or rethink. Carry unresolved annotations as explicit tasks, never silently
mark them approved. New interface proposals stay in [owner-selection concepts](design-ideas.md),
not production routes, until selected.
