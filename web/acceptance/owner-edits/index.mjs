// Owner edit pass 2026-10-12 (run 16717866-d6a9-4b6f-b59f-399eedc25b8a): one
// module per imported task. Each exports `task` (name, screenId, route,
// priority, acceptance) and `check(context)`, which asserts the task's
// acceptance criterion through the real console on the seeded demo fleet.
// Order matters: read-only checks run first; checks that request work (Refresh
// inventory) or move state run last.
import * as dashboard from "./dashboard.mjs";
import * as deviceList from "./device-list.mjs";
import * as deviceOverview from "./device-overview.mjs";
import * as deviceEncryption from "./device-encryption.mjs";
import * as deviceActions from "./device-actions.mjs";
import * as assistanceRecord from "./assistance-record.mjs";
import * as revealApproval from "./pass2-reveal-approval.mjs";
import * as advisories from "./advisories.mjs";
import * as enrollment from "./enrollment.mjs";
import * as rollouts from "./rollouts.mjs";
import * as approvals from "./approvals.mjs";
import * as audit from "./audit.mjs";
import * as wipeForm from "./wipe-form.mjs";
import * as pass2Bug4 from "./pass2-bug4-enrollment-stale.mjs";
import * as pass2Bug5 from "./pass2-bug5-token-cancel.mjs";
import * as pass2Bug6 from "./pass2-bug6-install-command.mjs";
import * as pass2SafetyUndo from "./pass2-safety-undo.mjs";
import * as pass2SafetyAssistance from "./pass2-safety-assistance.mjs";
import * as pass2SafetyReveal from "./pass2-safety-reveal.mjs";
import * as accounts from "./accounts.mjs";
import * as authorization from "./authorization.mjs";

export const ownerEdits = [
  dashboard,
  deviceList,
  deviceOverview,
  pass2SafetyUndo,
  deviceEncryption,
  deviceActions,
  assistanceRecord,
  revealApproval,
  advisories,
  enrollment,
  pass2Bug5,
  rollouts,
  accounts,
  authorization,
  approvals,
  audit,
  wipeForm,
  // Creates a one-time code, then approves the seed's pending enrollment.
  pass2Bug6,
  pass2Bug4,
  pass2SafetyAssistance,
  pass2SafetyReveal,
];
