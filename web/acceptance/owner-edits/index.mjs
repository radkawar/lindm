// Owner edit pass 2026-10-12 (run 16717866-d6a9-4b6f-b59f-399eedc25b8a) and later
// owner reports: one module per imported task. Each exports `task` (name,
// screenId when it came from the edit sheet, route, priority, acceptance) and
// `check(context)`, which asserts the task's acceptance criterion through the
// real console on the seeded demo fleet.
// Order matters: read-only checks run first; checks that request work (Refresh
// inventory) or move state run last.
import * as dashboard from "./dashboard.mjs";
import * as deviceList from "./device-list.mjs";
import * as deviceListSearch from "./device-list-search.mjs";
import * as deviceOverview from "./device-overview.mjs";
import * as deviceEncryption from "./device-encryption.mjs";
import * as recordedChoices from "./recorded-choices.mjs";
import * as deviceActions from "./device-actions.mjs";
import * as assistanceRecord from "./assistance-record.mjs";
import * as revealApproval from "./pass2-reveal-approval.mjs";
import * as assistanceGate from "./assistance-gate.mjs";
import * as advisories from "./advisories.mjs";
import * as advisoriesSources from "./advisories-sources.mjs";
import * as advisorySeverity from "./advisory-severity.mjs";
import * as enrollment from "./enrollment.mjs";
import * as agentRepository from "./agent-repository.mjs";
import * as rollouts from "./rollouts.mjs";
import * as profiles from "./profiles.mjs";
import * as profileEditor from "./profile-editor.mjs";
import * as profilePublish from "./profile-publish.mjs";
import * as pass2Bug7DialogScrolled from "./pass2-bug7-dialog-scrolled.mjs";
import * as pass2Bug8PickerSidebar from "./pass2-bug8-picker-sidebar.mjs";
import * as pass2P27StackedDialogs from "./pass2-p2-7-stacked-dialogs.mjs";
import * as pass2EmptySetting from "./pass2-bug1-empty-setting.mjs";
import * as pass2SafetyApprovals from "./pass2-safety-approvals.mjs";
import * as secrets from "./secrets.mjs";
import * as secretReveal from "./secret-reveal.mjs";
import * as approvals from "./approvals.mjs";
import * as audit from "./audit.mjs";
import * as pass2RestartDelay from "./pass2-bug2-restart-delay.mjs";
import * as pass2ReviewPreflight from "./pass2-bug3-review-preflight.mjs";
import * as pass2ApprovalPreflight from "./pass2-p2-5-approval-preflight.mjs";
import * as commandPalette from "./command-palette.mjs";
import * as commandPaletteTyping from "./command-palette-typing.mjs";
import * as auditLogPass2 from "./audit-log-pass2.mjs";
import * as wipeForm from "./wipe-form.mjs";
import * as customAttributeNames from "./custom-attribute-names.mjs";
import * as pass2Bug4 from "./pass2-bug4-enrollment-stale.mjs";
import * as pass2Bug5 from "./pass2-bug5-token-cancel.mjs";
import * as pass2Bug6 from "./pass2-bug6-install-command.mjs";
import * as pass2SafetyUndo from "./pass2-safety-undo.mjs";
import * as pass2SafetyAssistance from "./pass2-safety-assistance.mjs";
import * as pass2SafetyReveal from "./pass2-safety-reveal.mjs";
import * as accounts from "./accounts.mjs";
import * as authorization from "./authorization.mjs";
import * as pass2AssignmentProgress from "./pass2-assignment-progress.mjs";
import * as pass2SecretReveal from "./pass2-secret-reveal.mjs";
import * as pass2SafetyWipe from "./pass2-safety-wipe.mjs";
import * as pass2RevokedDevice from "./pass2-bug9-revoked-device.mjs";
import * as fleetPass2 from "./fleet-pass-2.mjs";
import * as pass2P2Approvals from "./pass2-p2-approvals.mjs";
import * as groups from "./groups.mjs";
import * as groupsDynamicCreate from "./groups-dynamic-create.mjs";

export const ownerEdits = [
  dashboard,
  deviceList,
  deviceListSearch,
  deviceOverview,
  pass2SafetyUndo,
  deviceEncryption,
  recordedChoices,
  pass2RevokedDevice,
  deviceActions,
  assistanceRecord,
  revealApproval,
  assistanceGate,
  advisories,
  advisoriesSources,
  advisorySeverity,
  enrollment,
  pass2Bug5,
  pass2SafetyApprovals,
  agentRepository,
  rollouts,
  accounts,
  authorization,
  profiles,
  profileEditor,
  // Read-only; the wipe form case needs the seed's stale storage, so before wipeForm.
  pass2Bug7DialogScrolled,
  pass2Bug8PickerSidebar,
  pass2P27StackedDialogs,
  pass2EmptySetting,
  secrets,
  secretReveal,
  approvals,
  // Proposes a risk acceptance and a revocation, then withdraws both.
  pass2P2Approvals,
  audit,
  auditLogPass2,
  groups,
  pass2RestartDelay,
  // Need the route device's inventory stale, so they precede the wipe check's refresh.
  pass2ReviewPreflight,
  pass2ApprovalPreflight,
  commandPalette,
  commandPaletteTyping,
  wipeForm,
  pass2SafetyWipe,
  fleetPass2,
  // Creates the "Cost center" custom attribute.
  customAttributeNames,
  // Creates a one-time code, then approves the seed's pending enrollment.
  pass2Bug6,
  pass2Bug4,
  pass2SafetyAssistance,
  pass2SafetyReveal,
  pass2SecretReveal,
  // Publishes one new, never-assigned profile.
  profilePublish,
  // Creates a dynamic group.
  groupsDynamicCreate,
  // Changes and restores the route device profile; keep last.
  pass2AssignmentProgress,
];
