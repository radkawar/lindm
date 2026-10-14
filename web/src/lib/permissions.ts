// SPDX-License-Identifier: Apache-2.0

import type { SessionPrincipal } from "../../gen/lindm/auth/v1/auth_pb";

export const permissionLabels: Record<string, string> = {
  "fleet.read": "View devices",
  "enrollment.manage": "Manage enrollment",
  "device.revoke": "Revoke devices",
  "audit.read": "View audit log",
  "execution_trust.manage": "Change which signing keys devices trust for commands",
  "profiles.manage": "Manage profiles",
  "resources.assign": "Assign resources",
  "accounts.manage": "Manage accounts",
  "inventory.manage": "Manage inventory",
  "recovery_keys.read": "Reveal recovery keys",
  "remote_execution.run": "Run remote actions",
  "remote_assistance.view": "View shared screens",
  "remote_assistance.control": "Control shared screens",
  "remote_assistance.policy.manage": "Manage assistance policy",
  "remote_assistance.clipboard": "Share clipboard text",
  "remote_assistance.keyboard": "Use assistance keyboard",
  "remote_assistance.display": "Adjust shared displays",
  "remote_assistance.message": "Send assistance messages",
  "remote_assistance.files": "Transfer assistance files",
  "remote_assistance.reconnect": "Reconnect assistance sessions",
  "remote_assistance.record": "Record assistance sessions",
  "remote_assistance.recordings.read": "Play assistance recordings",
  "remote_assistance.recordings.delete": "Delete assistance recordings",
  "remote_assistance.unattended": "Request unattended assistance",
  "remote_assistance.unattended.approve": "Approve unattended assistance",
  "remote_assistance.elevation_guidance": "Guide password prompts",
  "remote_assistance.annotate": "Point and mark on shared screens",
  "remote_assistance.audio": "Hear shared sound",
  "scripts.run": "Run scripts",
  "destructive.execute": "Run destructive actions",
  "approvals.manage": "Review approvals",
  "integrations.manage": "Manage integrations",
  "release_updates.manage": "Manage updates",
  "advisory_exceptions.manage": "Manage advisory exceptions",
  "encryption.manage": "Manage encryption",
  "actions.lock": "Lock devices",
  "actions.release-lock": "Release device locks",
  "actions.quarantine": "Quarantine devices",
  "secrets.manage": "Manage secrets",
  "secrets.reveal": "Reveal secrets",
};

// The server supplies effective permissions, including emergency-policy intersections,
// and the subset it grants without a device scope (which global resources such as
// enrollment, audit, accounts and catalogs require). The console never recomputes
// either from bindings or a role table. Visibility is only a convenience; every
// operation is authorized again by the server.
export function canPermission(
  principal: SessionPrincipal,
  permission: string,
  unrestricted = false,
): boolean {
  return (unrestricted ? principal.unrestrictedPermissions : principal.permissions).includes(
    permission,
  );
}

// Permissions whose requests can reach the approval inbox, as requester or approver.
const approvalPermissions = [
  "approvals.manage",
  "device.revoke",
  "resources.assign",
  "execution_trust.manage",
  "destructive.execute",
  "recovery_keys.read",
  "remote_execution.run",
  "scripts.run",
  "secrets.reveal",
];

export function canUseApprovals(principal: SessionPrincipal): boolean {
  return approvalPermissions.some((permission) => canPermission(principal, permission));
}
