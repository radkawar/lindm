import type { SessionPrincipal } from "../../gen/lindm/auth/v1/auth_pb";

export const permissionLabels: Record<string, string> = {
  "fleet.read": "View devices",
  "enrollment.manage": "Manage enrollment",
  "device.revoke": "Revoke devices",
  "audit.read": "View audit log",
  "execution_trust.manage": "Manage execution trust",
  "profiles.manage": "Manage profiles",
  "resources.assign": "Assign resources",
  "accounts.manage": "Manage accounts",
  "inventory.manage": "Manage inventory",
  "recovery_keys.read": "Reveal recovery keys",
  "remote_execution.run": "Run remote actions",
  "remote_assistance.run": "Run remote assistance",
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

// The server supplies effective permissions, including emergency-policy intersections.
// Visibility is only a convenience; every operation is authorized again by the server.
export function canPermission(
  principal: SessionPrincipal,
  permission: string,
  unrestricted = false,
): boolean {
  if (!principal.permissions.includes(permission)) return false;
  return (
    !unrestricted ||
    principal.bindings.some(
      (binding) => binding.permissions.includes(permission) && binding.scopes.length === 0,
    )
  );
}
