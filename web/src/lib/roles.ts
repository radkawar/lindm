// SPDX-License-Identifier: Apache-2.0

// Built-in role identifiers read as sentence-case names in primary text; custom
// role names are the administrator's own words and are shown unchanged.
const builtInRoleLabels: Record<string, string> = {
  owner: "Owner",
  admin: "Admin",
  operator: "Operator",
  helpdesk: "Helpdesk",
  auditor: "Auditor",
};

export function roleLabel(role: string): string {
  const trimmed = role.trim();
  if (!trimmed) return "No role";
  return builtInRoleLabels[trimmed] ?? trimmed;
}
