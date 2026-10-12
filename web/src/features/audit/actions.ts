import actionNames from "./action-names.json";

// Administrator-facing names for recorded audit action codes. action-names.json
// names every kind the server records (internal/auditkind; a Go test fails on a
// missing name). The code itself stays in Details.
const ACTION_NAMES: Readonly<Record<string, string>> = actionNames;

// What a device action does, by capability, for "Requested device action: Restart".
const DEVICE_ACTION_KINDS: Readonly<Record<string, string>> = {
  "device.escrow-rotate.v1": "Recovery key rotation",
  "device.tpm2-bind.v1": "TPM 2.0 unlock binding",
  "device.lock-sessions.v1": "Lock sessions and accounts",
  "device.release-lock.v1": "Undo account lock",
  "device.quarantine.v1": "Network quarantine",
  "device.release-quarantine.v1": "Release quarantine",
  "device.crypto-erase.v1": "Wipe encrypted storage",
  "device.sanitize.v1": "Sanitize offline disk",
  "device.restart.v1": "Restart",
  "device.shutdown.v1": "Shut down",
  "device.refresh-inventory.v1": "Inventory refresh",
  "device.local-admin-rotate.v1": "Local admin password rotation",
  "device.patch-now.v1": "Patch now",
};

export function auditActionLabel(action: string, deviceActionCapability = ""): string {
  const code = action.trim();
  if (!code) return "Not recorded";
  const name = ACTION_NAMES[code] ?? unmappedName(code);
  const kind = DEVICE_ACTION_KINDS[deviceActionCapability.trim()];
  return kind ? `${name}: ${kind}` : name;
}

// Only events recorded by an older or newer server reach this: split
// snake_case, dots and CamelCase method names into words.
function unmappedName(code: string): string {
  const words = code
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[._]+/g, " ")
    .toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}
