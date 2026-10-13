import { ManagementCapability } from "../../gen/lindm/agent/v1/management_capability_pb";
import {
  CapabilityStatus,
  type CapabilityPolicyObservation,
} from "../../gen/lindm/agent/v1/capability_policy_pb";

// Plain-language copy for the closed management capability catalogue. Shared by
// Settings → Device capabilities, the device page and blocked profile items, so
// one capability has one name everywhere.

export const CAPABILITIES_PATH = "/settings/capabilities";

export type CapabilityCopy = {
  name: string;
  description: string;
};

// Remotely enableable values in catalogue order; policies grant only these.
export const remoteCapabilities = [
  ManagementCapability.PACKAGES,
  ManagementCapability.FILES,
  ManagementCapability.KERNEL_MODULE_BLOCKLIST,
  ManagementCapability.LOCAL_ACCOUNTS,
  ManagementCapability.FIREWALL,
  ManagementCapability.OS_UPDATES,
  ManagementCapability.KERNEL_SETTINGS,
] as const;

// Local-only values: root on the device grants them in /etc/lindm/executor.json.
export const localCapabilities = [
  ManagementCapability.PASSWORD_POLICY,
  ManagementCapability.CUSTOM_FILE_ROOTS,
] as const;

const copy: Record<ManagementCapability, CapabilityCopy> = {
  [ManagementCapability.UNSPECIFIED]: {
    name: "Unrecognized capability",
    description: "This console doesn't recognize this capability.",
  },
  [ManagementCapability.PACKAGES]: {
    name: "Software packages",
    description:
      "Install packages from the OS vendor's repositories. Remove packages from these repositories. Devices verify vendor sources before installation.",
  },
  [ManagementCapability.FILES]: {
    name: "Files in standard locations",
    description: "Sign-in messages and banners in /etc/motd.d and /etc/issue.d.",
  },
  [ManagementCapability.KERNEL_MODULE_BLOCKLIST]: {
    name: "USB and kernel module blocklist",
    description: "Block kernel modules such as USB storage from loading.",
  },
  [ManagementCapability.LOCAL_ACCOUNTS]: {
    name: "Local users and groups",
    description: "Regular local users and groups, with home directories under /home.",
  },
  [ManagementCapability.FIREWALL]: {
    name: "Firewall",
    description:
      "Firewall zones. A connectivity check reverses a change if the device loses contact with lindm.",
  },
  [ManagementCapability.OS_UPDATES]: {
    name: "OS updates",
    description: "Automatic OS update schedules and maintenance windows.",
  },
  [ManagementCapability.KERNEL_SETTINGS]: {
    name: "Kernel settings",
    description: "Only the kernel parameters a policy lists.",
  },
  [ManagementCapability.PASSWORD_POLICY]: {
    name: "Password policy",
    description: "Local password rules.",
  },
  [ManagementCapability.CUSTOM_FILE_ROOTS]: {
    name: "Files in other locations",
    description: "Managed files outside the standard locations.",
  },
};

// The executor.json field root sets on the device for each local-only value.
export const localCapabilityField: Partial<Record<ManagementCapability, string>> = {
  [ManagementCapability.PASSWORD_POLICY]: "password_provider",
  [ManagementCapability.CUSTOM_FILE_ROOTS]: "file_provider.allowed_roots",
};

export function capabilityCopy(capability: ManagementCapability): CapabilityCopy {
  return copy[capability] ?? copy[ManagementCapability.UNSPECIFIED];
}

export function capabilityName(capability: ManagementCapability): string {
  return capabilityCopy(capability).name;
}

// Reason suffixes the server uses: capability_<name>_not_enabled.
const reasonNames: Record<string, ManagementCapability> = {
  packages: ManagementCapability.PACKAGES,
  files: ManagementCapability.FILES,
  kernel_module_blocklist: ManagementCapability.KERNEL_MODULE_BLOCKLIST,
  local_accounts: ManagementCapability.LOCAL_ACCOUNTS,
  firewall: ManagementCapability.FIREWALL,
  os_updates: ManagementCapability.OS_UPDATES,
  kernel_settings: ManagementCapability.KERNEL_SETTINGS,
  password_policy: ManagementCapability.PASSWORD_POLICY,
  custom_file_roots: ManagementCapability.CUSTOM_FILE_ROOTS,
};

export function capabilityFromReason(reason: string): ManagementCapability | undefined {
  const match = /^capability_([a-z_]+)_not_enabled$/.exec(reason);
  return match ? reasonNames[match[1]] : undefined;
}

// Closed causes the executor reports for an Unavailable capability.
const unavailableCauses: Record<string, string> = {
  platform_not_qualified: "lindm hasn't qualified this on the device's OS release.",
  vendor_key_unrecognized:
    "The device lacks a recognized OS repository signing key. Restore ubuntu-keyring or fedora-gpg-keys on the device. Check lindm's support for the vendor's current key if the keyring is intact.",
  firewall_settings_missing:
    "The deployment lacks management addresses or a connectivity check for Firewall.",
  firewall_restore_unit_disabled:
    "The device configuration disables lindm-firewall-restore.service.",
  native_tool_outdated:
    "The device's system tool is too old. Fedora requires dnf5 5.4.6.0 or newer. Apply All updates through an OS update policy or Patch now. Fedora security-only updates do not update dnf5.",
};

export function unavailableCause(detail: string): string {
  return (
    unavailableCauses[detail] ?? "The device reported an unknown cause. Details contain the code."
  );
}

export const capabilityStatusLabels: Record<CapabilityStatus, string> = {
  [CapabilityStatus.UNSPECIFIED]: "Not reported",
  [CapabilityStatus.NOT_ENABLED]: "Not enabled",
  [CapabilityStatus.ENABLED]: "Enabled",
  [CapabilityStatus.LOCAL]: "Set locally",
  [CapabilityStatus.UNAVAILABLE]: "Unavailable",
};

export function reportedCapability(
  reported: CapabilityPolicyObservation | undefined,
  capability: ManagementCapability,
) {
  return reported?.capabilities.find((entry) => entry.capability === capability);
}
