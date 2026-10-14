// SPDX-License-Identifier: Apache-2.0

const unavailableReasons: Record<string, string> = {
  patch_status_not_computed:
    "The device has not reported update status yet. Request fresh inventory after its next report.",
  patch_status_invalid:
    "The device's update status report is invalid. Request fresh inventory and check the device logs.",
  patch_status_boot_id_unavailable:
    "The device cannot identify its current startup. Request fresh inventory and check the device logs.",
  patch_status_previous_boot:
    "The update status report is from an earlier startup. Request fresh inventory.",
};

export function patchStatusUnavailableReason(reason: string): string {
  const text = Object.hasOwn(unavailableReasons, reason) ? unavailableReasons[reason] : undefined;
  return (
    text ?? "The device cannot report update status. Check Details and request fresh inventory."
  );
}

const rebootReasons: Record<string, string> = {
  policy_never: "The update policy does not schedule a reboot.",
  native_power_already_pending: "Another power action is pending on this device.",
  native_power_inhibited: "A device power inhibitor blocked the reboot.",
  reboot_deadline_elapsed: "The deadline for the reboot has passed.",
  no_window_before_deadline: "No reboot window was available before the deadline.",
};

export function patchRunRebootReason(reason: string): string {
  const text = Object.hasOwn(rebootReasons, reason) ? rebootReasons[reason] : undefined;
  return text ?? "The device reported a reboot reason. Check Details.";
}
