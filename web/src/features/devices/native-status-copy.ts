// SPDX-License-Identifier: Apache-2.0

const actionReasons: Record<string, string> = {
  target_not_allowlisted: "The device configuration does not allow actions on this storage target.",
  operation_not_qualified: "The device configuration does not allow this storage action.",
  independent_owner_recovery_required:
    "An independent owner recovery key must be present before this action.",
  no_free_keyslot: "The encrypted volume has no free key slot. Review its keys before retrying.",
  no_free_token:
    "The encrypted volume has no free unlock token. Review its tokens before retrying.",
  luks2_json_area_unknown:
    "The device could not determine the encrypted volume's metadata capacity.",
  luks2_metadata_space_exhausted:
    "The encrypted volume has no space for the required TPM unlock metadata.",
  retirement_requires_managed_slot: "Only a recovery key slot managed by lindm can be retired.",
  tpm2_resource_manager_unavailable: "The device cannot access its TPM 2.0 resource manager.",
  systemd_cryptenroll_unavailable: "The device cannot run systemd-cryptenroll.",
  systemd_cryptenroll_tpm2_binding_unsupported:
    "The installed systemd-cryptenroll does not support TPM 2.0 binding.",
  sanitize_requires_unencrypted_media: "This wipe method requires an unencrypted disk.",
  overwrite_requires_rotational_media: "Overwrite is supported only on a rotating disk.",
  nvme_method_or_scope_unsupported: "The NVMe device does not support this wipe method or scope.",
  session_lock_not_qualified: "The device configuration does not allow session locks.",
  quarantine_not_qualified: "The device configuration does not allow network quarantine.",
  power_actions_not_qualified: "The device configuration does not allow remote power actions.",
  patch_now_not_qualified: "The device configuration does not allow immediate updates.",
  management_endpoint_not_pinned:
    "A selected management IP is not approved in the device configuration.",
  all_management_endpoints_required:
    "Include every management IP approved in the device configuration.",
  local_admin_account_not_allowlisted:
    "The device configuration does not allow changes to this local account.",
  local_admin_root_refused: "lindm cannot change the root account through this action.",
  local_admin_account_missing: "The selected local account does not exist on the device.",
  unknown_action: "The device does not recognize this action.",
};

export function nativeActionReason(reason: string): string {
  return (
    actionReasons[reason] ??
    (reason
      ? "The device reported an unsupported condition. Open Details for the reason code."
      : "The device did not report a cause.")
  );
}

const updateReasons: Record<string, string> = {
  update_helper_state_unavailable:
    "The device could not read its update helper state. Check the device before retrying.",
  native_transaction_incomplete:
    "The native package update did not finish. Review the last update failure before retrying.",
  native_update_failed: "The native package update failed. Review the last update failure.",
  verified_transaction_expired:
    "The approved update expired before it finished. Check the installed version before retrying.",
  update_rejected_or_incomplete:
    "The update was rejected or did not finish. Review the last update failure.",
  update_checkpoint_failed:
    "The device could not save its update state. Check the device before retrying.",
};

export function agentUpdateReason(reason: string): string {
  return (
    updateReasons[reason] ??
    (reason
      ? "The device reported an update condition. Open Details for the reason code."
      : "No reason reported.")
  );
}

const updateStates: Record<string, string> = {
  disabled: "Off",
  idle: "Waiting for the next check",
  checking: "Checking for updates",
  staged: "Update prepared",
  applying: "Installing update",
  installing: "Installing update",
  installed: "Installed",
  rejected: "Rejected",
  recovery_required: "Needs recovery",
  incomplete: "Not completed",
  no_update: "No update available",
};

export function agentUpdateState(state: string): string {
  return updateStates[state] ?? "Unknown";
}

export function nativeUpdateStep(step: string): string {
  const labels: Record<string, string> = {
    validation: "Validate update",
    simulate: "Check package changes",
    apply: "Install packages",
    configure: "Configure installed packages",
    recovery: "Check interrupted update",
    payload_verify: "Verify update package",
  };
  return labels[step] ?? "Not reported";
}

export function nativeVerificationEvidence(evidence: string): string {
  if (evidence === "outcome_unknown_until_contact")
    return "The device accepted the power request. Its outcome remains unknown until the device reports again.";
  // Native prose includes safety limits that must remain visible, not just codes.
  return /^[a-z0-9]+(?:_[a-z0-9]+)+$/.test(evidence)
    ? "The device reported verification evidence. Open Details for the evidence code."
    : evidence;
}
