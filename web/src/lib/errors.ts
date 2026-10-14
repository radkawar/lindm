// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { ViolationsSchema } from "@bufbuild/protovalidate/gen/buf/validate/validate_pb.js";
import { DeviceActionSchema, type DeviceAction } from "../../gen/lindm/admin/v1/device_actions_pb";
import { describeViolationProto, requestProblem, type FieldError } from "@/lib/validation";
import { CapabilityStatus } from "../../gen/lindm/agent/v1/capability_policy_pb";
import { ManagementCapability } from "../../gen/lindm/agent/v1/management_capability_pb";
import type { DeviceCapabilityState } from "../../gen/lindm/admin/v1/capabilities_pb";
import {
  CAPABILITIES_PATH,
  capabilityFromReason,
  capabilityName,
  localCapabilityField,
  reportedCapability,
  unavailableCause,
} from "./capabilities";

export type RpcFailure = {
  code: Code;
  codeName: string;
  message: string;
  reason: string;
  unauthenticated: boolean;
  denied: boolean;
  ambiguous: boolean;
  // Field problems in plain words: a request the browser refused to send
  // (reason request_invalid), or the fields a server refusal names.
  fields?: readonly FieldError[];
  // The open action behind a device_action_pending refusal, when the server named it.
  blockingAction?: DeviceAction;
};

const AMBIGUOUS: Record<number, true> = {
  [Code.Canceled]: true,
  [Code.Unknown]: true,
  [Code.DeadlineExceeded]: true,
  [Code.Aborted]: true,
  [Code.Internal]: true,
  [Code.Unavailable]: true,
  [Code.DataLoss]: true,
};

// Reasons whose transport code is otherwise ambiguous but which the server
// returns only after rolling back: the request definitely changed nothing.
const DEFINITE_REASONS: Record<string, true> = { capability_policy_revision_conflict: true };

const CODE_NAME: Record<number, string> = {
  [Code.Canceled]: "Canceled",
  [Code.Unknown]: "Unknown",
  [Code.InvalidArgument]: "InvalidArgument",
  [Code.DeadlineExceeded]: "DeadlineExceeded",
  [Code.NotFound]: "NotFound",
  [Code.AlreadyExists]: "AlreadyExists",
  [Code.PermissionDenied]: "PermissionDenied",
  [Code.ResourceExhausted]: "ResourceExhausted",
  [Code.FailedPrecondition]: "FailedPrecondition",
  [Code.Aborted]: "Aborted",
  [Code.OutOfRange]: "OutOfRange",
  [Code.Unimplemented]: "Unimplemented",
  [Code.Internal]: "Internal",
  [Code.Unavailable]: "Unavailable",
  [Code.DataLoss]: "DataLoss",
  [Code.Unauthenticated]: "Unauthenticated",
};

export function toRpcFailure(error: unknown): RpcFailure {
  // A request the browser could not validate or encode never left it: a
  // definite, field-level refusal, never an ambiguous outcome or encoder text.
  const problem = requestProblem(error);
  if (problem)
    return {
      code: Code.InvalidArgument,
      codeName: CODE_NAME[Code.InvalidArgument],
      message: problem.message,
      reason: "request_invalid",
      unauthenticated: false,
      denied: false,
      ambiguous: false,
      fields: problem.fields,
    };
  const connectError = ConnectError.from(error);
  const raw = connectError.rawMessage.trim();
  const reason =
    connectError.metadata.get("Lindm-Reason")?.trim() || (/^[a-z][a-z0-9_]*$/.test(raw) ? raw : "");
  const ambiguous = AMBIGUOUS[connectError.code] === true && !DEFINITE_REASONS[reason];
  let message = raw === "" ? connectError.message.trim() : raw;
  if (message === "") {
    message = ambiguous
      ? "The server returned no result. Retry this same request before starting a new one."
      : "The server rejected the request.";
  }
  const fields =
    connectError.code === Code.InvalidArgument
      ? connectError
          .findDetails(ViolationsSchema)
          .flatMap((detail) => detail.violations.map((item) => describeViolationProto(item)))
      : [];
  return {
    code: connectError.code,
    codeName: CODE_NAME[connectError.code] ?? "Unknown",
    message,
    reason,
    unauthenticated: connectError.code === Code.Unauthenticated,
    denied: connectError.code === Code.PermissionDenied,
    ambiguous,
    blockingAction: connectError.findDetails(DeviceActionSchema)[0],
    ...(fields.length > 0 ? { fields } : {}),
  };
}

export type RpcFailurePresentation = {
  tone: "neutral" | "warning" | "destructive";
  title: string;
  message: string;
  action: string;
};

const RECOVERY_READINESS_MESSAGES: Record<string, string> = {
  device_action_recovery_readiness_missing:
    "The device has not reported recovery readiness. Refresh inventory before continuing.",
  device_action_recovery_readiness_stale:
    "Recovery readiness is stale. Refresh inventory before continuing.",
  device_action_recovery_readiness_unsupported:
    "This device does not report the required recovery capability.",
  device_action_recovery_owner_key_required:
    "Secure Boot does not enforce an enrolled owner key. Recovery sanitize requires that key.",
  device_action_recovery_artifact_required:
    "Select the configured signed recovery image to check required space.",
  device_action_recovery_artifact_unavailable:
    "The signed recovery image is unavailable. Ask an administrator to check the recovery release.",
  device_action_recovery_attestation_unavailable:
    "The device cannot prove its boot state with its TPM. lindm cannot verify recovery.",
  device_action_recovery_boot_mode_mismatch:
    "The device's boot mode changed after recovery preparation. Prepare recovery again.",
  device_action_recovery_kernel_mismatch:
    "The device's kernel changed after recovery preparation. Prepare recovery again.",
  device_action_esp_insufficient:
    "Unsupported: ESP capacity. The signed recovery image does not fit the EFI system partition. Use separately qualified external recovery media with an on-site operator. Do not remove ordinary boot files. Do not resize the ESP to bypass this gate.",
};

export function recoveryReadinessMessage(reason: string) {
  return (
    RECOVERY_READINESS_MESSAGES[reason] ??
    "lindm cannot confirm recovery readiness. Review the recorded reason before continuing."
  );
}

export function recoveryReadinessTone(reason: string): "neutral" | "warning" {
  switch (reason) {
    case "device_action_recovery_readiness_missing":
    case "device_action_recovery_readiness_unsupported":
    case "device_action_recovery_artifact_required":
      return "neutral";
    default:
      return "warning";
  }
}

const BLOCKED_REASON_LABELS: Record<string, string> = {
  secret_unavailable: "Blocked: the secret this profile uses is no longer available.",
  secret_binding_mismatch: "Blocked: the secret doesn't match what this setting expects.",
  device_encryption_key_unavailable:
    "Blocked: the device can't receive secrets yet. Wait for it to check in again.",
  secret_delivery_unauthorized:
    "Blocked: the admin who assigned this profile can no longer send secrets to this device.",
  policy_authority_changed:
    "Blocked: the admin who set this policy lost access. Set the policy again to resume.",
  escrow_unconfigured: "Blocked: the server does not provide secret storage.",
  native_package_manager_busy:
    "Another package manager was running. Nothing changed. lindm retries at the next check.",
  resource_executor_not_available:
    "lindm cannot manage this setting on devices. Remove it from the profile, or use another tool.",
  resource_ownership_operation_unavailable:
    "lindm cannot apply this item's ownership choice. Change the ownership choice in the profile.",
  resource_verification_not_available:
    "lindm cannot run the extra health checks. Keep only the device state check in the profile.",
  resource_feature_evidence_unavailable:
    "No device reports the required capabilities. Remove the capability requirement from the profile.",
  resource_platform_not_applicable:
    "Not applicable to this device: the profile limits it to other platforms.",
  device_platform_facts_unavailable:
    "lindm needs this device's operating system and architecture before it can check applicability.",
  adoption_approval_required:
    "Taking over this existing setting needs an approved assignment. Assign the profile again with an approval.",
  assignment_authority_changed:
    "The admin who assigned this profile no longer has permission. Assign the profile again to resume.",
  dependency_pending: "Waiting for the device to apply this item's dependencies.",
  dependency_attention: "An item this depends on needs attention. Fix that item first.",
  dependency_not_applicable:
    "A dependency does not apply to this device. lindm cannot apply this item. Change the profile.",
  native_unsupported: "The device cannot apply this setting. Nothing changed.",
  admission_precondition:
    "The device refused to start because a required condition failed. Nothing changed.",
  native_tool_path_unprotected:
    "The device refused to run a system tool in an unprotected folder. Nothing changed. Device inventory names the folder.",
  not_applicable: "The device reported this setting doesn't apply to it.",
  no_effect: "The last attempt ended before it started. Nothing changed. lindm sends it again.",
  verification_unknown: "The device couldn't confirm this setting's current state.",
  verification_drifted: "The device found this setting changed away from the profile.",
  outcome_unknown:
    "The device couldn't confirm whether the last change finished. Check the device before assigning again.",
  execution_failed: "The last change failed on the device. Its report is under Latest change.",
  preparation_precondition_failed:
    "The device stopped because a safety check failed. Nothing changed.",
  ownership_baseline_unavailable:
    "lindm has no record of this setting before management started. It leaves the setting unchanged.",
  precondition_failed:
    "The device refused to undo this setting because a required condition failed. Nothing changed.",
  release_failed: "The device couldn't undo this setting. Its report is under Recent changes.",
  expired_unstarted: "The request expired before the device started it. Nothing changed.",
  assignment_changed: "The profile changed before the device started it. Nothing changed.",
  targeting_paused_or_changed:
    "The rollout paused or changed before the device started it. Nothing changed.",
  authority_changed:
    "The assigning admin lost permission before the device started it. Nothing changed.",
};

// Server-recorded blocked, refused or attention reasons as one plain sentence.
// The code itself belongs in Details; unknown codes never reach primary text.
export function blockedReasonLabel(reason: string): string {
  const copy = blockedReasonCopy(reason);
  return copy.known && !copy.localField
    ? copy.sentence
    : "lindm recorded a reason it can't describe in words yet. The code is in Details.";
}

export type BlockedReasonCopy = {
  // One plain sentence; never the raw code (that belongs in Details).
  sentence: string;
  // An /etc/lindm/executor.json field root sets on the device, shown as code.
  localField?: string;
  link?: { to: typeof CAPABILITIES_PATH | "/rollouts"; label: string };
  known: boolean;
};

const ADOPTION_LINK = { to: "/rollouts", label: "Open Rollouts" } as const;
const ADOPTION_REMEDY =
  "Start a rollout with approved adoption. Approve the rollout to let lindm take over this item.";

// Causes a device names when a create-only item would overwrite something lindm
// didn't create; only an approved adoption may take it over.
const ADOPTION_CAUSES: Record<string, string> = {
  adoption_required: "Blocked: this item already exists on the device and lindm didn't create it.",
  existing_banner_file:
    "Blocked: the device has an SSH sign-in banner file that lindm did not create.",
  existing_file: "Blocked: a file lindm didn't create already exists at this path.",
  existing_account: "Blocked: a local user or group with this name already exists on the device.",
  existing_definition: "Blocked: a systemd unit with this name already exists on the device.",
  existing_package: "Blocked: this package exists on the device, but lindm did not install it.",
  existing_kernel_setting:
    "Blocked: a kernel setting file lindm didn't create already sets this parameter.",
};

// Causes only a change on the device can fix; approving adoption doesn't help.
const DEVICE_CAUSES: Record<string, string> = {
  existing_banner_dropin:
    "Blocked: an SSH configuration file already sets a banner. Remove that device setting, or remove the banner from the profile.",
  existing_update_timer:
    "Blocked: the device has automatic updates that lindm did not configure. Disable those updates, or remove the update policy from the profile.",
  existing_banner_symlink:
    "Blocked: the SSH banner file is a symbolic link. Replace it with a regular file, or remove the banner from the profile.",
  // The provider refuses as unsupported, so the row's status already says
  // Unsupported; these name why, with no second status word.
  native_tool_outdated:
    "The system tool is too old. Fedora requires dnf5 5.4.6.0 or newer. Apply All updates through an OS update policy or Patch now. Fedora security-only updates do not update dnf5. lindm retries when device packages change.",
  native_tool_missing:
    "Blocked: the device lacks a required system tool. Install it on the device.",
  existing_package_unverified:
    "Blocked: lindm cannot verify this installed package's repository. Remove the package from the device, or remove it from the profile.",
  explicit_account_identity_required:
    "Blocked: this local account needs explicit identity values. For a group, add its GID to the profile. For a user, add its UID, primary group, home folder and sign-in shell.",
  ssh_service_inactive:
    "Blocked: the SSH service isn't running on the device. Start SSH on the device, or remove the SSH setting from the profile.",
  ssh_config_invalid:
    "Blocked: sshd rejected the device's SSH configuration. lindm left it unchanged. Repair the SSH configuration on the device.",
  unit_not_installed:
    "The device lacks the required systemd unit. Install the package that provides it.",
  native_unsupported:
    "The device's agent can't manage this kind of item on its OS release. Nothing changed.",
};

// Plain copy for a server-recorded reason. `capabilities` is the device's
// granted and reported state, for a capability_*_not_enabled reason.
export function blockedReasonCopy(
  reason: string,
  capabilities?: DeviceCapabilityState,
): BlockedReasonCopy {
  const known = BLOCKED_REASON_LABELS[reason];
  if (known) return { sentence: known, known: true };
  const adoption = ADOPTION_CAUSES[reason];
  if (adoption)
    return { sentence: `${adoption} ${ADOPTION_REMEDY}`, link: ADOPTION_LINK, known: true };
  const device = DEVICE_CAUSES[reason];
  if (device) return { sentence: device, known: true };
  const settingsLink = { to: CAPABILITIES_PATH, label: "Open Device capabilities" } as const;
  if (reason === "capability_firewall_settings_required")
    return {
      sentence:
        "Blocked: Firewall needs management addresses and a connectivity check. Add these firewall settings in Settings → Device capabilities.",
      link: settingsLink,
      known: true,
    };
  const required = capabilityFromReason(reason);
  if (required === undefined)
    return {
      sentence:
        "The device reported a cause this console can't describe yet. The code is in Details.",
      known: false,
    };
  const name = capabilityName(required);
  const localField = localCapabilityField[required];
  if (localField)
    return {
      sentence: `Blocked: ${name} requires local configuration. Ask an administrator with root access to set the field in /etc/lindm/executor.json:`,
      localField,
      known: true,
    };
  const reported = reportedCapability(capabilities?.reported, required);
  if (reported?.status === CapabilityStatus.UNAVAILABLE)
    return {
      sentence: `Blocked: a policy allows ${name} on this device, but the device can't use it. ${unavailableCause(reported.detail)}`,
      known: true,
    };
  // The device has the capability, so this item asks for more than it allows.
  if (
    reported?.status === CapabilityStatus.ENABLED ||
    reported?.status === CapabilityStatus.LOCAL
  ) {
    if (required === ManagementCapability.PACKAGES)
      return {
        sentence:
          "Blocked: the device does not approve this item's repository. Policies approve only the OS vendor's archive. Root administrators approve other repositories in /etc/lindm/executor.json, field",
        localField: "package_provider.sources",
        known: true,
      };
    if (required === ManagementCapability.KERNEL_SETTINGS)
      return {
        sentence:
          "Blocked: the device cannot set this kernel parameter. Add it to this device group's kernel parameters in Settings → Device capabilities.",
        link: settingsLink,
        known: true,
      };
  }
  if (capabilities?.granted.some((grant) => grant.capability === required))
    return {
      sentence: `Blocked: the device has not applied the policy that allows ${name}. lindm retries after the device reports that policy.`,
      known: true,
    };
  return {
    sentence: `Blocked: no policy allows ${name}. Allow it for all devices or this device's group in Settings → Device capabilities.${
      required === ManagementCapability.FIREWALL
        ? " Configure firewall settings for all devices first."
        : ""
    }`,
    link: settingsLink,
    known: true,
  };
}

export function classifyRpcFailure(failure: RpcFailure): RpcFailurePresentation {
  // Match expected conditions only under their documented transport code.
  // An internal error carrying a familiar reason must remain a real failure.
  if (failure.code === Code.FailedPrecondition) {
    switch (failure.reason) {
      case "assistance_unconfigured":
        return {
          tone: "neutral",
          title: "Remote assistance unavailable",
          message: "This server does not provide remote assistance.",
          action: "Ask an administrator to review the assistance and relay settings.",
        };
      case "assistance_policy_ceiling":
        return {
          tone: "neutral",
          title: "Feature not enabled",
          message: "The deployment does not allow one or more selected assistance features.",
          action: "Refresh the assistance policy. Choose available features.",
        };
      case "assistance_capability_not_granted":
        return {
          tone: "neutral",
          title: "Feature not shared",
          message: "The current session does not allow this feature.",
          action: "Review the assistance policy and the features the user shared.",
        };
      case "assistance_content_expired":
        return {
          tone: "warning",
          title: "Clipboard text is no longer available",
          message: "The previously read clipboard text no longer exists in this session.",
          action: "Choose Read clipboard to request the current text again.",
        };
      case "assistance_command_busy":
        return {
          tone: "warning",
          title: "Another request is still running",
          message: "The device has not finished the current assistance request.",
          action: "Check its result before sending another request.",
        };
      case "assistance_busy":
        return {
          tone: "warning",
          title: "An assistance session is already open",
          message: "This device already has a pending or active assistance session.",
          action: "Review the session history and finish that session before requesting another.",
        };
      case "assistance_capacity":
        return {
          tone: "warning",
          title: "Assistance is at capacity",
          message: "The server has reached its limit for concurrent assistance sessions.",
          action: "Wait for another session to end before requesting a new one.",
        };
      case "assistance_not_active":
      case "assistance_state":
        return {
          tone: "warning",
          title: "Session is not ready",
          message: "The session cannot accept this request in its current state.",
          action: "Refresh the session. Wait for user consent and a connected screen.",
        };
      case "assistance_ended":
        return {
          tone: "neutral",
          title: "Assistance session ended",
          message: "This session no longer accepts requests.",
          action: "Request a new session if the user still needs assistance.",
        };
      case "device_action_recovery_readiness_missing":
      case "device_action_recovery_readiness_stale":
      case "device_action_recovery_readiness_unsupported":
      case "device_action_recovery_artifact_required":
      case "device_action_recovery_artifact_unavailable":
      case "device_action_recovery_owner_key_required":
      case "device_action_recovery_attestation_unavailable":
      case "device_action_recovery_boot_mode_mismatch":
      case "device_action_recovery_kernel_mismatch":
        return {
          tone: recoveryReadinessTone(failure.reason),
          title: "Recovery is not ready",
          message: recoveryReadinessMessage(failure.reason),
          action: "Review recovery readiness before requesting approval.",
        };
      case "device_action_esp_insufficient":
        return {
          tone: recoveryReadinessTone(failure.reason),
          title: "Unsupported: ESP capacity",
          message: recoveryReadinessMessage(failure.reason),
          action: "Arrange separately qualified external recovery media with an on-site operator.",
        };
      case "device_action_capability_not_delegated":
        return {
          tone: "neutral",
          title: "Action not enabled",
          message: "The deployment's trust delegation does not allow this action.",
          action: "Ask an administrator to review the action's signing delegation.",
        };
      case "approval_evidence_unavailable":
        return {
          tone: "warning",
          title: "Evidence no longer available",
          message: "The device no longer reports the evidence that this request needs.",
          action: "Reject this request. Propose a new one from the device if it still applies.",
        };
      case "advisory_unavailable":
      case "execution_signing_unconfigured":
      case "execution_authority_unconfigured":
      case "escrow_unconfigured":
        return {
          tone: "neutral",
          title: "Capability not configured",
          message: "The server configuration does not allow this capability.",
          action: "Ask an administrator to review the server configuration.",
        };
      case "device_action_tpm2_unavailable":
      case "device_action_storage_unavailable":
      case "device_action_sessions_unavailable":
        return {
          tone: "neutral",
          title: "Capability not available",
          message: "The device has not reported the capability required for this action.",
          action: "Review its inventory and action requirements before continuing.",
        };
      case "device_action_tpm2_binding_unsupported":
        return {
          tone: "neutral",
          title: "TPM binding not supported",
          message:
            "This systemd version cannot bind the disk to the TPM. The device requires systemd 252 or newer.",
          action: "Keep using the recovery key, or upgrade the OS release before binding.",
        };
      case "device_action_inventory_unavailable":
        return {
          tone: "neutral",
          title: "Inventory not available",
          message: "The device has not reported the inventory required for this action.",
          action: "Wait for the device to report inventory. Refresh the page.",
        };
      case "secret_version_conflict":
        return {
          tone: "warning",
          title: "Secret changed",
          message: "Another administrator added a secret version after this page loaded.",
          action: "Reload the secret. Rotate its current version with a new request.",
        };
      case "secret_unavailable":
        return {
          tone: "neutral",
          title: "Secret not available",
          message: "The server cannot open this secret version.",
          action: "Check the secret version and the server escrow configuration.",
        };
      case "secret_in_use":
        return {
          tone: "warning",
          title: "Secret in use",
          message: "A profile or device still uses this secret. The server did not remove it.",
          action:
            "Choose another secret in those profiles. Publish the profiles. Remove the unused secret.",
        };
      case "secret_deleted":
        return {
          tone: "neutral",
          title: "Secret removed",
          message: "The server removed this secret. You cannot repeat the request.",
          action: "Create a new secret if you still need it.",
        };
      case "local_admin_policy_required":
        return {
          tone: "neutral",
          title: "No local-admin policy",
          message: "This device has no managed local-admin password policy.",
          action: "Set a policy before requesting rotation.",
        };
      case "policy_authority_changed":
        return {
          tone: "warning",
          title: "Policy authority changed",
          message: "The policy author no longer has the required authorization.",
          action: "Set the policy again with current authority.",
        };
      case "snapshot_unavailable":
        return {
          tone: "neutral",
          title: "Package list not available",
          message: "This device hasn't reported a package list yet.",
          action: "Choose Latest snapshot, or wait for the device to report.",
        };
      case "snapshot_expired":
        return {
          tone: "warning",
          title: "This page expired",
          message: "The package list changed since you opened this page.",
          action: "Start a new search or choose Latest snapshot.",
        };
      case "page_expired":
        return {
          tone: "warning",
          title: "This page expired",
          message:
            "The server retains result pages for a limited time. New searches remove older pages.",
          action: "Start a new search.",
        };
      case "device_action_inventory_stale":
        return {
          tone: "warning",
          title: "Inventory needs refreshing",
          message:
            "The device's latest inventory is older than this action allows. Check-ins don't send inventory.",
          action: "Request fresh inventory. Check again after the device reports it.",
        };
      case "device_action_offline":
        return {
          tone: "warning",
          title: "Device is not connected",
          message: "This action requires recent contact with the device.",
          action: "Reconnect the device before trying again.",
        };
      case "device_action_pending":
        return {
          tone: "warning",
          title: "Another action is still open",
          message: "This device has an action that hasn't finished or expired yet.",
          action: "Open the device's actions. Wait for the current action to finish. Check again.",
        };
      case "device_action_generation_rejected":
      case "device_action_session_unavailable":
        return {
          tone: "warning",
          title: "Device enrollment changed",
          message: "Enrollment changed, or the device has not connected since enrollment.",
          action: "Reload the device page before trying again.",
        };
      case "device_revoked":
        return {
          tone: "neutral",
          title: "Device revoked",
          message: "lindm revoked this device. You can only view its records.",
          action: "Recover its enrollment from the Encryption tab to manage it again.",
        };
      case "device_quarantined":
        return {
          tone: "warning",
          title: "Network quarantine active",
          message: "The device accepts only requests to undo the active network quarantine.",
          action: "Undo the quarantine first, or wait for it to end.",
        };
      case "device_lock_release_required":
        return {
          tone: "warning",
          title: "Account lock active",
          message: "The device cannot accept a new lock while the current lock remains active.",
          action: "Undo the current account lock first.",
        };
      case "device_action_lock_changed":
      case "device_action_lock_binding_rejected":
        return {
          tone: "warning",
          title: "Account lock changed",
          message: "The lock this undo refers to is no longer the device's current lock.",
          action: "Reload the device page. Undo the current lock.",
        };
      case "device_action_session_lock_unsupported":
        return {
          tone: "neutral",
          title: "Screen lock not supported",
          message: "This device can't lock screens on their own; it can only lock accounts.",
          action: "Choose the accounts to lock instead.",
        };
      case "device_action_escrow_scope_incomplete":
        return {
          tone: "warning",
          title: "Select every encrypted volume",
          message:
            "This recovery-key removal must include every encrypted volume whose recovery key lindm stores.",
          action: "Select all the device's encrypted volumes. Review the request again.",
        };
      case "escrow_key_rejected":
        return {
          tone: "warning",
          title: "Recovery key settings changed",
          message: "The server's key for storing recovery keys changed after this page loaded.",
          action: "Reload the page. Start the action again.",
        };
      case "authorization_unavailable":
        return {
          tone: "neutral",
          title: "Capability not configured",
          message: "The server configuration does not allow this capability.",
          action: "Ask an administrator to review the server configuration.",
        };
      case "rotation_overlap_active":
        return {
          tone: "warning",
          title: "Previous secret still active",
          message: "The secret replaced by the last rotation still works for its overlap period.",
          action: "Rotate again after that period ends.",
        };
      case "webhook_required":
        return {
          tone: "neutral",
          title: "No signing secret",
          message: "Only webhook destinations have a signing secret.",
          action: "Choose a webhook destination.",
        };
      case "capability_firewall_settings_required":
        return {
          tone: "warning",
          title: "Firewall settings needed",
          message:
            "Firewall requires management addresses and a connectivity check. You cannot remove these settings while a policy enables Firewall.",
          action: "Save the deployment's firewall settings first, or leave Firewall off.",
        };
    }
  }
  if (failure.code === Code.Aborted && failure.reason === "capability_policy_revision_conflict") {
    return {
      tone: "warning",
      title: "Policy changed",
      message:
        "Another administrator changed this policy after you opened it. The server saved nothing.",
      action: "Reload the policy. Review it. Make your change again.",
    };
  }
  if (failure.code === Code.NotFound && failure.reason === "capability_policy_group_not_found") {
    return {
      tone: "warning",
      title: "Group not found",
      message: "The group no longer exists. The server saved nothing.",
      action: "Choose another group.",
    };
  }
  if (failure.code === Code.Unavailable && failure.reason === "directory_unavailable") {
    return {
      tone: "warning",
      title: "Couldn't re-check your access",
      message:
        "This change needs a fresh check of your account with the identity provider, which didn't answer.",
      action: "Retry this same change. If it keeps failing, check the identity provider.",
    };
  }
  if (failure.code === Code.ResourceExhausted && failure.reason === "device_action_capacity") {
    return {
      tone: "warning",
      title: "Action history is full",
      message: "This device has reached the number of actions the server keeps for it.",
      action: "Ask an administrator to re-enroll the device to start a new history.",
    };
  }
  if (failure.code === Code.PermissionDenied) {
    if (failure.reason === "assistance_policy_changed") {
      return {
        tone: "warning",
        title: "Assistance policy changed",
        message: "The current policy no longer allows this session's requested features.",
        action: "Review the policy and request a new session with the features now allowed.",
      };
    }
    if (failure.reason === "assistance_not_creator") {
      return {
        tone: "warning",
        title: "Only the requesting admin can continue",
        message: "Another admin requested this session.",
        action: "Ask that admin to continue, or request your own session after this one ends.",
      };
    }
    if (failure.reason === "actor_authorization_rejected") {
      return {
        tone: "warning",
        title: "Sign in again",
        message:
          "The identity provider no longer authorizes this change. The server saved nothing.",
        action:
          "Sign out. Sign in again. Retry the same change. Ask an owner to check your role if authorization still fails.",
      };
    }
    if (failure.reason === "recent_step_up_required") {
      return {
        tone: "warning",
        title: "Verify it's you",
        message: "This needs a recent identity check.",
        action: "Enter your password. Confirm your identity with your passkey.",
      };
    }
    if (failure.reason === "approval_required" || failure.reason === "human_approval_required") {
      return {
        tone: "warning",
        title: "Approval required",
        message: "This action requires independent approval.",
        action: "Use the approval controls before continuing.",
      };
    }
    return {
      tone: "warning",
      title: "Access not granted",
      message: "The server did not authorize this request.",
      action: "Review your permissions, device scope, and any required approval.",
    };
  }
  if (failure.code === Code.Unauthenticated) {
    if (failure.reason === "invalid_credentials") {
      return {
        tone: "warning",
        title: "Username or password is incorrect.",
        message: "Check the username and password. Retry signing in.",
        action: "Repeated failures lock the account for a while.",
      };
    }
    return {
      tone: "warning",
      title: "Sign-in required",
      message: "Your session could not authorize this request.",
      action: "Sign in again to continue.",
    };
  }
  if (failure.code === Code.ResourceExhausted && failure.reason === "assistance_command_capacity") {
    return {
      tone: "warning",
      title: "Assistance requests are at capacity",
      message: "The server cannot accept another assistance request right now.",
      action: "Wait for running requests to finish before sending this request again.",
    };
  }
  if (
    failure.code === Code.InvalidArgument &&
    (failure.reason === "invalid_assistance_command" ||
      failure.reason === "invalid_assistance_policy")
  ) {
    return {
      tone: "warning",
      title: "Assistance request needs updating",
      message: "The request does not meet the server's assistance requirements.",
      action: "Review the selected features and text. Refresh the page. Retry the request.",
    };
  }
  if (failure.code === Code.InvalidArgument && failure.reason === "request_invalid") {
    return {
      tone: "warning",
      title: "Check the form",
      message: failure.message,
      action: "The console sent nothing. Correct the values. Retry the request.",
    };
  }
  if (failure.code === Code.InvalidArgument && failure.fields && failure.fields.length > 0) {
    return {
      tone: "warning",
      title: "Check the form",
      message: failure.fields.map((field) => field.message).join(" "),
      action: "The server saved nothing. Correct the values. Retry the request.",
    };
  }
  if (failure.code === Code.InvalidArgument && failure.reason === "secret_purpose_mismatch") {
    return {
      tone: "warning",
      title: "Purpose does not match",
      message: "This value doesn't match the kind of secret you chose.",
      action: "Enter a value of the right kind.",
    };
  }
  if (failure.code === Code.InvalidArgument) {
    switch (failure.reason) {
      case "invalid_endpoint":
        return {
          tone: "warning",
          title: "Address not accepted",
          message:
            "Webhooks require HTTPS. Syslog requires an address such as tls://receiver.example:6514. Do not include a user name.",
          action: "Correct the address. Retry the request.",
        };
      case "invalid_ca":
        return {
          tone: "warning",
          title: "Certificate not accepted",
          message: "The CA certificate must be one or more PEM certificates and nothing else.",
          action: "Paste only blocks starting with -----BEGIN CERTIFICATE-----, never a key.",
        };
      case "destination_kind_immutable":
        return {
          tone: "warning",
          title: "Type can't change",
          message: "A destination keeps its original type.",
          action: "Add a new destination of the other type instead.",
        };
      case "invalid_request":
        return {
          tone: "warning",
          title: "The server rejected some values",
          message: "The server rejected one or more of the values entered.",
          action: "Check each field against its hint. Retry the request.",
        };
    }
  }
  if (
    failure.code === Code.AlreadyExists &&
    (failure.reason === "request_id_reused" ||
      failure.reason === "capability_policy_request_conflict")
  ) {
    return {
      tone: "warning",
      title: "Already submitted",
      message: "The server already received this form with different values.",
      action: "Start over to send a new request.",
    };
  }
  if (failure.code === Code.Unimplemented) {
    return {
      tone: "neutral",
      title: "Not supported",
      message: "This server doesn't support this action.",
      action: "Check the server version.",
    };
  }
  return {
    tone: "destructive",
    title: failure.ambiguous ? "Result unknown" : "Something went wrong",
    message: failure.ambiguous
      ? "The console cannot confirm whether the server accepted this request."
      : "The request failed.",
    action: failure.ambiguous
      ? "Check the current state. Retry only this same request before starting a new one."
      : "Retry the request. Share Details with support if the request still fails.",
  };
}

export function isUnauthenticated(error: unknown): boolean {
  return toRpcFailure(error).unauthenticated;
}
