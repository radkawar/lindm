import { Code, ConnectError } from "@connectrpc/connect";
import { requestProblem, type FieldError } from "@/lib/validation";

export type RpcFailure = {
  code: Code;
  codeName: string;
  message: string;
  reason: string;
  unauthenticated: boolean;
  denied: boolean;
  ambiguous: boolean;
  // Set only for a request the browser refused to send; nothing reached the server.
  fields?: readonly FieldError[];
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
  const ambiguous = AMBIGUOUS[connectError.code] === true;
  const raw = connectError.rawMessage.trim();
  let message = raw === "" ? connectError.message.trim() : raw;
  if (message === "") {
    message = ambiguous
      ? "The request ended without a result. Retry the same request ID before starting a new one."
      : "The request was rejected.";
  }
  return {
    code: connectError.code,
    codeName: CODE_NAME[connectError.code] ?? "Unknown",
    message,
    reason:
      connectError.metadata.get("Lindm-Reason")?.trim() ||
      (/^[a-z][a-z0-9_]*$/.test(raw) ? raw : ""),
    unauthenticated: connectError.code === Code.Unauthenticated,
    denied: connectError.code === Code.PermissionDenied,
    ambiguous,
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
    "No recovery readiness observed. Refresh inventory before continuing.",
  device_action_recovery_readiness_stale:
    "Recovery readiness is stale. Refresh inventory before continuing.",
  device_action_recovery_readiness_unsupported:
    "This device does not report the required recovery capability.",
  device_action_recovery_owner_key_required:
    "Secure Boot not enforced: recovery sanitize requires an enrolled owner key",
  device_action_recovery_artifact_required:
    "Select the configured signed recovery image to check required space.",
  device_action_recovery_artifact_unavailable:
    "The signed recovery image is unavailable. Ask an administrator to check the recovery release.",
  device_action_esp_insufficient:
    "Unsupported: ESP capacity. The signed recovery image does not fit the available EFI system partition space. Use separately qualified external recovery media with an on-site operator; do not remove ordinary boot files or resize the ESP to bypass this gate.",
};

export function recoveryReadinessMessage(reason: string) {
  return (
    RECOVERY_READINESS_MESSAGES[reason] ??
    "Recovery readiness is not confirmed. Review the recorded reason before continuing."
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
  escrow_unconfigured: "Blocked: secret storage isn't set up on the server.",
  native_package_manager_busy:
    "Waiting: another package manager (such as a release upgrade) was running. Nothing changed; it retries at the next check.",
  resource_executor_not_available:
    "lindm can't manage this kind of setting on devices yet, so it isn't sent. Remove it from the profile or manage it another way.",
  resource_ownership_operation_unavailable:
    "lindm can't yet take over or undo this setting the way the profile asks, so it isn't sent. Change the profile's ownership choice for this item.",
  resource_verification_not_available:
    "lindm can't run the extra health checks this profile asks for, so it isn't sent. Keep only the device state check in the profile.",
  resource_feature_evidence_unavailable:
    "No device reports the capabilities this setting requires yet, so it isn't sent. Remove the capability requirement from the profile.",
  resource_platform_not_applicable:
    "Not applicable to this device: the profile limits it to other platforms.",
  device_platform_facts_unavailable:
    "Waiting for this device to report its operating system and architecture; lindm then decides whether this applies.",
  adoption_approval_required:
    "Taking over this existing setting needs an approved assignment. Assign the profile again with an approval.",
  assignment_authority_changed:
    "The admin who assigned this profile no longer has permission. Assign the profile again to resume.",
  dependency_pending: "Waiting for the items it depends on to be applied first.",
  dependency_attention: "An item this depends on needs attention. Fix that item first.",
  dependency_not_applicable:
    "An item this depends on doesn't apply to this device, so this can't be applied. Change the profile.",
  native_unsupported: "The device reported it can't apply this setting. Nothing was changed.",
  admission_precondition:
    "The device refused to start because a required condition wasn't met. Nothing was changed.",
  native_tool_path_unprotected:
    "The device refused to run a system tool kept in an unprotected folder. Nothing was changed; the device inventory names the folder.",
  not_applicable: "The device reported this setting doesn't apply to it.",
  no_effect: "The last attempt ended before it started. Nothing was changed; lindm sends it again.",
  verification_unknown: "The device couldn't confirm this setting's current state.",
  verification_drifted: "The device found this setting changed away from the profile.",
  outcome_unknown:
    "The device couldn't confirm whether the last change finished. Check the device before assigning again.",
  execution_failed: "The last change failed on the device. Its report is under Latest change.",
  preparation_precondition_failed:
    "The device stopped before changing anything because a safety check failed, for example a package that was already installed without lindm. Nothing was changed.",
  ownership_baseline_unavailable:
    "lindm has no record of this setting from before it took over, so it leaves the device as it is.",
  precondition_failed:
    "The device refused to undo this because a required condition wasn't met. Nothing was changed.",
  release_failed: "The device couldn't undo this setting. Its report is under Recent changes.",
  expired_unstarted: "It expired before the device started it. Nothing was changed.",
  assignment_changed: "The profile changed before the device started it. Nothing was changed.",
  targeting_paused_or_changed:
    "The rollout paused or changed before the device started it. Nothing was changed.",
  authority_changed:
    "The assigning admin lost permission before the device started it. Nothing was changed.",
};

// Server-recorded blocked, refused or attention reasons as one plain sentence.
// The code itself belongs in Details; unknown codes never reach primary text.
export function blockedReasonLabel(reason: string): string {
  return (
    BLOCKED_REASON_LABELS[reason] ??
    "lindm recorded a reason it can't describe in words yet. The code is in Details."
  );
}

export function classifyRpcFailure(failure: RpcFailure): RpcFailurePresentation {
  // Match expected conditions only under their documented transport code.
  // An internal error carrying a familiar reason must remain a real failure.
  if (failure.code === Code.FailedPrecondition) {
    switch (failure.reason) {
      case "device_action_recovery_readiness_missing":
      case "device_action_recovery_readiness_stale":
      case "device_action_recovery_readiness_unsupported":
      case "device_action_recovery_artifact_required":
      case "device_action_recovery_artifact_unavailable":
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
          message: "This action is not enabled by this deployment's trust delegation.",
          action: "Ask an administrator to review the action's signing delegation.",
        };
      case "approval_evidence_unavailable":
        return {
          tone: "warning",
          title: "Evidence no longer available",
          message: "The device no longer reports what this request was made for.",
          action: "Reject this request. Propose a new one from the device if it still applies.",
        };
      case "advisory_unavailable":
      case "execution_signing_unconfigured":
      case "execution_authority_unconfigured":
      case "escrow_unconfigured":
        return {
          tone: "neutral",
          title: "Capability not configured",
          message: "This capability is not enabled on the server.",
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
            "This OS release's systemd cannot bind the disk to the TPM (systemd 252 or newer is required).",
          action: "Keep using the recovery key, or upgrade the OS release before binding.",
        };
      case "device_action_inventory_unavailable":
        return {
          tone: "neutral",
          title: "Inventory not available",
          message: "The device has not reported the inventory required for this action.",
          action: "Wait for a successful inventory report, then refresh.",
        };
      case "secret_version_conflict":
        return {
          tone: "warning",
          title: "Secret changed",
          message: "Another version was added after this page loaded.",
          action: "Reload the secret and rotate against its current version with a new request.",
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
          message: "A profile or device still uses this secret, so it wasn't deleted.",
          action: "Choose another secret in those profiles and publish them, then delete.",
        };
      case "secret_deleted":
        return {
          tone: "neutral",
          title: "Secret deleted",
          message: "This secret was deleted, so the request can't be repeated.",
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
          message: "The policy author's authorization changed or was revoked.",
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
            "Result pages are kept for a limited time, and older ones are cleared when you start new searches.",
          action: "Start a new search.",
        };
      case "device_action_inventory_stale":
        return {
          tone: "warning",
          title: "Inventory needs refreshing",
          message:
            "The device's latest inventory is older than this action allows. Check-ins don't send inventory.",
          action: "Request fresh inventory, then check again.",
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
          action: "Open the device's actions and wait for it to finish, then check again.",
        };
      case "device_action_generation_rejected":
      case "device_action_session_unavailable":
        return {
          tone: "warning",
          title: "Device enrollment changed",
          message: "This device was re-enrolled, revoked or hasn't connected since enrolling.",
          action: "Reload the device page before trying again.",
        };
    }
  }
  if (failure.code === Code.PermissionDenied) {
    if (failure.reason === "recent_step_up_required") {
      return {
        tone: "warning",
        title: "Verify your identity",
        message: "This action requires recent identity verification.",
        action: "Complete step-up verification before submitting again.",
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
    return {
      tone: "warning",
      title: "Sign-in required",
      message: "Your session could not authorize this request.",
      action: "Sign in again to continue.",
    };
  }
  if (failure.code === Code.InvalidArgument && failure.reason === "request_invalid") {
    return {
      tone: "warning",
      title: "Check the form",
      message: failure.message,
      action: "Nothing was sent. Correct the values, then try again.",
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
  if (failure.code === Code.AlreadyExists && failure.reason === "request_id_reused") {
    return {
      tone: "warning",
      title: "Already submitted",
      message: "This form was already submitted with different values.",
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
      ? "We couldn't confirm whether this went through."
      : "The request couldn't be completed.",
    action: failure.ambiguous
      ? "Check the current state before trying again."
      : "Try again. If it keeps failing, share the details below with support.",
  };
}

export function isUnauthenticated(error: unknown): boolean {
  return toRpcFailure(error).unauthenticated;
}
