import { Code, ConnectError } from "@connectrpc/connect";

export type RpcFailure = {
  code: Code;
  codeName: string;
  message: string;
  reason: string;
  unauthenticated: boolean;
  denied: boolean;
  ambiguous: boolean;
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
};

// Server-recorded blocked or attention reasons; unknown reasons are shown verbatim.
export function blockedReasonLabel(reason: string): string {
  return BLOCKED_REASON_LABELS[reason] ?? reason;
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
      case "page_expired":
        return {
          tone: "warning",
          title: "This page expired",
          message: "The package list changed since you opened this page.",
          action: "Start a new search or choose Latest snapshot.",
        };
      case "device_action_inventory_stale":
        return {
          tone: "warning",
          title: "Inventory needs refreshing",
          message: "The device's last report is too old for this action.",
          action: "Wait for the device to check in, then refresh.",
        };
      case "device_action_offline":
        return {
          tone: "warning",
          title: "Device is not connected",
          message: "This action requires recent contact with the device.",
          action: "Reconnect the device before trying again.",
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
