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
    "The EFI system partition needs more free space before recovery handoff.",
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
      case "device_action_esp_insufficient":
        return {
          tone: recoveryReadinessTone(failure.reason),
          title: "Recovery is not ready",
          message: recoveryReadinessMessage(failure.reason),
          action: "Review recovery readiness before requesting approval.",
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
      case "device_action_inventory_unavailable":
        return {
          tone: "neutral",
          title: "Inventory not available",
          message: "The device has not reported the inventory required for this action.",
          action: "Wait for a successful inventory report, then refresh.",
        };
      case "snapshot_unavailable":
        return {
          tone: "neutral",
          title: "Inventory snapshot not available",
          message: "No readable package snapshot is available for this view.",
          action:
            "Choose Latest snapshot to start a new view, or wait for the device to publish inventory.",
        };
      case "snapshot_expired":
      case "page_expired":
        return {
          tone: "warning",
          title: "Inventory view expired",
          message: "This inventory snapshot or saved page is no longer available.",
          action:
            "Start a new search or choose Latest snapshot. The current view will not be replaced silently.",
        };
      case "device_action_inventory_stale":
        return {
          tone: "warning",
          title: "Inventory needs refreshing",
          message: "The recorded inventory is too old to authorize this action.",
          action: "Wait for a fresh device report, then refresh.",
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
  if (failure.code === Code.Unimplemented) {
    return {
      tone: "neutral",
      title: "Capability not supported",
      message: "The server does not support this operation.",
      action: "Check the deployed server version and available capabilities.",
    };
  }
  return {
    tone: "destructive",
    title: failure.ambiguous ? "Request outcome unknown" : "Request failed",
    message: failure.ambiguous
      ? "The request ended without a confirmed result."
      : "The request could not be completed.",
    action: failure.ambiguous
      ? "Check the current result before retrying. If the operation supports request IDs, retry only the captured request with the same ID."
      : "Review the diagnostic details before trying again.",
  };
}

export function isUnauthenticated(error: unknown): boolean {
  return toRpcFailure(error).unauthenticated;
}
