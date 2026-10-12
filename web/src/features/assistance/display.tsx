import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { Code } from "@connectrpc/connect";
import { AssistanceState, type AssistanceSession } from "../../../gen/lindm/admin/v1/assistance_pb";
import { AssistanceEndCause, AssistanceMode } from "../../../gen/lindm/agent/v1/assistance_pb";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import type { RpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";

export const ASSISTANCE_PERMISSION = "remote_assistance.run";

const stateLabels: Record<AssistanceState, { label: string; tone: StatusTone }> = {
  [AssistanceState.UNSPECIFIED]: { label: "Unknown", tone: "neutral" },
  [AssistanceState.REQUESTED]: { label: "Waiting for device", tone: "info" },
  [AssistanceState.PROMPTED]: { label: "Waiting for user to accept", tone: "info" },
  [AssistanceState.OFFERED]: { label: "Accepted, ready to connect", tone: "warning" },
  [AssistanceState.ANSWERED]: { label: "Connecting", tone: "warning" },
  [AssistanceState.ACTIVE]: { label: "Live", tone: "info" },
  [AssistanceState.ENDED]: { label: "Ended", tone: "neutral" },
};

export const modeLabels: Record<AssistanceMode, string> = {
  [AssistanceMode.UNSPECIFIED]: "Unknown",
  [AssistanceMode.VIEW]: "View only",
  [AssistanceMode.CONTROL]: "View and request control",
};

const endCauseLabels: Record<AssistanceEndCause, string> = {
  [AssistanceEndCause.UNSPECIFIED]: "Ended.",
  [AssistanceEndCause.DECLINED]: "The user declined.",
  [AssistanceEndCause.CONSENT_TIMEOUT]: "The user didn't respond in time.",
  [AssistanceEndCause.OPERATOR_STOPPED]: "An admin stopped the session.",
  [AssistanceEndCause.USER_STOPPED]: "The user stopped the session.",
  [AssistanceEndCause.PORTAL_CLOSED]: "Screen sharing was closed on the device.",
  [AssistanceEndCause.SESSION_LOCKED]: "The device screen was locked.",
  [AssistanceEndCause.SESSION_ENDED]: "The user signed out or switched users.",
  [AssistanceEndCause.EXPIRED]: "The time limit was reached.",
  [AssistanceEndCause.AUTHORIZATION_LOST]: "The device lost contact with the server.",
  [AssistanceEndCause.NO_ELIGIBLE_SESSION]: "No one was signed in and unlocked on the device.",
  [AssistanceEndCause.UNAVAILABLE]: "Screen sharing isn't available on this device.",
  [AssistanceEndCause.CONNECTION_FAILED]: "The connection failed.",
  [AssistanceEndCause.DISABLED]: "Remote assistance is turned off for this device.",
};

export function AssistanceStateBadge({ state }: { state: AssistanceState }) {
  const presentation = stateLabels[state] ?? stateLabels[AssistanceState.UNSPECIFIED];
  return (
    <StatusBadge status={presentation.tone} dot={state === AssistanceState.ACTIVE}>
      {presentation.label}
    </StatusBadge>
  );
}

export function endCauseText(session: AssistanceSession): string {
  if (session.state !== AssistanceState.ENDED) return "";
  const label = endCauseLabels[session.endCause] ?? endCauseLabels[AssistanceEndCause.UNSPECIFIED];
  return session.endDetail ? `${label} (${session.endDetail})` : label;
}

export function localSessionText(session: AssistanceSession): string {
  const local = session.localSession;
  if (!local?.username) {
    if (session.state === AssistanceState.ENDED) {
      // A session that never started was never accepted by anyone on the device.
      if (!session.startedAt)
        return session.targetUsername
          ? `No one accepted (requested for ${session.targetUsername})`
          : "No one accepted";
      return session.targetUsername || "Not reported";
    }
    return session.targetUsername ? `Waiting (${session.targetUsername})` : "Waiting";
  }
  const kind = [local.sessionType, local.desktop].filter(Boolean).join(", ");
  return `${local.username}${kind ? ` (${kind})` : ""}`;
}

export function controlText(session: AssistanceSession): string {
  if (session.state === AssistanceState.ENDED) {
    if (session.mode !== AssistanceMode.CONTROL) return "Not requested";
    return session.controlGranted ? "Was granted; no longer active" : "Was not granted";
  }
  if (session.mode !== AssistanceMode.CONTROL) return "Not requested";
  if (session.controlGranted) return "Granted";
  if (session.state === AssistanceState.REQUESTED || session.state === AssistanceState.PROMPTED)
    return "Waiting for user";
  return "Not granted";
}

export function TimeCell({ value }: { value: Timestamp | undefined }) {
  const formatted = formatTimestamp(value);
  if (!formatted.date) return <span className="text-muted-foreground">{formatted.local}</span>;
  return (
    <time dateTime={formatted.utc} title={formatted.utc}>
      {formatted.local}
    </time>
  );
}

// Server reasons keyed by their documented transport code; a familiar reason under any
// other code stays a plain failure.
const failureMessages: Record<string, string> = {
  [`${Code.FailedPrecondition}:assistance_unconfigured`]:
    "Remote assistance isn't set up on this server.",
  [`${Code.FailedPrecondition}:device_offline`]:
    "The device is offline. Try again once it has checked in.",
  [`${Code.FailedPrecondition}:assistance_busy`]:
    "Another remote assistance session is already open on this device.",
  [`${Code.FailedPrecondition}:assistance_capacity`]:
    "Too many remote assistance sessions are running. Try again later.",
  [`${Code.FailedPrecondition}:assistance_state`]:
    "This session isn't waiting for a connection. It may be open in another tab.",
  [`${Code.FailedPrecondition}:assistance_ended`]: "The session has already ended.",
  [`${Code.FailedPrecondition}:assistance_non_relay`]:
    "Your browser couldn't connect through the server's relay.",
  [`${Code.InvalidArgument}:assistance_fingerprint`]:
    "Your browser couldn't set up a secure connection. Try again.",
  [`${Code.PermissionDenied}:assistance_not_creator`]:
    "Only the admin who requested this session can connect to it.",
  [`${Code.AlreadyExists}:idempotency_conflict`]:
    "This request was already sent with different details. Start over.",
};

// Expected assistance conditions; other failures use the shared RPC error presentation.
export function assistanceFailureMessage(failure: RpcFailure): string {
  return failureMessages[`${failure.code}:${failure.reason}`] ?? "";
}
