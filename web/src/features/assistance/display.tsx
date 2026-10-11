import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { Code } from "@connectrpc/connect";
import { AssistanceState, type AssistanceSession } from "../../../gen/lindm/admin/v1/assistance_pb";
import { AssistanceEndCause, AssistanceMode } from "../../../gen/lindm/agent/v1/assistance_pb";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import type { RpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";

export const ASSISTANCE_PERMISSION = "remote_assistance.run";

const stateLabels: Record<AssistanceState, { label: string; tone: StatusTone }> = {
  [AssistanceState.UNSPECIFIED]: { label: "State not reported", tone: "neutral" },
  [AssistanceState.REQUESTED]: { label: "Waiting for device", tone: "info" },
  [AssistanceState.PROMPTED]: { label: "Waiting for local consent", tone: "info" },
  [AssistanceState.OFFERED]: { label: "Consented, ready to connect", tone: "warning" },
  [AssistanceState.ANSWERED]: { label: "Connecting", tone: "warning" },
  [AssistanceState.ACTIVE]: { label: "Live", tone: "destructive" },
  [AssistanceState.ENDED]: { label: "Ended", tone: "neutral" },
};

export const modeLabels: Record<AssistanceMode, string> = {
  [AssistanceMode.UNSPECIFIED]: "Not recorded",
  [AssistanceMode.VIEW]: "View only",
  [AssistanceMode.CONTROL]: "View and request control",
};

const endCauseLabels: Record<AssistanceEndCause, string> = {
  [AssistanceEndCause.UNSPECIFIED]: "No cause recorded",
  [AssistanceEndCause.DECLINED]: "The local user declined the request.",
  [AssistanceEndCause.CONSENT_TIMEOUT]:
    "The local user did not respond before the consent deadline.",
  [AssistanceEndCause.OPERATOR_STOPPED]: "An operator stopped the session.",
  [AssistanceEndCause.USER_STOPPED]: "The local user stopped the session.",
  [AssistanceEndCause.PORTAL_CLOSED]: "The desktop screen-sharing session was closed.",
  [AssistanceEndCause.SESSION_LOCKED]: "The local session was locked.",
  [AssistanceEndCause.SESSION_ENDED]:
    "The local session ended, changed user, or lost its session helper.",
  [AssistanceEndCause.EXPIRED]: "The maximum session duration elapsed.",
  [AssistanceEndCause.AUTHORIZATION_LOST]:
    "Fresh server authorization was not observed in time, so the session ended.",
  [AssistanceEndCause.NO_ELIGIBLE_SESSION]:
    "No eligible active, unlocked local graphical session was available.",
  [AssistanceEndCause.UNAVAILABLE]:
    "The device could not provide the desktop portal, PipeWire, encoder or relay capability.",
  [AssistanceEndCause.CONNECTION_FAILED]: "The media connection failed or closed.",
  [AssistanceEndCause.DISABLED]: "Device policy does not enable remote assistance.",
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
  return session.endDetail ? `${label} Detail: ${session.endDetail}` : label;
}

export function localSessionText(session: AssistanceSession): string {
  const local = session.localSession;
  if (!local?.username) {
    return session.targetUsername
      ? `Not bound yet (requested user ${session.targetUsername})`
      : "Not bound yet";
  }
  const kind = [local.sessionType, local.desktop].filter(Boolean).join(", ");
  return `${local.username}@session ${local.logindSessionId}${kind ? ` (${kind})` : ""}`;
}

export function controlText(session: AssistanceSession): string {
  if (session.mode !== AssistanceMode.CONTROL) return "Not requested";
  if (session.controlGranted) return "Granted";
  if (session.state === AssistanceState.REQUESTED || session.state === AssistanceState.PROMPTED)
    return "Pending local approval";
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
    "Remote assistance is not configured on this server.",
  [`${Code.FailedPrecondition}:device_offline`]:
    "The device has not checked in within the last 2 minutes.",
  [`${Code.FailedPrecondition}:assistance_busy`]:
    "Another remote assistance session is already open on this device.",
  [`${Code.FailedPrecondition}:assistance_capacity`]:
    "The server is at its concurrent remote assistance limit. Try again later.",
  [`${Code.FailedPrecondition}:assistance_state`]:
    "The session is no longer waiting for a connection. It may already be connected from another page.",
  [`${Code.FailedPrecondition}:assistance_ended`]: "The session has already ended.",
  [`${Code.FailedPrecondition}:assistance_non_relay`]:
    "The browser offered a connection path that is not the configured assistance relay, so it was refused.",
  [`${Code.InvalidArgument}:assistance_fingerprint`]:
    "The browser answer did not carry exactly one DTLS fingerprint and was refused.",
  [`${Code.PermissionDenied}:assistance_not_creator`]:
    "Only the operator who requested this session can connect to it.",
  [`${Code.AlreadyExists}:idempotency_conflict`]:
    "This request ID was already used for a different request. Prepare a new request.",
};

// Expected assistance conditions; other failures use the shared RPC error presentation.
export function assistanceFailureMessage(failure: RpcFailure): string {
  return failureMessages[`${failure.code}:${failure.reason}`] ?? "";
}
