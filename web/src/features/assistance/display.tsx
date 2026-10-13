import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { Code } from "@connectrpc/connect";
import type { ReactNode } from "react";
import { AssistanceState, type AssistanceSession } from "../../../gen/lindm/admin/v1/assistance_pb";
import { AssistanceEndCause, AssistanceMode } from "../../../gen/lindm/agent/v1/assistance_pb";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import type { RpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";

export const ASSISTANCE_VIEW_PERMISSION = "remote_assistance.view";
export const ASSISTANCE_CONTROL_PERMISSION = "remote_assistance.control";

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
  [AssistanceEndCause.DISABLED]: "Remote assistance is turned off on this device.",
};

// Assistance is a device-local agent setting (packaged default: off); no console role
// can turn it on remotely.
export const disabledRemedy = (
  <>
    Someone with root on the device can set <code>remote_assistance.enabled</code> in{" "}
    <code>/etc/lindm/executor.json</code> and restart <code>lindm-executor</code>.
  </>
);

// The device refused or failed the request before anything was shared. Such a record
// reads "Couldn't start" with the remedy, never "Ended".
const startFailures: Partial<Record<AssistanceEndCause, ReactNode>> = {
  [AssistanceEndCause.DISABLED]: disabledRemedy,
  [AssistanceEndCause.NO_ELIGIBLE_SESSION]:
    "Ask the person to sign in to their desktop and unlock it, then request again.",
  [AssistanceEndCause.UNAVAILABLE]:
    "The desktop's screen-sharing portal or PipeWire is missing or failed on the device. Fix its desktop packages, then request again.",
  [AssistanceEndCause.CONNECTION_FAILED]:
    "Check that the device and your browser can reach this server's assistance relay, then request again.",
};

export function couldNotStart(session: AssistanceSession): boolean {
  return (
    session.state === AssistanceState.ENDED &&
    !session.startedAt &&
    session.endCause in startFailures
  );
}

// UNAVAILABLE details that no package fix resolves: the desktop itself cannot honour
// consent, lock or control. Every other detail keeps the packages remedy.
const unsupportedDesktop: Record<string, string> = {
  notification_actions_hidden:
    "This desktop's notification server shows no Allow or Decline buttons, so the person can't consent. Remote assistance isn't supported on this desktop.",
  session_lock_state_unreported:
    "This desktop doesn't report when its screen locks, so sharing couldn't stop at a lock. Remote assistance isn't supported on this desktop.",
  portal_remote_desktop_unavailable:
    "This desktop's screen-sharing portal offers no remote control. Request view only instead.",
};

export function startFailureRemedy(session: AssistanceSession): ReactNode {
  if (!couldNotStart(session)) return null;
  if (session.endCause === AssistanceEndCause.UNAVAILABLE) {
    const unsupported = unsupportedDesktop[session.endDetail];
    if (unsupported) return unsupported;
  }
  return startFailures[session.endCause];
}

export function AssistanceStateBadge({ session }: { session: AssistanceSession }) {
  if (couldNotStart(session))
    return <StatusBadge status="warning">Couldn&apos;t start</StatusBadge>;
  const presentation = stateLabels[session.state] ?? stateLabels[AssistanceState.UNSPECIFIED];
  return (
    <StatusBadge status={presentation.tone} dot={session.state === AssistanceState.ACTIVE}>
      {presentation.label}
    </StatusBadge>
  );
}

export function endCauseText(session: AssistanceSession): string {
  if (session.state !== AssistanceState.ENDED) return "";
  const label = endCauseLabels[session.endCause] ?? endCauseLabels[AssistanceEndCause.UNSPECIFIED];
  return session.endDetail ? `${label} (${session.endDetail})` : label;
}

// Empty for a refused request: it never reached a person, so there is nothing to report.
export function localSessionText(session: AssistanceSession): string {
  const local = session.localSession;
  if (!local?.username) {
    if (session.state === AssistanceState.ENDED) {
      // A refused request never reached anyone: no person to report.
      if (couldNotStart(session)) return "";
      // A session that never started was never accepted by anyone on the device.
      if (!session.startedAt)
        return session.targetUsername
          ? `No one accepted (requested for ${session.targetUsername})`
          : "No one accepted";
      return session.targetUsername;
    }
    return session.targetUsername ? `Waiting (${session.targetUsername})` : "Waiting";
  }
  const kind = [local.sessionType, local.desktop].filter(Boolean).join(", ");
  return `${local.username}${kind ? ` (${kind})` : ""}`;
}

// Empty for an ended control request the user never answered: no decision happened.
export function controlText(session: AssistanceSession): string {
  if (session.mode !== AssistanceMode.CONTROL) return "Not requested";
  if (session.state === AssistanceState.ENDED) {
    if (!session.consentedAt) return "";
    return session.controlGranted ? "Was granted; no longer active" : "Not granted by the user";
  }
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
const failureMessages: Record<string, ReactNode> = {
  [`${Code.FailedPrecondition}:assistance_unconfigured`]:
    "Remote assistance isn't set up on this server.",
  [`${Code.FailedPrecondition}:device_offline`]:
    "The device is offline. Try again once it has checked in.",
  [`${Code.FailedPrecondition}:assistance_busy`]:
    "Another remote assistance session is already open on this device.",
  [`${Code.FailedPrecondition}:assistance_disabled`]: (
    <>Remote assistance is turned off on this device. {disabledRemedy}</>
  ),
  [`${Code.FailedPrecondition}:assistance_no_desktop`]:
    "This device has no desktop session to share. Its latest inventory shows no one signed in to a desktop and no login screen.",
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
export function assistanceFailureMessage(failure: RpcFailure): ReactNode {
  return failureMessages[`${failure.code}:${failure.reason}`] ?? null;
}
