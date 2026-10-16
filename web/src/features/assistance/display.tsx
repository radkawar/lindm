// SPDX-License-Identifier: Apache-2.0

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
  [AssistanceEndCause.CONSENT_TIMEOUT]: "The user did not respond in time.",
  [AssistanceEndCause.OPERATOR_STOPPED]: "An admin stopped the session.",
  [AssistanceEndCause.USER_STOPPED]: "The user stopped the session.",
  [AssistanceEndCause.PORTAL_CLOSED]: "The device stopped screen sharing.",
  [AssistanceEndCause.SESSION_LOCKED]: "The device locked its screen.",
  [AssistanceEndCause.SESSION_ENDED]: "The user signed out or switched users.",
  [AssistanceEndCause.EXPIRED]: "The session reached its time limit.",
  [AssistanceEndCause.AUTHORIZATION_LOST]: "The device lost contact with the server.",
  [AssistanceEndCause.NO_ELIGIBLE_SESSION]: "No user had an unlocked desktop on the device.",
  [AssistanceEndCause.UNAVAILABLE]: "This device cannot share its screen.",
  [AssistanceEndCause.CONNECTION_FAILED]: "The connection failed.",
  [AssistanceEndCause.DISABLED]: "The device configuration disables remote assistance.",
  [AssistanceEndCause.RECORDING_FAILED]:
    "Required recording couldn't be shown, stored or continued, so the session ended.",
};

// Assistance is a device-local agent setting (packaged default: off); no console role
// can turn it on remotely.
export const disabledRemedy = (
  <>
    Ask an administrator with root access to enable <code>remote_assistance.enabled</code> in{" "}
    <code>/etc/lindm/executor.json</code>. Restart <code>lindm-executor</code> on the device.
  </>
);

// The device refused or failed the request before anything was shared. Such a record
// reads "Couldn't start" with the remedy, never "Ended".
const startFailures: Partial<Record<AssistanceEndCause, ReactNode>> = {
  [AssistanceEndCause.DISABLED]: disabledRemedy,
  [AssistanceEndCause.NO_ELIGIBLE_SESSION]:
    "Ask the user to sign in to the desktop. Ask them to unlock it. Request assistance again.",
  [AssistanceEndCause.UNAVAILABLE]:
    "The device reports a missing or failed screen-sharing portal or PipeWire. Repair the desktop packages. Request assistance again.",
  [AssistanceEndCause.CONNECTION_FAILED]:
    "Check access to the assistance relay from the device and browser. Request assistance again.",
};

export function couldNotStart(session: AssistanceSession): boolean {
  return (
    session.state === AssistanceState.ENDED &&
    !session.startedAt &&
    session.endCause in startFailures
  );
}

// Platform and runtime qualification refusals need their precise explanation
// instead of the generic capture-package repair remedy.
const unsupportedDesktop: Record<string, string> = {
  notification_actions_hidden:
    "This notification-server version hides Allow and Decline actions, so safe consent is unavailable. Use a verified action-button implementation; upgrading the portal alone is not enough.",
  notification_actions_unverified:
    "This notification implementation has not been verified to show safe consent buttons. A newer version or advertised actions capability alone is not sufficient.",
  desktop_runtime_unqualified:
    "The active desktop runtime does not match its reviewed assistance tuple. Stock or unlisted implementations remain refused.",
  session_lock_state_unreported:
    "This desktop does not report screen locks. Sharing cannot stop when the screen locks. This desktop does not support remote assistance.",
  portal_remote_desktop_unavailable:
    "The session portal does not expose RemoteDesktop. This desktop may also require it for viewing; check its platform support requirements.",
};

const captureDependencyRemedy = (
  <>
    Screen capture components are missing on the device. On Arch or Omarchy, install{" "}
    <code>gst-plugins-good</code>, <code>gst-plugin-pipewire</code>, <code>gst-plugins-base</code>{" "}
    and <code>gstreamer</code>. On Debian or Ubuntu, install <code>gstreamer1.0-plugins-good</code>,{" "}
    <code>gstreamer1.0-pipewire</code>, <code>gstreamer1.0-plugins-base</code> and{" "}
    <code>gstreamer1.0-tools</code>. On Fedora or RHEL-family systems, install{" "}
    <code>gstreamer1-plugins-good</code>, <code>pipewire-gstreamer</code>,{" "}
    <code>gstreamer1-plugins-base</code> and <code>gstreamer1</code>. Use the distribution&apos;s
    normal upgrade procedure, then request assistance again.
  </>
);

export function startFailureRemedy(session: AssistanceSession): ReactNode {
  if (!couldNotStart(session)) return null;
  if (session.endCause === AssistanceEndCause.UNAVAILABLE) {
    if (
      session.endDetail === "gst_launch_missing" ||
      session.endDetail === "gst_inspect_missing" ||
      session.endDetail.startsWith("gst_element_missing:")
    )
      return captureDependencyRemedy;
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
  return endCauseLabels[session.endCause] ?? endCauseLabels[AssistanceEndCause.UNSPECIFIED];
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
    return session.controlGranted
      ? "The user allowed control. Access has ended."
      : "The user did not allow control";
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
    "The device is offline. Wait for it to contact the server. Retry the request.",
  [`${Code.FailedPrecondition}:assistance_busy`]:
    "Another remote assistance session is already open on this device.",
  [`${Code.FailedPrecondition}:assistance_disabled`]: (
    <>The device configuration disables remote assistance. {disabledRemedy}</>
  ),
  [`${Code.FailedPrecondition}:assistance_no_desktop`]:
    "The latest inventory shows no desktop session or sign-in screen. This device has no desktop to share.",
  [`${Code.FailedPrecondition}:assistance_capacity`]:
    "Too many remote assistance sessions are running. Try again later.",
  [`${Code.FailedPrecondition}:assistance_state`]:
    "This session is not waiting for a connection. Check for an open session in another tab.",
  [`${Code.FailedPrecondition}:assistance_ended`]: "The session has already ended.",
  [`${Code.FailedPrecondition}:assistance_non_relay`]:
    "Your browser couldn't connect through the server's relay.",
  [`${Code.InvalidArgument}:assistance_fingerprint`]:
    "Your browser couldn't set up a secure connection. Try again.",
  [`${Code.PermissionDenied}:assistance_not_creator`]:
    "Only the admin who requested this session can connect to it.",
  [`${Code.FailedPrecondition}:assistance_recording_not_permitted`]:
    "This device's policy doesn't allow required recording. Choose optional recording or none.",
  [`${Code.FailedPrecondition}:assistance_recording_unavailable`]:
    "Recording isn't set up on this server. Request the session without recording.",
  [`${Code.FailedPrecondition}:assistance_reconnect_not_permitted`]:
    "This device's policy no longer allows reconnecting.",
  [`${Code.FailedPrecondition}:assistance_reconnect_expired`]:
    "The time to reconnect has passed. Request a new session.",
  [`${Code.FailedPrecondition}:assistance_reconnect_not_waiting`]:
    "This session can't be reconnected. It may already have a newer request, or it ended for a reason that doesn't allow reconnecting.",
  [`${Code.FailedPrecondition}:assistance_reconnect_exhausted`]:
    "This session has been reconnected as many times as the policy allows.",
  [`${Code.FailedPrecondition}:assistance_reconnect_unavailable`]:
    "This session wasn't requested with reconnect.",
  [`${Code.AlreadyExists}:idempotency_conflict`]:
    "This request was already sent with different details. Start over.",
};

// Expected assistance conditions; other failures use the shared RPC error presentation.
export function assistanceFailureMessage(failure: RpcFailure): ReactNode {
  return failureMessages[`${failure.code}:${failure.reason}`] ?? null;
}
