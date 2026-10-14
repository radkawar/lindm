// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import {
  AssistanceReconnectState,
  ReconnectAssistanceSessionRequestSchema,
  type AssistanceReconnectWorkflow,
  type AssistanceSession,
  type ReconnectAssistanceSessionRequest,
} from "../../../gen/lindm/admin/v1/assistance_pb";
import { AssistancePolicyMode } from "../../../gen/lindm/agent/v1/assistance_pb";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { usePrincipal } from "@/hooks/use-permissions";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { TimeCell, assistanceFailureMessage } from "./display";
import { RecordingStateBadge } from "./recordings";
import { validateRequest } from "@/lib/validation";

const RECONNECT_PERMISSION = "remote_assistance.reconnect";

const endReasons: Record<string, string> = {
  not_approved: "The user never accepted the original request.",
  not_granted: "This device does not allow reconnecting.",
  user_stopped: "The user stopped the session.",
  declined: "The user declined.",
  operator_stopped: "An admin stopped the session.",
  expired: "The session reached its time limit.",
  max_reconnects: "The session was reconnected as many times as allowed.",
  policy_changed: "The device policy no longer allows reconnecting.",
  operator_scope_lost: "The requesting admin no longer has reconnect permission.",
  operator_authorization_lost: "The requesting admin's access could not be confirmed.",
  superseded: "A new, unrelated session was requested.",
  window_elapsed: "The time to reconnect passed.",
};

// Recording and reconnect state of one session. Neither carries content: the
// recording is played from the device's recordings list with its own permission.
export function SessionWorkflow({
  session,
  deviceId,
}: {
  session: AssistanceSession;
  deviceId: string;
}) {
  const recording = session.recording;
  const workflow = session.reconnect;
  if (!recording && !workflow) return null;
  return (
    <section aria-label="Recording and reconnect" className="grid gap-3 border p-4 text-sm">
      {recording ? (
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">Recording</span>
          <RecordingStateBadge state={recording.state} />
          <span className="text-muted-foreground">
            {recording.required
              ? "Required for this session."
              : "The user chose whether to record."}{" "}
            Kept for {recording.retentionDays} days after it ends.
          </span>
        </div>
      ) : null}
      {workflow ? (
        <ReconnectState session={session} workflow={workflow} deviceId={deviceId} />
      ) : null}
    </section>
  );
}

function ReconnectState({
  session,
  workflow,
  deviceId,
}: {
  session: AssistanceSession;
  workflow: AssistanceReconnectWorkflow;
  deviceId: string;
}) {
  const principal = usePrincipal();
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const exact = useExactRequest<ReconnectAssistanceSessionRequest>();
  const automatic = workflow.mode === AssistancePolicyMode.ON;
  const latest = workflow.latestSessionId === session.id;
  const waiting = workflow.state === AssistanceReconnectState.WAITING && latest;
  const creator = session.operatorId === principal.id;
  const allowed = creator && canPermission(principal, RECONNECT_PERMISSION);
  const precondition = exact.failure ? assistanceFailureMessage(exact.failure) : "";

  function reconnect() {
    void exact.submit({
      capture: () => {
        const request = create(ReconnectAssistanceSessionRequestSchema, {
          requestId: newRequestId(),
          sessionId: session.id,
        });
        validateRequest(ReconnectAssistanceSessionRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.reconnectAssistanceSession(request, options),
      failureTitle: "Reconnect",
      onSuccess: async (response) => {
        await queryClient.invalidateQueries({
          queryKey: ["assistance-sessions", lifetime.generation, deviceId],
        });
        const next = response.session;
        if (next?.deviceId === deviceId && next.reconnectOf === session.id)
          void navigate({
            to: "/devices/$deviceId/assistance/$sessionId",
            params: { deviceId, sessionId: next.id },
          });
      },
    });
  }

  return (
    <div className="grid gap-2">
      <p>
        <span className="font-medium">Reconnect: </span>
        {automatic
          ? "after a sign-out, restart or lock, a new request is sent automatically."
          : "after a sign-out, restart or lock, the requesting admin can send a new request."}{" "}
        The user must accept every new request; nothing they allowed before carries over.
      </p>
      {session.reconnectOf ? (
        <p>
          This session continues{" "}
          <Link
            to="/devices/$deviceId/assistance/$sessionId"
            params={{ deviceId, sessionId: session.reconnectOf }}
            className="underline"
          >
            an earlier session
          </Link>
          .
        </p>
      ) : null}
      {waiting ? (
        <p role="status">
          Waiting for the device to return. Available until <TimeCell value={workflow.expiresAt} />;{" "}
          {workflow.reconnects} of {workflow.maxReconnects} new requests used.
        </p>
      ) : null}
      {!latest ? (
        <p>
          A newer request continues this session:{" "}
          <Link
            to="/devices/$deviceId/assistance/$sessionId"
            params={{ deviceId, sessionId: workflow.latestSessionId }}
            className="underline"
          >
            open it
          </Link>
          .
        </p>
      ) : null}
      {workflow.state === AssistanceReconnectState.ENDED ||
      workflow.state === AssistanceReconnectState.EXPIRED ? (
        <p className="text-muted-foreground">
          Reconnect is no longer available.{" "}
          {endReasons[workflow.endReason] ??
            "The session ended for a reason that doesn't allow it."}
        </p>
      ) : null}
      {waiting && allowed ? (
        <div className="flex flex-wrap gap-2">
          <Button type="button" disabled={exact.busy} onClick={reconnect}>
            {exact.busy ? "Sending…" : exact.ambiguous ? "Try sending again" : "Send a new request"}
          </Button>
        </div>
      ) : null}
      {exact.failure ? (
        <RpcError failure={exact.failure} title="New request not sent">
          {precondition ? <p>{precondition}</p> : null}
        </RpcError>
      ) : null}
    </div>
  );
}
