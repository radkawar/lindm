import { create } from "@bufbuild/protobuf";
import { ConnectError } from "@connectrpc/connect";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";
import {
  AnswerAssistanceSessionRequestSchema,
  AssistanceState,
  StopAssistanceSessionRequestSchema,
  type AssistanceSession,
  type StopAssistanceSessionRequest,
} from "../../../gen/lindm/admin/v1/assistance_pb";
import { AssistanceMode } from "../../../gen/lindm/agent/v1/assistance_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { usePrincipal } from "@/hooks/use-permissions";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import {
  ASSISTANCE_PERMISSION,
  AssistanceStateBadge,
  TimeCell,
  assistanceFailureMessage,
  controlText,
  endCauseText,
  localSessionText,
  modeLabels,
} from "./display";
import { InputCapture, videoFramePoint } from "./input";
import { assistanceSessionQueryOptions } from "./queries";
import { validateAssistanceRequest } from "./validation";

const INPUT_CHANNEL_LABEL = "lindm-input";
const ICE_GATHERING_TIMEOUT_MS = 10_000;
const SIGNALING_TIMEOUT_MS = 30_000;
const STOP_ON_LEAVE_TIMEOUT_MS = 10_000;

type LinkStage = "idle" | "joining" | "negotiating" | "answering" | "answered" | "failed";

type LinkState = {
  stage: LinkStage;
  failure: RpcFailure | null;
  error: string;
  // Join may be repeated while the session is still OFFERED; once an answer was sent
  // the single-use answer must not be repeated from this page.
  retryable: boolean;
};

const idleLink: LinkState = { stage: "idle", failure: null, error: "", retryable: false };

const stageLabels: Record<LinkStage, string> = {
  idle: "Not connected",
  joining: "Fetching the device offer",
  negotiating: "Preparing the relay connection",
  answering: "Sending the answer",
  answered: "Answer sent",
  failed: "Connection setup failed",
};

// Resolves when ICE gathering completes, or false after the contract's 10 s bound.
function waitForGathering(pc: RTCPeerConnection, signal: AbortSignal): Promise<boolean> {
  if (pc.iceGatheringState === "complete") return Promise.resolve(true);
  return new Promise((resolve, reject) => {
    const finish = (complete: boolean) => {
      window.clearTimeout(timer);
      pc.removeEventListener("icegatheringstatechange", onChange);
      signal.removeEventListener("abort", onAbort);
      resolve(complete);
    };
    const onChange = () => {
      if (pc.iceGatheringState === "complete") finish(true);
    };
    const onAbort = () => {
      finish(false);
      reject(signal.reason);
    };
    const timer = window.setTimeout(() => finish(false), ICE_GATHERING_TIMEOUT_MS);
    pc.addEventListener("icegatheringstatechange", onChange);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function stopOnLeave(lifetime: AuthLifetime, sessionId: string) {
  if (lifetime.signal.aborted) return;
  adminClient
    .stopAssistanceSession(
      { sessionId },
      { signal: lifetime.signal, timeoutMs: STOP_ON_LEAVE_TIMEOUT_MS },
    )
    .catch((error: unknown) => {
      if (lifetime.signal.aborted) return;
      toast.error("Remote assistance stop not confirmed", {
        description: `${toRpcFailure(error).message} Open the session from the device page and stop it.`,
      });
    });
}

function remainingLabel(milliseconds: number): string {
  const total = Math.max(0, Math.floor(milliseconds / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

export function AssistanceViewerPage({
  deviceId,
  sessionId,
}: {
  deviceId: string;
  sessionId: string;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const query = useQuery(assistanceSessionQueryOptions(lifetime, deviceId, sessionId));
  const session = query.data;
  const allowed = canPermission(principal, ASSISTANCE_PERMISSION);
  const creator = session !== undefined && session.operatorId === principal.id;
  const ended = session?.state === AssistanceState.ENDED;

  // Joining starts once, when the creator first observes OFFERED; the connection then
  // outlives the OFFERED → ANSWERED → ACTIVE transitions until the session ends.
  const [armed, setArmed] = useState(false);
  if (!armed && allowed && creator && session.state === AssistanceState.OFFERED) setArmed(true);

  // Leaving the page (route change, unmount, tab close) while the creator's session is
  // still open ends it. Media and input also stop when the peer connection closes.
  const stopOnLeaveRef = useRef(false);
  useEffect(() => {
    stopOnLeaveRef.current = allowed && creator && !ended;
  }, [allowed, creator, ended]);
  useEffect(() => {
    const leave = () => {
      if (!stopOnLeaveRef.current) return;
      stopOnLeaveRef.current = false;
      stopOnLeave(lifetime, sessionId);
    };
    window.addEventListener("pagehide", leave);
    return () => {
      window.removeEventListener("pagehide", leave);
      leave();
    };
  }, [lifetime, sessionId]);

  return (
    <section className="grid min-w-0 gap-4">
      <nav aria-label="Remote assistance breadcrumbs" className="flex flex-wrap gap-2 text-sm">
        <Link to="/devices" className="underline">
          Devices
        </Link>
        <span aria-hidden="true">/</span>
        <Link to="/devices/$deviceId" params={{ deviceId }} className="underline">
          {deviceId}
        </Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">Remote assistance</span>
      </nav>
      <PageHeader
        title="Remote assistance"
        description="The local user can stop sharing at any time. Leaving this page ends a session you requested."
        actions={
          session && !ended && allowed ? (
            <StopButton sessionId={sessionId} deviceId={deviceId} />
          ) : null
        }
      />
      {query.error ? (
        <RpcError failure={toRpcFailure(query.error)} title="Session status unavailable" />
      ) : null}
      {query.isPending ? <p role="status">Loading session…</p> : null}
      {session ? (
        <>
          <SessionStatus session={session} />
          {creator && allowed ? (
            <AssistanceConnection
              key={`${lifetime.generation}:${sessionId}`}
              session={session}
              deviceId={deviceId}
              armed={armed && !ended}
            />
          ) : !ended ? (
            <Alert>
              <AlertTitle>Status only</AlertTitle>
              <AlertDescription>
                {allowed
                  ? "Only the operator who requested this session can connect to it. You can stop it."
                  : "Only the operator who requested this session can connect to it."}
              </AlertDescription>
            </Alert>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

function SessionStatus({ session }: { session: AssistanceSession }) {
  const ended = session.state === AssistanceState.ENDED;
  const now = useNow(!ended);
  const endsAt = session.endsAt ? timestampDate(session.endsAt).getTime() : NaN;
  const consentBy = session.consentDeadline
    ? timestampDate(session.consentDeadline).getTime()
    : NaN;
  const live = session.state === AssistanceState.ACTIVE;
  const waiting =
    session.state === AssistanceState.REQUESTED || session.state === AssistanceState.PROMPTED;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-3">
          <AssistanceStateBadge state={session.state} />
          {live ? (
            <StatusBadge status="destructive" dot role="status" aria-live="polite">
              Session live
              {Number.isFinite(endsAt) ? `, ${remainingLabel(endsAt - now)} remaining` : ""}
            </StatusBadge>
          ) : null}
          {waiting && Number.isFinite(consentBy) ? (
            <span className="text-sm font-normal text-muted-foreground">
              Consent window closes in {remainingLabel(consentBy - now)}
            </span>
          ) : null}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <Fact label="Mode">{modeLabels[session.mode]}</Fact>
          <Fact label="Operator">{session.operatorDisplay || session.operatorId}</Fact>
          <Fact label="Local user">{localSessionText(session)}</Fact>
          <Fact label="Control">{controlText(session)}</Fact>
          <Fact label="Created">
            <TimeCell value={session.createdAt} />
          </Fact>
          <Fact label="Started">
            <TimeCell value={session.startedAt} />
          </Fact>
          <Fact label="Ends at the latest">
            <TimeCell value={session.endsAt} />
          </Fact>
          <Fact label="Ended">
            <TimeCell value={session.endedAt} />
          </Fact>
          <div className="sm:col-span-2 lg:col-span-4">
            <Fact label="Reason">{session.reason}</Fact>
          </div>
          {ended ? (
            <div className="sm:col-span-2 lg:col-span-4">
              <Fact label="End cause">{endCauseText(session)}</Fact>
            </div>
          ) : null}
        </dl>
        {!ended ? (
          <p className="mt-3 text-xs text-muted-foreground">
            Remaining time uses this browser's clock against the server's hard limit; the device and
            server end the session on their own clocks.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="mb-1 text-muted-foreground">{label}</dt>
      <dd className="break-words">{children}</dd>
    </div>
  );
}

function useNow(running: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [running]);
  return now;
}

function StopButton({ sessionId, deviceId }: { sessionId: string; deviceId: string }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const exact = useExactRequest<StopAssistanceSessionRequest>();
  return (
    <div className="grid justify-items-end gap-2">
      <Button
        variant="destructive"
        disabled={exact.busy}
        onClick={() =>
          void exact.submit({
            capture: () => create(StopAssistanceSessionRequestSchema, { sessionId }),
            send: (request, options) => adminClient.stopAssistanceSession(request, options),
            failureTitle: "Stop remote assistance",
            onSuccess: async (response) => {
              toast.success("Remote assistance stopped");
              if (response.session?.id === sessionId && response.session.deviceId === deviceId) {
                queryClient.setQueryData(
                  assistanceSessionQueryOptions(lifetime, deviceId, sessionId).queryKey,
                  response.session,
                );
              }
              await queryClient.invalidateQueries({
                queryKey: ["assistance-sessions", lifetime.generation, deviceId],
              });
            },
          })
        }
      >
        {exact.busy ? "Stopping…" : exact.ambiguous ? "Retry stop" : "Stop session"}
      </Button>
      {exact.failure ? <RpcError failure={exact.failure} title="Session not stopped" /> : null}
    </div>
  );
}

function AssistanceConnection({
  session,
  deviceId,
  armed,
}: {
  session: AssistanceSession;
  deviceId: string;
  armed: boolean;
}) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const sessionId = session.id;
  const controlRequested = session.mode === AssistanceMode.CONTROL;
  const [attempt, setAttempt] = useState(0);
  const [link, setLink] = useState<LinkState>(idleLink);
  const [connectionState, setConnectionState] = useState<RTCPeerConnectionState>("new");
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [channel, setChannel] = useState<RTCDataChannel | null>(null);
  const [channelOpen, setChannelOpen] = useState(false);
  const [controlOn, setControlOn] = useState(false);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const surfaceRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!armed) return;
    const controller = new AbortController();
    const signal = AbortSignal.any([controller.signal, lifetime.signal]);
    let pc: RTCPeerConnection | null = null;
    let answerSent = false;
    const update = (next: Partial<LinkState>) => {
      if (!signal.aborted) setLink((current) => ({ ...current, ...next }));
    };
    const run = async () => {
      update({ ...idleLink, stage: "joining" });
      const join = await adminClient.joinAssistanceSession(
        { sessionId },
        { signal, timeoutMs: SIGNALING_TIMEOUT_MS },
      );
      signal.throwIfAborted();
      if (join.session?.id !== sessionId || join.session.deviceId !== deviceId) {
        throw new Error("The join response does not match this device and session.");
      }
      if (!join.offerSdp) throw new Error("The device offer is missing.");
      if (
        join.iceServers.length === 0 ||
        join.iceServers.some(
          (server) =>
            server.urls.length === 0 || server.urls.some((url) => !/^turns?:\S+$/.test(url)),
        )
      ) {
        throw new Error("The server did not provide relay-only ICE servers.");
      }
      update({ stage: "negotiating" });
      const peer = new RTCPeerConnection({
        iceServers: join.iceServers.map((server) => ({
          urls: [...server.urls],
          username: server.username,
          credential: server.credential,
        })),
        iceTransportPolicy: "relay",
        bundlePolicy: "max-bundle",
      });
      pc = peer;
      peer.addEventListener("connectionstatechange", () => {
        if (!signal.aborted) setConnectionState(peer.connectionState);
      });
      peer.addEventListener("track", (event) => {
        if (signal.aborted) return;
        setStream(event.streams[0] ?? new MediaStream([event.track]));
      });
      peer.addEventListener("datachannel", (event) => {
        const incoming = event.channel;
        // View sessions carry no input channel at all; refuse anything unexpected.
        if (signal.aborted || !controlRequested || incoming.label !== INPUT_CHANNEL_LABEL) {
          incoming.close();
          return;
        }
        incoming.addEventListener("open", () => {
          if (!signal.aborted) setChannelOpen(true);
        });
        incoming.addEventListener("close", () => {
          if (!signal.aborted) {
            setChannelOpen(false);
            setControlOn(false);
          }
        });
        setChannel(incoming);
        setChannelOpen(incoming.readyState === "open");
      });
      await peer.setRemoteDescription({ type: "offer", sdp: join.offerSdp });
      const answer = await peer.createAnswer();
      await peer.setLocalDescription(answer);
      await waitForGathering(peer, signal);
      signal.throwIfAborted();
      const answerSdp = peer.localDescription?.sdp ?? "";
      if (!/^a=candidate:.* typ relay\b/m.test(answerSdp)) {
        throw new Error(
          "No relay candidate was gathered within 10 seconds. Check that this browser can reach the assistance relay.",
        );
      }
      const request = create(AnswerAssistanceSessionRequestSchema, { sessionId, answerSdp });
      validateAssistanceRequest(AnswerAssistanceSessionRequestSchema, request);
      update({ stage: "answering" });
      answerSent = true;
      const response = await adminClient.answerAssistanceSession(request, {
        signal,
        timeoutMs: SIGNALING_TIMEOUT_MS,
      });
      signal.throwIfAborted();
      update({ stage: "answered" });
      if (response.session?.id === sessionId && response.session.deviceId === deviceId) {
        queryClient.setQueryData(
          assistanceSessionQueryOptions(lifetime, deviceId, sessionId).queryKey,
          response.session,
        );
      }
    };
    run().catch((error: unknown) => {
      if (signal.aborted) return;
      pc?.close();
      setStream(null);
      setChannel(null);
      setChannelOpen(false);
      setControlOn(false);
      const rpc = error instanceof ConnectError;
      update({
        stage: "failed",
        failure: rpc ? toRpcFailure(error) : null,
        error: rpc ? "" : error instanceof Error ? error.message : "Connection setup failed.",
        retryable: !answerSent,
      });
    });
    return () => {
      controller.abort();
      pc?.close();
      setStream(null);
      setChannel(null);
      setChannelOpen(false);
      setControlOn(false);
    };
  }, [armed, attempt, sessionId, deviceId, controlRequested, lifetime, queryClient]);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    video.srcObject = stream;
    return () => {
      video.srcObject = null;
    };
  }, [stream]);

  const controlAvailable = session.controlGranted && channel !== null && channelOpen;
  const capturing = controlOn && controlAvailable;

  useEffect(() => {
    const surface = surfaceRef.current;
    const video = videoRef.current;
    if (!capturing || !surface || !video || !channel) return;
    const capture = new InputCapture(channel);
    const point = (event: PointerEvent) =>
      videoFramePoint(video, event.clientX, event.clientY, capture.dragging);
    const onPointerMove = (event: PointerEvent) => {
      const next = point(event);
      if (next) capture.move(next);
    };
    const onPointerDown = (event: PointerEvent) => {
      const next = point(event);
      if (!next) return;
      event.preventDefault();
      surface.focus();
      surface.setPointerCapture(event.pointerId);
      capture.move(next);
      capture.button(event.button, true);
    };
    const onPointerUp = (event: PointerEvent) => {
      const next = point(event);
      if (next) capture.move(next);
      if (capture.button(event.button, false)) event.preventDefault();
      if (surface.hasPointerCapture(event.pointerId))
        surface.releasePointerCapture(event.pointerId);
    };
    const onWheel = (event: WheelEvent) => {
      if (!videoFramePoint(video, event.clientX, event.clientY, false)) return;
      event.preventDefault();
      capture.wheel(event);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.isComposing) return;
      if (capture.key(event.code, event.type === "keydown")) event.preventDefault();
    };
    const release = () => capture.releaseAll();
    const suppress = (event: Event) => event.preventDefault();
    surface.addEventListener("pointermove", onPointerMove);
    surface.addEventListener("pointerdown", onPointerDown);
    surface.addEventListener("pointerup", onPointerUp);
    surface.addEventListener("pointercancel", release);
    surface.addEventListener("wheel", onWheel, { passive: false });
    surface.addEventListener("keydown", onKey);
    surface.addEventListener("keyup", onKey);
    surface.addEventListener("blur", release);
    surface.addEventListener("contextmenu", suppress);
    window.addEventListener("blur", release);
    surface.focus();
    return () => {
      surface.removeEventListener("pointermove", onPointerMove);
      surface.removeEventListener("pointerdown", onPointerDown);
      surface.removeEventListener("pointerup", onPointerUp);
      surface.removeEventListener("pointercancel", release);
      surface.removeEventListener("wheel", onWheel);
      surface.removeEventListener("keydown", onKey);
      surface.removeEventListener("keyup", onKey);
      surface.removeEventListener("blur", release);
      surface.removeEventListener("contextmenu", suppress);
      window.removeEventListener("blur", release);
      capture.dispose();
    };
  }, [capturing, channel]);

  const precondition = link.failure ? assistanceFailureMessage(link.failure) : "";
  const ended = session.state === AssistanceState.ENDED;
  const attachedElsewhere =
    !ended &&
    link.stage === "idle" &&
    (session.state === AssistanceState.ANSWERED || session.state === AssistanceState.ACTIVE);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center justify-between gap-3">
          <span>Screen</span>
          <span className="flex flex-wrap items-center gap-2 text-sm font-normal">
            <span className="text-muted-foreground">
              {link.stage === "answered" ? `Media: ${connectionState}` : stageLabels[link.stage]}
            </span>
            {controlRequested ? (
              <Button
                variant={capturing ? "default" : "outline"}
                aria-pressed={capturing}
                disabled={!controlAvailable || ended}
                onClick={() => setControlOn((current) => !current)}
              >
                {capturing ? "Control on" : "Control off"}
              </Button>
            ) : null}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-3">
        {session.state === AssistanceState.REQUESTED ||
        session.state === AssistanceState.PROMPTED ? (
          <p role="status">
            Waiting for the local user to accept on the device. Keep this page open; leaving it
            cancels the request.
          </p>
        ) : null}
        {attachedElsewhere ? (
          <Alert>
            <AlertTitle>Connected from another page</AlertTitle>
            <AlertDescription>
              This session was already answered and cannot be joined again. Stop it and request a
              new session to reconnect.
            </AlertDescription>
          </Alert>
        ) : null}
        {link.failure ? (
          <RpcError failure={link.failure} title="Connection not established">
            {precondition ? <p>{precondition}</p> : null}
          </RpcError>
        ) : null}
        {link.error ? (
          <Alert variant="destructive">
            <AlertTitle>Connection not established</AlertTitle>
            <AlertDescription>{link.error}</AlertDescription>
          </Alert>
        ) : null}
        {link.stage === "failed" && link.retryable && session.state === AssistanceState.OFFERED ? (
          <Button
            variant="outline"
            className="w-fit"
            onClick={() => setAttempt((current) => current + 1)}
          >
            Retry connection
          </Button>
        ) : null}
        {connectionState === "failed" ? (
          <p role="alert" className="text-sm text-destructive">
            The relay connection failed. The device ends the session.
          </p>
        ) : null}
        {controlRequested && !session.controlGranted && session.state === AssistanceState.ACTIVE ? (
          <p className="text-sm text-muted-foreground">
            The local user granted viewing only. Control stays unavailable for this session.
          </p>
        ) : null}
        <div
          ref={surfaceRef}
          tabIndex={capturing ? 0 : -1}
          aria-label={
            capturing
              ? "Remote screen. Keyboard and pointer input is sent to the device. Click outside to release the keyboard."
              : "Remote screen"
          }
          className={
            capturing
              ? "relative aspect-video w-full touch-none overflow-hidden rounded-lg bg-black outline-none ring-2 ring-destructive"
              : "relative aspect-video w-full overflow-hidden rounded-lg bg-black"
          }
        >
          <video
            ref={videoRef}
            className="pointer-events-none size-full object-contain"
            autoPlay
            playsInline
            muted
            disablePictureInPicture
          />
          {!stream ? (
            <p className="absolute inset-0 grid place-items-center text-sm text-white/70">
              {ended ? "Session ended" : "No video yet"}
            </p>
          ) : null}
        </div>
        {capturing ? (
          <p className="text-sm text-muted-foreground">
            Control is on while the screen has focus. Keys and clicks go to the device; browser
            shortcuts such as closing the tab still apply. Click outside the screen to release the
            keyboard.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
