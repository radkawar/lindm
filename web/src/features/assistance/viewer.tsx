// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { ConnectError } from "@connectrpc/connect";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";
import {
  AnswerAssistanceSessionRequestSchema,
  AssistanceState,
  StopAssistanceSessionRequestSchema,
  type AssistanceSession,
  type StopAssistanceSessionRequest,
} from "../../../gen/lindm/admin/v1/assistance_pb";
import {
  AssistanceCommandKind,
  AssistanceMode,
  AssistancePolicyMode,
} from "../../../gen/lindm/agent/v1/assistance_pb";
import { AssistanceInputPause } from "../../../gen/lindm/agent/v1/assistance_guidance_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { usePrincipal } from "@/hooks/use-permissions";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import {
  ASSISTANCE_CONTROL_PERMISSION,
  ASSISTANCE_VIEW_PERMISSION,
  AssistanceStateBadge,
  TimeCell,
  assistanceFailureMessage,
  controlText,
  couldNotStart,
  endCauseText,
  localSessionText,
  modeLabels,
  startFailureRemedy,
} from "./display";
import { policyMode, type CapabilityField } from "./capabilities";
import { AssistanceControls } from "./controls";
import { useAssistanceCommand } from "./commands";
import { InputCapture, InputEpochFence, videoFramePoint, type KeyboardMode } from "./input";
import { AssistanceFiles } from "./files";
import { ANNOTATION_CHANNEL_LABEL, AnnotationSender } from "./annotation";
import { AssistanceGuidance } from "./guidance";
import { SessionWorkflow } from "./workflow";
import { FILE_CHANNEL_LABEL } from "./files-stream";
import {
  cursorVisibilityNote,
  DisplayPresentationFence,
  parseDisplayFrameMarker,
} from "./presentation";
import { assistanceSessionQueryOptions } from "./queries";
import { validateRequest } from "@/lib/validation";

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
  joining: "Connecting",
  negotiating: "Connecting",
  answering: "Connecting",
  answered: "Connecting",
  failed: "Couldn't connect",
};

const mediaLabels: Record<string, string> = {
  new: "Connecting",
  connecting: "Connecting",
  connected: "Connected",
  disconnected: "Connection interrupted",
  failed: "Connection lost",
  closed: "Disconnected",
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
    .catch(() => {
      if (lifetime.signal.aborted) return;
      toast.error("Couldn't confirm the session stopped", {
        description: "Open the session from the device page and stop it.",
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
  deviceName,
  sessionId,
}: {
  deviceId: string;
  deviceName: string;
  sessionId: string;
}) {
  const lifetime = useAuthLifetime();
  return (
    <AssistanceViewerSession
      key={`${lifetime.generation}:${sessionId}`}
      deviceId={deviceId}
      deviceName={deviceName}
      sessionId={sessionId}
    />
  );
}

function AssistanceViewerSession({
  deviceId,
  deviceName,
  sessionId,
}: {
  deviceId: string;
  deviceName: string;
  sessionId: string;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const query = useQuery(assistanceSessionQueryOptions(lifetime, deviceId, sessionId));
  // A failed poll invalidates actions, not the mounted session/command identity.
  const session = query.data;
  const canStop = canPermission(principal, ASSISTANCE_VIEW_PERMISSION);
  const allowed =
    canStop &&
    session !== undefined &&
    (session.mode === AssistanceMode.VIEW ||
      (session.mode === AssistanceMode.CONTROL &&
        canPermission(principal, ASSISTANCE_CONTROL_PERMISSION)));
  const creator = session !== undefined && session.operatorId === principal.id;
  const ended = session?.state === AssistanceState.ENDED;

  // Joining starts once, when the creator first observes OFFERED; the connection then
  // outlives the OFFERED → ANSWERED → ACTIVE transitions until the session ends.
  const [armed, setArmed] = useState(false);
  if (!armed && allowed && creator && session?.state === AssistanceState.OFFERED) setArmed(true);

  // Leaving the page (route change, unmount, tab close) while the creator's session is
  // still open ends it. Media and input also stop when the peer connection closes.
  const stopOnLeaveRef = useRef(false);
  useLayoutEffect(() => {
    if (query.error || !session) return;
    if (ended) stopOnLeaveRef.current = false;
    else if (creator) stopOnLeaveRef.current = true;
  }, [query.error, session, creator, ended]);
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
    <section
      className="grid min-w-0 gap-4"
      data-review-page="assistance"
      data-assistance-state={session ? AssistanceState[session.state].toLowerCase() : "loading"}
    >
      <nav aria-label="Remote assistance breadcrumbs" className="flex flex-wrap gap-2 text-sm">
        <Link to="/devices" className="underline">
          Devices
        </Link>
        <span aria-hidden="true">/</span>
        <Link to="/devices/$deviceId" params={{ deviceId }} className="underline">
          {deviceName}
        </Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">Remote assistance</span>
      </nav>
      <PageHeader
        title="Remote assistance"
        description={
          ended
            ? session.startedAt
              ? "Session record. Sharing and control have ended."
              : "Request record. The device shared nothing."
            : creator
              ? "The user chooses what to share. Leaving this page stops your session."
              : "Only the requesting admin can connect. The user can stop sharing at any time."
        }
        actions={
          session && !ended && canStop ? (
            <div data-review-next-action>
              <StopButton sessionId={sessionId} deviceId={deviceId} />
            </div>
          ) : (
            <Button
              variant="outline"
              data-review-next-action
              render={<Link to="/devices/$deviceId" params={{ deviceId }} />}
            >
              Return to device
            </Button>
          )
        }
      />
      {query.error ? (
        <div data-review-state="blocked">
          <RpcError failure={toRpcFailure(query.error)} title="Couldn't load session" />
          <Button
            variant="outline"
            disabled={query.isFetching}
            onClick={() => void query.refetch()}
          >
            Refresh session
          </Button>
        </div>
      ) : null}
      {query.isPending ? (
        <p role="status" data-review-state="blocked">
          Loading session…
        </p>
      ) : null}
      {session ? (
        <>
          {!query.error ? (
            <SessionStatus
              session={session}
              identifiers={[
                { label: "Device ID", value: deviceId },
                { label: "Session ID", value: sessionId },
                { label: "Operator ID", value: session.operatorId },
                { label: "End detail", value: session.endDetail },
              ]}
            />
          ) : null}
          {!query.error ? <SessionWorkflow session={session} deviceId={deviceId} /> : null}
          {creator && allowed && !ended ? (
            <AssistanceConnection
              key={`${lifetime.generation}:${sessionId}`}
              session={session}
              deviceId={deviceId}
              armed={armed && !ended}
              sessionAvailable={!query.error}
            />
          ) : !ended ? (
            <Alert>
              <AlertTitle>Session details only</AlertTitle>
              <AlertDescription>
                {creator && !allowed
                  ? "Your role no longer allows this session's requested access."
                  : "Only the admin who requested this session can connect."}
                {canStop ? " You can still stop it." : ""}
              </AlertDescription>
            </Alert>
          ) : null}
        </>
      ) : null}
      {ended ? null : (
        <TechnicalDetails
          items={[
            { label: "Device ID", value: deviceId },
            { label: "Session ID", value: sessionId },
            { label: "Operator ID", value: session?.operatorId },
          ]}
        />
      )}
    </section>
  );
}

function SessionStatus({
  session,
  identifiers,
}: {
  session: AssistanceSession;
  identifiers: readonly { label: string; value: ReactNode }[];
}) {
  const ended = session.state === AssistanceState.ENDED;
  const failed = couldNotStart(session);
  const now = useNow(!ended);
  const endsAt = session.endsAt ? timestampDate(session.endsAt).getTime() : NaN;
  const consentBy = session.consentDeadline
    ? timestampDate(session.consentDeadline).getTime()
    : NaN;
  const live = session.state === AssistanceState.ACTIVE;
  const waiting =
    session.state === AssistanceState.REQUESTED || session.state === AssistanceState.PROMPTED;
  // An ended record lists only what happened: the person the device bound, the
  // control decision they made, and a duration only when sharing started.
  const person = localSessionText(session);
  const control = controlText(session);
  return (
    <section
      aria-label="Session situation"
      data-assistance-situation
      className="grid gap-4 border-l-2 border-primary bg-muted/30 p-4"
    >
      <div className="flex flex-wrap items-center gap-3">
        <AssistanceStateBadge session={session} />
        {live && Number.isFinite(endsAt) ? (
          <span role="status" className="text-sm">
            {remainingLabel(endsAt - now)} remaining
          </span>
        ) : null}
        {waiting && Number.isFinite(consentBy) ? (
          <span className="text-sm text-muted-foreground">
            User has {remainingLabel(consentBy - now)} to accept
          </span>
        ) : null}
      </div>
      <div>
        <h2 className="text-base font-semibold">
          {failed ? "Why it couldn't start" : ended ? "Why this session ended" : "Support request"}
        </h2>
        <p className="mt-1 text-sm">{ended ? endCauseText(session) : session.reason}</p>
        {failed ? <p className="mt-1 text-sm">{startFailureRemedy(session)}</p> : null}
        {failed ? (
          <p className="mt-1 text-sm text-muted-foreground" data-review-state="clear">
            Request failed <TimeCell value={session.endedAt} />. Resolve the reported cause. Return
            to the device to request assistance again.
          </p>
        ) : ended ? (
          <p className="mt-1 text-sm text-muted-foreground" data-review-state="clear">
            Ended <TimeCell value={session.endedAt} />. Return to the device to help again. Request
            a new session with fresh consent.
          </p>
        ) : waiting ? (
          <p className="mt-1 text-sm text-muted-foreground" data-review-state="blocked">
            The device shares no screen or input yet. Wait for user consent, or stop the request.
          </p>
        ) : null}
      </div>
      <dl className="grid gap-4 text-sm sm:grid-cols-2">
        {ended ? (
          <>
            <Fact
              label={session.localSession?.username ? "Reason shown to the user" : "Support reason"}
            >
              {session.reason}
            </Fact>
            {session.startedAt ? <Fact label="Duration">{sessionDuration(session)}</Fact> : null}
            {person ? <Fact label="Device user during the session">{person}</Fact> : null}
          </>
        ) : (
          <Fact label="Person on the device">{person}</Fact>
        )}
        <Fact label="Requesting admin">{session.operatorDisplay || "Unknown"}</Fact>
        <Fact label="Requested access">{modeLabels[session.mode]}</Fact>
        {!ended ? (
          <Fact label="User's control permission">{control}</Fact>
        ) : session.mode === AssistanceMode.CONTROL && control ? (
          <Fact label="Control permission during the session">{control}</Fact>
        ) : null}
      </dl>
      {ended ? (
        <TechnicalDetails
          summary={session.startedAt ? "Session record" : "Details"}
          className="border-t pt-3 text-sm text-foreground"
          items={identifiers}
        >
          <SessionTimes session={session} ended />
        </TechnicalDetails>
      ) : (
        <details className="border-t pt-3 text-sm">
          <summary className="w-fit cursor-pointer font-medium">Session record</summary>
          <SessionTimes session={session} ended={false} />
        </details>
      )}
      {!ended ? (
        <p className="text-xs text-muted-foreground">
          Remaining time is an estimate from this browser&apos;s clock.
        </p>
      ) : null}
    </section>
  );
}

function SessionTimes({ session, ended }: { session: AssistanceSession; ended: boolean }) {
  const started = Boolean(session.startedAt);
  return (
    <dl className="mt-3 grid gap-4 text-sm sm:grid-cols-2">
      <Fact label="Requested">
        <TimeCell value={session.createdAt} />
      </Fact>
      {started ? (
        <Fact label="Started">
          <TimeCell value={session.startedAt} />
        </Fact>
      ) : null}
      {ended ? (
        <Fact label={couldNotStart(session) ? "Refused" : "Ended"}>
          <TimeCell value={session.endedAt} />
        </Fact>
      ) : null}
      {started || !ended ? (
        <Fact label={ended ? "Original time limit" : "Ends by"}>
          <TimeCell value={session.endsAt} />
        </Fact>
      ) : null}
    </dl>
  );
}

// Time screen sharing was live: start to end. Shown only for sessions that started.
function sessionDuration(session: AssistanceSession): string {
  if (!session.startedAt || !session.endedAt) return "Not recorded";
  const seconds = Math.max(
    0,
    Math.round(
      (timestampDate(session.endedAt).getTime() - timestampDate(session.startedAt).getTime()) /
        1000,
    ),
  );
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  if (hours) return minutes ? `${hours} h ${minutes} min` : `${hours} h`;
  if (minutes) return rest ? `${minutes} min ${rest} sec` : `${minutes} min`;
  return `${rest} sec`;
}

function Fact({
  label,
  className,
  children,
}: {
  label: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className={className ? `min-w-0 ${className}` : "min-w-0"}>
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
                const { queryKey } = assistanceSessionQueryOptions(lifetime, deviceId, sessionId);
                // An older in-flight poll must not replace the confirmed ended record.
                await queryClient.cancelQueries({ queryKey, exact: true });
                queryClient.setQueryData(queryKey, response.session);
              }
              await queryClient.invalidateQueries({
                queryKey: ["assistance-sessions", lifetime.generation, deviceId],
              });
            },
          })
        }
      >
        {exact.busy ? "Stopping…" : exact.ambiguous ? "Try stopping again" : "Stop session"}
      </Button>
      {exact.failure ? <RpcError failure={exact.failure} title="Couldn't stop session" /> : null}
    </div>
  );
}

function AssistanceConnection({
  session,
  deviceId,
  armed,
  sessionAvailable,
}: {
  session: AssistanceSession;
  deviceId: string;
  armed: boolean;
  sessionAvailable: boolean;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const controlHelpId = useId();
  const queryClient = useQueryClient();
  const sessionId = session.id;
  const controlRequested = session.mode === AssistanceMode.CONTROL;
  const ended = session.state === AssistanceState.ENDED;
  const cursorNote = cursorVisibilityNote(ended, session.grantedCapabilities?.cursorHidden);
  const waitingForUser =
    session.state === AssistanceState.REQUESTED || session.state === AssistanceState.PROMPTED;
  const [attempt, setAttempt] = useState(0);
  const [link, setLink] = useState<LinkState>(idleLink);
  const [connectionState, setConnectionState] = useState<RTCPeerConnectionState>("new");
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [channel, setChannel] = useState<RTCDataChannel | null>(null);
  const [channelOpen, setChannelOpen] = useState(false);
  const [fileChannel, setFileChannel] = useState<RTCDataChannel | null>(null);
  const [annotationChannel, setAnnotationChannel] = useState<RTCDataChannel | null>(null);
  const [audioStream, setAudioStream] = useState<MediaStream | null>(null);
  const [pointing, setPointing] = useState(false);
  const annotationSenderRef = useRef<AnnotationSender | null>(null);
  const [filesBusy, setFilesBusy] = useState(false);
  const [inputReady, setInputReady] = useState(false);
  const inputEpochFence = useRef(new InputEpochFence());
  const [controlOn, setControlOn] = useState(false);
  const [message, setMessage] = useState("");
  const [keyboardMode, setKeyboardMode] = useState<KeyboardMode>("text");
  const [actualSize, setActualSize] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [displayError, setDisplayError] = useState("");
  const [frameSize, setFrameSize] = useState({ width: 0, height: 0 });
  const [presentation, setPresentation] = useState({
    ready: false,
    display: "",
    generation: 0,
    metadataAvailable: null as boolean | null,
  });
  const fenceRef = useRef(new DisplayPresentationFence());
  const refreshPresentationRef = useRef(() => {});
  const inputCaptureRef = useRef<InputCapture | null>(null);
  const fullscreenRef = useRef<HTMLDivElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const surfaceRef = useRef<HTMLDivElement | null>(null);
  const frameCoverRef = useRef<HTMLParagraphElement | null>(null);

  useEffect(() => {
    if (!armed) return;
    const controller = new AbortController();
    const signal = AbortSignal.any([controller.signal, lifetime.signal]);
    let pc: RTCPeerConnection | null = null;
    let answerSent = false;
    let inputSeen = false;
    let filesSeen = false;
    let annotationSeen = false;
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
        throw new Error("The server returned a different session. Reload the page.");
      }
      if (!join.offerSdp) throw new Error("The device didn't send its screen. Try again.");
      if (
        join.iceServers.length === 0 ||
        join.iceServers.some(
          (server) =>
            server.urls.length === 0 || server.urls.some((url) => !/^turns?:\S+$/.test(url)),
        )
      ) {
        throw new Error("The server's relay isn't set up correctly. Contact your server admin.");
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
        if (event.track.kind === "audio") {
          // Sound plays only after the user's local choice; the video element stays muted.
          setAudioStream(new MediaStream([event.track]));
          return;
        }
        setStream(event.streams[0] ?? new MediaStream([event.track]));
      });
      peer.addEventListener("datachannel", (event) => {
        const incoming = event.channel;
        const filesAllowed =
          policyMode(join.session?.effectiveCapabilities, "files") >=
            AssistancePolicyMode.LIMITED &&
          policyMode(join.session?.grantedCapabilities?.policy, "files") >=
            AssistancePolicyMode.LIMITED;
        const annotationAllowed =
          policyMode(join.session?.effectiveCapabilities, "annotation") >=
            AssistancePolicyMode.LIMITED &&
          policyMode(join.session?.grantedCapabilities?.policy, "annotation") >=
            AssistancePolicyMode.LIMITED;
        const isInput = incoming.label === INPUT_CHANNEL_LABEL;
        const isFiles = incoming.label === FILE_CHANNEL_LABEL;
        const isAnnotation = incoming.label === ANNOTATION_CHANNEL_LABEL;
        if (
          signal.aborted ||
          (!isInput && !isFiles && !isAnnotation) ||
          (isInput && (!controlRequested || inputSeen)) ||
          (isFiles && (!filesAllowed || filesSeen)) ||
          (isAnnotation && (!annotationAllowed || annotationSeen)) ||
          !incoming.ordered ||
          incoming.maxRetransmits !== null ||
          incoming.maxPacketLifeTime !== null
        ) {
          incoming.close();
          return;
        }
        if (isAnnotation) {
          annotationSeen = true;
          incoming.addEventListener("open", () => {
            if (!signal.aborted) setAnnotationChannel(incoming);
          });
          incoming.addEventListener("close", () => {
            if (!signal.aborted) {
              setAnnotationChannel(null);
              setPointing(false);
            }
          });
          if (incoming.readyState === "open") setAnnotationChannel(incoming);
          return;
        }
        if (isFiles) {
          filesSeen = true;
          incoming.binaryType = "arraybuffer";
          incoming.addEventListener("open", () => {
            if (!signal.aborted) setFileChannel(incoming);
          });
          incoming.addEventListener("close", () => {
            if (!signal.aborted) setFileChannel(null);
          });
          if (incoming.readyState === "open") setFileChannel(incoming);
          return;
        }
        inputSeen = true;
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
        incoming.addEventListener("message", (event: MessageEvent<unknown>) => {
          if (signal.aborted) return;
          const marker = parseDisplayFrameMarker(event.data);
          if (!marker) return;
          fenceRef.current.receive(marker);
          refreshPresentationRef.current();
        });
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
          "Could not reach the server's relay within 10 seconds. Check your network. Retry the connection.",
        );
      }
      const request = create(AnswerAssistanceSessionRequestSchema, { sessionId, answerSdp });
      validateRequest(AnswerAssistanceSessionRequestSchema, request);
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
      setAudioStream(null);
      setAnnotationChannel(null);
      setChannel(null);
      setFileChannel(null);
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
      setAudioStream(null);
      setAnnotationChannel(null);
      setPointing(false);
      setChannel(null);
      setFileChannel(null);
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

  const active =
    sessionAvailable && session.state === AssistanceState.ACTIVE && connectionState === "connected";
  const inputEpoch = session.inputState?.epoch;
  const inputPaused = session.inputState?.paused !== false;
  useLayoutEffect(() => {
    inputCaptureRef.current?.releaseAll();
    setControlOn(false);
    setInputReady(
      inputEpochFence.current.receive(
        inputEpoch === undefined ? undefined : { epoch: inputEpoch, paused: inputPaused },
      ),
    );
  }, [inputEpoch, inputPaused]);
  const commandsActive = active && inputReady && !inputPaused && !filesBusy;
  const commands = useAssistanceCommand(session, commandsActive, () => setMessage(""));
  const frameReady =
    active &&
    !commands.displayPending &&
    presentation.ready &&
    presentation.display === session.selectedDisplayId &&
    presentation.generation === session.displayGeneration;
  const controlAvailable =
    frameReady &&
    inputReady &&
    !inputPaused &&
    !filesBusy &&
    session.controlGranted &&
    channel !== null &&
    channelOpen;
  const capturing = controlOn && controlAvailable;

  // Reconcile all three independent clocks before paint. Marker receipt also
  // calls this synchronously, hiding an obsolete frame and releasing held input
  // without waiting for a React render or the next video callback.
  useLayoutEffect(() => {
    const fence = fenceRef.current;
    inputCaptureRef.current?.releaseAll();
    setControlOn(false);
    fence.select(session.selectedDisplayId, session.displayGeneration);
    if (!active) fence.clearPresentation();
    const refresh = () => {
      const ready = active && !commands.displayPending && fence.ready;
      if (frameCoverRef.current) frameCoverRef.current.style.display = ready ? "none" : "grid";
      if (!ready) {
        inputCaptureRef.current?.releaseAll();
        setControlOn(false);
      }
      setPresentation((current) =>
        current.ready === ready &&
        current.display === session.selectedDisplayId &&
        current.generation === session.displayGeneration &&
        current.metadataAvailable === fence.metadataAvailable
          ? current
          : {
              ready,
              display: session.selectedDisplayId,
              generation: session.displayGeneration,
              metadataAvailable: fence.metadataAvailable,
            },
      );
    };
    refreshPresentationRef.current = refresh;
    refresh();
  }, [active, commands.displayPending, session.selectedDisplayId, session.displayGeneration]);

  // VIEW never gets an input channel. Its exact media marker arrives in the
  // session projection, independent of the separately consented files channel.
  useLayoutEffect(() => {
    const marker = session.displayFrame;
    if (!sessionAvailable || !marker) return;
    fenceRef.current.receive({
      t: "display-frame",
      display: marker.displayId,
      generation: marker.generation,
      rtpTimestamp: marker.rtpTimestamp,
    });
    refreshPresentationRef.current();
  }, [sessionAvailable, session.displayFrame]);

  useEffect(() => {
    const video = videoRef.current;
    if (!video || !stream) return;
    const fence = fenceRef.current;
    fence.clearPresentation();
    if (typeof video.requestVideoFrameCallback !== "function") {
      fence.present(undefined);
      refreshPresentationRef.current();
      return;
    }
    let callback = 0;
    const presented: VideoFrameRequestCallback = (_now, metadata) => {
      fence.present(metadata.rtpTimestamp);
      refreshPresentationRef.current();
      callback = video.requestVideoFrameCallback(presented);
    };
    refreshPresentationRef.current();
    callback = video.requestVideoFrameCallback(presented);
    return () => {
      video.cancelVideoFrameCallback(callback);
      fence.clearPresentation();
    };
  }, [stream]);
  const requiredKeyboardMode =
    keyboardMode === "physical" ? AssistancePolicyMode.ON : AssistancePolicyMode.LIMITED;
  const keyboardAllowed =
    canPermission(principal, "remote_assistance.keyboard") &&
    policyMode(session.effectiveCapabilities, "keyboard") >= requiredKeyboardMode &&
    policyMode(session.grantedCapabilities?.policy, "keyboard") >= requiredKeyboardMode;
  const displayAllowed =
    active &&
    canPermission(principal, "remote_assistance.display") &&
    policyMode(session.effectiveCapabilities, "display") >= AssistancePolicyMode.LIMITED &&
    policyMode(session.grantedCapabilities?.policy, "display") >= AssistancePolicyMode.LIMITED;
  const controlReason = !controlRequested
    ? ""
    : session.state === AssistanceState.ENDED
      ? "The session has ended, so control is no longer available."
      : !session.controlGranted
        ? session.state === AssistanceState.ACTIVE
          ? "The user allowed viewing only, so you can't control this session."
          : "Control is available after the user accepts and allows it."
        : !active
          ? "Control is available once the screen connects."
          : session.inputState?.paused &&
              session.inputState.pause === AssistanceInputPause.ELEVATION
            ? "Controls are paused while the user enters a password. Only they can resume them."
            : session.inputState?.paused || filesBusy
              ? "Controls are paused during the file request. Choose Take control after it finishes."
              : !inputReady
                ? "Current input permission could not be confirmed. Stop this session and reconnect."
                : presentation.metadataAvailable === false
                  ? "This browser cannot confirm the shared screen. Remote control is unavailable."
                  : !frameReady
                    ? "Wait for the selected screen to appear."
                    : !controlAvailable
                      ? "Wait for the screen and controls to connect."
                      : "";

  useEffect(() => {
    const container = fullscreenRef.current;
    const changed = () => setFullscreen(document.fullscreenElement === container);
    document.addEventListener("fullscreenchange", changed);
    return () => {
      document.removeEventListener("fullscreenchange", changed);
      if (document.fullscreenElement === container)
        void document.exitFullscreen().catch(() => {
          toast.error("Couldn't exit full screen. Press Escape.");
        });
    };
  }, []);

  async function toggleFullscreen() {
    setControlOn(false);
    setDisplayError("");
    try {
      if (document.fullscreenElement === fullscreenRef.current) await document.exitFullscreen();
      else await fullscreenRef.current?.requestFullscreen();
    } catch {
      setDisplayError("Couldn't change full screen. Check your browser's permissions.");
    }
  }

  useLayoutEffect(() => {
    const surface = surfaceRef.current;
    const video = videoRef.current;
    if (!capturing || !surface || !video || !channel || inputEpoch === undefined) return;
    const capture = new InputCapture(
      channel,
      session.selectedDisplayId,
      session.displayGeneration,
      inputEpoch,
    );
    inputCaptureRef.current = capture;
    const currentFrame = () => fenceRef.current.ready && channel.readyState === "open";
    const point = (event: PointerEvent) =>
      currentFrame()
        ? videoFramePoint(video, event.clientX, event.clientY, capture.dragging)
        : null;
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
      if (!currentFrame()) return;
      const next = point(event);
      if (next) capture.move(next);
      if (capture.button(event.button, false)) event.preventDefault();
      if (surface.hasPointerCapture(event.pointerId))
        surface.releasePointerCapture(event.pointerId);
    };
    const onWheel = (event: WheelEvent) => {
      if (!currentFrame()) return;
      if (!videoFramePoint(video, event.clientX, event.clientY, false)) return;
      event.preventDefault();
      capture.wheel(event);
    };
    const onKey = (event: KeyboardEvent) => {
      if (!keyboardAllowed || !currentFrame()) return;
      if (capture.key(event, keyboardMode)) event.preventDefault();
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
    const visibility = () => {
      if (document.hidden) release();
    };
    document.addEventListener("visibilitychange", visibility);
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
      document.removeEventListener("visibilitychange", visibility);
      inputCaptureRef.current = null;
      capture.dispose();
    };
  }, [
    capturing,
    channel,
    keyboardAllowed,
    keyboardMode,
    session.selectedDisplayId,
    session.displayGeneration,
    inputEpoch,
  ]);

  // Pointing never uses the input channel: frames go only to the overlay channel
  // and carry no clicks or keys, so it is unavailable while control is on.
  const marksGranted =
    policyMode(session.grantedCapabilities?.policy, "annotation") === AssistancePolicyMode.ON;
  const pointingActive =
    pointing &&
    session.annotation?.enabled === true &&
    frameReady &&
    !capturing &&
    annotationChannel !== null;
  useLayoutEffect(() => {
    const surface = surfaceRef.current;
    const video = videoRef.current;
    if (!pointingActive || !surface || !video || !annotationChannel) return;
    const sender = new AnnotationSender(
      annotationChannel,
      session.selectedDisplayId,
      session.displayGeneration,
      marksGranted,
    );
    annotationSenderRef.current = sender;
    let drawing = false;
    const point = (event: PointerEvent) =>
      fenceRef.current.ready ? videoFramePoint(video, event.clientX, event.clientY, drawing) : null;
    const onMove = (event: PointerEvent) => {
      const next = point(event);
      if (!next) return;
      if (drawing) sender.extendStroke(next);
      else sender.pointer(next);
    };
    const onDown = (event: PointerEvent) => {
      const next = point(event);
      if (!next) return;
      event.preventDefault();
      drawing = sender.beginStroke(next);
      if (drawing) surface.setPointerCapture(event.pointerId);
    };
    const onUp = (event: PointerEvent) => {
      if (!drawing) return;
      const next = point(event);
      if (next) sender.extendStroke(next);
      sender.endStroke();
      drawing = false;
      if (surface.hasPointerCapture(event.pointerId))
        surface.releasePointerCapture(event.pointerId);
    };
    surface.addEventListener("pointermove", onMove);
    surface.addEventListener("pointerdown", onDown);
    surface.addEventListener("pointerup", onUp);
    surface.addEventListener("pointercancel", onUp);
    return () => {
      surface.removeEventListener("pointermove", onMove);
      surface.removeEventListener("pointerdown", onDown);
      surface.removeEventListener("pointerup", onUp);
      surface.removeEventListener("pointercancel", onUp);
      sender.dispose();
      annotationSenderRef.current = null;
    };
  }, [
    pointingActive,
    annotationChannel,
    marksGranted,
    session.selectedDisplayId,
    session.displayGeneration,
  ]);

  const precondition = link.failure ? assistanceFailureMessage(link.failure) : "";
  const attachedElsewhere =
    link.stage === "idle" &&
    (session.state === AssistanceState.ANSWERED || session.state === AssistanceState.ACTIVE);

  return (
    <div
      ref={fullscreenRef}
      data-assistance-fullscreen
      className={
        fullscreen ? "flex h-dvh min-h-0 flex-col overflow-hidden bg-background" : "bg-background"
      }
    >
      <Card className={fullscreen ? "flex min-h-0 flex-1 flex-col overflow-hidden" : undefined}>
        <CardHeader className="shrink-0">
          <CardTitle className="flex flex-wrap items-center justify-between gap-3">
            <h2>Screen</h2>
            <div className="flex flex-wrap items-center gap-2 text-sm font-normal">
              <span className="text-muted-foreground">
                {link.stage === "answered"
                  ? (mediaLabels[connectionState] ?? "Connecting")
                  : stageLabels[link.stage]}
              </span>
              {controlRequested ? (
                <Button
                  variant={capturing ? "default" : "outline"}
                  aria-describedby={controlReason ? controlHelpId : undefined}
                  disabled={!controlOn && (!controlAvailable || ended)}
                  onClick={() => {
                    if (controlOn) {
                      inputCaptureRef.current?.releaseAll();
                      setControlOn(false);
                    } else if (controlAvailable && fenceRef.current.ready) setControlOn(true);
                  }}
                >
                  {controlOn ? "Release control" : "Take control"}
                </Button>
              ) : null}
              <Button
                variant="outline"
                disabled={!fullscreen && (!displayAllowed || !document.fullscreenEnabled)}
                aria-describedby="assistance-display-help"
                onClick={() => void toggleFullscreen()}
              >
                {fullscreen ? "Exit full screen" : "Full screen"}
              </Button>
              {fullscreen && !ended ? (
                <StopButton sessionId={session.id} deviceId={deviceId} />
              ) : null}
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className={fullscreen ? "grid min-h-0 gap-3 overflow-y-auto" : "grid gap-3"}>
          {controlReason ? (
            <p id={controlHelpId} className="text-sm text-muted-foreground">
              {controlReason}
            </p>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              aria-pressed={!actualSize}
              disabled={!displayAllowed}
              aria-describedby="assistance-display-help"
              onClick={() => {
                setControlOn(false);
                setActualSize(false);
              }}
            >
              Fit
            </Button>
            <Button
              variant="outline"
              aria-pressed={actualSize}
              disabled={!displayAllowed}
              aria-describedby="assistance-display-help"
              onClick={() => {
                setControlOn(false);
                setActualSize(true);
              }}
            >
              Actual size
            </Button>
          </div>
          <p id="assistance-display-help" className="text-sm text-muted-foreground">
            {!displayAllowed
              ? "Display adjustments require an active session and permission from the policy and user."
              : !document.fullscreenEnabled
                ? "This browser does not allow full screen."
                : "Choose how the shared display fits in this window."}
          </p>
          {displayError ? (
            <p role="alert" className="text-sm text-destructive">
              {displayError}
            </p>
          ) : null}
          {waitingForUser ? (
            <p role="status">
              Waiting for the user to accept. Keep this page open. Leaving cancels the request.
            </p>
          ) : null}
          {attachedElsewhere ? (
            <Alert>
              <AlertTitle>Open in another tab</AlertTitle>
              <AlertDescription>
                Another page has this session's connection. Stop that session before requesting a
                new one here.
              </AlertDescription>
            </Alert>
          ) : null}
          {link.failure ? (
            <RpcError failure={link.failure} title="Couldn't connect">
              {precondition ? <p>{precondition}</p> : null}
            </RpcError>
          ) : null}
          {link.error ? (
            <Alert variant="destructive">
              <AlertTitle>Couldn't connect</AlertTitle>
              <AlertDescription>{link.error}</AlertDescription>
            </Alert>
          ) : null}
          {link.stage === "failed" &&
          link.retryable &&
          session.state === AssistanceState.OFFERED ? (
            <Button
              variant="outline"
              className="w-fit"
              onClick={() => setAttempt((current) => current + 1)}
            >
              Try again
            </Button>
          ) : null}
          {connectionState === "failed" ? (
            <p role="alert" className="text-sm text-destructive">
              The connection was lost. The session will end.
            </p>
          ) : null}
          {waitingForUser ? <UserSidePreview session={session} /> : null}
          {cursorNote ? (
            <p role="status" className="text-sm text-muted-foreground">
              {cursorNote}
            </p>
          ) : null}
          <div className="relative" hidden={waitingForUser}>
            <div
              ref={surfaceRef}
              tabIndex={capturing ? 0 : -1}
              role="region"
              aria-label="Remote screen"
              aria-describedby={
                capturing
                  ? `${controlHelpId}-capture`
                  : pointingActive
                    ? `${controlHelpId}-pointing`
                    : undefined
              }
              className={
                capturing
                  ? "relative aspect-video w-full touch-none overflow-auto bg-viewer outline-none ring-2 ring-destructive"
                  : "relative aspect-video w-full overflow-auto bg-viewer"
              }
            >
              <video
                ref={videoRef}
                className={
                  actualSize && displayAllowed
                    ? "pointer-events-none max-w-none object-contain"
                    : "pointer-events-none size-full object-contain"
                }
                style={
                  actualSize && displayAllowed && frameSize.width
                    ? { width: frameSize.width, height: frameSize.height }
                    : undefined
                }
                onLoadedMetadata={(event) =>
                  setFrameSize({
                    width: event.currentTarget.videoWidth,
                    height: event.currentTarget.videoHeight,
                  })
                }
                onResize={(event) =>
                  setFrameSize({
                    width: event.currentTarget.videoWidth,
                    height: event.currentTarget.videoHeight,
                  })
                }
                autoPlay
                playsInline
                muted
                disablePictureInPicture
              />
              {stream && controlAvailable && !capturing ? (
                <p className="pointer-events-none absolute bottom-2 left-2 bg-viewer/70 p-2 text-sm text-viewer-foreground">
                  Select Take control to use the mouse and keyboard.
                </p>
              ) : null}
            </div>
            {/* Keep the video rendering for presentation metadata; cover stale pixels
              outside its scroll area so actual-size panning cannot expose them. */}
            <p
              ref={frameCoverRef}
              role="status"
              style={{ display: frameReady ? "none" : "grid" }}
              className="absolute inset-0 place-items-center bg-viewer p-3 text-center text-sm text-viewer-foreground/70"
            >
              {ended
                ? "Session ended"
                : !sessionAvailable
                  ? "Session details unavailable. You cannot use controls."
                  : !stream
                    ? "No video yet"
                    : !active
                      ? "Connection interrupted. You cannot use controls."
                      : presentation.metadataAvailable === false
                        ? "This browser cannot confirm the shared screen. Use a browser with RTP presentation metadata."
                        : "Waiting for the selected screen…"}
            </p>
          </div>
          {capturing ? (
            <p id={`${controlHelpId}-capture`} className="text-sm text-muted-foreground">
              Control is on. Your keys and clicks go to the device. Select outside the screen to
              release the keyboard.
            </p>
          ) : pointingActive ? (
            <p id={`${controlHelpId}-pointing`} className="text-sm text-muted-foreground">
              Your pointer is shown on the device; nothing is clicked or typed.
            </p>
          ) : null}
          <AssistanceControls
            session={session}
            active={commandsActive}
            controlOn={capturing}
            frameReady={frameReady}
            commands={commands}
            message={message}
            onMessage={setMessage}
            onSpecialKey={(specialKey) => {
              if (!capturing || !fenceRef.current.ready || channel?.readyState !== "open") return;
              inputCaptureRef.current?.releaseAll();
              setControlOn(false);
              void commands.run({ kind: AssistanceCommandKind.SPECIAL_KEYS, specialKey });
            }}
            keyboardMode={keyboardMode}
            onKeyboardMode={setKeyboardMode}
            releaseControl={() => {
              inputCaptureRef.current?.releaseAll();
              setControlOn(false);
            }}
            portalContainer={fullscreenRef}
          />
          <AssistanceGuidance
            session={session}
            active={commandsActive}
            commands={commands}
            pointing={pointingActive}
            onPointing={setPointing}
            annotationReady={annotationChannel !== null && frameReady && !capturing}
            onClearMarks={() => {
              if (!annotationChannel) return;
              (
                annotationSenderRef.current ??
                new AnnotationSender(
                  annotationChannel,
                  session.selectedDisplayId,
                  session.displayGeneration,
                  marksGranted,
                )
              ).clear();
            }}
            audioStream={audioStream}
            releaseControl={() => {
              inputCaptureRef.current?.releaseAll();
              setControlOn(false);
            }}
          />
          <AssistanceFiles
            key={session.id}
            session={session}
            channel={fileChannel}
            active={active}
            commandsBusy={commands.busy}
            onBusy={setFilesBusy}
            releaseControl={() => {
              inputCaptureRef.current?.releaseAll();
              setControlOn(false);
            }}
          />
        </CardContent>
      </Card>
    </div>
  );
}

// What the person at the device sees while the request waits, mirroring the
// desktop agent's consent notification (internal/agent/desktop/session.go
// promptNotification and capabilities.go capabilityConsentText): a persistent
// critical notification with Allow and Decline, then the desktop's own
// screen-sharing dialog after Allow.
function UserSidePreview({ session }: { session: AssistanceSession }) {
  const control = session.mode === AssistanceMode.CONTROL;
  const operator = session.operatorDisplay || "The requesting admin";
  const prompted = session.state === AssistanceState.PROMPTED;
  // The agent asks only for features both requested and allowed by the policy.
  const consented = (field: CapabilityField) =>
    Math.min(
      policyMode(session.requestedCapabilities, field),
      policyMode(session.effectiveCapabilities, field),
    );
  const clipboard = consented("clipboard");
  const keyboard = consented("keyboard");
  const capabilityLines = [
    clipboard === AssistancePolicyMode.LIMITED
      ? "Clipboard: the operator can send plain text to your clipboard. They cannot read it."
      : clipboard === AssistancePolicyMode.ON
        ? "Clipboard: the operator can send plain text to your clipboard and request its text."
        : "",
    keyboard === AssistancePolicyMode.LIMITED
      ? "Keyboard: the operator can send printable symbols only. They cannot send shortcuts."
      : keyboard === AssistancePolicyMode.ON
        ? "Keyboard: the operator can send text, physical keys and shortcuts."
        : "",
    consented("display") === AssistancePolicyMode.ON
      ? "Displays: the operator can switch between the monitors you select in the system dialog."
      : "",
    consented("messages") !== AssistancePolicyMode.OFF
      ? "Messages: the operator can send plain-text notifications during this session."
      : "",
  ].filter(Boolean);
  return (
    <section
      aria-label="What the user sees"
      data-assistance-user-side
      className="grid gap-3 rounded-md border bg-muted/30 p-4 text-sm"
    >
      <h3 className="font-semibold">What the user sees</h3>
      <p className="text-muted-foreground">
        {prompted
          ? "The device shows this notification until the user chooses Allow or Decline."
          : "The device has not shown the request yet."}
      </p>
      <div className="grid max-w-md gap-2 rounded-md border bg-background p-3 shadow-sm">
        <p className="font-medium">Remote assistance request</p>
        <p>
          {!control
            ? `${operator} asks to view your screen.`
            : keyboard !== AssistancePolicyMode.OFF
              ? `${operator} asks to view your screen and control your keyboard and pointer.`
              : `${operator} asks to view your screen and control your pointer. Keyboard control is not requested.`}
        </p>
        <p>Reason: {session.reason}</p>
        <p>
          {control
            ? "The operator requests control. You can allow viewing only in the system dialog."
            : "The operator does not request control. Select the shared screen in the system dialog."}
        </p>
        {capabilityLines.map((line) => (
          <p key={line}>{line}</p>
        ))}
        <div className="flex gap-2" aria-hidden="true">
          <span className="rounded-md border px-3 py-1">Allow</span>
          <span className="rounded-md border px-3 py-1">Decline</span>
        </div>
      </div>
      <p className="text-muted-foreground">
        If they choose Allow, their desktop asks which screen to share
        {control ? " and whether to allow control" : ""}. The device shares nothing until they
        confirm it.
      </p>
    </section>
  );
}
