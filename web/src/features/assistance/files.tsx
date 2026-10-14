// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { ConnectError } from "@connectrpc/connect";
import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import {
  StartAssistanceFileTransferRequestSchema,
  type AssistanceSession,
} from "../../../gen/lindm/admin/v1/assistance_pb";
import { AssistanceMode, AssistancePolicyMode } from "../../../gen/lindm/agent/v1/assistance_pb";
import {
  AssistanceFileDirection,
  AssistanceFileReportSchema,
  AssistanceFileState,
  type AssistanceFileMetadata,
  type AssistanceFileReport,
} from "../../../gen/lindm/agent/v1/assistance_files_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { policyMode } from "./capabilities";
import { ASSISTANCE_CONTROL_PERMISSION, ASSISTANCE_VIEW_PERMISSION } from "./display";
import { FileLimitsSummary } from "./file-policy";
import {
  FileCleanupError,
  FileRemoteCancellationError,
  FileTransferStream,
  awaitFileOperation,
  decodeFileFrame,
  prepareFile,
  retireFileRequest,
  sameFile,
  type FileDestination,
} from "./files-stream";
import { validateRequest } from "@/lib/validation";

// The DOM library does not declare this limited-availability browser API.
// The implementation is always the browser's picker, never an injected fallback.
type SavePickerWindow = Window & {
  showSaveFilePicker?: (options: { suggestedName: string }) => Promise<{
    createWritable: (options: { keepExistingData: false }) => Promise<FileDestination>;
  }>;
};

type Operation = {
  requestId: string;
  direction: AssistanceFileDirection;
  controller: AbortController;
  stream: FileTransferStream | null;
  channel: RTCDataChannel | null;
  submitted: boolean;
  running: boolean;
  cancellation: Promise<void> | null;
  cleanupFailed: boolean;
  terminal: boolean;
  report: AssistanceFileReport | null;
  verified: AssistanceFileMetadata | null;
  deadline: number;
};

function terminalReport(report: AssistanceFileReport) {
  return report.state >= AssistanceFileState.SUCCEEDED;
}

const failureCopy: Record<string, string> = {
  file_published_unconfirmed:
    "The file may have been saved, but confirmation failed. Check Downloads on the device before sending again.",
  file_type_denied:
    "This file type is not allowed. Review the file limits before trying another file.",
  file_size_denied: "This file exceeds the allowed size. Choose a smaller file.",
  file_digest_mismatch:
    "The file contents could not be verified. Check the source before trying again.",
  file_source_changed:
    "The selected file changed during transfer. Ask the user to select it again.",
  file_protocol_invalid:
    "The file connection sent unexpected data. Stop the session and reconnect.",
};

export function AssistanceFiles({
  session,
  channel,
  active,
  commandsBusy,
  releaseControl,
  onBusy,
}: {
  session: AssistanceSession;
  channel: RTCDataChannel | null;
  active: boolean;
  commandsBusy: boolean;
  releaseControl: () => void;
  onBusy: (busy: boolean) => void;
}) {
  const id = useId();
  const principal = usePrincipal();
  const lifetime = useAuthLifetime();
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [checking, setChecking] = useState(false);
  const [status, setStatus] = useState("");
  const [bytes, setBytes] = useState(0);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [error, setError] = useState("");
  const [report, setReport] = useState<AssistanceFileReport | null>(null);
  const operation = useRef<Operation | null>(null);
  const [retiredRequests] = useState(() => new Set<string>());
  const mounted = useRef(true);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const policy = session.effectiveCapabilities?.fileLimits;
  const granted = session.grantedCapabilities?.policy;
  const allowed =
    canPermission(principal, ASSISTANCE_VIEW_PERMISSION) &&
    (session.mode === AssistanceMode.VIEW ||
      (session.mode === AssistanceMode.CONTROL &&
        canPermission(principal, ASSISTANCE_CONTROL_PERMISSION))) &&
    canPermission(principal, "remote_assistance.files") &&
    session.operatorId === principal.id;
  const browserSave =
    window.isSecureContext && typeof (window as SavePickerWindow).showSaveFilePicker === "function";
  const mode = Math.min(
    policyMode(session.effectiveCapabilities, "files"),
    policyMode(granted, "files"),
  );
  const enabled =
    active &&
    allowed &&
    !!policy &&
    mode >= AssistancePolicyMode.LIMITED &&
    channel?.readyState === "open";
  const latest = useRef({ enabled, channel, mode, policy });

  useLayoutEffect(() => {
    latest.current = { enabled, channel, mode, policy };
    if (
      !enabled ||
      (operation.current?.running && operation.current.channel !== channel) ||
      (operation.current?.direction === AssistanceFileDirection.FROM_USER &&
        mode < AssistancePolicyMode.ON)
    ) {
      setFile(null);
      if (fileInput.current) fileInput.current.value = "";
      operation.current?.controller.abort(
        new Error("File access ended. Check the result before sending again."),
      );
    }
  }, [enabled, channel, mode, policy]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      operation.current?.controller.abort(new Error("The session page closed."));
      operation.current?.stream?.dispose();
    };
  }, []);

  useEffect(() => {
    if (!channel) return;
    const unsolicited = (event: MessageEvent<unknown>) => {
      if (operation.current?.stream && !operation.current.terminal) return;
      try {
        if (retiredRequests.has(decodeFileFrame(event.data).requestId)) return;
      } catch {
        // Malformed late traffic is still a protocol failure.
      }
      channel.close();
    };
    channel.addEventListener("message", unsolicited);
    return () => channel.removeEventListener("message", unsolicited);
  }, [channel, retiredRequests]);

  function retire(op: Operation): boolean {
    try {
      retireFileRequest(retiredRequests, op.requestId);
      return true;
    } catch (cause) {
      op.controller.abort(cause);
      op.channel?.close();
      return false;
    }
  }

  function finish(op: Operation, next: AssistanceFileReport) {
    if (!retire(op)) return;
    op.report = next;
    op.terminal = true;
    if (!mounted.current || lifetime.signal.aborted || operation.current !== op) return;
    setReport(next);
    // The running task keeps controls locked until its stream and cleanup have joined.
    setUncertain(op.cleanupFailed);
    if (next.state === AssistanceFileState.SUCCEEDED) {
      if (!op.verified || !next.file || !sameFile(op.verified, next.file)) {
        setStatus("Completion could not be verified. Check the destination before sending again.");
        setUncertain(true);
        return;
      }
      setStatus(
        op.direction === AssistanceFileDirection.TO_USER
          ? "File verified and saved in the user's Downloads."
          : "File verified and saved to your chosen destination.",
      );
      setError("");
      setFailure(null);
    } else if (next.state === AssistanceFileState.CANCELLED) {
      setStatus("Transfer cancelled. Check the destination if saving had already started.");
    } else if (next.state === AssistanceFileState.DENIED) {
      setStatus("The file was not approved. Ask the user before trying again.");
    } else {
      setStatus(
        failureCopy[next.reason] ??
          "The transfer did not finish. Check the destination and transfer details before trying again.",
      );
    }
  }

  function acceptReport(
    op: Operation,
    next: AssistanceFileReport | undefined,
  ): AssistanceFileReport {
    if (!next || next.requestId !== op.requestId || next.direction !== op.direction)
      throw new Error("The file result does not match this operation. Stop the session.");
    validateRequest(AssistanceFileReportSchema, next);
    if (op.report && next.state < op.report.state)
      throw new Error("The file result is out of date. Stop the session.");
    if (op.report && terminalReport(op.report) && next.state !== op.report.state)
      throw new Error("The completed file result changed. Stop the session.");
    op.report = next;
    if (mounted.current && !lifetime.signal.aborted && operation.current === op) setReport(next);
    return next;
  }

  function cancelOperation(op: Operation): Promise<void> {
    if (op.cancellation) return op.cancellation;
    if (op.submitted && !retire(op)) return Promise.resolve();
    op.controller.abort(new Error("The transfer was cancelled."));
    if (!op.submitted || op.terminal || lifetime.signal.aborted) return Promise.resolve();
    // The UI task and the cancellation button join the same RPC. In particular,
    // aborting the poll cannot dispose authority while its cancellation runs.
    op.cancellation = (async () => {
      try {
        const response = await adminClient.cancelAssistanceFileTransfer(
          { sessionId: session.id, requestId: op.requestId },
          { signal: lifetime.signal, timeoutMs: 10_000 },
        );
        const next = acceptReport(op, response.transfer);
        if (terminalReport(next)) finish(op, next);
        else if (mounted.current) setUncertain(true);
      } catch (cause) {
        if (mounted.current && !lifetime.signal.aborted) {
          setFailure(toRpcFailure(cause));
          setUncertain(true);
          setStatus("Couldn't confirm cancellation. Check the result or stop the session.");
        }
      }
    })();
    return op.cancellation;
  }

  async function checkResult() {
    const op = operation.current;
    if (!op?.submitted || checking) return;
    setChecking(true);
    try {
      const response = await adminClient.getAssistanceFileTransfer(
        { sessionId: session.id, requestId: op.requestId },
        { signal: lifetime.signal, timeoutMs: 10_000 },
      );
      const next = acceptReport(op, response.transfer);
      if (terminalReport(next)) finish(op, next);
      else
        setStatus(
          "Still waiting for a confirmed outcome. Cancel the transfer or stop the session.",
        );
    } catch (cause) {
      if (!lifetime.signal.aborted) setFailure(toRpcFailure(cause));
    } finally {
      if (mounted.current) setChecking(false);
    }
  }

  async function start(direction: AssistanceFileDirection) {
    if (
      operation.current &&
      (operation.current.running || !operation.current.terminal || uncertain)
    )
      return;
    if (!latest.current.enabled || commandsBusy || session.inputState?.paused !== false) return;
    const sourceFile = direction === AssistanceFileDirection.TO_USER ? file : null;
    if (direction === AssistanceFileDirection.TO_USER && !sourceFile) return;
    if (
      direction === AssistanceFileDirection.FROM_USER &&
      (!browserSave || mode < AssistancePolicyMode.ON)
    )
      return;
    const op: Operation = {
      requestId: newRequestId(),
      direction,
      controller: new AbortController(),
      stream: null,
      channel,
      submitted: false,
      terminal: false,
      report: null,
      verified: null,
      running: true,
      cancellation: null,
      cleanupFailed: false,
      deadline: Math.min(
        Date.now() + 300_000,
        session.endsAt ? timestampDate(session.endsAt).getTime() : Date.now(),
      ),
    };
    operation.current = op;
    const signal = AbortSignal.any([op.controller.signal, lifetime.signal]);
    const timer = window.setTimeout(
      () =>
        op.controller.abort(
          new Error("The transfer expired. Check the result before trying again."),
        ),
      Math.max(0, op.deadline - Date.now()),
    );
    let destination: FileDestination | null = null;
    let streamOwnsDestination = false;
    let transfer: Promise<void> | null = null;
    let openingPending = false;
    let discarding: Promise<void> | null = null;
    const discardDestination = () => {
      if (!destination) return Promise.resolve();
      if (!discarding) {
        const writable = destination;
        discarding = awaitFileOperation(
          Promise.resolve().then(() => writable.abort(signal.reason)),
          AbortSignal.timeout(10_000),
        ).catch(() => {
          op.cleanupFailed = true;
          if (mounted.current && operation.current === op) {
            setUncertain(true);
            setError(
              "Couldn't confirm removal of the unfinished download. Check the destination and stop the session.",
            );
          }
        });
      }
      return discarding;
    };
    setBusy(true);
    setSubmitted(false);
    onBusy(true);
    releaseControl();
    setReport(null);
    setBytes(0);
    setError("");
    setFailure(null);
    setUncertain(false);
    try {
      signal.throwIfAborted();
      if (direction === AssistanceFileDirection.FROM_USER) {
        setStatus("Choose where to save the file on this computer.");
        // Must remain before the first await/RPC, while the Request file click is active.
        const selected = await awaitFileOperation(
          (window as SavePickerWindow).showSaveFilePicker!({ suggestedName: "assistance-file" }),
          signal,
        );
        signal.throwIfAborted();
        openingPending = true;
        const opening = selected.createWritable({ keepExistingData: false }).then(
          async (writable) => {
            destination = writable;
            openingPending = false;
            if (signal.aborted) {
              await discardDestination();
              throw signal.reason;
            }
          },
          (cause: unknown) => {
            openingPending = false;
            throw cause;
          },
        );
        await awaitFileOperation(opening, signal);
        signal.throwIfAborted();
      }
      const current = latest.current;
      if (
        !current.enabled ||
        current.channel !== channel ||
        !current.policy ||
        (direction === AssistanceFileDirection.FROM_USER && current.mode < AssistancePolicyMode.ON)
      )
        throw new Error("File access changed. Stop the session before trying again.");
      setStatus(sourceFile ? "Checking the selected file…" : "Waiting for local file selection");
      const metadata = sourceFile
        ? await prepareFile(sourceFile, current.policy, signal, setBytes)
        : null;
      signal.throwIfAborted();
      setBytes(0);
      setFile(null);
      if (fileInput.current) fileInput.current.value = "";
      const stream = new FileTransferStream(channel!, op.requestId, signal, retiredRequests);
      op.stream = stream;
      streamOwnsDestination = true;
      // Attach completion/error handlers immediately; the bounded mailbox waits for authorization.
      transfer = stream
        .transfer(
          direction,
          current.policy,
          sourceFile && metadata ? { file: sourceFile, metadata } : null,
          destination,
          (count) => {
            if (mounted.current && !signal.aborted) {
              setBytes(count);
              setStatus("Transferring file…");
            }
          },
        )
        .then((verified) => {
          op.verified = verified;
          if (mounted.current && !signal.aborted)
            setStatus("File contents verified. Confirming completion…");
        })
        .catch((cause: unknown) => {
          if (cause instanceof FileRemoteCancellationError && !signal.aborted) {
            // Device denial can overtake its next authenticated Sync report.
            // Keep reading the same operation; do not race it with an operator
            // Cancel mutation that would overwrite the local refusal outcome.
            if (mounted.current) setStatus("Waiting for the device to confirm the file result.");
            return;
          }
          if (cause instanceof FileCleanupError) op.cleanupFailed = true;
          op.controller.abort(cause);
        });
      const request = create(StartAssistanceFileTransferRequestSchema, {
        sessionId: session.id,
        transfer: { requestId: op.requestId, direction, file: metadata ?? undefined },
      });
      validateRequest(StartAssistanceFileTransferRequestSchema, request);
      op.submitted = true;
      setSubmitted(true);
      // Never retry this mutation. Ambiguous acceptance retains its original identity for reads/cancel.
      const response = await adminClient
        .startAssistanceFileTransfer(request, { signal, timeoutMs: 10_000 })
        .catch((cause: unknown) => {
          if (!toRpcFailure(cause).ambiguous) {
            op.submitted = false;
            if (mounted.current) setSubmitted(false);
          }
          throw cause;
        });
      signal.throwIfAborted();
      acceptReport(op, response.transfer);
      setStatus(
        direction === AssistanceFileDirection.TO_USER
          ? "Waiting for local approval"
          : "Waiting for local file selection",
      );
      for (;;) {
        signal.throwIfAborted();
        const response = await adminClient.getAssistanceFileTransfer(
          { sessionId: session.id, requestId: op.requestId },
          { signal, timeoutMs: 10_000 },
        );
        signal.throwIfAborted();
        const next = acceptReport(op, response.transfer);
        if (
          next.state === AssistanceFileState.TRANSFERRING &&
          !(stream.signal.reason instanceof FileRemoteCancellationError)
        )
          stream.authorize();
        if (terminalReport(next)) {
          if (next.state === AssistanceFileState.SUCCEEDED) {
            await transfer;
            signal.throwIfAborted();
          } else op.controller.abort(new Error("The transfer ended on the device."));
          finish(op, next);
          break;
        }
        await new Promise<void>((resolve, reject) => {
          const aborted = () => {
            window.clearTimeout(pollTimer);
            reject(signal.reason);
          };
          const pollTimer = window.setTimeout(() => {
            signal.removeEventListener("abort", aborted);
            resolve();
          }, 500);
          signal.addEventListener("abort", aborted, { once: true });
          if (signal.aborted) aborted();
        });
      }
    } catch (cause) {
      op.controller.abort(cause);
      if (mounted.current && !lifetime.signal.aborted) {
        if (cause instanceof ConnectError) setFailure(toRpcFailure(cause));
        else
          setError(
            cause instanceof DOMException
              ? cause.name === "AbortError"
                ? "File selection was cancelled."
                : "The browser could not open the file destination. Check its file permissions and try again."
              : cause instanceof Error
                ? cause.message
                : "The transfer stopped. Check the destination before trying again.",
          );
        setStatus(
          op.verified
            ? "File saved, but completion was not confirmed. Check the result before trying again."
            : "Transfer stopped. Checking cancellation…",
        );
        setUncertain(op.submitted);
      }
      if (op.submitted) await cancelOperation(op);
      else {
        op.terminal = true;
        if (mounted.current) setStatus("No file was transferred.");
      }
    } finally {
      window.clearTimeout(timer);
      if (op.submitted) retire(op);
      op.stream?.dispose();
      await transfer;
      op.stream = null;
      op.running = false;
      if (openingPending) op.cleanupFailed = true;
      if (destination && !streamOwnsDestination) await discardDestination();
      if (op.cleanupFailed && mounted.current) {
        setUncertain(true);
        setError(
          "Couldn't confirm removal of the unfinished download. Check the destination and stop the session.",
        );
      }
      if (mounted.current && operation.current === op) {
        setBusy(false);
        onBusy(false);
      }
    }
  }

  const reason = !allowed
    ? "Your role does not allow file transfer. Ask an admin for file-sharing permission."
    : !active
      ? "Connect to an active session before transferring files."
      : policyMode(session.effectiveCapabilities, "files") < AssistancePolicyMode.LIMITED
        ? "Files were not requested or are off in the policy. Request a new session with files enabled."
        : policyMode(granted, "files") < AssistancePolicyMode.LIMITED
          ? "The user or desktop did not allow files. Check desktop file-sharing support and request a new session."
          : !policy
            ? "File limits are unavailable. Ask your server admin to configure them."
            : channel?.readyState !== "open"
              ? "The file connection is unavailable. Stop this session and request a new one."
              : session.inputState?.paused !== false
                ? "Wait for the user's local dialog to finish and the controls to reconnect."
                : commandsBusy
                  ? "Wait for the current assistance request to finish."
                  : uncertain
                    ? submitted
                      ? "Check the previous transfer result before starting another file."
                      : "The browser could not confirm download cleanup. Check your destination and stop the session."
                    : "";
  const requestReason = !browserSave
    ? "Receiving files requires a browser with the File System Access save picker over a secure connection. Use a supported Chromium browser."
    : mode < AssistancePolicyMode.ON
      ? "The policy and user must allow both sending and requesting files. Request a new session with both enabled."
      : reason;
  const disabled = !!reason || busy;

  return (
    <section className="grid gap-3 border-t pt-3" aria-labelledby={`${id}-title`}>
      <h3 id={`${id}-title`} className="font-semibold">
        Files
      </h3>
      <p className="text-sm">
        The user approves incoming files in Downloads and selects outgoing files on the device.
      </p>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-source`}>File to send</Label>
        <Input
          ref={fileInput}
          id={`${id}-source`}
          type="file"
          disabled={disabled}
          accept={policy?.allowedExtensions.join(",")}
          onChange={(event) => setFile(event.target.files?.item(0) ?? null)}
        />
      </div>
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          disabled={disabled || !file}
          aria-describedby={`${id}-send-help`}
          onClick={() => void start(AssistanceFileDirection.TO_USER)}
        >
          Send file
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={!!requestReason || busy}
          aria-describedby={`${id}-request-help`}
          onClick={() => void start(AssistanceFileDirection.FROM_USER)}
        >
          Request file
        </Button>
        {busy || (uncertain && submitted) ? (
          <Button
            type="button"
            variant="outline"
            disabled={checking}
            onClick={() => {
              const op = operation.current;
              if (op) void cancelOperation(op);
            }}
          >
            Cancel transfer
          </Button>
        ) : null}
        {uncertain && submitted ? (
          <Button
            type="button"
            variant="outline"
            disabled={checking || !allowed}
            onClick={() => void checkResult()}
          >
            {checking ? "Checking…" : "Check transfer result"}
          </Button>
        ) : null}
      </div>
      <p id={`${id}-send-help`} className="text-sm text-muted-foreground">
        {reason || "Select one file on this computer, then ask the user to approve it."}
      </p>
      <p id={`${id}-request-help`} className="text-sm text-muted-foreground">
        {requestReason ||
          "Choose a save destination here first, then ask the user to select one file."}
      </p>
      {status ? (
        <p role="status" className="break-words text-sm">
          {status}
        </p>
      ) : null}
      {busy && bytes > 0 ? (
        <p className="text-sm tabular-nums">{bytes.toLocaleString()} bytes processed</p>
      ) : null}
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
      {failure ? <RpcError failure={failure} title="Couldn't confirm the file transfer" /> : null}
      <details className="text-sm">
        <summary className="cursor-pointer">File limits and consent</summary>
        <div className="mt-2 grid gap-2">
          <FileLimitsSummary policy={policy} />
          <p>
            Files travel over the encrypted session, not through server storage. Leaving this page
            cancels unfinished transfers. This browser may ask before replacing a file at your
            chosen destination.
          </p>
          <p>
            Unfinished content is discarded without deleting your chosen destination. A newly
            selected file may remain empty after cancellation.
          </p>
        </div>
      </details>
      <TechnicalDetails
        items={[
          { label: "File capability", value: session.grantedCapabilities?.filesReason },
          { label: "Request ID", value: allowed ? report?.requestId : undefined },
          { label: "Result reason", value: allowed ? report?.reason : undefined },
          {
            label: "Verified SHA-256",
            value:
              allowed && report?.file?.sha256.length
                ? Array.from(report.file.sha256, (byte) => byte.toString(16).padStart(2, "0")).join(
                    "",
                  )
                : undefined,
          },
        ]}
      />
    </section>
  );
}
