// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  RunAssistanceCommandRequestSchema,
  type AssistanceSession,
  type RunAssistanceCommandRequest,
} from "../../../gen/lindm/admin/v1/assistance_pb";
import {
  AssistanceCommandKind,
  AssistanceCommandSchema,
  AssistanceCommandResultSchema,
  AssistanceCommandStatus,
  type AssistanceCommand,
  type AssistanceCommandResult,
} from "../../../gen/lindm/agent/v1/assistance_pb";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { assistanceSessionQueryOptions } from "./queries";
import { checkRequest, validateRequest } from "@/lib/validation";

type PendingCommand = {
  requestId: string;
  kind: AssistanceCommandKind;
  deadline: number;
  contentEpoch: number;
  displayId: string;
  fromGeneration: number;
  submitted: boolean;
};

type DisplayCompletion = {
  result: AssistanceCommandResult;
  displayId: string;
  generation: number;
};

type CommandInput = Pick<AssistanceCommand, "kind"> &
  Partial<Pick<AssistanceCommand, "text" | "specialKey" | "displayId">>;

export type AssistanceCommandController = {
  run: (command: CommandInput) => Promise<void>;
  result: AssistanceCommandResult | null;
  clearResult: () => void;
  clipboardReady: boolean;
  notice: string;
  pending: PendingCommand | null;
  displayPending: boolean;
  busy: boolean;
  failure: RpcFailure | null;
  invalid: string;
  check: () => void;
};

// Mount once for the session, not for the media connection. Pending identity is
// content-free and survives interruptions; an uncertain side effect is only read,
// never resubmitted under a new ID. Clipboard/message content stays out of Query.
export function useAssistanceCommand(
  session: AssistanceSession,
  active: boolean,
  clearContent: () => void,
): AssistanceCommandController {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const exact = useExactRequest<RunAssistanceCommandRequest>();
  const sessionId = session.id;
  const deviceId = session.deviceId;
  const [pending, setPending] = useState<PendingCommand | null>(null);
  const [displayCompletion, setDisplayCompletion] = useState<DisplayCompletion | null>(null);
  const [result, setResult] = useState<AssistanceCommandResult | null>(null);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [notice, setNotice] = useState("");
  const [readAttempt, setReadAttempt] = useState(0);
  const [clipboardReady, setClipboardReady] = useState(false);
  const content = useRef<AssistanceCommand | null>(null);
  const resultRef = useRef<AssistanceCommandResult | null>(null);
  const clearRef = useRef(clearContent);
  const resetRef = useRef(exact.reset);
  const activeRef = useRef(active);
  const visible = useRef(!document.hidden && document.hasFocus());
  const epoch = useRef(0);
  const submitting = useRef(false);
  useLayoutEffect(() => {
    clearRef.current = clearContent;
    resetRef.current = exact.reset;
    activeRef.current = active;
  }, [clearContent, exact.reset, active]);

  const clearSensitive = useCallback(() => {
    epoch.current++;
    if (content.current) content.current.text = "";
    if (resultRef.current) resultRef.current.text = "";
    setClipboardReady(false);
    clearRef.current();
  }, []);

  useLayoutEffect(() => {
    if (!active) clearSensitive();
  }, [active, clearSensitive]);

  useEffect(() => {
    const blur = () => {
      visible.current = false;
      clearSensitive();
    };
    const focus = () => {
      visible.current = !document.hidden;
    };
    const visibility = () => {
      if (document.hidden) blur();
      else focus();
    };
    window.addEventListener("blur", blur);
    window.addEventListener("focus", focus);
    document.addEventListener("visibilitychange", visibility);
    lifetime.signal.addEventListener("abort", blur, { once: true });
    return () => {
      window.removeEventListener("blur", blur);
      window.removeEventListener("focus", focus);
      document.removeEventListener("visibilitychange", visibility);
      lifetime.signal.removeEventListener("abort", blur);
      clearSensitive();
    };
  }, [lifetime.signal, clearSensitive]);

  // A fresh session read is not sufficient by itself: wait until that exact
  // projection has reached the viewer before publishing success/unlocking it.
  useEffect(() => {
    if (
      !active ||
      !displayCompletion ||
      session.selectedDisplayId !== displayCompletion.displayId ||
      session.displayGeneration !== displayCompletion.generation
    )
      return;
    resetRef.current();
    resultRef.current = displayCompletion.result;
    setResult(displayCompletion.result);
    setFailure(null);
    setNotice("");
    setPending(null);
    setDisplayCompletion(null);
  }, [active, displayCompletion, session.selectedDisplayId, session.displayGeneration]);

  useEffect(() => {
    if (!pending?.submitted || displayCompletion) return;
    const controller = new AbortController();
    const signal = AbortSignal.any([controller.signal, lifetime.signal]);
    let timer: number | undefined;
    const poll = async () => {
      try {
        const response = await adminClient.getAssistanceCommand(
          { sessionId, requestId: pending.requestId },
          { signal, timeoutMs: 10_000 },
        );
        signal.throwIfAborted();
        const next = response.result;
        if (!next || next.requestId !== pending.requestId || next.kind !== pending.kind)
          throw new Error("The command response does not match this request.");
        if (checkRequest(AssistanceCommandResultSchema, next))
          throw new Error("The device returned a command result this console can't read.");
        const retainText =
          activeRef.current &&
          visible.current &&
          epoch.current === pending.contentEpoch &&
          Date.now() < pending.deadline + 30_000;
        if (!retainText) next.text = "";
        if (next.status === AssistanceCommandStatus.PENDING) {
          setNotice("Request accepted. Waiting for the device.");
          if (Date.now() < pending.deadline) timer = window.setTimeout(() => void poll(), 500);
          else setNotice("Couldn't confirm completion. Check the result before continuing.");
          return;
        }
        if (next.status === AssistanceCommandStatus.UNSPECIFIED)
          throw new Error("The device has not reported a command outcome.");
        if (
          next.kind === AssistanceCommandKind.SELECT_DISPLAY &&
          next.status === AssistanceCommandStatus.SUCCEEDED
        ) {
          setNotice("Display changed on the device. Confirming the shared screen…");
          const options = assistanceSessionQueryOptions(lifetime, deviceId, sessionId);
          // Do not reuse a read started before the terminal command result.
          await queryClient.cancelQueries({ queryKey: options.queryKey, exact: true });
          signal.throwIfAborted();
          const projection = await adminClient.getAssistanceSession(
            { sessionId },
            { signal, timeoutMs: 10_000 },
          );
          signal.throwIfAborted();
          const selected = projection.session;
          if (
            !selected ||
            selected.id !== sessionId ||
            selected.deviceId !== deviceId ||
            selected.selectedDisplayId !== pending.displayId ||
            selected.displayGeneration <= pending.fromGeneration
          ) {
            throw new Error("Couldn't confirm the selected display. Check the result again.");
          }
          // Cancel any interval read started during reconciliation as well.
          await queryClient.cancelQueries({ queryKey: options.queryKey, exact: true });
          signal.throwIfAborted();
          queryClient.setQueryData(options.queryKey, selected);
          setDisplayCompletion({
            result: next,
            displayId: selected.selectedDisplayId,
            generation: selected.displayGeneration,
          });
          return;
        }
        setFailure(null);
        setNotice("");
        resetRef.current();
        setClipboardReady(
          retainText &&
            next.kind === AssistanceCommandKind.CLIPBOARD_READ &&
            next.status === AssistanceCommandStatus.SUCCEEDED,
        );
        resultRef.current = next;
        setResult(next);
        setPending(null);
      } catch (error) {
        if (!signal.aborted) {
          const nextFailure = toRpcFailure(error);
          setFailure(nextFailure);
          if (
            nextFailure.reason === "assistance_content_expired" &&
            pending.kind === AssistanceCommandKind.CLIPBOARD_READ
          ) {
            resetRef.current();
            setPending(null);
            setNotice("Clipboard text is no longer available. Choose Read clipboard again.");
          }
        }
      }
    };
    void poll();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [pending, displayCompletion, sessionId, deviceId, lifetime, queryClient, readAttempt]);

  async function run(command: CommandInput) {
    if (!activeRef.current || pending || submitting.current) return;
    submitting.current = true;
    exact.reset();
    if (resultRef.current) resultRef.current.text = "";
    resultRef.current = null;
    setResult(null);
    setClipboardReady(false);
    setFailure(null);
    setNotice("");
    await exact.submit({
      capture: () => {
        const request = create(RunAssistanceCommandRequestSchema, {
          sessionId,
          command: create(AssistanceCommandSchema, { ...command, requestId: newRequestId() }),
        });
        command.text = "";
        validateRequest(RunAssistanceCommandRequestSchema, request);
        content.current = request.command ?? null;
        return request;
      },
      discard: (request) => {
        if (request.command) request.command.text = "";
      },
      send: async (request, options) => {
        const current = request.command;
        if (!current) throw new Error("The command is missing.");
        // This deadline bounds result polling only, not execution authority.
        const identity: PendingCommand = {
          requestId: current.requestId,
          kind: current.kind,
          deadline: Date.now() + 35_000,
          contentEpoch: epoch.current,
          displayId: current.displayId,
          fromGeneration: session.displayGeneration,
          submitted: false,
        };
        setPending(identity);
        try {
          const response = await adminClient.runAssistanceCommand(request, options);
          // Treat even a terminal mutation response as acceptance; read a fresh
          // scoped result before presenting completion or clipboard content.
          if (response.result) response.result.text = "";
          if (!options.signal.aborted) setPending({ ...identity, submitted: true });
          return response;
        } catch (error) {
          if (!options.signal.aborted)
            setPending(toRpcFailure(error).ambiguous ? { ...identity, submitted: true } : null);
          throw error;
        } finally {
          current.text = "";
          content.current = null;
          clearRef.current();
        }
      },
      failureTitle: "Assistance command",
      onSuccess: () => {
        setNotice("Request accepted. Waiting for the device.");
      },
    });
    command.text = "";
    submitting.current = false;
  }

  const clearResult = useCallback(() => {
    if (resultRef.current) resultRef.current.text = "";
    resultRef.current = null;
    setResult(null);
    setClipboardReady(false);
  }, []);

  return {
    run,
    result,
    clearResult,
    clipboardReady,
    notice,
    pending,
    displayPending: pending?.kind === AssistanceCommandKind.SELECT_DISPLAY,
    busy: exact.busy || pending !== null,
    failure: failure ?? exact.failure,
    invalid: exact.invalid,
    check: () => {
      setFailure(null);
      setReadAttempt((value) => value + 1);
    },
  };
}
