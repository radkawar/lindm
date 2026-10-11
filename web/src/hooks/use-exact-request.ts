import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";

type Captured<T> = { request: T; discard?: (request: T) => void };

export type ExactRequestStatus = {
  busy: boolean;
  failure: RpcFailure | null;
  invalid: string;
  ambiguous: boolean;
};

function release<T>(captured: Captured<T> | null) {
  if (captured) captured.discard?.(captured.request);
}

// One captured mutation per form, sent without a query or mutation cache so request
// material is never retained there. Mutations are never retried automatically: an
// ambiguous outcome keeps the exact request and its request ID for an explicit retry,
// and every other outcome discards (and lets the caller zeroize) the captured request.
export function useExactRequest<T>() {
  const lifetime = useAuthLifetime();
  const captured = useRef<Captured<T> | null>(null);
  const inFlight = useRef(false);
  const controllerRef = useRef<AbortController | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [invalid, setInvalid] = useState("");
  const [ambiguous, setAmbiguous] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    controllerRef.current = controller;
    const drop = () => {
      release(captured.current);
      captured.current = null;
    };
    lifetime.signal.addEventListener("abort", drop, { once: true });
    return () => {
      controller.abort();
      lifetime.signal.removeEventListener("abort", drop);
      drop();
    };
  }, [lifetime.signal]);

  async function submit<R>({
    capture,
    send,
    discard,
    failureTitle,
    onSuccess,
  }: {
    capture: () => T;
    send: (request: T, options: { signal: AbortSignal; timeoutMs: number }) => Promise<R>;
    discard?: (request: T) => void;
    failureTitle: string;
    onSuccess: (response: R, request: T) => void | Promise<void>;
  }) {
    const controller = controllerRef.current;
    if (!controller || inFlight.current || controller.signal.aborted || lifetime.signal.aborted)
      return;
    setFailure(null);
    setInvalid("");
    let current = captured.current;
    if (!current) {
      try {
        current = { request: capture(), discard };
      } catch (error) {
        setInvalid(error instanceof Error ? error.message : "The request is not valid.");
        return;
      }
      captured.current = current;
    }
    inFlight.current = true;
    setBusy(true);
    try {
      const response = await send(current.request, {
        signal: AbortSignal.any([controller.signal, lifetime.signal]),
        timeoutMs: 30_000,
      });
      if (controller.signal.aborted || lifetime.signal.aborted) return;
      captured.current = null;
      release(current);
      setAmbiguous(false);
      await onSuccess(response, current.request);
    } catch (error) {
      if (controller.signal.aborted || lifetime.signal.aborted) return;
      const result = toRpcFailure(error);
      if (!result.ambiguous && captured.current === current) {
        captured.current = null;
        release(current);
      }
      setAmbiguous(result.ambiguous && captured.current === current);
      setFailure(result);
      const { tone, title } = classifyRpcFailure(result);
      toast[tone === "destructive" ? "error" : tone === "warning" ? "warning" : "message"](
        result.ambiguous ? `${failureTitle}: outcome unknown` : title,
        { description: "Review the inline result before continuing." },
      );
    } finally {
      inFlight.current = false;
      if (!controller.signal.aborted && !lifetime.signal.aborted) setBusy(false);
    }
  }

  // Abandons an ambiguous captured request after its outcome has been checked.
  function reset() {
    if (inFlight.current) return;
    release(captured.current);
    captured.current = null;
    setAmbiguous(false);
    setFailure(null);
    setInvalid("");
  }

  return { busy, failure, invalid, ambiguous, submit, reset };
}
