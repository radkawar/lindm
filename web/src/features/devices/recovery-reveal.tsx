import { create } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
  RevealRecoveryKeyRequestSchema,
  type RevealRecoveryKeyRequest,
} from "../../../gen/lindm/admin/v1/device_actions_pb";
import { ApprovalState } from "../../../gen/lindm/admin/v1/approvals_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { validateInventory } from "./validation";

export function RecoveryKeyReveal({ deviceId, actionId }: { deviceId: string; actionId: string }) {
  const lifetime = useAuthLifetime();
  const [reason, setReason] = useState("");
  const [approvalId, setApprovalId] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [approvalState, setApprovalState] = useState<ApprovalState | null>(null);
  const [ambiguous, setAmbiguous] = useState<"reveal" | "approval" | null>(null);
  const [secret, setSecret] = useState<Uint8Array | null>(null);
  const held = useRef<Uint8Array | null>(null);
  const request = useRef<RevealRecoveryKeyRequest | null>(null);
  const inFlight = useRef(false);
  const controllerRef = useRef<AbortController | null>(null);

  function hide() {
    held.current?.fill(0);
    held.current = null;
    setSecret(null);
  }

  useEffect(() => {
    const controller = new AbortController();
    controllerRef.current = controller;
    return () => {
      controller.abort();
      held.current?.fill(0);
      held.current = null;
    };
  }, []);

  useEffect(() => {
    if (!secret) return;
    const dismiss = () => {
      held.current?.fill(0);
      held.current = null;
      setSecret(null);
    };
    const timer = window.setTimeout(dismiss, 30_000);
    window.addEventListener("blur", dismiss);
    document.addEventListener("visibilitychange", dismiss);
    lifetime.signal.addEventListener("abort", dismiss, { once: true });
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("blur", dismiss);
      document.removeEventListener("visibilitychange", dismiss);
      lifetime.signal.removeEventListener("abort", dismiss);
    };
  }, [secret, lifetime.signal]);

  function capture() {
    if (!request.current) {
      const payload = create(RevealRecoveryKeyRequestSchema, {
        requestId: newRequestId(),
        deviceId,
        actionId,
        reason: reason.trim(),
        approvalId: approvalId.trim(),
      });
      validateInventory(RevealRecoveryKeyRequestSchema, payload);
      request.current = payload;
    }
    return request.current;
  }

  async function requestApproval() {
    const controller = controllerRef.current;
    if (
      !controller ||
      inFlight.current ||
      ambiguous === "reveal" ||
      controller.signal.aborted ||
      lifetime.signal.aborted
    )
      return;
    setFailure("");
    try {
      const payload = capture();
      inFlight.current = true;
      setBusy(true);
      const response = await adminClient.createApproval(
        { lifetimeSeconds: 600, payload: { case: "revealRecoveryKey", value: payload } },
        { signal: AbortSignal.any([controller.signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      if (controller.signal.aborted || lifetime.signal.aborted) return;
      if (!response.approval?.id) throw new Error("The server did not return an approval receipt.");
      setApprovalId(response.approval.id);
      setApprovalState(response.approval.state);
      request.current = create(RevealRecoveryKeyRequestSchema, {
        ...payload,
        approvalId: response.approval.id,
      });
      setAmbiguous(null);
      toast.success("Recovery approval receipt received", {
        description: "Review the recorded approval state before requesting access.",
      });
    } catch (error) {
      if (!controller.signal.aborted && !lifetime.signal.aborted) {
        const result = toRpcFailure(error);
        setAmbiguous(result.ambiguous ? "approval" : null);
        setFailure(
          `${result.ambiguous ? "Approval delivery unknown. Retry the exact approval request. " : ""}${result.message}`,
        );
        toast.error(
          result.ambiguous ? "Approval delivery unknown" : "Recovery approval request failed",
          {
            description: "Review the inline result and captured request before continuing.",
          },
        );
      }
    } finally {
      inFlight.current = false;
      if (!controller.signal.aborted && !lifetime.signal.aborted) setBusy(false);
    }
  }

  async function reveal() {
    const controller = controllerRef.current;
    if (
      !controller ||
      inFlight.current ||
      ambiguous === "approval" ||
      lifetime.signal.aborted ||
      controller.signal.aborted
    )
      return;
    hide();
    setFailure("");
    try {
      const payload = capture();
      inFlight.current = true;
      setBusy(true);
      // Deliberately no query or mutation cache: even a zero-GC mutation retains data.
      const response = await adminClient.revealRecoveryKey(payload, {
        signal: AbortSignal.any([controller.signal, lifetime.signal]),
        timeoutMs: 30_000,
      });
      if (controller.signal.aborted || lifetime.signal.aborted) {
        response.recoveryKey.fill(0);
        return;
      }
      request.current = null;
      setAmbiguous(null);
      setApprovalId("");
      setApprovalState(null);
      if (
        response.recoveryKey.length !== 64 ||
        !response.recoveryKey.every(
          (byte) => (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102),
        )
      ) {
        response.recoveryKey.fill(0);
        setFailure("Recovery key has an unsupported encoding; no key was displayed.");
        return;
      }
      if (document.visibilityState !== "visible" || !document.hasFocus()) {
        response.recoveryKey.fill(0);
        setFailure(
          "The response arrived while this page was hidden; the recovery key was dismissed.",
        );
        return;
      }
      held.current = response.recoveryKey;
      setSecret(response.recoveryKey);
      toast.success("Recovery key received", {
        description: "The key is shown temporarily in the recovery panel only.",
      });
    } catch (error) {
      if (!controller.signal.aborted && !lifetime.signal.aborted) {
        const result = toRpcFailure(error);
        setAmbiguous(result.ambiguous ? "reveal" : null);
        setFailure(
          `${result.ambiguous ? "Delivery unknown. Retry keeps the exact request; no new reveal is issued automatically. " : ""}${result.message}`,
        );
        toast.error(
          result.ambiguous ? "Recovery key delivery unknown" : "Recovery key request failed",
          {
            description: "Review the inline result and captured request before continuing.",
          },
        );
      }
    } finally {
      inFlight.current = false;
      if (!controller.signal.aborted && !lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <div className="grid gap-3 rounded-md border p-3">
      <p className="text-sm">
        Recovery-key access requires its dedicated permission, an audit reason, and recent step-up
        authentication. A policy may also require approval. The key is dismissed after 30 seconds,
        on blur, or on navigation; browser memory cannot be guaranteed erased.
      </p>
      <Label htmlFor={`reveal-reason-${actionId}`}>Recovery-key access reason</Label>
      <Textarea
        id={`reveal-reason-${actionId}`}
        value={reason}
        readOnly={busy || request.current !== null}
        onChange={(event) => setReason(event.target.value)}
      />
      <Label htmlFor={`reveal-approval-${actionId}`}>Approval receipt ID</Label>
      <Input id={`reveal-approval-${actionId}`} value={approvalId} readOnly autoComplete="off" />
      {approvalState !== null ? (
        <p>
          Last observed approval: {ApprovalState[approvalState]}.{" "}
          <Link to="/approvals" className="underline">
            Open approvals
          </Link>
        </p>
      ) : null}
      {failure ? (
        <Alert variant="destructive">
          <AlertTitle>Recovery key not revealed</AlertTitle>
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      <div className="flex gap-2">
        <Button
          variant="outline"
          disabled={busy || secret !== null || ambiguous === "approval"}
          onClick={() => void reveal()}
        >
          {busy
            ? "Requesting…"
            : ambiguous === "reveal"
              ? "Retry exact reveal request"
              : "Reveal recovery key"}
        </Button>
        <Button
          variant="outline"
          disabled={busy || secret !== null || ambiguous === "reveal"}
          onClick={() => void requestApproval()}
        >
          {approvalState === null ? "Request independent approval" : "Refresh exact approval state"}
        </Button>
        {request.current && ambiguous === null ? (
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => {
              request.current = null;
              setApprovalId("");
              setApprovalState(null);
              setFailure("");
            }}
          >
            Prepare different access request
          </Button>
        ) : null}
        {secret ? (
          <Button variant="outline" onClick={hide}>
            Dismiss now
          </Button>
        ) : null}
      </div>
      {secret ? (
        <pre
          className="whitespace-pre-wrap break-all rounded-md border p-3 text-sm"
          aria-label="Recovery key"
        >
          {new TextDecoder().decode(secret)}
        </pre>
      ) : null}
    </div>
  );
}
