import { create } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
  RevealRecoveryKeyRequestSchema,
  type RevealRecoveryKeyRequest,
} from "../../../gen/lindm/admin/v1/device_actions_pb";
import { ApprovalState } from "../../../gen/lindm/admin/v1/approvals_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { validateInventory } from "./validation";

export function RecoveryKeyReveal({ deviceId, actionId }: { deviceId: string; actionId: string }) {
  const lifetime = useAuthLifetime();
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [approvalId, setApprovalId] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [notice, setNotice] = useState("");
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
      if (confirmation !== deviceId) throw new Error("Type the device ID exactly to confirm.");
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
    setFailure(null);
    setNotice("");
    try {
      const payload = capture();
      inFlight.current = true;
      setBusy(true);
      const response = await adminClient.createApproval(
        { lifetimeSeconds: 600, payload: { case: "revealRecoveryKey", value: payload } },
        { signal: AbortSignal.any([controller.signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      if (controller.signal.aborted || lifetime.signal.aborted) return;
      if (!response.approval?.id)
        throw new Error("The server didn't confirm the approval request.");
      setApprovalId(response.approval.id);
      setApprovalState(response.approval.state);
      request.current = create(RevealRecoveryKeyRequestSchema, {
        ...payload,
        approvalId: response.approval.id,
      });
      setAmbiguous(null);
      toast.success("Approval requested", {
        description: "Reveal the key once another admin approves.",
      });
    } catch (error) {
      if (!controller.signal.aborted && !lifetime.signal.aborted) {
        const result = toRpcFailure(error);
        setAmbiguous(result.ambiguous ? "approval" : null);
        setFailure(result);
        toast[classifyRpcFailure(result).tone === "destructive" ? "error" : "warning"](
          result.ambiguous ? "Couldn't confirm approval request" : "Couldn't request approval",
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
    setFailure(null);
    setNotice("");
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
        setFailure(
          toRpcFailure(
            new Error("The recovery key can't be displayed. It has an unexpected format."),
          ),
        );
        return;
      }
      if (document.visibilityState !== "visible" || !document.hasFocus()) {
        response.recoveryKey.fill(0);
        setNotice("The page was hidden when the key arrived, so it wasn't shown. Try again.");
        return;
      }
      held.current = response.recoveryKey;
      setSecret(response.recoveryKey);
      toast.success("Recovery key revealed", {
        description: "It hides after 30 seconds or when you leave the page.",
      });
    } catch (error) {
      if (!controller.signal.aborted && !lifetime.signal.aborted) {
        const result = toRpcFailure(error);
        setAmbiguous(result.ambiguous ? "reveal" : null);
        setFailure(result);
        toast[classifyRpcFailure(result).tone === "destructive" ? "error" : "warning"](
          result.ambiguous ? "Couldn't confirm key reveal" : "Couldn't reveal recovery key",
        );
      }
    } finally {
      inFlight.current = false;
      if (!controller.signal.aborted && !lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <div className="grid gap-3 rounded-md border p-3">
      <p className="text-sm text-muted-foreground">
        The key hides after 30 seconds or when you leave the page.
      </p>
      <Label htmlFor={`reveal-reason-${actionId}`}>Reason</Label>
      <Textarea
        id={`reveal-reason-${actionId}`}
        value={reason}
        readOnly={busy || request.current !== null}
        onChange={(event) => setReason(event.target.value)}
      />
      <Label htmlFor={`reveal-confirmation-${actionId}`}>Type the device ID to confirm</Label>
      <p className="break-all font-mono text-xs text-muted-foreground">{deviceId}</p>
      <Input
        id={`reveal-confirmation-${actionId}`}
        value={confirmation}
        onChange={(event) => setConfirmation(event.target.value)}
        readOnly={busy || request.current !== null}
        autoComplete="off"
      />
      <TechnicalDetails items={[{ label: "Approval ID", value: approvalId }]} />
      {approvalState !== null ? (
        <p>
          Approval: {ApprovalState[approvalState]?.toLowerCase()}.{" "}
          <Link to="/approvals" className="underline">
            Open approvals
          </Link>
        </p>
      ) : null}
      {failure ? <RpcError failure={failure} title="Couldn't reveal recovery key" /> : null}
      {notice ? (
        <p role="status" className="text-sm text-muted-foreground">
          {notice}
        </p>
      ) : null}
      <div className="flex gap-2">
        <Button
          variant="outline"
          disabled={busy || secret !== null || ambiguous === "approval"}
          onClick={() => void reveal()}
        >
          {busy ? "Requesting…" : ambiguous === "reveal" ? "Retry" : "Reveal recovery key"}
        </Button>
        <Button
          variant="outline"
          disabled={busy || secret !== null || ambiguous === "reveal"}
          onClick={() => void requestApproval()}
        >
          {approvalState === null ? "Request approval" : "Refresh approval status"}
        </Button>
        {request.current && ambiguous === null ? (
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => {
              request.current = null;
              setApprovalId("");
              setApprovalState(null);
              setFailure(null);
              setNotice("");
            }}
          >
            Start over
          </Button>
        ) : null}
        {secret ? (
          <Button variant="outline" onClick={hide}>
            Hide now
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
