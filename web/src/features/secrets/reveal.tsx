import { create } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { ApprovalState } from "../../../gen/lindm/admin/v1/approvals_pb";
import {
  RevealSecretRequestSchema,
  type RevealSecretRequest,
} from "../../../gen/lindm/admin/v1/secrets_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { revealedText } from "@/lib/reveal";
import { adminClient } from "@/lib/rpc";
import { validateRequest } from "./validation";

const approvalStateLabels: Partial<Record<ApprovalState, string>> = {
  [ApprovalState.PENDING]: "waiting for another admin",
  [ApprovalState.APPROVED]: "approved",
  [ApprovalState.REJECTED]: "rejected",
  [ApprovalState.CONSUMED]: "used",
  [ApprovalState.EXPIRED]: "expired",
};

export function SecretReveal({ secretId, version }: { secretId: string; version: bigint }) {
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
  const request = useRef<RevealSecretRequest | null>(null);
  const inFlight = useRef(false);
  const controllerRef = useRef<AbortController | null>(null);
  const idPrefix = `secret-reveal-${secretId}-${version}`;

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
      if (confirmation !== secretId)
        throw new Error("Type the secret ID exactly as shown to confirm.");
      const payload = create(RevealSecretRequestSchema, {
        requestId: newRequestId(),
        secretId,
        version,
        reason: reason.trim(),
        approvalId: approvalId.trim(),
      });
      validateRequest(RevealSecretRequestSchema, payload);
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
        { lifetimeSeconds: 600, payload: { case: "revealSecret", value: payload } },
        { signal: AbortSignal.any([controller.signal, lifetime.signal]), timeoutMs: 30_000 },
      );
      if (controller.signal.aborted || lifetime.signal.aborted) return;
      if (!response.approval?.id) throw new Error("The approval request wasn't saved. Try again.");
      setApprovalId(response.approval.id);
      setApprovalState(response.approval.state);
      request.current = create(RevealSecretRequestSchema, {
        ...payload,
        approvalId: response.approval.id,
      });
      setAmbiguous(null);
      toast.success("Approval requested", {
        description: "Reveal the secret once another admin approves.",
      });
    } catch (error) {
      if (!controller.signal.aborted && !lifetime.signal.aborted) {
        const result = toRpcFailure(error);
        setAmbiguous(result.ambiguous ? "approval" : null);
        setFailure(result);
        toast[classifyRpcFailure(result).tone === "destructive" ? "error" : "warning"](
          result.ambiguous
            ? "Approval request may not have been sent"
            : "Couldn't request approval",
          {
            description: "Refresh before trying again.",
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
    setFailure(null);
    setNotice("");
    try {
      const payload = capture();
      inFlight.current = true;
      setBusy(true);
      // Deliberately no query or mutation cache: even a zero-GC mutation retains data.
      const response = await adminClient.revealSecret(payload, {
        signal: AbortSignal.any([controller.signal, lifetime.signal]),
        timeoutMs: 30_000,
      });
      const material = response.material?.material.value;
      if (controller.signal.aborted || lifetime.signal.aborted) {
        material?.fill(0);
        return;
      }
      request.current = null;
      setAmbiguous(null);
      setApprovalId("");
      setApprovalState(null);
      if (!material) {
        setFailure(toRpcFailure(new Error("No value came back. Try again.")));
        return;
      }
      if (document.visibilityState !== "visible" || !document.hasFocus()) {
        material.fill(0);
        setNotice("The page was hidden when the value arrived, so it wasn't shown. Try again.");
        return;
      }
      held.current = material;
      setSecret(material);
      toast.success("Secret revealed", {
        description: "It disappears after 30 seconds.",
      });
    } catch (error) {
      if (!controller.signal.aborted && !lifetime.signal.aborted) {
        const result = toRpcFailure(error);
        setAmbiguous(result.ambiguous ? "reveal" : null);
        setFailure(result);
        toast[classifyRpcFailure(result).tone === "destructive" ? "error" : "warning"](
          result.ambiguous ? "Secret may not have been revealed" : "Couldn't reveal secret",
          {
            description: "Refresh before trying again.",
          },
        );
      }
    } finally {
      inFlight.current = false;
      if (!controller.signal.aborted && !lifetime.signal.aborted) setBusy(false);
    }
  }

  const shown = secret ? revealedText(secret) : null;
  return (
    <div className="grid gap-3 rounded-md border p-3">
      <p className="text-sm text-muted-foreground">
        The value disappears after 30 seconds or when you leave this page.
      </p>
      <Label htmlFor={`${idPrefix}-reason`}>Reason</Label>
      <Textarea
        id={`${idPrefix}-reason`}
        value={reason}
        readOnly={busy || request.current !== null}
        onChange={(event) => setReason(event.target.value)}
      />
      <TechnicalDetails items={[]}>
        <div className="mt-2 grid gap-2">
          <Label htmlFor={`${idPrefix}-approval`}>Approval ID</Label>
          <Input id={`${idPrefix}-approval`} value={approvalId} readOnly autoComplete="off" />
        </div>
      </TechnicalDetails>
      <Label htmlFor={`${idPrefix}-confirmation`}>
        Type <span className="break-all font-mono">{secretId}</span> to confirm
      </Label>
      <Input
        id={`${idPrefix}-confirmation`}
        value={confirmation}
        onChange={(event) => setConfirmation(event.target.value)}
        readOnly={busy || request.current !== null}
        autoComplete="off"
      />
      <p className="text-sm text-muted-foreground">Reveals version {version.toString()}.</p>
      {approvalState !== null ? (
        <p>
          Approval: {approvalStateLabels[approvalState] ?? "Unknown"}.{" "}
          <Link to="/approvals" className="underline">
            Open approvals
          </Link>
        </p>
      ) : null}
      {failure ? <RpcError failure={failure} title="Secret not revealed" /> : null}
      {notice ? (
        <p role="status" className="text-sm text-muted-foreground">
          {notice}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          disabled={busy || secret !== null || ambiguous === "approval"}
          onClick={() => void reveal()}
        >
          {busy ? "Requesting…" : ambiguous === "reveal" ? "Try again" : "Reveal secret"}
        </Button>
        <Button
          variant="outline"
          disabled={busy || secret !== null || ambiguous === "reveal"}
          onClick={() => void requestApproval()}
        >
          {approvalState === null ? "Request approval" : "Check approval"}
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
      {shown ? (
        <>
          {shown.hex ? (
            <p className="text-sm text-muted-foreground">
              Shown as hexadecimal because it isn't plain text.
            </p>
          ) : null}
          <pre
            className="whitespace-pre-wrap break-all rounded-md border p-3 text-sm select-all"
            aria-label="Secret value"
          >
            {shown.text}
          </pre>
        </>
      ) : null}
    </div>
  );
}
