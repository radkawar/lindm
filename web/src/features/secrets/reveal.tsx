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
        throw new Error("Type the exact secret ID to confirm secret access.");
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
      if (!response.approval?.id) throw new Error("The server did not return an approval receipt.");
      setApprovalId(response.approval.id);
      setApprovalState(response.approval.state);
      request.current = create(RevealSecretRequestSchema, {
        ...payload,
        approvalId: response.approval.id,
      });
      setAmbiguous(null);
      toast.success("Secret approval receipt received", {
        description: "Review the recorded approval state before requesting access.",
      });
    } catch (error) {
      if (!controller.signal.aborted && !lifetime.signal.aborted) {
        const result = toRpcFailure(error);
        setAmbiguous(result.ambiguous ? "approval" : null);
        setFailure(result);
        toast[classifyRpcFailure(result).tone === "destructive" ? "error" : "warning"](
          result.ambiguous ? "Approval delivery unknown" : "Secret approval request failed",
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
        setFailure(toRpcFailure(new Error("The server returned no secret material.")));
        return;
      }
      if (document.visibilityState !== "visible" || !document.hasFocus()) {
        material.fill(0);
        setNotice("The response arrived while this page was hidden; the secret was dismissed.");
        return;
      }
      held.current = material;
      setSecret(material);
      toast.success("Secret received", {
        description: "The value is shown temporarily in the reveal panel only.",
      });
    } catch (error) {
      if (!controller.signal.aborted && !lifetime.signal.aborted) {
        const result = toRpcFailure(error);
        setAmbiguous(result.ambiguous ? "reveal" : null);
        setFailure(result);
        toast[classifyRpcFailure(result).tone === "destructive" ? "error" : "warning"](
          result.ambiguous ? "Secret delivery unknown" : "Secret request failed",
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

  const shown = secret ? revealedText(secret) : null;
  return (
    <div className="grid gap-3 rounded-md border p-3">
      <details className="text-sm text-muted-foreground">
        <summary className="cursor-pointer">Secret access requirements</summary>
        <p className="mt-2">
          Access requires an unrestricted secret reveal grant, an audit reason, and recent step-up
          authentication. A policy may require approval. The value is dismissed after 30 seconds, on
          blur, or on navigation; browser memory cannot be guaranteed erased.
        </p>
      </details>
      <Label htmlFor={`${idPrefix}-reason`}>Secret access reason</Label>
      <Textarea
        id={`${idPrefix}-reason`}
        value={reason}
        readOnly={busy || request.current !== null}
        onChange={(event) => setReason(event.target.value)}
      />
      <Label htmlFor={`${idPrefix}-approval`}>Approval receipt ID</Label>
      <Input id={`${idPrefix}-approval`} value={approvalId} readOnly autoComplete="off" />
      <Label htmlFor={`${idPrefix}-confirmation`}>Type the secret ID to confirm access</Label>
      <Input
        id={`${idPrefix}-confirmation`}
        value={confirmation}
        onChange={(event) => setConfirmation(event.target.value)}
        readOnly={busy || request.current !== null}
        autoComplete="off"
      />
      <p className="text-sm text-muted-foreground">
        This reveals version {version.toString()} of this secret.
      </p>
      {approvalState !== null ? (
        <p>
          Last observed approval: {ApprovalState[approvalState]}.{" "}
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
          {busy
            ? "Requesting…"
            : ambiguous === "reveal"
              ? "Retry exact reveal request"
              : "Reveal secret"}
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
              setFailure(null);
              setNotice("");
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
      {shown ? (
        <>
          {shown.hex ? (
            <p className="text-sm text-muted-foreground">
              Shown as hexadecimal: the value is not valid UTF-8 text.
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
