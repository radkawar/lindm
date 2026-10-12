import { create } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { ApprovalState } from "../../../gen/lindm/admin/v1/approvals_pb";
import {
  RevealSecretRequestSchema,
  type RevealApproval,
  type RevealSecretRequest,
} from "../../../gen/lindm/admin/v1/secrets_pb";
import { RevealApprovalNote, revealApprovalRequired } from "@/components/ui/reveal-approval-note";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { RevealedSecret } from "@/components/ui/revealed-secret";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { revealedText } from "@/lib/reveal";
import { adminClient } from "@/lib/rpc";
import { validateRequest } from "@/lib/validation";
import { CONFIRMATION_HINT, confirmsSecretName } from "./actions";

const approvalStateLabels: Partial<Record<ApprovalState, string>> = {
  [ApprovalState.PENDING]: "waiting for another admin",
  [ApprovalState.APPROVED]: "approved",
  [ApprovalState.REJECTED]: "rejected",
  [ApprovalState.CONSUMED]: "used",
  [ApprovalState.EXPIRED]: "expired",
};

export function SecretReveal({
  secretId,
  secretName,
  version,
  approval,
}: {
  secretId: string;
  secretName: string;
  version: bigint;
  approval: RevealApproval | undefined;
}) {
  const approvalRequired = revealApprovalRequired(approval);
  const confirmationName = secretName.trim() || secretId;
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
  const [hidesAt, setHidesAt] = useState(0);
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
      if (!confirmsSecretName(confirmation, confirmationName))
        throw new Error("Type the secret name as shown to confirm.");
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
      setHidesAt(Date.now() + 30_000);
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
  // A refusal naming approval_required means the server wants a second admin
  // even if the policy summary didn't say so: lead with Request approval.
  const approvalRefused =
    failure?.reason === "approval_required" || failure?.reason === "human_approval_required";
  const awaitingApproval =
    (approvalRequired === true || approvalRefused) && approvalState !== ApprovalState.APPROVED;
  return (
    <div className="grid gap-3 rounded-md border p-3">
      {shown ? (
        <RevealedSecret
          label="Secret value"
          display={shown.text}
          raw={shown.text}
          hidesAt={hidesAt}
          note={
            shown.hex ? "Shown and copied as hexadecimal because it isn't plain text." : undefined
          }
          copiedMessage="Secret copied"
          onHide={hide}
        />
      ) : (
        <p className="text-sm text-muted-foreground">
          The value disappears after 30 seconds or when you leave this page.
        </p>
      )}
      <Label htmlFor={`${idPrefix}-reason`}>Reason</Label>
      <Textarea
        id={`${idPrefix}-reason`}
        data-freeform="audit reason"
        value={reason}
        readOnly={busy || request.current !== null}
        onChange={(event) => setReason(event.target.value)}
      />
      <TechnicalDetails
        items={[
          { label: "Secret ID", value: secretId },
          { label: "Approval ID", value: approvalId },
        ]}
      />
      {/* Block, not the flex default: flex gaps doubled the spaces around the name. */}
      <Label htmlFor={`${idPrefix}-confirmation`} className="block leading-normal">
        Type <span className="break-all">{confirmationName}</span> to confirm
      </Label>
      <Input
        id={`${idPrefix}-confirmation`}
        data-freeform="typed confirmation of the secret name"
        value={confirmation}
        onChange={(event) => setConfirmation(event.target.value)}
        readOnly={busy || request.current !== null}
        autoComplete="off"
        aria-describedby={`${idPrefix}-confirmation-hint`}
        aria-invalid={
          confirmation.trim() !== "" && !confirmsSecretName(confirmation, confirmationName)
        }
      />
      <p id={`${idPrefix}-confirmation-hint`} className="text-sm text-muted-foreground">
        {CONFIRMATION_HINT} Reveals version {version.toString()}.
      </p>
      <RevealApprovalNote approval={approval} />
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
          variant={approvalRequired === null || awaitingApproval ? "outline" : "default"}
          disabled={busy || secret !== null || ambiguous === "approval" || awaitingApproval}
          onClick={() => void reveal()}
        >
          {busy ? "Requesting…" : ambiguous === "reveal" ? "Try again" : "Reveal secret"}
        </Button>
        {approvalRequired === false && !approvalRefused ? null : (
          <Button
            variant={awaitingApproval ? "default" : "outline"}
            disabled={busy || secret !== null || ambiguous === "reveal"}
            onClick={() => void requestApproval()}
          >
            {approvalState === null ? "Request approval" : "Check approval"}
          </Button>
        )}
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
      </div>
    </div>
  );
}
