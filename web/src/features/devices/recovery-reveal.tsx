import { create } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
  RevealRecoveryKeyRequestSchema,
  type RevealRecoveryKeyRequest,
} from "../../../gen/lindm/admin/v1/device_actions_pb";
import { ApprovalState } from "../../../gen/lindm/admin/v1/approvals_pb";
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
import { adminClient } from "@/lib/rpc";
import { validateInventory } from "./validation";
import { deviceEncryptionQueryOptions } from "./action-queries";

export function RecoveryKeyReveal({
  deviceId,
  deviceName,
  actionId,
}: {
  deviceId: string;
  deviceName: string;
  actionId: string;
}) {
  const confirmationName = deviceName.trim() || deviceId;
  const lifetime = useAuthLifetime();
  // The server re-decides on every reveal; this only routes the operator.
  const approval = useQuery(deviceEncryptionQueryOptions(lifetime, deviceId)).data
    ?.recoveryKeyRevealApproval;
  const approvalRequired = revealApprovalRequired(approval);
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
      if (confirmation !== confirmationName)
        throw new Error("Type the device name exactly as shown to confirm.");
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
      setHidesAt(Date.now() + 30_000);
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

  const awaitingApproval = approvalRequired === true && approvalState !== ApprovalState.APPROVED;
  return (
    <div className="grid gap-3 rounded-md border p-3">
      {secret ? (
        <RevealedSecret
          label="Recovery key"
          display={groupKey(new TextDecoder().decode(secret))}
          raw={new TextDecoder().decode(secret)}
          hidesAt={hidesAt}
          note="Grouped in fours for reading aloud; Copy copies it without dashes."
          copiedMessage="Recovery key copied"
          onHide={hide}
        />
      ) : (
        <p className="text-sm text-muted-foreground">
          The key hides after 30 seconds or when you leave the page.
        </p>
      )}
      <Label htmlFor={`reveal-reason-${actionId}`}>Reason</Label>
      <Textarea
        id={`reveal-reason-${actionId}`}
        value={reason}
        readOnly={busy || request.current !== null}
        onChange={(event) => setReason(event.target.value)}
      />
      <Label htmlFor={`reveal-confirmation-${actionId}`}>Type the device name to confirm</Label>
      <p className="break-all text-sm">{confirmationName}</p>
      <Input
        id={`reveal-confirmation-${actionId}`}
        value={confirmation}
        onChange={(event) => setConfirmation(event.target.value)}
        readOnly={busy || request.current !== null}
        autoComplete="off"
      />
      <TechnicalDetails
        items={[
          { label: "Device ID", value: deviceId },
          { label: "Approval ID", value: approvalId },
        ]}
      />
      <RevealApprovalNote approval={approval} />
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
          variant={approvalRequired === null || awaitingApproval ? "outline" : "default"}
          disabled={busy || secret !== null || ambiguous === "approval" || awaitingApproval}
          onClick={() => void reveal()}
        >
          {busy ? "Requesting…" : ambiguous === "reveal" ? "Retry" : "Reveal recovery key"}
        </Button>
        {approvalRequired === false ? null : (
          <Button
            variant={awaitingApproval ? "default" : "outline"}
            disabled={busy || secret !== null || ambiguous === "reveal"}
            onClick={() => void requestApproval()}
          >
            {approvalState === null ? "Request approval" : "Refresh approval status"}
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

function groupKey(key: string) {
  return key.match(/.{1,4}/g)?.join("-") ?? key;
}
