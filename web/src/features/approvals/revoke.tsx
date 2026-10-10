import { create } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import {
  RevokeDeviceRequestSchema,
  type RevokeDeviceRequest,
} from "../../../gen/lindm/admin/v1/approvals_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { adminClient } from "@/lib/rpc";

export function RevokeApprovalRequest({ deviceId }: { deviceId: string }) {
  const principal = usePrincipal();
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const [reason, setReason] = useState("");
  const [payload, setPayload] = useState<RevokeDeviceRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [approvalId, setApprovalId] = useState("");
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  if (!canPermission(principal, "device.revoke")) return null;

  async function requestApproval() {
    if (busy || lifetime.signal.aborted) return;
    const exact =
      payload ??
      create(RevokeDeviceRequestSchema, { requestId: crypto.randomUUID(), deviceId, reason });
    setPayload(exact);
    setBusy(true);
    setFailure(null);
    try {
      const result = await adminClient.createApproval(
        { lifetimeSeconds: 3600, payload: { case: "revokeDevice", value: exact } },
        { signal: lifetime.signal, timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      setApprovalId(result.approval?.id ?? "");
      toast.success("Revocation approval requested");
      await client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const next = toRpcFailure(error);
        setFailure(next);
        toast.error(
          next.ambiguous ? "Approval request outcome unknown" : "Approval request failed",
          {
            description: "Review the inline result before continuing.",
          },
        );
        if (!next.ambiguous) setPayload(null);
      }
    } finally {
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <form
      className="grid min-w-0 gap-3 border border-destructive/30 bg-destructive/5 p-4"
      onSubmit={(event) => {
        event.preventDefault();
        void requestApproval();
      }}
    >
      <p className="text-sm">
        Revocation requires approval by a different authorized human. Approval expires in one hour.
      </p>
      <label className="grid gap-2 text-sm font-medium">
        Revocation reason
        <Input
          aria-label="Revocation reason"
          required
          value={reason}
          disabled={busy || payload !== null || approvalId !== ""}
          onChange={(event) => setReason(event.target.value)}
        />
      </label>
      {approvalId ? (
        <p role="status" className="break-words text-sm">
          Approval {approvalId} requested.{" "}
          <Link to="/approvals" className="underline underline-offset-4">
            Open approvals to execute after approval
          </Link>
        </p>
      ) : (
        <Button
          className="w-fit"
          type="submit"
          variant="destructive"
          disabled={busy || reason.trim() === ""}
        >
          {busy
            ? "Requesting approval…"
            : failure?.ambiguous
              ? "Retry exact approval request"
              : "Request revocation approval"}
        </Button>
      )}
      {failure ? (
        <Alert variant="destructive">
          <AlertTitle>
            {failure.ambiguous ? "Outcome unknown" : "Approval request failed"}
          </AlertTitle>
          <AlertDescription>
            {failure.codeName}: {failure.message}
            {failure.ambiguous
              ? " The outcome is unknown; retry uses the same request ID and payload."
              : ""}
          </AlertDescription>
        </Alert>
      ) : null}
    </form>
  );
}
