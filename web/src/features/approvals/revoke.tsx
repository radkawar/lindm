import { create } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import {
  RevokeDeviceRequestSchema,
  type RevokeDeviceRequest,
} from "../../../gen/lindm/admin/v1/approvals_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
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
      toast.success("Approval requested");
      await client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const next = toRpcFailure(error);
        setFailure(next);
        const { tone, title } = classifyRpcFailure(next);
        toast[tone === "destructive" ? "error" : tone === "warning" ? "warning" : "message"](
          title,
          {
            description: "Refresh before trying again.",
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
      className="grid min-w-0 gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        void requestApproval();
      }}
    >
      <p className="text-sm">Another admin must approve this within one hour.</p>
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
          Approval requested.{" "}
          <Link to="/approvals" className="underline underline-offset-4">
            Open approvals to finish revoking once approved
          </Link>
        </p>
      ) : (
        <Button
          className="w-fit"
          type="submit"
          variant="default"
          disabled={busy || reason.trim() === ""}
        >
          {busy
            ? "Requesting approval…"
            : failure?.ambiguous
              ? "Try again"
              : "Request revocation approval"}
        </Button>
      )}
      {failure ? (
        <RpcError failure={failure}>
          {failure.ambiguous ? <p>Check approvals before trying again.</p> : null}
        </RpcError>
      ) : null}
    </form>
  );
}
