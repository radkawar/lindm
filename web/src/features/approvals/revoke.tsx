// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { Link } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useSyncExternalStore } from "react";
import { toast } from "sonner";
import {
  ApprovalState,
  RevokeDeviceRequestSchema,
  type Approval,
  type RevokeDeviceRequest,
} from "../../../gen/lindm/admin/v1/approvals_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Timestamp } from "@/components/ui/timestamp";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { getAuthLifetime, subscribeAuthLifetime, type AuthLifetime } from "@/lib/auth-lifetime";
import { canPermission } from "@/lib/permissions";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { adminClient } from "@/lib/rpc";
import { deviceApprovalsQueryOptions } from "./queries";

// A device's revocation approval request. It lives outside the revoke dialog,
// which unmounts its form on close, so an in-flight request, its exact payload
// (retried with the same request ID when the outcome is ambiguous) and the
// created approval survive closing and reopening the dialog.
type RevokeRequest = {
  payload: RevokeDeviceRequest | null;
  busy: boolean;
  approvalId: string;
  failure: RpcFailure | null;
};

const idle: RevokeRequest = { payload: null, busy: false, approvalId: "", failure: null };
const requests = new Map<string, RevokeRequest>();
const listeners = new Set<() => void>();

function emit() {
  for (const listener of listeners) listener();
}

subscribeAuthLifetime(() => {
  requests.clear();
  emit();
});

function setRevokeRequest(lifetime: AuthLifetime, deviceId: string, request: RevokeRequest) {
  if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return false;
  requests.set(deviceId, request);
  emit();
  return true;
}

function useRevokeRequest(deviceId: string): RevokeRequest {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => requests.get(deviceId) ?? idle,
  );
}

export function RevokeApprovalRequest({ deviceId }: { deviceId: string }) {
  const principal = usePrincipal();
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const [reason, setReason] = useState("");
  const { payload, busy, approvalId, failure } = useRevokeRequest(deviceId);
  const open = useOpenRevocation(deviceId);
  if (!canPermission(principal, "device.revoke")) return null;
  // One open request at a time: show it instead of inviting a duplicate.
  if (open && !approvalId) return <DeviceRevocationStatus deviceId={deviceId} />;

  async function requestApproval() {
    if (busy || lifetime.signal.aborted) return;
    const exact =
      payload ??
      create(RevokeDeviceRequestSchema, { requestId: crypto.randomUUID(), deviceId, reason });
    if (!setRevokeRequest(lifetime, deviceId, { ...idle, payload: exact, busy: true })) return;
    try {
      const result = await adminClient.createApproval(
        { lifetimeSeconds: 3600, payload: { case: "revokeDevice", value: exact } },
        { signal: lifetime.signal, timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      setRevokeRequest(lifetime, deviceId, {
        payload: exact,
        busy: false,
        approvalId: result.approval?.id ?? "",
        failure: null,
      });
      toast.success("Approval requested");
      await client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const next = toRpcFailure(error);
        setRevokeRequest(lifetime, deviceId, {
          payload: next.ambiguous ? exact : null,
          busy: false,
          approvalId: "",
          failure: next,
        });
        const { tone, title } = classifyRpcFailure(next);
        toast[tone === "destructive" ? "error" : tone === "warning" ? "warning" : "message"](
          title,
          {
            description: "Refresh before trying again.",
          },
        );
      }
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
          data-freeform="audit reason for revocation"
          required
          value={payload?.reason ?? reason}
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
          data-review-confirm
          className="w-fit"
          type="submit"
          variant="default"
          disabled={busy || (payload?.reason ?? reason).trim() === ""}
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

// The device's open revocation request in the caller's inbox, if any.
function useOpenRevocation(deviceId: string): Approval | undefined {
  const lifetime = useAuthLifetime();
  const list = useQuery(deviceApprovalsQueryOptions(lifetime, deviceId));
  return list.data?.approvals.find(
    (approval) =>
      approval.payload.case === "revokeDevice" &&
      (approval.state === ApprovalState.PENDING || approval.state === ApprovalState.APPROVED),
  );
}

// Device-page notice for an open revocation: who asked, whether another admin
// has approved it, and, for the requester of an approved one, the final step.
export function DeviceRevocationStatus({ deviceId }: { deviceId: string }) {
  const principal = usePrincipal();
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const open = useOpenRevocation(deviceId);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [done, setDone] = useState(false);
  if (!open || open.payload.case !== "revokeDevice") return null;
  const request = open.payload.value;
  const requester = open.requesterDisplayName.trim() || "another admin";
  const approved = open.state === ApprovalState.APPROVED;
  const mine = open.requesterId === principal.id;

  async function revokeNow() {
    if (busy || lifetime.signal.aborted || !open) return;
    setBusy(true);
    setFailure(null);
    try {
      await adminClient.revokeDevice(
        { ...request, approvalId: open.id },
        { signal: lifetime.signal, timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      setDone(true);
      toast.success("Device access revoked");
      await client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
      await client.invalidateQueries({ queryKey: ["devices", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) setFailure(toRpcFailure(error));
    } finally {
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <section
      aria-label="Revocation request"
      data-slot="revocation-status"
      className="grid min-w-0 gap-2 border border-l-4 border-destructive/40 p-3 text-sm"
    >
      <p className="font-medium">
        {approved
          ? mine
            ? `Revocation approved by ${open.approverDisplayName.trim() || "another admin"}. Revoke now to cut this device off.`
            : `Revocation approved. Waiting for ${requester} to revoke it.`
          : `Revocation requested by ${mine ? "you" : requester}. Waiting for another admin to approve.`}
      </p>
      <p className="text-muted-foreground">
        Request expires <Timestamp value={open.expiresAt} />.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        {approved && mine && !done ? (
          <Button variant="destructive" disabled={busy} onClick={() => void revokeNow()}>
            {busy ? "Revoking…" : failure?.ambiguous ? "Try again" : "Revoke now"}
          </Button>
        ) : null}
        <Link to="/approvals" className="underline underline-offset-4">
          Open approval inbox
        </Link>
      </div>
      {done ? <p role="status">Device access revoked.</p> : null}
      {failure ? (
        <RpcError failure={failure}>
          {failure.ambiguous ? <p>Refresh to check whether it went through.</p> : null}
        </RpcError>
      ) : null}
    </section>
  );
}
