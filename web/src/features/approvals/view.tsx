import { toJsonString } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  ApprovalSchema,
  ApprovalState,
  type Approval,
} from "../../../gen/lindm/admin/v1/approvals_pb";
import type { RevealRecoveryKeyResponse } from "../../../gen/lindm/admin/v1/device_actions_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { approvalsQueryOptions } from "./queries";

export function ApprovalsView() {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const [revealed, setRevealed] = useState<RevealRecoveryKeyResponse | null>(null);
  useEffect(() => {
    if (!revealed) return;
    const dismiss = () => {
      revealed.recoveryKey.fill(0);
      setRevealed(null);
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
      revealed.recoveryKey.fill(0);
    };
  }, [revealed, lifetime]);
  const list = useQuery(approvalsQueryOptions(lifetime, pageToken));
  const failure = list.error ? toRpcFailure(list.error) : null;
  return (
    <section className="grid min-w-0 gap-6" aria-busy={list.isFetching}>
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Approval inbox</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Review the exact target, action and payload digest before deciding. Requesters cannot
          approve their own requests. The server rechecks scope, authority and expiry at decision
          and execution.
        </p>
      </header>
      {revealed ? (
        <section
          className="grid min-w-0 gap-3 border-2 border-destructive bg-destructive/5 p-4"
          aria-label="Revealed recovery key"
        >
          <h2 className="font-semibold">Recovery key — sensitive</h2>
          <p>
            Keep this key in trusted custody. It remains only in page memory for 30 seconds and is
            cleared when dismissed, focus changes, or you leave.
          </p>
          <pre className="whitespace-pre-wrap break-all select-all">
            {new TextDecoder().decode(revealed.recoveryKey)}
          </pre>
          <Button className="w-fit" variant="outline" onClick={() => setRevealed(null)}>
            Dismiss recovery key
          </Button>
        </section>
      ) : null}
      <Button
        className="w-fit"
        variant="outline"
        disabled={list.isFetching}
        onClick={() => void list.refetch()}
      >
        Refresh approvals
      </Button>
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading approvals…</span>
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-40 w-full" />
        </div>
      ) : null}
      {failure ? (
        <Alert variant="destructive">
          <AlertTitle>{failure.denied ? "Not authorized" : "Approvals unavailable"}</AlertTitle>
          <AlertDescription>
            {failure.codeName}: {failure.message}
          </AlertDescription>
        </Alert>
      ) : null}
      {list.data?.approvals.length === 0 ? (
        <p
          role="status"
          className="border border-dashed bg-muted/30 px-6 py-10 text-center text-sm text-muted-foreground"
        >
          No approvals on this page.
        </p>
      ) : null}
      {list.data?.approvals.map((approval) => (
        <ApprovalCard
          key={`${approval.id}:${approval.state}`}
          approval={approval}
          onReveal={setRevealed}
        />
      ))}
      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          disabled={pageToken === "" || list.isFetching}
          onClick={() => setPageToken("")}
        >
          First page
        </Button>
        <Button
          variant="outline"
          disabled={!list.data?.nextPageToken || list.isFetching}
          onClick={() => setPageToken(list.data?.nextPageToken ?? "")}
        >
          Next page
        </Button>
      </div>
    </section>
  );
}

function ApprovalCard({
  approval,
  onReveal,
}: {
  approval: Approval;
  onReveal: (response: RevealRecoveryKeyResponse) => void;
}) {
  const principal = usePrincipal();
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [completed, setCompleted] = useState(false);
  const [attempt, setAttempt] = useState<{
    action: "approve" | "reject" | "execute";
    reason: string;
  } | null>(null);
  const unexpired =
    !!approval.expiresAt && timestampDate(approval.expiresAt).getTime() > Date.now();
  const decisionAllowed =
    unexpired &&
    approval.state === ApprovalState.PENDING &&
    !principal.serviceAccount &&
    principal.id !== approval.requesterId &&
    canPermission(principal, "approvals.manage") &&
    canPermission(principal, approval.permission);
  const executionAllowed =
    unexpired &&
    approval.state === ApprovalState.APPROVED &&
    principal.id === approval.requesterId &&
    canPermission(principal, approval.permission);

  async function act(action: "approve" | "reject" | "execute") {
    if (busy || lifetime.signal.aborted) return;
    const exact = attempt ?? { action, reason };
    setAttempt(exact);
    setFailure(null);
    setBusy(true);
    try {
      const options = { signal: lifetime.signal, timeoutMs: 30_000 };
      if (exact.action === "approve") {
        await adminClient.approveApproval(
          { approvalId: approval.id, reason: exact.reason },
          options,
        );
      } else if (exact.action === "reject") {
        await adminClient.rejectApproval(
          { approvalId: approval.id, reason: exact.reason },
          options,
        );
      } else {
        switch (approval.payload.case) {
          case "revokeDevice":
            await adminClient.revokeDevice(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            break;
          case "setResourceAssignment":
            await adminClient.setResourceAssignment(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            break;
          case "activateTargetPreview":
            await adminClient.activateTargetPreview(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            break;
          case "updateExecutionAuthority":
            await adminClient.updateExecutionAuthority(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            break;
          case "createDeviceAction":
            await adminClient.createDeviceAction(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            break;
          case "revealRecoveryKey": {
            const response = await adminClient.revealRecoveryKey(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            if (lifetime.signal.aborted) {
              response.recoveryKey.fill(0);
              lifetime.signal.throwIfAborted();
            }
            if (
              response.recoveryKey.length !== 64 ||
              !response.recoveryKey.every(
                (byte) => (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102),
              )
            ) {
              response.recoveryKey.fill(0);
              throw new ConnectError("Unsupported recovery-key encoding.", Code.FailedPrecondition);
            }
            onReveal(response);
            break;
          }
          default:
            throw new Error("This approval has no executable payload.");
        }
      }
      lifetime.signal.throwIfAborted();
      setCompleted(true);
      toast.success("Approval operation completed");
      await client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
      if (exact.action === "execute") {
        await client.invalidateQueries({ queryKey: ["targeting", lifetime.generation] });
        await client.invalidateQueries({ queryKey: ["device-resources", lifetime.generation] });
      }
      if (exact.action === "execute")
        await client.invalidateQueries({ queryKey: ["devices", lifetime.generation] });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        const next = toRpcFailure(error);
        setFailure(next);
        toast.error(
          next.ambiguous ? "Approval operation outcome unknown" : "Approval operation failed",
          {
            description: "Review the inline result and exact payload before continuing.",
          },
        );
        if (!next.ambiguous) setAttempt(null);
      }
    } finally {
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <article className="grid min-w-0 gap-4 border bg-card p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="break-words font-semibold">{approval.action}</h2>
        <Badge variant={approval.state === ApprovalState.PENDING ? "outline" : "secondary"}>
          {ApprovalState[approval.state]}
        </Badge>
      </div>
      <dl className="grid gap-4 break-all text-sm sm:grid-cols-2 [&_dt]:mb-1 [&_dt]:text-xs [&_dt]:text-muted-foreground">
        <div>
          <dt>Approval ID</dt>
          <dd>{approval.id}</dd>
        </div>
        <div>
          <dt>Target</dt>
          <dd>{approval.deviceId || "Control-plane execution authority"}</dd>
        </div>
        <div>
          <dt>Permission</dt>
          <dd>{approval.permission}</dd>
        </div>
        <div>
          <dt>Payload SHA-256</dt>
          <dd className="font-mono">
            {Array.from(approval.payloadSha256, (byte) => byte.toString(16).padStart(2, "0")).join(
              "",
            )}
          </dd>
        </div>
        <div>
          <dt>Requester</dt>
          <dd>{approval.requesterId}</dd>
        </div>
        <div>
          <dt>Approver / decision actor</dt>
          <dd>{approval.approverId || "Not decided"}</dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{formatTimestamp(approval.createdAt).local}</dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd>
            {formatTimestamp(approval.expiresAt).local}
            {!unexpired ? " (expired)" : ""}
          </dd>
        </div>
        <div>
          <dt>Decision reason</dt>
          <dd>{approval.decisionReason || "Not decided"}</dd>
        </div>
      </dl>
      <details className="min-w-0 border bg-muted/30 p-3">
        <summary className="cursor-pointer text-sm font-medium">
          Exact server-stored payload and approval
        </summary>
        <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">
          {toJsonString(ApprovalSchema, approval, { prettySpaces: 2 })}
        </pre>
      </details>
      {!completed && decisionAllowed ? (
        <div className="grid gap-2">
          <label className="grid gap-2 text-sm font-medium">
            Decision reason
            <Input
              aria-label="Approval decision reason"
              value={reason}
              disabled={busy || attempt !== null}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={
                busy || reason.trim() === "" || (attempt !== null && attempt.action !== "approve")
              }
              onClick={() => void act("approve")}
            >
              Approve exact payload
            </Button>
            <Button
              variant="destructive"
              disabled={
                busy || reason.trim() === "" || (attempt !== null && attempt.action !== "reject")
              }
              onClick={() => void act("reject")}
            >
              Reject
            </Button>
          </div>
        </div>
      ) : null}
      {!completed && executionAllowed && approval.payload.case ? (
        <Button
          className="w-fit"
          variant="destructive"
          disabled={busy}
          onClick={() => void act("execute")}
        >
          {failure?.ambiguous ? "Retry exact approved execution" : "Execute exact approved payload"}
        </Button>
      ) : null}
      {busy ? (
        <p role="status" className="text-sm text-muted-foreground">
          Submitting exact request…
        </p>
      ) : null}
      {completed ? (
        <p role="status" className="border bg-muted/30 p-3 text-sm">
          Operation completed.
        </p>
      ) : null}
      {failure ? (
        <Alert variant="destructive">
          <AlertTitle>{failure.ambiguous ? "Outcome unknown" : "Operation failed"}</AlertTitle>
          <AlertDescription>
            {failure.codeName}: {failure.message}
            {failure.ambiguous
              ? " Outcome unknown. Refresh first; any explicit retry preserves the same ID and exact payload."
              : ""}
          </AlertDescription>
        </Alert>
      ) : null}
    </article>
  );
}
