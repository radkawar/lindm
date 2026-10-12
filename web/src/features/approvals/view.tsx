import { toJsonString } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  ApprovalSchema,
  ApprovalState,
  type Approval,
} from "../../../gen/lindm/admin/v1/approvals_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission, permissionLabels } from "@/lib/permissions";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { revealedText } from "@/lib/reveal";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { approvalsQueryOptions } from "./queries";
import { actionLabels, DeviceActionSpecView } from "@/features/devices/action-display";
import { RecoveryReadinessView } from "@/features/devices/recovery-readiness";

const APPROVAL_STATES: Record<ApprovalState, string> = {
  [ApprovalState.UNSPECIFIED]: "Unknown",
  [ApprovalState.PENDING]: "Pending",
  [ApprovalState.APPROVED]: "Approved",
  [ApprovalState.REJECTED]: "Rejected",
  [ApprovalState.CONSUMED]: "Completed",
  [ApprovalState.EXPIRED]: "Expired",
};

const approvalEffects: Record<NonNullable<Approval["payload"]["case"]>, string> = {
  revokeDevice: "Revoke device access",
  setResourceAssignment: "Change resource assignment",
  updateExecutionAuthority: "Change who can run actions",
  createDeviceAction: "Run device action",
  revealRecoveryKey: "Reveal recovery key",
  approvePendingEnrollment: "Approve device enrollment",
  recoverDevice: "Recover device enrollment",
  activateTargetPreview: "Activate assignment rollout",
  revealSecret: "Reveal secret",
  revealLocalAdminPassword: "Reveal local-admin password",
  acceptAdvisoryFinding: "Accept advisory risk",
};

// Revealed bytes stay in page memory only and are zeroized on dismissal.
type Revealed = { label: string; secret: Uint8Array; note: string };

export function ApprovalsView() {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  useEffect(() => {
    if (!revealed) return;
    const dismiss = () => {
      revealed.secret.fill(0);
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
      revealed.secret.fill(0);
    };
  }, [revealed, lifetime]);
  const list = useQuery(approvalsQueryOptions(lifetime, pageToken));
  const failure = list.error ? toRpcFailure(list.error) : null;
  const shown = revealed ? revealedText(revealed.secret) : null;
  return (
    <section className="grid min-w-0 gap-6" aria-busy={list.isFetching}>
      <PageHeader
        title="Approval inbox"
        description="Approve or reject requests from other admins."
      />
      {revealed ? (
        <section
          className="grid min-w-0 gap-3 border border-warning/30 bg-warning/10 p-4"
          aria-label={`Revealed ${revealed.label}`}
        >
          <h2 className="font-semibold">Sensitive {revealed.label}</h2>
          <p>Copy it now. It disappears after 30 seconds or when you leave this page.</p>
          {revealed.note ? <p>{revealed.note}</p> : null}
          {shown?.hex ? (
            <p className="text-sm">Shown as hexadecimal because it isn't plain text.</p>
          ) : null}
          <pre className="whitespace-pre-wrap break-all select-all">{shown?.text}</pre>
          <Button className="w-fit" variant="outline" onClick={() => setRevealed(null)}>
            Dismiss {revealed.label}
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
      {failure ? <RpcError failure={failure} /> : null}
      {list.data?.approvals.length === 0 ? <EmptyState title="No approvals waiting" /> : null}
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
  onReveal: (revealed: Revealed) => void;
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
  const actionRequest =
    approval.payload.case === "createDeviceAction" ? approval.payload.value : undefined;
  const actionSpec = actionRequest?.spec;
  const effect = actionSpec?.action.case
    ? actionLabels[actionSpec.action.case]
    : approval.payload.case
      ? approvalEffects[approval.payload.case]
      : "Review requested action";
  const recovery =
    actionSpec?.action.case === "sanitize" ? actionSpec.action.value.recovery : undefined;
  const readiness = useQuery({
    queryKey: ["approval-recovery-readiness", lifetime.generation, approval.id] as const,
    meta: { authGeneration: lifetime.generation },
    enabled: !!recovery,
    retry: false,
    refetchInterval: 10_000,
    queryFn: async ({ signal }) => {
      const result = await adminClient.listDeviceStorageTargets(
        {
          deviceId: actionRequest!.deviceId,
          actionKind: "sanitize",
          recoveryImageSha256: recovery!.imageSha256,
        },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
  });
  const currentReadiness =
    !readiness.error && readiness.data?.enrollmentGeneration === actionRequest?.enrollmentGeneration
      ? readiness.data?.recoveryReadiness
      : undefined;
  const recoveryReady = !recovery || currentReadiness?.ready === true;
  const advisoryRequest =
    approval.payload.case === "acceptAdvisoryFinding" ? approval.payload.value : undefined;
  const exceptionUnexpired =
    !advisoryRequest ||
    (!!advisoryRequest.expiresAt &&
      timestampDate(advisoryRequest.expiresAt).getTime() > Date.now());
  const advisoryReady = !advisoryRequest || (!!approval.advisoryFinding && exceptionUnexpired);
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
          case "acceptAdvisoryFinding":
            await adminClient.acceptAdvisoryFinding(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            break;
          case "approvePendingEnrollment":
            await adminClient.approvePendingEnrollment(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            break;
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
            onReveal({ label: "recovery key", secret: response.recoveryKey, note: "" });
            break;
          }
          case "revealSecret": {
            const response = await adminClient.revealSecret(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            const material = response.material?.material.value;
            if (lifetime.signal.aborted) {
              material?.fill(0);
              lifetime.signal.throwIfAborted();
            }
            if (!material)
              throw new ConnectError(
                "The server returned no secret material.",
                Code.FailedPrecondition,
              );
            onReveal({
              label: "secret",
              secret: material,
              note: `Version ${approval.payload.value.version.toString()}.`,
            });
            break;
          }
          case "revealLocalAdminPassword": {
            const response = await adminClient.revealLocalAdminPassword(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            if (lifetime.signal.aborted) {
              response.password.fill(0);
              lifetime.signal.throwIfAborted();
            }
            onReveal({
              label: "local-admin password",
              secret: response.password,
              note: `Account ${response.escrow?.accountName || "unknown"}. ${
                response.rotationDueAt
                  ? `The password will be changed ${formatTimestamp(response.rotationDueAt).local}.`
                  : "The password won't be changed automatically."
              }`,
            });
            break;
          }
          default:
            throw new Error("This approval has nothing to run.");
        }
      }
      lifetime.signal.throwIfAborted();
      setCompleted(true);
      toast.success(
        exact.action === "approve"
          ? "Approved"
          : exact.action === "reject"
            ? "Rejected"
            : approval.payload.case === "acceptAdvisoryFinding"
              ? "Risk accepted"
              : "Action started",
      );
      await client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
      if (exact.action === "execute") {
        await client.invalidateQueries({ queryKey: ["targeting", lifetime.generation] });
        await client.invalidateQueries({ queryKey: ["advisory-findings", lifetime.generation] });
        await client.invalidateQueries({ queryKey: ["advisory-summary", lifetime.generation] });
        await client.invalidateQueries({ queryKey: ["device-resources", lifetime.generation] });
      }
      if (exact.action === "execute") {
        await client.invalidateQueries({ queryKey: ["devices", lifetime.generation] });
        await client.invalidateQueries({
          queryKey: ["local-admin-password", lifetime.generation],
        });
      }
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
        if (!next.ambiguous) setAttempt(null);
      }
    } finally {
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <article className="grid min-w-0 gap-4 border bg-card p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="break-words font-semibold">
          {effect}
          {approval.deviceId ? ` on ${approval.deviceHostname.trim() || "Unnamed device"}` : ""}
        </h2>
        <StatusBadge
          status={
            approval.state === ApprovalState.REJECTED
              ? "destructive"
              : approval.state === ApprovalState.EXPIRED
                ? "warning"
                : approval.state === ApprovalState.APPROVED
                  ? "success"
                  : approval.state === ApprovalState.PENDING
                    ? "info"
                    : "neutral"
          }
        >
          {APPROVAL_STATES[approval.state] ?? "Unknown"}
        </StatusBadge>
      </div>
      <dl className="grid gap-4 break-words text-sm sm:grid-cols-2 [&_dt]:mb-1 [&_dt]:text-xs [&_dt]:text-muted-foreground">
        <div>
          <dt>Target</dt>
          <dd>
            {approval.deviceId ? (
              <Link
                to="/devices/$deviceId"
                params={{ deviceId: approval.deviceId }}
                search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
                className="underline underline-offset-4"
              >
                {approval.deviceHostname.trim() || "Unnamed device"}
              </Link>
            ) : approval.payload.case === "activateTargetPreview" ? (
              "Assignment rollout"
            ) : approval.payload.case === "approvePendingEnrollment" ? (
              "Pending device enrollment"
            ) : approval.payload.case === "revealSecret" ? (
              `Secret, version ${approval.payload.value.version.toString()}`
            ) : (
              "Deployment"
            )}
          </dd>
        </div>
        <div>
          <dt>Permission</dt>
          <dd>{permissionLabels[approval.permission] ?? "Other permission"}</dd>
        </div>
        <div>
          <dt>Requester</dt>
          <dd>{approval.requesterDisplayName.trim() || "Unknown"}</dd>
        </div>
        <div>
          <dt>Decided by</dt>
          <dd>
            {approval.approverId ? approval.approverDisplayName.trim() || "Unknown" : "Not decided"}
          </dd>
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
        {actionRequest?.reason ? (
          <div className="sm:col-span-2">
            <dt>Request reason</dt>
            <dd className="whitespace-pre-wrap">{actionRequest.reason}</dd>
          </div>
        ) : null}
      </dl>
      {approval.payload.case === "acceptAdvisoryFinding" ? (
        <div className="grid gap-2 border border-warning/30 bg-warning/10 p-3 text-sm">
          <p>This accepts risk on this device only; it does not fix the package.</p>
          {approval.advisoryFinding ? (
            <p>
              {approval.advisoryFinding.advisoryId}: {approval.advisoryFinding.packageName}{" "}
              {approval.advisoryFinding.installedVersion} ({approval.advisoryFinding.architecture})
            </p>
          ) : (
            <p role="alert">
              Finding evidence is no longer available. Return to the device and investigate before
              proposing a new exception.
            </p>
          )}
          <p className="whitespace-pre-wrap">Reason: {approval.payload.value.reason}</p>
          <p>Risk acceptance expires: {formatTimestamp(approval.payload.value.expiresAt).local}</p>
        </div>
      ) : null}
      {actionRequest ? <DeviceActionSpecView spec={actionSpec} /> : null}
      {recovery ? (
        readiness.error ? (
          <RpcError failure={toRpcFailure(readiness.error)} />
        ) : readiness.isPending ? (
          <p role="status">Checking recovery readiness…</p>
        ) : (
          <RecoveryReadinessView readiness={currentReadiness} />
        )
      ) : null}
      <TechnicalDetails
        items={[
          { label: "Approval ID", value: approval.id },
          { label: "Device ID", value: approval.deviceId },
          ...(approval.payload.case === "revealSecret"
            ? [{ label: "Secret ID", value: approval.payload.value.secretId }]
            : []),
          { label: "Requester ID", value: approval.requesterId },
          { label: "Approver ID", value: approval.approverId },
          { label: "Action", value: approval.action },
          { label: "Permission", value: approval.permission },
          {
            label: "Payload SHA-256",
            value: Array.from(approval.payloadSha256, (byte) =>
              byte.toString(16).padStart(2, "0"),
            ).join(""),
          },
        ]}
      >
        <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">
          {toJsonString(ApprovalSchema, approval, { prettySpaces: 2 })}
        </pre>
      </TechnicalDetails>
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
                busy ||
                (!recoveryReady && !(failure?.ambiguous && attempt?.action === "approve")) ||
                (!advisoryReady && !(failure?.ambiguous && attempt?.action === "approve")) ||
                reason.trim() === "" ||
                (attempt !== null && attempt.action !== "approve")
              }
              onClick={() => void act("approve")}
            >
              Approve
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
      {advisoryRequest && !exceptionUnexpired ? (
        <p role="alert" className="text-sm">
          The requested expiry has passed. Reject this request and propose a new expiry from the
          device finding.
        </p>
      ) : null}
      {!completed && executionAllowed && approval.payload.case ? (
        <Button
          className="w-fit"
          variant="destructive"
          disabled={busy || ((!recoveryReady || !advisoryReady) && !failure?.ambiguous)}
          onClick={() => void act("execute")}
        >
          {failure?.ambiguous
            ? "Try again"
            : approval.payload.case === "acceptAdvisoryFinding"
              ? "Accept approved risk"
              : "Run now"}
        </Button>
      ) : null}
      {busy ? (
        <p role="status" className="text-sm text-muted-foreground">
          Submitting…
        </p>
      ) : null}
      {completed ? (
        <p role="status" className="border bg-muted/30 p-3 text-sm">
          Done.
        </p>
      ) : null}
      {failure ? (
        <RpcError failure={failure}>
          {failure.ambiguous ? (
            <p>Refresh to check whether it went through before trying again.</p>
          ) : null}
        </RpcError>
      ) : null}
    </article>
  );
}
