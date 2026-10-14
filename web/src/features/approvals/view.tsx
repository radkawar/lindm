// SPDX-License-Identifier: Apache-2.0

import { toJsonString } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { createContext, useContext, useEffect, useId, useState } from "react";
import { toast } from "sonner";
import {
  ApprovalEvidenceState,
  ApprovalSchema,
  ApprovalState,
  type Approval,
} from "../../../gen/lindm/admin/v1/approvals_pb";
import { CryptoEraseMode } from "../../../gen/lindm/agent/v1/device_actions_pb";
import type { TargetRef } from "../../../gen/lindm/policy/v1/targeting_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { ListPagination } from "@/components/ui/list-pagination";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Timestamp } from "@/components/ui/timestamp";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { formatBytes } from "@/lib/bytes";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { revealedText } from "@/lib/reveal";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { approvalsQueryOptions } from "./queries";
import {
  actionLabels,
  deviceActionDetailItems,
  DeviceActionSpecView,
} from "@/features/devices/action-display";
import {
  recoveryReadinessDetailItems,
  RecoveryReadinessView,
} from "@/features/devices/recovery-readiness";

const APPROVAL_STATES: Record<ApprovalState, string> = {
  [ApprovalState.UNSPECIFIED]: "Unknown",
  [ApprovalState.PENDING]: "Pending",
  [ApprovalState.APPROVED]: "Approved",
  [ApprovalState.REJECTED]: "Rejected",
  [ApprovalState.CONSUMED]: "Completed",
  [ApprovalState.EXPIRED]: "Expired",
  [ApprovalState.WITHDRAWN]: "Withdrawn",
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
  startRollout: "Roll out",
  revealSecret: "Reveal secret",
  revealLocalAdminPassword: "Reveal local-admin password",
  acceptAdvisoryFinding: "Accept advisory risk",
  authorizeUnattendedAssistance: "Allow unattended remote assistance",
};

// Unattended assistance is decided under its own independent permission, never
// the requester's.
const reviewerPermissions: Record<string, string> = {
  "remote_assistance.unattended": "remote_assistance.unattended.approve",
};

// One line naming what an approved destructive request irreversibly does to
// which device; empty for requests that are not destructive.
function destructiveConsequence(approval: Approval, hostname: string): string {
  const payload = approval.payload;
  if (payload.case === "revokeDevice")
    return `Cuts ${hostname} off from management · its device certificate stops working · undoing it needs a recovery enrollment`;
  if (payload.case !== "createDeviceAction") return "";
  const action = payload.value.spec?.action;
  if (action?.case === "cryptoErase") {
    const live = action.value.mode === CryptoEraseMode.LIVE_ROOT_HEADER;
    let targets = action.value.targets;
    if (!live) targets = action.value.target ? [action.value.target] : [];
    const total = formatBytes(targets.reduce((sum, target) => sum + target.sizeBytes, 0n));
    const scope =
      targets.length === 0
        ? ""
        : targets.length === 1
          ? ` · ${total} volume`
          : ` · ${targets.length} volumes, ${total} in total`;
    return `Wipes all data on ${hostname}${scope}${live ? " · powers it off" : ""} · irreversible`;
  }
  if (action?.case === "sanitize") {
    const size =
      action.value.target?.sizeBytes ?? action.value.nvmeScope?.identity?.namespaceSizeBytes;
    const scope = action.value.nvmeScope?.controllerWide
      ? "every namespace on the disk controller"
      : size === undefined
        ? "the selected disk"
        : `${formatBytes(size)} disk`;
    return `Wipes all data on ${hostname} · ${scope} · irreversible`;
  }
  return "";
}

// Revealed bytes stay in page memory only and are zeroized on dismissal.
type Revealed = { label: string; secret: Uint8Array; note: string };

// Names for a rollout approval's profile version and target, composed by the route.
type NameLabel = { text: string; ready: boolean };
export type RolloutApprovalNames = {
  useTargetLabel: (target?: TargetRef) => NameLabel;
  useProfileVersionLabel: (id: string) => NameLabel;
};
const unnamed = () => ({ text: "Name unavailable", ready: false });
const RolloutNames = createContext<RolloutApprovalNames>({
  useTargetLabel: unnamed,
  useProfileVersionLabel: unnamed,
});

// "Workstation baseline, version 2 to Engineering workstations".
function RolloutTargetName({ approval }: { approval: Approval }) {
  const names = useContext(RolloutNames);
  const request = approval.payload.case === "startRollout" ? approval.payload.value : undefined;
  const assignment = approval.rollout?.assignment ?? request?.assignment;
  // Server-projected names first; the first-page lookups run only without them.
  const version = approval.rollout?.profileVersion;
  const profile = names.useProfileVersionLabel(
    version ? "" : (assignment?.profileRevisionId ?? ""),
  );
  const target = names.useTargetLabel(
    approval.rollout?.targetName ? undefined : assignment?.target,
  );
  return (
    <>
      {version
        ? `${version.profileName}, version ${version.revisionNumber.toString()}`
        : profile.text}{" "}
      to {approval.rollout?.targetName || target.text}
    </>
  );
}

function RolloutApproval({ approval }: { approval: Approval }) {
  const request = approval.payload.case === "startRollout" ? approval.payload.value : undefined;
  const state = approval.rollout;
  const rings = (state?.rollout ?? request?.rollout)?.rings ?? [];
  const adopted = state?.adopted ?? [];
  return (
    <div className="grid gap-2 text-sm" data-slot="rollout-approval">
      <p>
        {state
          ? `${state.plannedCount} ${state.plannedCount === 1 ? "device" : "devices"}`
          : "Device count unavailable"}{" "}
        ·{" "}
        {rings.length === 1
          ? "everyone at once"
          : `${rings.length} stages: ${rings.map((ring) => ring.name).join(", ")}`}
      </p>
      {adopted.length && state ? (
        <p className="text-warning">
          Adopts the existing{" "}
          {adopted.map((ref, index) => (
            <span key={`${ref.kind}:${ref.canonicalKey}`}>
              {index ? ", " : ""}
              <code className="font-mono text-[0.92em] break-all">{ref.canonicalKey}</code>
            </span>
          ))}{" "}
          on {state.adoptingCount} {state.adoptingCount === 1 ? "device" : "devices"}: lindm takes
          over settings these devices already have.
        </p>
      ) : null}
      <p className="text-muted-foreground">
        {approval.state === ApprovalState.PENDING
          ? "Approving starts the rollout within a minute. Nothing changes before that."
          : "The rollout's progress is on Rollouts."}{" "}
        <Link to="/rollouts" className="underline underline-offset-4">
          Open Rollouts
        </Link>
      </p>
    </div>
  );
}

export function ApprovalsView({ rolloutNames }: { rolloutNames: RolloutApprovalNames }) {
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
    <RolloutNames value={rolloutNames}>
      <section className="grid min-w-0 gap-6" aria-busy={list.isFetching}>
        <PageHeader
          title="Approval inbox"
          description="Approve or reject requests from other admins."
          actions={
            <Button
              variant="outline"
              disabled={list.isFetching}
              onClick={() => void list.refetch()}
            >
              Refresh
            </Button>
          }
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
              <p className="text-sm">
                The value contains binary data. lindm shows it as hexadecimal.
              </p>
            ) : null}
            <pre className="whitespace-pre-wrap break-all select-all">{shown?.text}</pre>
            <Button className="w-fit" variant="outline" onClick={() => setRevealed(null)}>
              Dismiss {revealed.label}
            </Button>
          </section>
        ) : null}
        {list.isPending ? (
          <div role="status" className="grid gap-3">
            <span className="text-sm text-muted-foreground">Loading approvals…</span>
            <Skeleton className="h-40 w-full" />
            <Skeleton className="h-40 w-full" />
          </div>
        ) : null}
        {failure ? <RpcError failure={failure} /> : null}
        {list.data?.approvals.length === 0 ? (
          <EmptyState
            title="No approvals waiting"
            description="Requests that need another administrator appear here."
          />
        ) : null}
        {list.data && list.data.approvals.length > 0 ? (
          <ApprovalGroups approvals={list.data.approvals} onReveal={setRevealed} />
        ) : null}
        <ListPagination
          label="Approval pages"
          onPrevious={pageToken === "" ? undefined : () => setPageToken("")}
          onNext={
            list.data?.nextPageToken
              ? () => setPageToken(list.data?.nextPageToken ?? "")
              : undefined
          }
          busy={list.isFetching}
        />
      </section>
    </RolloutNames>
  );
}

function ApprovalGroups({
  approvals,
  onReveal,
}: {
  approvals: Approval[];
  onReveal: (revealed: Revealed) => void;
}) {
  const principal = usePrincipal();
  // Open requests still await a decision or their requester's run. The server
  // reports expiry as its own state and lists open requests first. Approved
  // requests only their requester can run lead, as that requester's next step.
  const ready = approvals.filter(
    (approval) =>
      approval.state === ApprovalState.APPROVED && approval.requesterId === principal.id,
  );
  const open = approvals.filter(
    (approval) =>
      !ready.includes(approval) &&
      (approval.state === ApprovalState.PENDING || approval.state === ApprovalState.APPROVED),
  );
  const closed = approvals.filter(
    (approval) => !ready.includes(approval) && !open.includes(approval),
  );
  return (
    <>
      {ready.length > 0 ? (
        <section className="grid min-w-0 gap-4" aria-labelledby="approvals-ready">
          <h2 id="approvals-ready" className="text-base font-semibold">
            Ready for you to run{" "}
            <span className="font-normal text-muted-foreground">({ready.length})</span>
          </h2>
          {ready.map((approval) => (
            <ApprovalCard
              key={`${approval.id}:${approval.state}`}
              approval={approval}
              open
              onReveal={onReveal}
            />
          ))}
        </section>
      ) : null}
      <section className="grid min-w-0 gap-4" aria-labelledby="approvals-open">
        <h2 id="approvals-open" className="text-base font-semibold">
          Open requests <span className="font-normal text-muted-foreground">({open.length})</span>
        </h2>
        {open.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Nothing on this page is waiting for a decision.
          </p>
        ) : null}
        {open.map((approval) => (
          <ApprovalCard
            key={`${approval.id}:${approval.state}`}
            approval={approval}
            open
            onReveal={onReveal}
          />
        ))}
      </section>
      {closed.length > 0 ? (
        <details className="min-w-0">
          <summary className="w-fit cursor-pointer py-1">
            <h2 className="inline text-base font-semibold">Recent decisions</h2>{" "}
            <span className="text-sm text-muted-foreground">
              {closed.length === 1 ? "1 request" : `${closed.length} requests`}
            </span>
          </summary>
          <div className="mt-4 grid min-w-0 gap-4">
            {closed.map((approval) => (
              <ApprovalCard
                key={`${approval.id}:${approval.state}`}
                approval={approval}
                open={false}
                onReveal={onReveal}
              />
            ))}
          </div>
        </details>
      ) : null}
    </>
  );
}

function ApprovalCard({
  approval,
  open,
  onReveal,
}: {
  approval: Approval;
  open: boolean;
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
    action: "approve" | "reject" | "withdraw" | "execute";
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
  const unexpired =
    !!approval.expiresAt && timestampDate(approval.expiresAt).getTime() > Date.now();
  // The server decides whether bound evidence still holds and refuses approval
  // when it does not; the card never infers it from a missing finding.
  const evidenceGone =
    unexpired &&
    (approval.state === ApprovalState.PENDING || approval.state === ApprovalState.APPROVED) &&
    approval.evidenceState === ApprovalEvidenceState.UNAVAILABLE;
  const advisoryReady =
    !advisoryRequest ||
    (approval.evidenceState === ApprovalEvidenceState.CURRENT && exceptionUnexpired);
  const awaitingDecision = unexpired && approval.state === ApprovalState.PENDING;
  // The server refuses any decision by the requester; say so instead of hiding it.
  const ownRequest = awaitingDecision && principal.id === approval.requesterId;
  const decisionAllowed =
    awaitingDecision &&
    !ownRequest &&
    !principal.serviceAccount &&
    canPermission(principal, "approvals.manage") &&
    canPermission(principal, reviewerPermissions[approval.permission] ?? approval.permission);
  const ownRequestReasonId = useId();
  const decisionHintId = useId();
  const evidenceGoneId = useId();
  const hostname = approval.deviceHostname.trim() || "Unnamed device";
  const consequence = open ? destructiveConsequence(approval, hostname) : "";
  // An approved rollout starts on its own; its requester has nothing to run.
  const executionAllowed =
    unexpired &&
    approval.state === ApprovalState.APPROVED &&
    approval.payload.case !== "startRollout" &&
    principal.id === approval.requesterId &&
    canPermission(principal, approval.permission);
  const rolloutRequest =
    approval.payload.case === "startRollout" ? approval.payload.value : undefined;
  const requestReason = actionRequest?.reason ?? rolloutRequest?.reason;

  async function act(action: "approve" | "reject" | "withdraw" | "execute") {
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
      } else if (exact.action === "withdraw") {
        await adminClient.withdrawApproval(
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
          case "authorizeUnattendedAssistance":
            await adminClient.authorizeUnattendedAssistance(
              { ...approval.payload.value, approvalId: approval.id },
              options,
            );
            break;
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
                  ? `lindm changes the password ${formatTimestamp(response.rotationDueAt).local}.`
                  : "lindm does not change the password automatically."
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
            : exact.action === "withdraw"
              ? "Request withdrawn"
              : approval.payload.case === "acceptAdvisoryFinding"
                ? "Risk accepted"
                : "Action started",
      );
      await client.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
      // Approving, rejecting and running all change what Enrollment shows.
      if (approval.payload.case === "approvePendingEnrollment")
        await client.invalidateQueries({
          queryKey: ["pending-enrollments", lifetime.generation],
        });
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
            description:
              next.reason === "recent_step_up_required"
                ? "Verify in the request card. lindm then sends the same request again."
                : "Refresh before trying again.",
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
        <h3 className="break-words font-semibold">
          {effect}
          {rolloutRequest ? (
            ` ${approval.rollout?.rollout?.name || rolloutRequest.rollout?.name || "a profile version"}`
          ) : approval.deviceId ? (
            <>
              {" on "}
              <Link
                to="/devices/$deviceId"
                params={{ deviceId: approval.deviceId }}
                search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
                className="underline underline-offset-4"
              >
                {hostname}
              </Link>
            </>
          ) : approval.payload.case === "revealSecret" ? (
            `, version ${approval.payload.value.version.toString()}`
          ) : (
            ""
          )}
        </h3>
        <StatusBadge
          status={
            evidenceGone
              ? "warning"
              : approval.state === ApprovalState.REJECTED
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
          {evidenceGone ? "Invalid" : (APPROVAL_STATES[approval.state] ?? "Unknown")}
        </StatusBadge>
      </div>
      {consequence ? (
        <p className="break-words text-sm font-medium text-destructive" data-slot="consequence">
          {consequence}
        </p>
      ) : null}
      {evidenceGone ? (
        <p id={evidenceGoneId} role="alert" className="text-sm">
          The device no longer reports this finding. You cannot approve this request. Reject it.
          Propose a new acceptance from the device if the risk remains.
        </p>
      ) : null}
      <dl
        className="flex flex-wrap gap-x-4 gap-y-1 break-words text-sm text-muted-foreground [&_dd]:inline [&_dd]:text-foreground [&_dt]:inline"
        data-slot="approval-facts"
      >
        {rolloutRequest ? (
          <div>
            <dt>Delivers: </dt>
            <dd>
              <RolloutTargetName approval={approval} />
            </dd>
          </div>
        ) : null}
        <div>
          <dt>Requester: </dt>
          <dd>{approval.requesterDisplayName.trim() || "Unknown"}</dd>
        </div>
        <div>
          <dt>Requested: </dt>
          <dd>
            <Timestamp value={approval.createdAt} />
          </dd>
        </div>
        <div>
          <dt>{unexpired ? "Expires: " : "Expired: "}</dt>
          <dd>
            <Timestamp value={approval.expiresAt} />
          </dd>
        </div>
        {approval.payload.case === "authorizeUnattendedAssistance" ? (
          <div className="sm:col-span-2">
            <dt>Unattended access: </dt>
            <dd className="whitespace-pre-wrap">
              {`${approval.payload.value.reason}\nUser ${approval.payload.value.targetUsername}, ${
                approval.payload.value.mode === 2 ? "view and control" : "view only"
              }, ${Math.round(approval.payload.value.durationSeconds / 3600)} hours from ${
                formatTimestamp(approval.payload.value.notBefore).local
              }${approval.payload.value.schedule ? ", weekly schedule" : ""}. The user opted in on the device and always sees a banner with Stop.`}
            </dd>
          </div>
        ) : null}
        {approval.approverId ? (
          <div>
            <dt>Decided by: </dt>
            <dd>{approval.approverDisplayName.trim() || "Unknown"}</dd>
          </div>
        ) : null}
      </dl>
      {requestReason || approval.decisionReason ? (
        <dl className="grid gap-3 break-words text-sm sm:grid-cols-2 [&_dt]:mb-1 [&_dt]:text-xs [&_dt]:text-muted-foreground">
          {requestReason ? (
            <div>
              <dt>Request reason</dt>
              <dd className="whitespace-pre-wrap">{requestReason}</dd>
            </div>
          ) : null}
          {approval.decisionReason ? (
            <div>
              <dt>Decision reason</dt>
              <dd className="whitespace-pre-wrap">{approval.decisionReason}</dd>
            </div>
          ) : null}
        </dl>
      ) : null}
      {rolloutRequest ? <RolloutApproval approval={approval} /> : null}
      {approval.payload.case === "acceptAdvisoryFinding" ? (
        <div className="grid gap-2 border border-l-4 border-warning/40 p-3 text-sm">
          <p>This accepts risk on this device only; it does not fix the package.</p>
          {approval.advisoryFinding ? (
            <p>
              {approval.advisoryFinding.advisoryId}: {approval.advisoryFinding.packageName}{" "}
              {approval.advisoryFinding.installedVersion} ({approval.advisoryFinding.architecture})
            </p>
          ) : null}
          <p className="whitespace-pre-wrap">Reason: {approval.payload.value.reason}</p>
          <p>
            Risk acceptance expires: <Timestamp value={approval.payload.value.expiresAt} />
          </p>
        </div>
      ) : null}
      {/* An open destructive request's consequence line already names its
          target, size and mode; the exact storage identity stays in Details. */}
      {actionRequest && !consequence ? (
        <DeviceActionSpecView spec={actionSpec} technicalDetails={false} />
      ) : null}
      {recovery ? (
        readiness.error ? (
          <RpcError failure={toRpcFailure(readiness.error)} />
        ) : readiness.isPending ? (
          <p role="status">Checking recovery readiness…</p>
        ) : (
          <RecoveryReadinessView readiness={currentReadiness} technicalDetails={false} />
        )
      ) : null}
      {!completed && decisionAllowed ? (
        <div className="grid gap-2">
          <label className="grid gap-2 text-sm font-medium">
            Decision reason
            <Input
              aria-label="Approval decision reason"
              aria-describedby={reason.trim() === "" ? decisionHintId : undefined}
              data-freeform="audit reason for the decision"
              value={reason}
              disabled={busy || attempt !== null}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>
          <div className="flex flex-wrap gap-2">
            <Button
              aria-describedby={
                [evidenceGone ? evidenceGoneId : "", reason.trim() === "" ? decisionHintId : ""]
                  .filter(Boolean)
                  .join(" ") || undefined
              }
              disabled={
                busy ||
                evidenceGone ||
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
              aria-describedby={reason.trim() === "" ? decisionHintId : undefined}
              disabled={
                busy || reason.trim() === "" || (attempt !== null && attempt.action !== "reject")
              }
              onClick={() => void act("reject")}
            >
              Reject
            </Button>
          </div>
          {reason.trim() === "" ? (
            <p id={decisionHintId} className="text-sm text-muted-foreground">
              {evidenceGone
                ? "Enter a reason to reject this request. lindm records the reason in the audit log."
                : "Enter a reason for your decision. lindm records the reason in the audit log."}
            </p>
          ) : null}
        </div>
      ) : null}
      {!completed && ownRequest ? (
        <div className="grid gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <Button className="w-fit" disabled aria-describedby={ownRequestReasonId}>
              Approve
            </Button>
            <p id={ownRequestReasonId} className="text-sm text-muted-foreground">
              You requested this; another admin must approve.
            </p>
          </div>
          <label className="grid gap-2 text-sm font-medium">
            Withdrawal reason
            <Input
              aria-label="Withdrawal reason"
              aria-describedby={reason.trim() === "" ? decisionHintId : undefined}
              data-freeform="audit reason for withdrawing the request"
              value={reason}
              disabled={busy || attempt !== null}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>
          <Button
            className="w-fit"
            variant="outline"
            aria-describedby={reason.trim() === "" ? decisionHintId : undefined}
            disabled={
              busy || reason.trim() === "" || (attempt !== null && attempt.action !== "withdraw")
            }
            onClick={() => void act("withdraw")}
          >
            {failure?.ambiguous && attempt?.action === "withdraw"
              ? "Try again"
              : "Withdraw request"}
          </Button>
          {reason.trim() === "" ? (
            <p id={decisionHintId} className="text-sm text-muted-foreground">
              Enter a reason to withdraw. lindm records the reason in the audit log.
            </p>
          ) : null}
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
        <RpcError failure={failure} onRetry={() => void act("execute")}>
          {failure.ambiguous ? (
            <p>Refresh to check whether it went through before trying again.</p>
          ) : null}
        </RpcError>
      ) : null}
      <TechnicalDetails
        items={[
          { label: "Approval ID", value: approval.id },
          { label: "Device ID", value: approval.deviceId },
          { label: "Rollout ID", value: rolloutRequest?.rollout?.rolloutId },
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
          ...deviceActionDetailItems(actionSpec),
          ...(recovery ? recoveryReadinessDetailItems(currentReadiness) : []),
        ]}
      >
        <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">
          {toJsonString(ApprovalSchema, approval, { prettySpaces: 2 })}
        </pre>
      </TechnicalDetails>
    </article>
  );
}
