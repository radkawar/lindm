import { create } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  ControlRolloutRequest_Operation,
  ControlRolloutRequestSchema,
  RolloutDeviceState,
  RolloutStatus,
  type ControlRolloutRequest,
  type RolloutDevice,
  type ProfileVersionLabel,
  type RolloutState,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import type { TargetCandidate } from "../../../gen/lindm/policy/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { ListPagination } from "@/components/ui/list-pagination";
import { Timestamp } from "@/components/ui/timestamp";
import { RolloutFlow } from "./assignment";
import { ReasonControl } from "./controls";
import { Adoption, versionText } from "./impact";
import { formatSeconds } from "./duration";
import { ListStatus } from "./list";
import { useTargetLabel, useTargetNames } from "./pickers";
import { TargetPreviewView } from "./preview";
import {
  rolloutDevicesQueryOptions,
  rolloutsQueryOptions,
  targetAssignmentsQueryOptions,
} from "./queries";

const PAUSE_REASONS: Record<string, string> = {
  failure_threshold: "Too many devices reported a failure. Check the failed devices below.",
  unavailable_threshold: "Too many devices are unreachable. Check their latest contact.",
  unknown_threshold: "Too many devices haven't confirmed the change. Check the devices below.",
  rollout_authorization_denied:
    "The administrator who started it can no longer roll out changes. Review their access.",
};

const NEEDS_REVIEW: Record<string, string> = {
  preview_changed: "Its settings changed after review. The rollout skipped this device.",
  device_reenrolled: "It enrolled again after review. The rollout skipped this device.",
  assigned_directly:
    "An administrator assigned a profile directly after review. The rollout skipped this device.",
  device_not_active: "Active management enrollment ended. The rollout skipped this device.",
  resolution_not_ready: "Settings conflict or cannot apply. The rollout skipped this device.",
  adoption_not_approved:
    "Approval did not cover the existing settings. The rollout skipped this device.",
  membership_unknown: "Its inventory is too old to confirm it's still in the target.",
};

const DEVICE_STATES: Record<RolloutDeviceState, { label: string; tone: StatusTone }> = {
  [RolloutDeviceState.UNSPECIFIED]: { label: "Unknown", tone: "neutral" },
  [RolloutDeviceState.WAITING]: { label: "Waiting for a later stage", tone: "neutral" },
  [RolloutDeviceState.STARTING]: { label: "Starting", tone: "info" },
  [RolloutDeviceState.APPLYING]: { label: "Applying", tone: "info" },
  [RolloutDeviceState.APPLIED]: { label: "Applied", tone: "success" },
  [RolloutDeviceState.FAILED]: { label: "Failed", tone: "destructive" },
  [RolloutDeviceState.UNAVAILABLE]: { label: "Unreachable", tone: "warning" },
  [RolloutDeviceState.NEEDS_REVIEW]: { label: "Needs review", tone: "warning" },
};

type Flow = { open: boolean; candidate?: TargetCandidate; generation: number };

export function RolloutsView({
  initialDevice = "",
  creating,
  onCreatingChange,
}: {
  initialDevice?: string;
  // ?create=true (the command palette's New rollout) opens the dialog once.
  creating: boolean;
  onCreatingChange: (creating: boolean) => void;
}) {
  const principal = usePrincipal();
  const lifetime = useAuthLifetime();
  const canAssign = canPermission(principal, "resources.assign", true);
  const [flow, setFlow] = useState<Flow>({ open: false, generation: 0 });
  const [afterId, setAfterId] = useState("");
  const rollouts = useQuery({
    ...rolloutsQueryOptions(lifetime, afterId, ""),
    enabled: canAssign,
    refetchInterval: 10_000,
    refetchIntervalInBackground: false,
  });
  const assignments = useQuery({
    ...targetAssignmentsQueryOptions(lifetime, ""),
    enabled: canAssign,
  });
  const rollOut = (candidate?: TargetCandidate) =>
    setFlow((current) => ({
      open: true,
      candidate,
      generation:
        current.candidate?.assignment?.assignmentId === candidate?.assignment?.assignmentId
          ? current.generation
          : current.generation + 1,
    }));
  useEffect(() => {
    if (!creating || !canAssign) return;
    rollOut();
    onCreatingChange(false);
    // rollOut only reads state through its updater.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [creating, canAssign]);
  return (
    <section className="grid min-w-0 gap-6">
      <PageHeader
        title="Rollouts"
        description="Which profile versions are reaching which devices, and what needs you."
        onRefresh={
          canAssign
            ? () => {
                void rollouts.refetch();
                void assignments.refetch();
              }
            : undefined
        }
        refreshing={rollouts.isFetching || assignments.isFetching}
        actions={
          canAssign ? (
            <Button type="button" onClick={() => rollOut()}>
              New rollout
            </Button>
          ) : null
        }
      />
      {initialDevice ? (
        <TargetPreviewView key={initialDevice} initialDevice={initialDevice} />
      ) : null}
      {canAssign ? (
        <>
          <RolloutList
            states={rollouts.data}
            pending={rollouts.isPending}
            error={rollouts.error}
            candidates={assignments.data?.assignments}
            firstPage={!afterId}
            onRollOut={rollOut}
          />
          <ListPagination
            label="Rollout pages"
            onPrevious={afterId ? () => setAfterId("") : undefined}
            onNext={
              rollouts.data?.length === 100
                ? () => setAfterId(rollouts.data?.at(-1)?.rollout?.rolloutId ?? "")
                : undefined
            }
            busy={rollouts.isFetching}
          />
          <AlsoInEffect
            candidates={assignments.data?.assignments}
            labels={assignments.data?.revisionLabels}
            error={assignments.error}
            states={rollouts.data}
            onRollOut={rollOut}
          />
          <Dialog
            open={flow.open}
            onOpenChange={(open) => setFlow((current) => ({ ...current, open }))}
          >
            <DialogContent keepMounted className="max-h-[90svh] overflow-y-auto sm:max-w-3xl">
              <DialogHeader>
                <DialogTitle>{flow.candidate ? "Roll out a change" : "New rollout"}</DialogTitle>
                <DialogDescription>
                  Choose a profile version and its target, review the impact, then roll out.
                </DialogDescription>
              </DialogHeader>
              <RolloutFlow
                key={`${flow.candidate?.assignment?.assignmentId ?? "new"}:${flow.generation}`}
                candidate={flow.candidate}
                onClose={() =>
                  setFlow((current) => ({
                    open: false,
                    generation: current.generation + 1,
                  }))
                }
              />
            </DialogContent>
          </Dialog>
        </>
      ) : (
        <p className="text-sm text-muted-foreground">
          You can inspect devices you manage. Ask an administrator with full assignment access to
          roll out changes.
        </p>
      )}
      {!canAssign && !initialDevice ? <TargetPreviewView /> : null}
    </section>
  );
}

function sortKey(state: RolloutState) {
  const live =
    state.status === RolloutStatus.AWAITING_APPROVAL || state.status === RolloutStatus.ACTIVE;
  return [live ? 0 : 1, -(state.createdAt ? timestampDate(state.createdAt).getTime() : 0)];
}

function RolloutList({
  states,
  pending,
  error,
  candidates,
  onRollOut,
  firstPage,
}: {
  states?: RolloutState[];
  pending: boolean;
  error: unknown;
  candidates?: TargetCandidate[];
  onRollOut: (candidate: TargetCandidate) => void;
  firstPage: boolean;
}) {
  const listed = (states ?? [])
    .filter((state) => state.rollout)
    .sort((a, b) => {
      const [liveA, timeA] = sortKey(a);
      const [liveB, timeB] = sortKey(b);
      return liveA - liveB || timeA - timeB;
    });
  // The newest rollout of each assignment offers rolling out its next change.
  const newest = new Map<string, RolloutState>();
  for (const state of listed) {
    const id = state.assignment?.assignmentId;
    if (id && !newest.has(id)) newest.set(id, state);
  }
  const awaiting = listed.filter((state) => state.status === RolloutStatus.AWAITING_APPROVAL);
  const active = listed.filter((state) => state.status === RolloutStatus.ACTIVE);
  const paused = active.filter((state) => state.paused).length;
  const summary = [
    `${active.length - paused} rolling out`,
    paused ? `${paused} paused` : "",
    awaiting.length ? `${awaiting.length} waiting for approval` : "",
  ]
    .filter(Boolean)
    .join(" · ");
  return (
    <section aria-labelledby="rollout-list-title" className="grid min-w-0 gap-3">
      <div className="grid gap-1">
        <h2 id="rollout-list-title" className="text-base font-semibold">
          Recent rollouts
        </h2>
        {states && !error ? (
          <p className="text-sm text-muted-foreground" data-rollout-summary>
            {summary}
            {states.length === 100 ? " on this page" : ""}.
          </p>
        ) : null}
      </div>
      <ListStatus
        pending={pending}
        error={error}
        empty={states?.length === 0}
        noun="rollouts"
        firstPage={firstPage}
        emptyDescription="Choose New rollout to deliver a profile version to a group or device."
      />
      {!error
        ? listed.map((state) => {
            const assignmentId = state.assignment?.assignmentId;
            const candidate =
              assignmentId && newest.get(assignmentId) === state
                ? candidates?.find((item) => item.assignment?.assignmentId === assignmentId)
                : undefined;
            return (
              <RolloutCard
                key={state.rollout?.rolloutId}
                state={state}
                onRollOut={
                  candidate && state.status !== RolloutStatus.AWAITING_APPROVAL
                    ? () => onRollOut(candidate)
                    : undefined
                }
              />
            );
          })
        : null}
    </section>
  );
}

function statusView(state: RolloutState, inProgress: number, final: boolean) {
  switch (state.status) {
    case RolloutStatus.AWAITING_APPROVAL:
      return {
        label: "Waiting for approval",
        tone: "info" as StatusTone,
        note: state.approvalId
          ? "Nothing changes on any device until another administrator approves."
          : "No administrator has requested approval. Nothing changes. The rollout ends one hour after creation.",
      };
    case RolloutStatus.ACTIVE:
      if (state.paused)
        return {
          label: "Paused",
          tone: "warning" as StatusTone,
          note:
            PAUSE_REASONS[state.pauseReason] ??
            "An administrator paused it. Devices that already changed keep the change.",
        };
      if (final && state.waitingCount === 0 && inProgress === 0 && state.needsReviewCount === 0)
        return state.failedCount > 0
          ? {
              label: "Finished with failures",
              tone: "destructive" as StatusTone,
              note: "The rollout attempted every planned device. Some devices reported failure.",
            }
          : { label: "Finished", tone: "success" as StatusTone, note: "" };
      return { label: "Rolling out", tone: "info" as StatusTone, note: "" };
    case RolloutStatus.REJECTED:
      return {
        label: "Rejected",
        tone: "destructive" as StatusTone,
        note: "Another administrator rejected it. Nothing changed on any device.",
      };
    case RolloutStatus.APPROVAL_EXPIRED:
      return {
        label: "Approval expired",
        tone: "neutral" as StatusTone,
        note: "No one approved it in time. Nothing changed on any device.",
      };
    case RolloutStatus.ASSIGNMENT_CHANGED:
      return {
        label: "Stopped",
        tone: "warning" as StatusTone,
        note: "The assignment changed after review. The rollout applied nothing. Start a rollout to review the change again.",
      };
    case RolloutStatus.SUPERSEDED:
      return {
        label: "Replaced",
        tone: "neutral" as StatusTone,
        note: "A later rollout of the same assignment took over its remaining devices.",
      };
    case RolloutStatus.UNPLANNED:
      return {
        label: "Stage plan only",
        tone: "neutral" as StatusTone,
        note: "Created before rollouts changed devices; it only groups devices into stages.",
      };
    default:
      return { label: "Status unknown", tone: "neutral" as StatusTone, note: "" };
  }
}

function RolloutCard({ state, onRollOut }: { state: RolloutState; onRollOut?: () => void }) {
  const names = useTargetNames();
  const rollout = state.rollout;
  const assignment = state.assignment;
  // Server-projected names make the picker lookups unnecessary; they only run
  // for a rollout whose label is missing.
  const profile = names.useProfileVersionLabel(
    state.profileVersion ? "" : (assignment?.profileRevisionId ?? ""),
  );
  const target = useTargetLabel(
    state.targetName ? undefined : (assignment?.target ?? rollout?.rings[0]?.cohort),
  );
  if (!rollout) return null;
  const rings = rollout.rings;
  const stage = rings[state.ringIndex];
  const next = rings[state.ringIndex + 1];
  // Server-projected names first; the first-page picker lookups are a fallback.
  const profileText = versionText(state.profileVersion) || profile.text;
  const targetText = state.targetName || target.text;
  const profileShort = state.profileVersion
    ? `${state.profileVersion.profileName} v${state.profileVersion.revisionNumber.toString()}`
    : profile.short;
  const delivery = assignment ? `${profileText} to ${targetText}` : "";
  // Old rollouts have no name; describe what they deliver, never their stage names.
  const title = rollout.name || delivery || `Staged rollout to ${targetText}`;
  const inProgress = Math.max(
    0,
    state.startingCount + state.activatedCount - state.healthyCount - state.failedCount,
  );
  const status = statusView(state, inProgress, !next);
  const active = state.status === RolloutStatus.ACTIVE;
  const awaiting = state.status === RolloutStatus.AWAITING_APPROVAL;
  const planned = state.plannedCount > 0;
  const promotion =
    active && !state.paused && next ? (
      state.gateReason ? (
        (PAUSE_REASONS[state.gateReason] ??
        `Health checks for ${stage?.name ?? "this stage"} haven't passed yet.`)
      ) : stage?.manualPromotion ? (
        `Waiting for an administrator to advance to ${next.name}.`
      ) : state.nextPromotionAt ? (
        <>
          Advances to {next.name} after <Timestamp value={state.nextPromotionAt} relative={false} />{" "}
          if health checks pass.
        </>
      ) : (
        `Advances to ${next.name} once enough devices report back healthy.`
      )
    ) : (
      ""
    );
  return (
    <article
      className="grid min-w-0 gap-3 border p-4"
      data-rollout-status={RolloutStatus[state.status]}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 className="min-w-0 break-words text-sm font-semibold">{title}</h3>
        <StatusBadge status={status.tone}>{status.label}</StatusBadge>
      </div>
      {/* A custom name still says what is delivered where; a generated one already does. */}
      {rollout.name && delivery && rollout.name !== `${profileShort} to ${targetText}` ? (
        <p className="break-words text-sm">{delivery}</p>
      ) : null}
      <p className="flex flex-wrap gap-x-1.5 gap-y-1 text-sm text-muted-foreground">
        <span>
          {awaiting
            ? `${rings.length === 1 ? "One stage" : `${rings.length} stages`}: ${rings.map((ring) => ring.name).join(", ")}`
            : `Stage ${state.ringIndex + 1} of ${rings.length}: ${stage?.name ?? "unknown"}`}
        </span>
        {state.creatorDisplayName ? (
          <>
            <span aria-hidden="true">·</span>
            <span>
              {awaiting ? "Requested" : "Started"} by {state.creatorDisplayName}
            </span>
          </>
        ) : null}
        {state.createdAt ? (
          <>
            <span aria-hidden="true">·</span>
            <Timestamp value={state.createdAt} />
          </>
        ) : null}
      </p>
      {status.note ? <p className="text-sm">{status.note}</p> : null}
      {awaiting ? (
        <p className="text-sm">
          {state.plannedCount} {state.plannedCount === 1 ? "device" : "devices"} planned
          {state.adopted.length && state.adoptingCount ? (
            <>
              {" · "}
              <Adoption adopted={state.adopted} devices={state.adoptingCount} />
            </>
          ) : null}
          .{" "}
          {state.approvalId ? (
            <Link to="/approvals" className="underline underline-offset-4">
              Open Approvals
            </Link>
          ) : null}
        </p>
      ) : planned ? (
        <dl
          className="flex flex-wrap gap-x-6 gap-y-2 text-sm [&_dd]:font-semibold [&_dd]:tabular-nums [&_dt]:text-xs [&_dt]:text-muted-foreground"
          aria-label="Device results"
        >
          <div>
            <dt>Applied</dt>
            <dd>{state.healthyCount}</dd>
          </div>
          <div>
            <dt>In progress</dt>
            <dd>{inProgress}</dd>
          </div>
          <div>
            <dt>Failed</dt>
            <dd className={state.failedCount ? "text-destructive" : undefined}>
              {state.failedCount}
            </dd>
          </div>
          <div>
            <dt>Waiting for a later stage</dt>
            <dd>{state.waitingCount}</dd>
          </div>
          <div>
            <dt>Needs review</dt>
            <dd className={state.needsReviewCount ? "text-warning" : undefined}>
              {state.needsReviewCount}
            </dd>
          </div>
          <div>
            <dt>Planned</dt>
            <dd>{state.plannedCount}</dd>
          </div>
        </dl>
      ) : null}
      {promotion ? <p className="text-sm text-muted-foreground">{promotion}</p> : null}
      {active && state.needsReviewCount > 0 ? <NeedsReview rolloutId={rollout.rolloutId} /> : null}
      {(active || onRollOut) && (
        <div className="flex flex-wrap gap-2">
          {active && !state.paused ? (
            <ControlButton
              state={state}
              title={title}
              operation={ControlRolloutRequest_Operation.PAUSE}
            />
          ) : null}
          {active && state.paused ? (
            <ControlButton
              state={state}
              title={title}
              operation={ControlRolloutRequest_Operation.RESUME}
            />
          ) : null}
          {active && !state.paused && next && stage?.manualPromotion ? (
            <ControlButton
              state={state}
              title={title}
              operation={ControlRolloutRequest_Operation.PROMOTE}
            />
          ) : null}
          {onRollOut ? (
            <Button type="button" variant="outline" onClick={onRollOut}>
              Roll out a change
            </Button>
          ) : null}
        </div>
      )}
      <RolloutDetails state={state} devices={planned && !awaiting} />
    </article>
  );
}

function DeviceRow({ device }: { device: RolloutDevice }) {
  const view = DEVICE_STATES[device.state] ?? DEVICE_STATES[RolloutDeviceState.UNSPECIFIED];
  const review = device.state === RolloutDeviceState.NEEDS_REVIEW;
  return (
    <TableRow>
      <TableCell className="min-w-32 whitespace-normal">
        <Link
          to="/devices/$deviceId"
          params={{ deviceId: device.deviceId }}
          className="break-words underline underline-offset-4"
        >
          {device.hostname || "Unnamed device"}
        </Link>
      </TableCell>
      <TableCell>
        <StatusBadge status={view.tone}>{view.label}</StatusBadge>
      </TableCell>
      <TableCell className="whitespace-normal">
        <span className="grid gap-1">
          {device.reason ? (
            <span>{NEEDS_REVIEW[device.reason] ?? device.reason.replaceAll("_", " ")}</span>
          ) : null}
          {device.adoptsExisting ? <span>Adopts settings it already has.</span> : null}
          {review ? (
            <Link
              to="/rollouts"
              search={{ device: device.deviceId }}
              className="w-fit underline underline-offset-4"
            >
              Inspect this device
            </Link>
          ) : null}
        </span>
      </TableCell>
      <TableCell className="text-muted-foreground">
        <Timestamp value={device.updatedAt} missing="Not yet" />
      </TableCell>
    </TableRow>
  );
}

function DeviceTable({ devices }: { devices: RolloutDevice[] }) {
  return (
    <Table aria-label="Rollout devices">
      <TableHeader>
        <TableRow>
          <TableHead>Device</TableHead>
          <TableHead>Result</TableHead>
          <TableHead>Detail</TableHead>
          <TableHead>Updated</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {devices.map((device) => (
          <DeviceRow key={device.deviceId} device={device} />
        ))}
      </TableBody>
    </Table>
  );
}

// Devices that need review are the exception: shown with their cause, not hidden.
function NeedsReview({ rolloutId }: { rolloutId: string }) {
  const query = useQuery(
    rolloutDevicesQueryOptions(useAuthLifetime(), rolloutId, "", RolloutDeviceState.NEEDS_REVIEW),
  );
  if (query.error) return <RpcError failure={toRpcFailure(query.error)} />;
  if (!query.data?.length) return null;
  return (
    <div className="grid gap-2" data-rollout-needs-review>
      <h4 className="text-sm font-medium">Needs review</h4>
      <DeviceTable devices={query.data} />
    </div>
  );
}

// The card's one disclosure: its devices (when it has a device plan), the stage
// plan and the copyable identifiers.
function RolloutDetails({ state, devices }: { state: RolloutState; devices: boolean }) {
  const lifetime = useAuthLifetime();
  const [open, setOpen] = useState(false);
  const [after, setAfter] = useState("");
  const rolloutId = state.rollout?.rolloutId ?? "";
  const query = useQuery({
    ...rolloutDevicesQueryOptions(lifetime, rolloutId, after, RolloutDeviceState.UNSPECIFIED),
    enabled: open && devices,
  });
  const total = state.plannedCount;
  const identifiers = [
    { label: "Rollout ID", value: rolloutId },
    { label: "Revision", value: state.revision.toString() },
    { label: "Assignment ID", value: state.assignment?.assignmentId },
    { label: "Approval ID", value: state.approvalId },
    { label: "Status reason", value: state.statusReason },
    { label: "Pause reason", value: state.pauseReason },
    { label: "Promotion check", value: state.gateReason },
  ].filter((item) => item.value);
  return (
    <details
      className="text-sm"
      onToggle={(event) => setOpen(event.currentTarget.open)}
      data-rollout-devices={devices ? "" : undefined}
    >
      <summary className="w-fit cursor-pointer py-1 font-medium">
        {devices
          ? `${total} ${total === 1 ? "device" : "devices"} and stage plan`
          : "Stage plan and details"}
      </summary>
      <div className="mt-2 grid gap-3">
        {devices ? (
          <>
            <ListStatus
              pending={query.isPending}
              error={query.error}
              empty={query.data?.length === 0}
              noun="devices"
              firstPage={!after}
            />
            {query.data?.length ? <DeviceTable devices={query.data} /> : null}
            <ListPagination
              label="Device pages"
              previousLabel="First devices"
              onPrevious={after ? () => setAfter("") : undefined}
              onNext={
                query.data?.length === 100
                  ? () => setAfter(query.data?.at(-1)?.deviceId ?? "")
                  : undefined
              }
              busy={query.isFetching}
            />
          </>
        ) : null}
        <ol className="grid gap-1">
          {state.rollout?.rings.map((ring, index) => (
            <li key={ring.name}>
              Stage {index + 1}, {ring.name}: {ring.cumulativeBasisPoints / 100}% of devices; pauses
              above {ring.failureBasisPoints / 100}% failed, {ring.unknownBasisPoints / 100}%
              unverified or {ring.unavailableBasisPoints / 100}% unreachable; observes{" "}
              {formatSeconds(ring.soakSeconds)}
              {ring.manualPromotion ? "; an administrator advances it" : ""}.
            </li>
          ))}
        </ol>
        {state.reason ? <p className="whitespace-pre-wrap">Reason: {state.reason}</p> : null}
        {state.stageStartedAt ? (
          <p>
            Current stage started <Timestamp value={state.stageStartedAt} />
          </p>
        ) : null}
        <dl className="grid gap-1 text-xs text-muted-foreground">
          {identifiers.map((item) => (
            <div key={item.label}>
              <dt className="inline font-medium">{item.label}: </dt>
              <dd className="inline">
                <code className="font-mono break-all">{item.value}</code>
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </details>
  );
}

function ControlButton({
  state,
  title,
  operation,
}: {
  state: RolloutState;
  title: string;
  operation: ControlRolloutRequest_Operation;
}) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [sent, setSent] = useState<ControlRolloutRequest>();
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<RpcFailure>();
  const next = state.rollout?.rings[state.ringIndex + 1];
  const nextName = next?.name ?? "the next stage";
  const label =
    operation === ControlRolloutRequest_Operation.PAUSE
      ? "Pause"
      : operation === ControlRolloutRequest_Operation.RESUME
        ? "Resume"
        : `Advance to ${nextName}`;
  const effect =
    operation === ControlRolloutRequest_Operation.PAUSE
      ? "No more devices start this change until you resume. Devices that already changed keep it."
      : operation === ControlRolloutRequest_Operation.RESUME
        ? "Devices in the current stage continue to get this change while health checks pass."
        : `If health checks pass, ${nextName} starts. Up to ${(next?.cumulativeBasisPoints ?? 0) / 100}% of targeted devices get this change.`;
  async function send() {
    if (busy) return;
    const request =
      sent ??
      create(ControlRolloutRequestSchema, {
        requestId: newRequestId(),
        rolloutId: state.rollout?.rolloutId,
        expectedRevision: state.revision,
        operation,
        reason: reason.trim(),
      });
    setSent(request);
    setBusy(true);
    setFailure(undefined);
    try {
      await adminClient.controlRollout(request, { signal: lifetime.signal });
      lifetime.signal.throwIfAborted();
      toast.success(`${label}: done`);
      setOpen(false);
      setSent(undefined);
      setReason("");
      void client.invalidateQueries({ queryKey: ["targeting", lifetime.generation] });
    } catch (cause) {
      if (lifetime.signal.aborted) return;
      const outcome = toRpcFailure(cause);
      setFailure(outcome);
      if (!outcome.ambiguous) setSent(undefined);
    } finally {
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }
  const ambiguous = !!sent && !!failure?.ambiguous;
  return (
    <Dialog
      open={open}
      onOpenChange={(value) => {
        if (busy) return;
        setOpen(value);
        if (!value && !ambiguous) setFailure(undefined);
      }}
    >
      <DialogTrigger render={<Button type="button" variant="outline" />}>{label}</DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{`${label}: ${title}`}</DialogTitle>
          <DialogDescription>{effect}</DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void send();
          }}
        >
          <fieldset disabled={busy || ambiguous} className="grid gap-3">
            <ReasonControl label="Reason" value={sent?.reason ?? reason} onChange={setReason} />
          </fieldset>
          {failure ? (
            <RpcError failure={failure}>
              {ambiguous ? <p>We couldn't confirm it. Retry; it won't apply twice.</p> : null}
            </RpcError>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy || (!sent && !reason.trim())}>
              {busy ? "Sending…" : ambiguous ? "Retry" : label}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function AlsoInEffectRow({
  candidate,
  label,
  onRollOut,
}: {
  candidate: TargetCandidate;
  label?: ProfileVersionLabel;
  onRollOut: () => void;
}) {
  const names = useTargetNames();
  const assignment = candidate.assignment;
  // The server names the version; the picker lookup (which can fan out over
  // every profile's history) is only for a label the page lacked.
  const fallback = names.useProfileVersionLabel(label ? "" : (assignment?.profileRevisionId ?? ""));
  const profile = label ? { text: versionText(label) } : fallback;
  const target = useTargetLabel(assignment?.target);
  if (!assignment) return null;
  return (
    <li className="flex min-w-0 flex-wrap items-center justify-between gap-2 py-2 text-sm">
      <span className="grid min-w-0 gap-0.5">
        <span className="break-words font-medium">
          {profile.text} to {target.text}
        </span>
        <span className="text-xs text-muted-foreground">
          {assignment.disabled ? "Stopped · " : ""}Priority {assignment.priority}
          {assignment.exclusions.length
            ? ` · ${assignment.exclusions.length} ${assignment.exclusions.length === 1 ? "exclusion" : "exclusions"}`
            : ""}
          {assignment.expiresAt ? (
            <>
              {" · stops applying "}
              <Timestamp value={assignment.expiresAt} relative={false} />
            </>
          ) : null}
        </span>
      </span>
      <Button type="button" variant="outline" size="sm" onClick={onRollOut}>
        Roll out a change
      </Button>
    </li>
  );
}

// Assignments no listed rollout delivers: saved before rollouts, or by an older rollout.
function AlsoInEffect({
  candidates,
  labels,
  error,
  states,
  onRollOut,
}: {
  candidates?: TargetCandidate[];
  labels?: ProfileVersionLabel[];
  error: unknown;
  states?: RolloutState[];
  onRollOut: (candidate: TargetCandidate) => void;
}) {
  const delivered = new Set(
    (states ?? []).flatMap((state) =>
      state.assignment?.assignmentId ? [state.assignment.assignmentId] : [],
    ),
  );
  const rest = (candidates ?? []).filter(
    (candidate) => candidate.assignment && !delivered.has(candidate.assignment.assignmentId),
  );
  if (error) return <RpcError failure={toRpcFailure(error)} />;
  if (!rest.length) return null;
  return (
    <section aria-labelledby="also-in-effect-title" className="grid min-w-0 gap-1">
      <h2 id="also-in-effect-title" className="text-base font-semibold">
        Also in effect
      </h2>
      <p className="text-sm text-muted-foreground">
        Assignments without a rollout on this page. Changing one starts a rollout.
      </p>
      <ul className="grid divide-y">
        {rest.map((candidate) => (
          <AlsoInEffectRow
            key={candidate.assignment?.assignmentId}
            candidate={candidate}
            label={labels?.find(
              (label) => label.revisionId === candidate.assignment?.profileRevisionId,
            )}
            onRollOut={() => onRollOut(candidate)}
          />
        ))}
      </ul>
    </section>
  );
}
