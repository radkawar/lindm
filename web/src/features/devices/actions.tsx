import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ChevronRight, Lock } from "lucide-react";
import type { DeviceAction } from "../../../gen/lindm/admin/v1/device_actions_pb";
import { useState } from "react";
import {
  DeviceActionFailure,
  DeviceActionState,
} from "../../../gen/lindm/agent/v1/device_actions_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp, freshnessLabel } from "@/lib/time";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { EmptyState } from "@/components/ui/empty-state";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import {
  CryptoEraseVerificationView,
  DeviceActionSpecView,
  NativeSanitizeVerificationView,
  actionStateLabels,
  actionLabels,
  actionPermissions,
  type DeviceActionKind,
} from "./action-display";
import { DeviceActionDialog } from "./action-menu";
import { deviceActionQueryOptions, deviceActionsQueryOptions } from "./action-queries";
import { Fact, ObservedClock, ObservedTime } from "./observations";

const failureLabels: Partial<Record<DeviceActionFailure, string>> = {
  [DeviceActionFailure.PRECONDITION]: "The device wasn't ready for this action",
  [DeviceActionFailure.UNSUPPORTED]: "Not supported on this device",
  [DeviceActionFailure.NATIVE]: "The operating system reported an error",
  [DeviceActionFailure.OBSERVATION]: "The device couldn't confirm the result",
  [DeviceActionFailure.AUTHORITY]: "The device rejected the authorization",
  [DeviceActionFailure.EXPIRED]: "Expired before it finished",
  [DeviceActionFailure.INTERRUPTED]: "Interrupted before it finished",
};

// Server close reasons. "result" and "outcome_unknown" repeat the status badge.
const closedReasonLabels: Record<string, string> = {
  expired_unstarted: "Expired before the device started it",
  recovery_result: "Closed by the recovery result",
};

// Who asked for an action, in the console's actor wording.
export function actionActorLabel(action: DeviceAction, principalId: string): string {
  if (!action.actorId.trim()) return "the system";
  const name = action.actorDisplayName.trim();
  if (action.actorId === principalId) return name ? `${name} (you)` : "you";
  return name || "another administrator";
}

export function actionOutcome(action: DeviceAction): { tone: StatusTone; label: string } {
  const state = action.status?.state;
  if (state === DeviceActionState.OUTCOME_UNKNOWN || action.closedReason === "outcome_unknown")
    return { tone: "warning", label: "Outcome unknown, don't retry" };
  if (state === undefined) return { tone: "info", label: "Sent, waiting for device" };
  return {
    tone:
      state === DeviceActionState.FAILED
        ? "destructive"
        : state === DeviceActionState.SUCCEEDED
          ? "success"
          : state === DeviceActionState.EXPIRED
            ? "neutral"
            : "info",
    label: actionStateLabels[state],
  };
}

type Restriction = {
  kind: "lock" | "quarantine";
  // The device reported the restricting action as completed and verified.
  confirmed: boolean;
  action: DeviceAction | undefined;
  until?: Timestamp;
};

function verifiedSuccess(action: DeviceAction | undefined) {
  return (
    action?.status?.state === DeviceActionState.SUCCEEDED &&
    action.status.verification?.verified === true
  );
}

// Restrictions in force from the server fence, matched to the action that set them.
// The fence clears only when a release completes, so a listed restriction has no
// later release.
function useDeviceRestrictions(deviceId: string) {
  const lifetime = useAuthLifetime();
  const query = useQuery(deviceActionsQueryOptions(lifetime, deviceId, ""));
  const data = query.error ? undefined : query.data;
  const lockId = data?.sessionsLocked ? data.lockActionId : "";
  const listedLock = lockId
    ? data?.actions.find((action) => action.actionId === lockId)
    : undefined;
  const lockQuery = useQuery({
    ...deviceActionQueryOptions(lifetime, deviceId, lockId),
    enabled: lockId !== "" && !listedLock,
  });
  const lockAction = listedLock ?? (lockQuery.error ? undefined : lockQuery.data);
  const restrictions: Restriction[] = [];
  if (data?.sessionsLocked)
    restrictions.push({ kind: "lock", action: lockAction, confirmed: verifiedSuccess(lockAction) });
  if (data?.quarantined) {
    // Newest first: the newest quarantine on this page set the current fence.
    const action = data.actions.find((item) => item.spec?.action.case === "quarantine");
    restrictions.push({
      kind: "quarantine",
      action,
      confirmed: verifiedSuccess(action),
      until: data.quarantineUntil,
    });
  }
  return {
    query,
    restrictions,
    pending: query.isPending || (lockId !== "" && !listedLock && lockQuery.isPending),
  };
}

const restrictionNames = {
  lock: { confirmed: "Accounts locked", sent: "Account lock sent" },
  quarantine: { confirmed: "Network quarantined", sent: "Network quarantine sent" },
} as const;
const releaseKinds: Record<Restriction["kind"], DeviceActionKind> = {
  lock: "releaseLock",
  quarantine: "releaseQuarantine",
};

function RestrictionText({ restriction }: { restriction: Restriction }) {
  const principal = usePrincipal();
  const { action, confirmed, kind } = restriction;
  const names = restrictionNames[kind];
  const until = restriction.until ? (
    <>
      {" "}
      Ends <ObservedClock value={restriction.until} />.
    </>
  ) : null;
  if (!action) {
    return (
      <p>
        {names.confirmed}. The action that set it isn&apos;t in recent history.
        {until}
      </p>
    );
  }
  const actor = actionActorLabel(action, principal.id);
  return confirmed ? (
    <p>
      {names.confirmed} since <ObservedClock value={action.status?.completedAt} /> by {actor}.
      {until}
    </p>
  ) : (
    <p>
      {names.sent} at <ObservedClock value={action.createdAt} /> by {actor}. The device hasn&apos;t
      confirmed it.{until}
    </p>
  );
}

// Active restrictions with one Undo per restriction, using the release action flow.
export function DeviceRestrictions({
  deviceId,
  deviceName,
}: {
  deviceId: string;
  deviceName: string;
}) {
  const principal = usePrincipal();
  const { query, restrictions, pending } = useDeviceRestrictions(deviceId);
  const [release, setRelease] = useState<DeviceActionKind | null>(null);
  if (pending) return <p role="status">Checking restrictions…</p>;
  if (query.error)
    return <RpcError failure={toRpcFailure(query.error)} title="Restrictions unavailable" />;
  if (!restrictions.length) return <p>None</p>;
  return (
    <div className="grid gap-3">
      {restrictions.map((restriction) => {
        const kind = releaseKinds[restriction.kind];
        return (
          <div
            key={restriction.kind}
            data-device-restriction={restriction.kind}
            data-confirmed={restriction.confirmed}
            className="grid gap-1"
          >
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <RestrictionText restriction={restriction} />
              {canPermission(principal, actionPermissions[kind]) ? (
                <Button
                  size="sm"
                  variant="outline"
                  aria-haspopup="dialog"
                  aria-label={actionLabels[kind]}
                  onClick={() => setRelease(kind)}
                >
                  Undo
                </Button>
              ) : null}
            </div>
            <p className="text-xs text-muted-foreground">
              {restriction.kind === "lock"
                ? "Undo restores the local accounts lindm disabled. Screens stay locked until a user unlocks them."
                : "Undo restores normal network access when the device next checks in."}
              {canPermission(principal, actionPermissions[kind])
                ? ""
                : " Ask an admin with permission to undo it."}
            </p>
          </div>
        );
      })}
      <DeviceActionDialog
        deviceId={deviceId}
        deviceName={deviceName}
        kind={release}
        onClose={() => setRelease(null)}
      />
    </div>
  );
}

// Compact header status: only restrictions the device confirmed.
export function DeviceRestrictionBadges({ deviceId }: { deviceId: string }) {
  const { restrictions } = useDeviceRestrictions(deviceId);
  return (
    <>
      {restrictions
        .filter((restriction) => restriction.confirmed)
        .map((restriction) => (
          <StatusBadge key={restriction.kind} status="warning">
            <Lock aria-hidden="true" />
            {restrictionNames[restriction.kind].confirmed}
          </StatusBadge>
        ))}
    </>
  );
}

export function DeviceActionsPanel({
  deviceId,
  deviceName,
}: {
  deviceId: string;
  deviceName: string;
}) {
  const principal = usePrincipal();
  const starts = (["cryptoErase", "sanitize", "escrowRotate", "tpm2Bind"] as const).filter((kind) =>
    canPermission(principal, actionPermissions[kind]),
  );
  return (
    <div className="grid gap-4">
      <section className="grid gap-2 border-b pb-4" aria-labelledby={`restrictions-${deviceId}`}>
        <h2 id={`restrictions-${deviceId}`} className="text-base font-semibold">
          Active restrictions
        </h2>
        <div className="text-sm">
          <DeviceRestrictions deviceId={deviceId} deviceName={deviceName} />
        </div>
      </section>
      {starts.length ? (
        <section className="grid gap-2">
          <h2 className="text-base font-semibold">Storage and encryption actions</h2>
          <p className="text-sm text-muted-foreground">
            These open their own page. Other actions are under Actions at the top of the page.
          </p>
          <div className="flex flex-wrap gap-4">
            {starts.map((kind) => (
              <Link
                key={kind}
                to="/devices/$deviceId/actions/new/$kind"
                params={{ deviceId, kind }}
                search={{ luksUuid: "" }}
                className="text-sm underline"
              >
                {actionLabels[kind]}
              </Link>
            ))}
          </div>
        </section>
      ) : null}
      <DeviceActionHistory deviceId={deviceId} />
    </div>
  );
}

export function DeviceActionHistory({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const query = useQuery(deviceActionsQueryOptions(lifetime, deviceId, pageToken));
  const failure = query.error ? toRpcFailure(query.error) : null;
  const data = failure ? undefined : query.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Device action history</CardTitle>
        <CardDescription>
          One line per action, newest first. Open a line for its full result.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-semibold">Recent actions</h3>
          <Button
            variant="outline"
            disabled={query.isFetching}
            onClick={() => void query.refetch()}
          >
            Refresh
          </Button>
        </div>
        {query.isPending ? <p role="status">Loading action history…</p> : null}
        {failure ? <RpcError failure={failure} /> : null}
        {data?.actions.length === 0 ? (
          <EmptyState
            title="No actions yet"
            description="Use Actions at the top of the page to start one."
          />
        ) : null}
        {data?.actions.length ? (
          <ul className="grid divide-y rounded-md border" aria-label="Recent actions">
            {data.actions.map((action) => (
              <li key={action.actionId}>
                <DeviceActionRow action={action} />
              </li>
            ))}
          </ul>
        ) : null}
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={!pageToken || query.isFetching}
            onClick={() => setPageToken("")}
          >
            Newest actions
          </Button>
          <Button
            variant="outline"
            disabled={!data?.nextPageToken || query.isFetching}
            onClick={() => setPageToken(data?.nextPageToken ?? "")}
          >
            Older actions
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function RelativeTime({ value }: { value: Timestamp | undefined }) {
  const formatted = formatTimestamp(value);
  return formatted.date ? (
    <time dateTime={formatted.utc} title={`${formatted.local} · ${formatted.utc}`}>
      {freshnessLabel(formatted.date, new Date())}
    </time>
  ) : (
    <span>{formatted.local}</span>
  );
}

// One summary line (what, by whom, when, outcome); the full result opens below it.
function DeviceActionRow({ action }: { action: DeviceAction }) {
  const principal = usePrincipal();
  const outcome = actionOutcome(action);
  const what = action.spec?.action.case ? actionLabels[action.spec.action.case] : "Unknown action";
  return (
    <details data-device-action-row className="group">
      <summary className="flex cursor-pointer list-none flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm hover:bg-muted/50 focus-visible:outline focus-visible:outline-ring [&::-webkit-details-marker]:hidden">
        <ChevronRight
          aria-hidden="true"
          className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-90"
        />
        {/* No min-w-0: the name never shrinks below its longest word, so narrow rows wrap. */}
        <span className="flex-1 basis-48 font-medium break-words">{what}</span>
        <span className="text-muted-foreground">by {actionActorLabel(action, principal.id)}</span>
        <span className="text-muted-foreground">
          <RelativeTime value={action.createdAt} />
        </span>
        <StatusBadge className="h-auto min-h-5 whitespace-normal" status={outcome.tone}>
          {outcome.label}
        </StatusBadge>
      </summary>
      <div className="border-t p-3">
        <DeviceActionResult action={action} embedded />
      </div>
    </details>
  );
}

export function DeviceActionResult({
  action,
  linked = true,
  embedded = false,
}: {
  action: DeviceAction;
  linked?: boolean;
  // Inside a history row, which already shows the outcome.
  embedded?: boolean;
}) {
  const principal = usePrincipal();
  const status = action.status;
  const outcome = actionOutcome(action);
  const unknown =
    status?.state === DeviceActionState.OUTCOME_UNKNOWN ||
    action.closedReason === "outcome_unknown";
  const needsCredential =
    action.spec?.action.case === "escrowRotate" || action.spec?.action.case === "tpm2Bind";
  return (
    <article
      key={action.actionId}
      className={embedded ? "grid gap-3" : "grid gap-3 rounded-md border p-4"}
    >
      {embedded ? null : (
        <StatusBadge className="h-auto min-h-5 max-w-full whitespace-normal" status={outcome.tone}>
          {outcome.label}
        </StatusBadge>
      )}
      <dl className="grid gap-3 text-sm sm:grid-cols-2">
        <Fact label="Requested by">{actionActorLabel(action, principal.id)}</Fact>
        <Fact label="Created">
          <ObservedTime value={action.createdAt} server />
        </Fact>
        <Fact label="Expires">
          <ObservedTime value={action.expiresAt} server />
        </Fact>
        {closedReasonLabels[action.closedReason] ? (
          <Fact label="Closed because">{closedReasonLabels[action.closedReason]}</Fact>
        ) : null}
      </dl>
      {linked ? (
        <Link
          to="/devices/$deviceId/actions/$actionId"
          params={{ deviceId: action.deviceId, actionId: action.actionId }}
          className="w-fit text-sm underline"
        >
          View action
        </Link>
      ) : null}
      <DeviceActionSpecView spec={action.spec} />
      {status ? (
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <Fact label="Accepted by device">
            <ObservedTime value={status.acceptedAt} />
          </Fact>
          <Fact label="Started">
            <ObservedTime value={status.startedAt} />
          </Fact>
          <Fact label="Finished">
            <ObservedTime value={status.completedAt} />
          </Fact>
          {status.failure !== DeviceActionFailure.NONE &&
          status.failure !== DeviceActionFailure.UNSPECIFIED ? (
            <Fact label="Failure">{failureLabels[status.failure] ?? "Unknown failure"}</Fact>
          ) : null}
          <Fact label="Supported on this device">
            {status.before?.supported ? "Yes" : "No"}
            {status.before?.reason ? `: ${status.before.reason}` : ""}
          </Fact>
          <Fact label="Verified">
            {status.verification?.verified ? "Verified by device" : "Not verified"}
          </Fact>
          {status.verification?.evidence ? (
            <Fact label="Details">{status.verification.evidence}</Fact>
          ) : null}
          {action.spec?.action.case === "restart" || action.spec?.action.case === "shutdown" ? (
            <>
              <Fact label="Power request">
                {status.verification?.powerRequestAccepted ? "Accepted by device" : "Not confirmed"}
              </Fact>
            </>
          ) : null}
          {action.spec?.action.case === "refreshInventory" ? (
            <Fact label="Inventory sequence">
              {status.verification?.inventorySequence.toString() || "Not reported"}
            </Fact>
          ) : null}
          {action.spec?.action.case === "patchNow" ? (
            <Fact label="Native update run">
              {status.verification?.patchRunStarted
                ? "Started. See Patch status for the run result."
                : "Not confirmed"}
            </Fact>
          ) : null}
          {action.spec?.action.case === "lockSessions" ||
          action.spec?.action.case === "releaseLock" ? (
            <>
              <Fact label="Disabled local accounts">
                {status.verification?.after?.disabledAccounts.join(", ") || "None reported"}
              </Fact>
              <Fact label="Untouched local accounts">
                {status.verification?.after?.preservedAccounts.join(", ") ||
                  status.before?.preservedAccounts.join(", ") ||
                  "None reported"}
              </Fact>
              <Fact label="Sessions locked">
                {status.verification?.after?.sessionsLocked ? "Yes" : "Not confirmed"}
              </Fact>
            </>
          ) : null}
        </dl>
      ) : null}
      <TechnicalDetails
        items={[
          { label: "Action ID", value: action.actionId },
          { label: "Closed reason", value: action.closedReason },
          {
            label: "Failure code",
            value: status ? DeviceActionFailure[status.failure] : undefined,
          },
          { label: "Enrollment generation", value: String(action.enrollmentGeneration) },
          { label: "Revision", value: action.actionRevision.toString() },
          { label: "Boot ID before", value: status?.before?.bootId },
          { label: "Boot ID after", value: status?.verification?.bootId },
        ]}
      />
      {status?.volatileResult ? (
        <Alert>
          <AlertTitle>Result sent before power-off</AlertTitle>
          <AlertDescription>
            The device reported this result just before it powered off. If no result arrived, the
            outcome is unknown.
          </AlertDescription>
        </Alert>
      ) : null}
      <CryptoEraseVerificationView verification={status?.verification} />
      <NativeSanitizeVerificationView verification={status?.verification} />
      {needsCredential && status?.state !== DeviceActionState.SUCCEEDED ? (
        <p className="text-sm">
          This needs a recovery credential entered on the device, or a TPM. You can&apos;t provide
          it from the console.
        </p>
      ) : null}
      {unknown ? (
        <Alert className="border-warning/25 bg-warning/10">
          <AlertTitle>Effects may already have happened</AlertTitle>
          <AlertDescription>
            Check device history and recovery records before acting. Don&apos;t repeat a destructive
            action.
          </AlertDescription>
        </Alert>
      ) : null}
    </article>
  );
}
