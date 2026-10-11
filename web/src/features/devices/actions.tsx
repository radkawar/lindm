import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { DeviceAction } from "../../../gen/lindm/admin/v1/device_actions_pb";
import { useState } from "react";
import {
  DeviceActionFailure,
  DeviceActionState,
} from "../../../gen/lindm/agent/v1/device_actions_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
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
} from "./action-display";
import { deviceActionsQueryOptions } from "./action-queries";
import { Fact, ObservedTime } from "./observations";

export function DeviceLockRestriction({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const query = useQuery(deviceActionsQueryOptions(lifetime, deviceId, ""));
  if (query.isPending) return <p role="status">Loading lock status…</p>;
  if (query.error) {
    return <RpcError failure={toRpcFailure(query.error)} title="Lock status unavailable" />;
  }
  if (!query.data?.sessionsLocked) return null;
  return (
    <Alert>
      <AlertTitle>Accounts on this device may be locked</AlertTitle>
      <AlertDescription>
        <p>
          A lock action may have locked sessions or disabled local accounts. Use Undo account lock
          to restore them. Screens stay locked until a user unlocks them.
        </p>
        <TechnicalDetails items={[{ label: "Lock action ID", value: query.data.lockActionId }]} />
        <Button variant="outline" disabled={query.isFetching} onClick={() => void query.refetch()}>
          Refresh
        </Button>
      </AlertDescription>
    </Alert>
  );
}

export function DeviceActionsPanel({ deviceId }: { deviceId: string }) {
  const principal = usePrincipal();
  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Start a device action</CardTitle>
          <CardDescription>
            Use Actions at the top of the page for quick actions. Storage actions open their own
            page.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-4">
          {(["cryptoErase", "sanitize", "escrowRotate", "tpm2Bind"] as const)
            .filter((kind) => canPermission(principal, actionPermissions[kind]))
            .map((kind) => (
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
        </CardContent>
      </Card>
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
        <CardDescription>Actions sent to this device and their results.</CardDescription>
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
        {data ? (
          <Alert>
            <AlertTitle>Active restrictions</AlertTitle>
            <AlertDescription>
              <dl className="grid gap-3 sm:grid-cols-3">
                <Fact label="Account lock">{data.sessionsLocked ? "Active" : "None"}</Fact>
                <Fact label="Network quarantine">{data.quarantined ? "Active" : "None"}</Fact>
                <Fact label="Quarantine ends">
                  <ObservedTime value={data.quarantineUntil} server />
                </Fact>
              </dl>
              <p>Offline devices may keep restrictions until they reconnect.</p>
              <TechnicalDetails items={[{ label: "Lock action ID", value: data.lockActionId }]} />
            </AlertDescription>
          </Alert>
        ) : null}
        {data?.actions.length === 0 ? (
          <EmptyState
            title="No actions yet"
            description="Use Actions at the top of the page to start one."
          />
        ) : null}
        {data?.actions.map((action) => (
          <DeviceActionResult key={action.actionId} action={action} />
        ))}
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

export function DeviceActionResult({
  action,
  linked = true,
}: {
  action: DeviceAction;
  linked?: boolean;
}) {
  const status = action.status;
  const unknown =
    status?.state === DeviceActionState.OUTCOME_UNKNOWN ||
    action.closedReason === "outcome_unknown";
  const needsCredential =
    action.spec?.action.case === "escrowRotate" || action.spec?.action.case === "tpm2Bind";
  return (
    <article key={action.actionId} className="grid gap-3 rounded-md border p-4">
      <StatusBadge
        className="h-auto min-h-5 max-w-full whitespace-normal"
        status={
          unknown
            ? "warning"
            : status?.state === DeviceActionState.FAILED
              ? "destructive"
              : status?.state === DeviceActionState.SUCCEEDED
                ? "success"
                : status?.state === DeviceActionState.EXPIRED
                  ? "neutral"
                  : "info"
        }
      >
        {unknown
          ? "Outcome unknown, don't retry"
          : status
            ? actionStateLabels[status.state]
            : "Sent, waiting for device"}
      </StatusBadge>
      <dl className="grid gap-3 text-sm sm:grid-cols-2">
        <Fact label="Created">
          <ObservedTime value={action.createdAt} server />
        </Fact>
        <Fact label="Expires">
          <ObservedTime value={action.expiresAt} server />
        </Fact>
        {action.closedReason ? <Fact label="Closed because">{action.closedReason}</Fact> : null}
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
          <Fact label="Failure">
            {DeviceActionFailure[status.failure] ?? "Unknown failure code"}
          </Fact>
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
