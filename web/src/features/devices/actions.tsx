import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  DeviceActionFailure,
  DeviceActionState,
} from "../../../gen/lindm/agent/v1/device_actions_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { DeviceActionForm } from "./action-form";
import {
  CryptoEraseVerificationView,
  DeviceActionSpecView,
  NativeSanitizeVerificationView,
  actionStateLabels,
} from "./action-display";
import { deviceActionsQueryOptions } from "./action-queries";
import { Fact, ObservedTime } from "./observations";

export function DeviceLockRestriction({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const query = useQuery(deviceActionsQueryOptions(lifetime, deviceId, ""));
  if (query.isPending) return <p role="status">Loading conservative lock restriction…</p>;
  if (query.error) {
    return (
      <Alert variant="destructive">
        <AlertTitle>Lock restriction unknown</AlertTitle>
        <AlertDescription>{toRpcFailure(query.error).message}</AlertDescription>
      </Alert>
    );
  }
  if (!query.data?.sessionsLocked) return null;
  return (
    <Alert>
      <AlertTitle>Lock restriction retained</AlertTitle>
      <AlertDescription>
        <p className="break-all">Original action: {query.data.lockActionId}</p>
        <p>
          A start grant may have locked sessions or disabled local accounts. This is not a fresh
          observation or proof of completion. Only a signed, verified release matching this original
          action clears this restriction; release never unlocks a screen. Do not repeat unknown
          work.
        </p>
        <Button variant="outline" disabled={query.isFetching} onClick={() => void query.refetch()}>
          Refresh lock restriction
        </Button>
      </AlertDescription>
    </Alert>
  );
}

export function DeviceActionsPanel({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  return (
    <Card>
      <CardHeader>
        <CardTitle>Device actions</CardTitle>
        <CardDescription>
          Imperative, signed one-time actions. Acceptance is not completion. Review protected
          outcomes in the History tab; never repeat destructive work merely because a result is
          missing.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <DeviceActionForm
          key={`${lifetime.generation}:${deviceId}`}
          deviceId={deviceId}
          mode="actions"
        />
      </CardContent>
    </Card>
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
          Lost connectivity or interrupted destructive work remains OUTCOME UNKNOWN and must not be
          automatically repeated. Server restrictions are not native-state observations.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-semibold">Protected action history</h3>
          <Button
            variant="outline"
            disabled={query.isFetching}
            onClick={() => void query.refetch()}
          >
            Refresh action outcomes
          </Button>
        </div>
        {query.isPending ? <p role="status">Loading action history…</p> : null}
        {failure ? (
          <Alert variant="destructive">
            <AlertTitle>
              {failure.denied ? "Action access denied" : "Action history unavailable"}
            </AlertTitle>
            <AlertDescription>{failure.message}</AlertDescription>
          </Alert>
        ) : null}
        {data ? (
          <Alert>
            <AlertTitle>Server restriction fences</AlertTitle>
            <AlertDescription>
              <dl className="grid gap-3 sm:grid-cols-3">
                <Fact label="Lock restriction">{data.sessionsLocked ? "Retained" : "Not set"}</Fact>
                <Fact label="Original lock action">{data.lockActionId || "None"}</Fact>
                <Fact label="Quarantine fence">{data.quarantined ? "Set" : "Not set"}</Fact>
                <Fact label="Quarantine fence expiry">
                  <ObservedTime value={data.quarantineUntil} server />
                </Fact>
              </dl>
              <p>
                These are control-plane restriction fences, not a fresh observation of native
                session locks or firewall state. Expiry is not proof that disconnected device
                effects have cleared.
              </p>
            </AlertDescription>
          </Alert>
        ) : null}
        {data?.actions.length === 0 ? <p>No actions on this page.</p> : null}
        {data?.actions.map((action) => {
          const status = action.status;
          const unknown =
            status?.state === DeviceActionState.OUTCOME_UNKNOWN ||
            action.closedReason === "outcome_unknown";
          const needsCredential =
            action.spec?.action.case === "escrowRotate" || action.spec?.action.case === "tpm2Bind";
          return (
            <article key={action.actionId} className="grid gap-3 rounded-md border p-4">
              <Badge
                className="h-auto min-h-5 max-w-full whitespace-normal"
                variant={
                  unknown || status?.state === DeviceActionState.FAILED
                    ? "destructive"
                    : status?.state === DeviceActionState.SUCCEEDED
                      ? "success"
                      : "warning"
                }
              >
                {unknown
                  ? "OUTCOME UNKNOWN — no automatic retry"
                  : status
                    ? actionStateLabels[status.state]
                    : "Accepted — no protected result received"}
              </Badge>
              <dl className="grid gap-3 break-all text-sm sm:grid-cols-2">
                <Fact label="Action ID">{action.actionId}</Fact>
                <Fact label="Frozen enrollment generation">{action.enrollmentGeneration}</Fact>
                <Fact label="Created (server)">
                  <ObservedTime value={action.createdAt} server />
                </Fact>
                <Fact label="Intent expiry">
                  <ObservedTime value={action.expiresAt} server />
                </Fact>
                <Fact label="Closed reason">{action.closedReason || "Not closed"}</Fact>
                <Fact label="Revision">{action.actionRevision.toString()}</Fact>
              </dl>
              <DeviceActionSpecView spec={action.spec} />
              {status ? (
                <dl className="grid gap-3 text-sm sm:grid-cols-2">
                  <Fact label="Root accepted">
                    <ObservedTime value={status.acceptedAt} />
                  </Fact>
                  <Fact label="Root started">
                    <ObservedTime value={status.startedAt} />
                  </Fact>
                  <Fact label="Root completed">
                    <ObservedTime value={status.completedAt} />
                  </Fact>
                  <Fact label="Failure">
                    {DeviceActionFailure[status.failure] ?? "Unknown failure code"}
                  </Fact>
                  <Fact label="Native support">
                    {status.before?.supported
                      ? "Supported for this exact preflight"
                      : "Unsupported / not observed"}
                    {status.before?.reason ? ` — ${status.before.reason}` : ""}
                  </Fact>
                  <Fact label="Verification">
                    {status.verification?.verified ? "Verified by executor" : "Not verified"}
                  </Fact>
                  {status.verification?.evidence ? (
                    <Fact label="Native evidence">{status.verification.evidence}</Fact>
                  ) : null}
                  {action.spec?.action.case === "lockSessions" ||
                  action.spec?.action.case === "releaseLock" ? (
                    <>
                      <Fact label="Observed disabled local accounts">
                        {status.verification?.after?.disabledAccounts.join(", ") || "None reported"}
                      </Fact>
                      <Fact label="Preserved local accounts">
                        {status.verification?.after?.preservedAccounts.join(", ") ||
                          status.before?.preservedAccounts.join(", ") ||
                          "None reported"}
                      </Fact>
                      <Fact label="Observed session lock">
                        {status.verification?.after?.sessionsLocked ? "Locked" : "Not established"}
                      </Fact>
                    </>
                  ) : null}
                </dl>
              ) : null}
              {status?.volatileResult ? (
                <Alert>
                  <AlertTitle>Volatile executor result</AlertTitle>
                  <AlertDescription>
                    This terminal proof was held only in executor memory after live-root header
                    erasure and delivered to the server. It was not committed to the erased root
                    journal. Power-off is unconditional; absence of proof remains OUTCOME UNKNOWN.
                  </AlertDescription>
                </Alert>
              ) : null}
              <CryptoEraseVerificationView verification={status?.verification} />
              <NativeSanitizeVerificationView verification={status?.verification} />
              {needsCredential && status?.state !== DeviceActionState.SUCCEEDED ? (
                <p className="text-sm">
                  Encryption operations require an action-bound, memory-only one-shot credential
                  supplied through the protected root-local socket, or a qualified TPM token. This
                  console never accepts owner credentials. Missing credentials remain an explicit
                  precondition, not successful rotation.
                </p>
              ) : null}
              {unknown ? (
                <Alert variant="destructive">
                  <AlertTitle>Effects may already have happened</AlertTitle>
                  <AlertDescription>
                    Inspect protected device history and recovery evidence out of band. A lost
                    result, power-off, or restart is not proof of failure. Do not create a
                    replacement destructive action merely to recover a response.
                  </AlertDescription>
                </Alert>
              ) : null}
            </article>
          );
        })}
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
