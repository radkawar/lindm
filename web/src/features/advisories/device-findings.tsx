import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { AdvisoryFindingState } from "../../../gen/lindm/admin/v1/advisories_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { canPermission } from "@/lib/permissions";
import { formatTimestamp } from "@/lib/time";
import { AcceptanceForm } from "./acceptance-form";
import { AdvisoryPaging, findingStateLabel, unexpired, useFreshnessClock } from "./display";
import { deviceFindingsQueryOptions } from "./queries";

export function DeviceFindings({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const [pageToken, setPageToken] = useState("");
  const now = useFreshnessClock();
  const findings = useQuery(deviceFindingsQueryOptions(lifetime, deviceId, pageToken));
  const freshness = findings.data?.freshness;
  const current =
    !findings.error &&
    freshness !== undefined &&
    unexpired(freshness.inventoryExpiresAt, now) &&
    unexpired(freshness.feedExpiresAt, now);
  const state = current ? findingStateLabel(freshness.state) : "Unknown";
  return (
    <Card className="min-w-0" aria-busy={findings.isFetching}>
      <CardHeader>
        <CardTitle>
          <h2>Distro advisory findings</h2>
        </CardTitle>
        <CardDescription>
          Package findings from the latest inventory and distro sources. Accepting a finding records
          the risk; it does not fix the package.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <Button
          className="w-fit"
          variant="outline"
          disabled={findings.isFetching}
          onClick={() => void findings.refetch()}
        >
          Refresh advisory findings
        </Button>
        <p role="status" className="flex flex-wrap items-center gap-2 text-sm">
          Exposure:{" "}
          <StatusBadge
            status={
              state === "Affected" ? "destructive" : state === "Accepted" ? "warning" : "neutral"
            }
          >
            {state}
          </StatusBadge>
          {freshness?.reason ? ` (${freshness.reason})` : ""}
        </p>
        {!current ? (
          <p className="border bg-muted/30 p-3 text-sm">
            Current exposure is unknown. Refresh the inventory or advisory sources.
          </p>
        ) : null}
        {findings.isPending ? (
          <div role="status" className="grid gap-3">
            <span className="text-sm text-muted-foreground">Loading advisory findings…</span>
            <Skeleton className="h-32 w-full" />
          </div>
        ) : null}
        {findings.error ? <RpcError failure={toRpcFailure(findings.error)} /> : null}
        {freshness ? (
          <dl className="grid gap-3 border-y py-4 text-sm sm:grid-cols-2">
            <div>
              <dt className="inline font-medium">Inventory collected: </dt>
              <dd className="inline">{formatTimestamp(freshness.inventoryAt).local}</dd>
            </div>
            <div>
              <dt className="inline font-medium">Inventory expires: </dt>
              <dd className="inline">{formatTimestamp(freshness.inventoryExpiresAt).local}</dd>
            </div>
            <div>
              <dt className="inline font-medium">Feed checked: </dt>
              <dd className="inline">{formatTimestamp(freshness.feedCheckedAt).local}</dd>
            </div>
            <div>
              <dt className="inline font-medium">Feed expires: </dt>
              <dd className="inline">{formatTimestamp(freshness.feedExpiresAt).local}</dd>
            </div>
            <div className="break-all">
              <dt className="inline font-medium">Feed / snapshot: </dt>
              <dd className="inline">
                {freshness.feedId || "Unavailable"} / {freshness.snapshotId || "Unavailable"}
              </dd>
            </div>
            <div className="break-all">
              <dt className="inline font-medium">Source SHA-256: </dt>
              <dd className="inline font-mono">{freshness.sourceSha256 || "Unavailable"}</dd>
            </div>
          </dl>
        ) : null}
        {findings.data?.findings.length === 0 ? (
          <EmptyState
            title="No findings on this page"
            description="Check inventory and source coverage before treating this device as unaffected."
          />
        ) : null}
        {findings.data?.findings.map((finding) => {
          const accepted =
            finding.state === AdvisoryFindingState.ACCEPTED &&
            unexpired(finding.exception?.expiresAt, now);
          const label =
            !current || freshness?.state === AdvisoryFindingState.UNKNOWN
              ? "Unknown"
              : finding.state === AdvisoryFindingState.ACCEPTED && !accepted
                ? "Affected (acceptance expired)"
                : findingStateLabel(finding.state);
          return (
            <article key={finding.id} className="grid min-w-0 gap-4 border p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="break-words font-semibold">{finding.advisoryId}</h3>
                <StatusBadge
                  status={
                    label.startsWith("Affected")
                      ? "destructive"
                      : label === "Accepted"
                        ? "warning"
                        : "neutral"
                  }
                >
                  {label}
                </StatusBadge>
              </div>
              <dl className="grid gap-3 break-words text-sm sm:grid-cols-2">
                <div>
                  <dt className="inline font-medium">Package: </dt>
                  <dd className="inline">
                    {finding.packageName} ({finding.architecture || "architecture unavailable"})
                  </dd>
                </div>
                <div>
                  <dt className="inline font-medium">Installed version: </dt>
                  <dd className="inline">{finding.installedVersion || "Unavailable"}</dd>
                </div>
                <div>
                  <dt className="inline font-medium">Fixed version: </dt>
                  <dd className="inline">{finding.fixedVersion || "No fixed version published"}</dd>
                </div>
                <div>
                  <dt className="inline font-medium">Severity: </dt>
                  <dd className="inline">{finding.severity || "Unknown"}</dd>
                </div>
                <div>
                  <dt className="inline font-medium">CVEs: </dt>
                  <dd className="inline">{finding.cves.join(", ") || "None supplied"}</dd>
                </div>
                <div>
                  <dt className="inline font-medium">Published: </dt>
                  <dd className="inline">{formatTimestamp(finding.publishedAt).local}</dd>
                </div>
                <div className="break-all">
                  <dt className="inline font-medium">Source: </dt>
                  <dd className="inline">
                    {finding.feedId}: {finding.sourceUrl || "Unavailable"}
                  </dd>
                </div>
              </dl>
              {finding.exception ? (
                <div className="space-y-2 border bg-muted/30 p-3 text-sm">
                  <p>
                    Acceptance by {finding.exception.actorId}, recorded{" "}
                    {formatTimestamp(finding.exception.acceptedAt).local}; expires{" "}
                    {formatTimestamp(finding.exception.expiresAt).local}.
                  </p>
                  <p className="whitespace-pre-wrap break-words">
                    Reason: {finding.exception.reason}
                  </p>
                  <p>
                    {accepted
                      ? "Risk accepted until the displayed expiry, subject to current authorization."
                      : "This acceptance is no longer current."}
                  </p>
                </div>
              ) : null}
              {canPermission(principal, "advisory_exceptions.manage") ? (
                <details>
                  <summary className="cursor-pointer font-medium">
                    Record time-limited risk acceptance
                  </summary>
                  <div className="mt-3">
                    <AcceptanceForm
                      key={`${lifetime.generation}/${finding.id}`}
                      deviceId={deviceId}
                      findingId={finding.id}
                    />
                  </div>
                </details>
              ) : null}
            </article>
          );
        })}
        <AdvisoryPaging
          token={pageToken}
          next={findings.data?.nextPageToken ?? ""}
          busy={findings.isFetching}
          onPage={setPageToken}
        />
      </CardContent>
    </Card>
  );
}
