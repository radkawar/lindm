import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { AdvisoryFindingState } from "../../../gen/lindm/admin/v1/advisories_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { canPermission } from "@/lib/permissions";
import { formatTimestamp } from "@/lib/time";
import { AcceptanceForm } from "./acceptance-form";
import {
  AdvisoryPaging,
  advisoryReasonText,
  findingStateLabel,
  publishedSeverity,
  unexpired,
  useFreshnessClock,
} from "./display";
import { deviceFindingsQueryOptions } from "./queries";
import { UncoveredPackages } from "./uncovered-packages";

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
  const partial = current && freshness.state === AdvisoryFindingState.PARTIAL;
  return (
    <Card className="min-w-0" aria-busy={findings.isFetching}>
      <CardHeader>
        <CardTitle>
          <h2>Security findings</h2>
        </CardTitle>
        <CardDescription>Packages on this device with known security advisories.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <Button
          className="w-fit"
          variant="outline"
          disabled={findings.isFetching}
          onClick={() => void findings.refetch()}
        >
          Refresh findings
        </Button>
        <p role="status" className="flex flex-wrap items-center gap-2 text-sm">
          Status:{" "}
          <StatusBadge
            status={
              state === "Affected"
                ? "destructive"
                : state === "Accepted" || state === "Partial"
                  ? "warning"
                  : "neutral"
            }
          >
            {state}
          </StatusBadge>
        </p>
        {!current ? (
          <p className="border bg-muted/30 p-3 text-sm">
            Status unknown. The device inventory or advisory sources are out of date.
          </p>
        ) : null}
        {partial ? (
          <div className="grid gap-4 border bg-muted/30 p-3 text-sm">
            <p className="font-medium">Partly checked: {advisoryReasonText(freshness.reason)}.</p>
            <p>
              The base distribution&apos;s advisories are applied only to packages verified as
              installed from its signed archive. The other {freshness.uncoveredPackages.toString()}{" "}
              installed packages are not checked, so this device is never shown as unaffected.
            </p>
            <UncoveredPackages deviceId={deviceId} />
          </div>
        ) : null}
        {findings.isPending ? (
          <div role="status" className="grid gap-3">
            <span className="text-sm text-muted-foreground">Loading findings…</span>
            <Skeleton className="h-32 w-full" />
          </div>
        ) : null}
        {findings.error ? <RpcError failure={toRpcFailure(findings.error)} /> : null}
        {freshness ? (
          <>
            <dl className="grid gap-3 border-y py-4 text-sm sm:grid-cols-2">
              <div>
                <dt className="inline font-medium">Inventory collected: </dt>
                <dd className="inline">{formatTimestamp(freshness.inventoryAt).local}</dd>
              </div>
              <div>
                <dt className="inline font-medium">Advisories checked: </dt>
                <dd className="inline">{formatTimestamp(freshness.feedCheckedAt).local}</dd>
              </div>
            </dl>
            <TechnicalDetails
              items={[
                { label: "Reason", value: freshness.reason },
                {
                  label: "Inventory expires",
                  value: formatTimestamp(freshness.inventoryExpiresAt).local,
                },
                { label: "Feed expires", value: formatTimestamp(freshness.feedExpiresAt).local },
                { label: "Feed ID", value: freshness.feedId },
                { label: "Snapshot ID", value: freshness.snapshotId },
                { label: "Source SHA-256", value: freshness.sourceSha256 },
              ]}
            />
          </>
        ) : null}
        {findings.data?.findings.length === 0 ? (
          <EmptyState
            title="No findings on this page"
            description="If the inventory or advisory sources are out of date, the device may still be affected."
          />
        ) : null}
        {findings.data?.findings.map((finding) => {
          const accepted =
            finding.state === AdvisoryFindingState.ACCEPTED &&
            unexpired(finding.exception?.expiresAt, now);
          const label =
            finding.reason === "source_record_rejected"
              ? "Unknown (advisory unreadable)"
              : !current || freshness?.state === AdvisoryFindingState.UNKNOWN
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
                    {finding.packageName}
                    {finding.architecture ? ` (${finding.architecture})` : ""}
                  </dd>
                </div>
                <div>
                  <dt className="inline font-medium">Installed version: </dt>
                  <dd className="inline">{finding.installedVersion || "Unknown"}</dd>
                </div>
                <div>
                  <dt className="inline font-medium">Fixed version: </dt>
                  <dd className="inline">{finding.fixedVersion || "No fix yet"}</dd>
                </div>
                <div>
                  <dt className="inline font-medium">Severity: </dt>
                  <dd className="inline">
                    {publishedSeverity(finding.severity) || "Not published"}
                  </dd>
                </div>
                {finding.cves.length ? (
                  <div>
                    <dt className="inline font-medium">CVEs: </dt>
                    <dd className="inline">{finding.cves.join(", ")}</dd>
                  </div>
                ) : null}
                <div>
                  <dt className="inline font-medium">Published: </dt>
                  <dd className="inline">{formatTimestamp(finding.publishedAt).local}</dd>
                </div>
              </dl>
              <TechnicalDetails items={[{ label: "Source URL", value: finding.sourceUrl }]} />
              {finding.exception ? (
                <div className="space-y-2 border bg-muted/30 p-3 text-sm">
                  <p>
                    Risk accepted by{" "}
                    {!finding.exception.actorId.trim()
                      ? "the system"
                      : finding.exception.actorId === principal.id
                        ? "you"
                        : "another administrator"}
                    . Acceptance expiry: {formatTimestamp(finding.exception.expiresAt).local}.
                  </p>
                  <p className="whitespace-pre-wrap break-words">
                    Reason: {finding.exception.reason}
                  </p>
                  <TechnicalDetails
                    items={[{ label: "Actor ID", value: finding.exception.actorId }]}
                  />
                </div>
              ) : null}
              {finding.reason !== "source_record_rejected" &&
              canPermission(principal, "advisory_exceptions.manage") ? (
                <details>
                  <summary className="cursor-pointer font-medium">Accept this risk</summary>
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
