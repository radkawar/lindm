import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { AdvisoryPaging, unexpired, useFreshnessClock } from "./display";
import { advisoryFeedsQueryOptions, advisorySummaryQueryOptions } from "./queries";

export function AdvisoryFleet() {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const now = useFreshnessClock();
  const summary = useQuery(advisorySummaryQueryOptions(lifetime, pageToken));
  const feeds = useQuery(advisoryFeedsQueryOptions(lifetime));
  const feedUnknown =
    !feeds.data?.feeds.length ||
    !!feeds.error ||
    feeds.data.feeds.some(
      (feed) =>
        !!feed.error ||
        !feed.fresh ||
        !unexpired(feed.expiresAt, now) ||
        feed.rejectedRecords.length > 0,
    );
  return (
    <div className="grid min-w-0 gap-6">
      <PageHeader
        title="Advisories"
        description="Review package findings and advisory source coverage across your devices."
        actions={
          <Link to="/devices" className="text-sm underline underline-offset-4">
            Inspect device findings
          </Link>
        }
      />
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Fleet summary</h2>
          </CardTitle>
          <CardDescription>Accepting a finding does not fix affected devices.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Button
            className="w-fit"
            variant="outline"
            disabled={summary.isFetching}
            onClick={() => void summary.refetch()}
          >
            Refresh fleet summary
          </Button>
          {summary.isPending ? (
            <div role="status" className="grid gap-3">
              <span className="text-sm text-muted-foreground">Loading fleet summary…</span>
              <Skeleton className="h-32 w-full" />
            </div>
          ) : null}
          {summary.error ? <RpcError failure={toRpcFailure(summary.error)} /> : null}
          {feedUnknown ? (
            <p className="text-sm text-muted-foreground">
              Counts may be incomplete. Review each feed source below before assessing current fleet
              exposure.
            </p>
          ) : null}
          {summary.data ? (
            <>
              <dl className="grid gap-4 border bg-muted/30 p-4 sm:grid-cols-2">
                <div>
                  <dt className="text-xs text-muted-foreground">Evaluated devices</dt>
                  <dd className="mt-1 text-2xl font-semibold tabular-nums">
                    {summary.data.evaluatedDevices.toString()}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">Unknown devices</dt>
                  <dd className="mt-1 text-2xl font-semibold tabular-nums">
                    {summary.data.unknownDevices.toString()}
                  </dd>
                </div>
              </dl>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Advisory / CVEs</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Affected devices</TableHead>
                    <TableHead>Accepted devices</TableHead>
                    <TableHead>Unknown devices</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {summary.data.advisories.map((advisory) => (
                    <TableRow key={advisory.advisoryId}>
                      <TableCell>
                        <p>{advisory.advisoryId}</p>
                        <p className="text-xs text-muted-foreground">
                          {advisory.cves.join(", ") || "No CVEs supplied"}
                        </p>
                      </TableCell>
                      <TableCell>
                        <StatusBadge status="neutral">{advisory.severity || "Unknown"}</StatusBadge>
                      </TableCell>
                      <TableCell>{advisory.affectedDevices.toString()}</TableCell>
                      <TableCell>{advisory.acceptedDevices.toString()}</TableCell>
                      <TableCell>{advisory.unknownDevices.toString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {!summary.data.advisories.length ? (
                <EmptyState
                  title="No advisory summaries on this page"
                  description="No findings are listed. Check source coverage before treating a device as unaffected."
                />
              ) : null}
            </>
          ) : null}
          <AdvisoryPaging
            token={pageToken}
            next={summary.data?.nextPageToken ?? ""}
            busy={summary.isFetching}
            onPage={setPageToken}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Feed freshness and status</h2>
          </CardTitle>
          <CardDescription>
            Each source needs a current refresh. Devices also need current inventory.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Button
            className="w-fit"
            variant="outline"
            disabled={feeds.isFetching}
            onClick={() => void feeds.refetch()}
          >
            Refresh feed status
          </Button>
          {feeds.isPending ? (
            <div role="status" className="grid gap-3">
              <span className="text-sm text-muted-foreground">Loading advisory feeds…</span>
              <Skeleton className="h-32 w-full" />
            </div>
          ) : null}
          {feeds.error ? <RpcError failure={toRpcFailure(feeds.error)} /> : null}
          {feeds.isSuccess && feeds.data.feeds.length === 0 ? (
            <EmptyState
              title="No advisory feeds configured"
              description="Add distro sources to advisories.feeds in the control-plane configuration. Enable scheduled refreshes or import a verified offline feed, then refresh this status view."
            />
          ) : null}
          {feeds.data?.feeds.map((feed) => (
            <article key={feed.id} className="grid min-w-0 gap-2 border bg-muted/20 p-4 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="break-words font-semibold">{feed.id}</h3>
                <StatusBadge
                  status={
                    feeds.error
                      ? "neutral"
                      : feed.error
                        ? "destructive"
                        : feed.fresh && unexpired(feed.expiresAt, now)
                          ? feed.rejectedRecords.length > 0
                            ? "warning"
                            : "success"
                          : feed.checkedAt
                            ? "warning"
                            : "neutral"
                  }
                >
                  {feeds.error
                    ? "Status unavailable"
                    : feed.error
                      ? "Refresh failed"
                      : feed.fresh && unexpired(feed.expiresAt, now)
                        ? feed.rejectedRecords.length > 0
                          ? `Current, ${feed.rejectedRecords.length} records rejected`
                          : "Current"
                        : !feed.checkedAt
                          ? "Awaiting refresh"
                          : unexpired(feed.expiresAt, now)
                            ? "Incomplete coverage"
                            : "Stale"}
                </StatusBadge>
              </div>
              <p className="break-all">Source: {feed.sourceUrl}</p>
              <p>
                {feed.distro} {feed.release}
                {feed.platformStream ? ` (${feed.platformStream})` : ""} ·{" "}
                {feed.advisoryCount.toString()} advisory records
              </p>
              <p>
                Last successful refresh:{" "}
                {feed.checkedAt ? formatTimestamp(feed.checkedAt).local : "Not recorded"}
              </p>
              <p>
                Signed snapshot:{" "}
                {feed.snapshotAt ? formatTimestamp(feed.snapshotAt).local : "Not recorded"}
              </p>
              <p>Expires: {formatTimestamp(feed.expiresAt).local}</p>
              <p>Last attempt: {formatTimestamp(feed.attemptedAt).local}</p>
              <p className={feed.error ? "text-destructive" : "text-muted-foreground"}>
                Reason:{" "}
                {feeds.error
                  ? "The latest status request failed. Showing the last retrieved source details."
                  : feed.error === "refresh_failed"
                    ? "The source refresh failed. Check control-plane logs for details."
                    : feed.error ||
                      (feed.rejectedRecords.length > 0
                        ? "Some source records could not be evaluated. Exposure counts may be incomplete."
                        : feed.fresh && unexpired(feed.expiresAt, now)
                          ? "The source is current."
                          : !feed.checkedAt
                            ? "No successful refresh is recorded."
                            : !unexpired(feed.expiresAt, now)
                              ? "The last successful refresh is out of date."
                              : "The source snapshot has incomplete coverage.")}
              </p>
              {feed.error ? (
                <p className="break-all text-xs text-muted-foreground">
                  Reported reason: {feed.error}
                </p>
              ) : null}
              {feed.rejectedRecords.length > 0 ? (
                <details>
                  <summary className="cursor-pointer font-medium">
                    Rejected source records ({feed.rejectedRecords.length})
                  </summary>
                  <ul className="mt-3 grid gap-3">
                    {feed.rejectedRecords.map((record, index) => (
                      <li
                        key={`${record.id}:${index}`}
                        className="grid gap-1 break-words border-l-2 border-warning pl-3"
                      >
                        <p className="font-medium">{record.id || "Record without an ID"}</p>
                        <p>{record.reason}</p>
                        <p className="text-muted-foreground">
                          {record.unscoped
                            ? "Affected packages could not be identified."
                            : `Packages: ${record.packageNames.join(", ")}`}
                        </p>
                      </li>
                    ))}
                  </ul>
                </details>
              ) : null}
              <p className="break-all font-mono">
                Snapshot SHA-256: {feed.sourceSha256 || "Unavailable"}
              </p>
              {feed.artifacts.length > 0 ? (
                <details>
                  <summary className="cursor-pointer">Source artifact integrity</summary>
                  <ul className="mt-2 grid gap-3">
                    {feed.artifacts.map((artifact) => (
                      <li key={artifact.url} className="grid gap-1 break-all">
                        <p>{artifact.url}</p>
                        <p className="font-mono">
                          SHA-256:{" "}
                          {Array.from(artifact.sha256, (byte) =>
                            byte.toString(16).padStart(2, "0"),
                          ).join("")}
                        </p>
                        <p className="font-mono">
                          Signer: {artifact.signerFingerprint || "Signature not recorded"}
                        </p>
                      </li>
                    ))}
                  </ul>
                </details>
              ) : null}
            </article>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
