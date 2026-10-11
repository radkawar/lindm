import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
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
        description="Security advisories affecting your devices, and whether advisory sources are up to date."
        actions={
          <Link to="/devices" className="text-sm underline underline-offset-4">
            View findings by device
          </Link>
        }
      />
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Across your devices</h2>
          </CardTitle>
          <CardDescription>
            Accepting a finding hides it; it doesn't fix the device.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Button
            className="w-fit"
            variant="outline"
            disabled={summary.isFetching}
            onClick={() => void summary.refetch()}
          >
            Refresh
          </Button>
          {summary.isPending ? (
            <div role="status" className="grid gap-3">
              <span className="text-sm text-muted-foreground">Loading advisories…</span>
              <Skeleton className="h-32 w-full" />
            </div>
          ) : null}
          {summary.error ? <RpcError failure={toRpcFailure(summary.error)} /> : null}
          {feedUnknown ? (
            <p className="text-sm text-muted-foreground">
              Counts may be incomplete. Check advisory sources below.
            </p>
          ) : null}
          {summary.data ? (
            <>
              <dl className="grid gap-4 border bg-muted/30 p-4 sm:grid-cols-3">
                <div>
                  <dt className="text-xs text-muted-foreground">Devices checked</dt>
                  <dd className="mt-1 text-2xl font-semibold tabular-nums">
                    {summary.data.evaluatedDevices.toString()}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">
                    Devices partly checked (some packages not covered)
                  </dt>
                  <dd className="mt-1 text-2xl font-semibold tabular-nums">
                    {summary.data.partialDevices.toString()}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">Devices not checked</dt>
                  <dd className="mt-1 text-2xl font-semibold tabular-nums">
                    {summary.data.unknownDevices.toString()}
                  </dd>
                </div>
              </dl>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Advisory</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Affected devices</TableHead>
                    <TableHead>Accepted</TableHead>
                    <TableHead>Not checked</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {summary.data.advisories.map((advisory) => (
                    <TableRow key={advisory.advisoryId}>
                      <TableCell>
                        <p>{advisory.advisoryId}</p>
                        <p className="text-xs text-muted-foreground">
                          {advisory.cves.join(", ") || "No CVEs listed"}
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
                  title="No advisories on this page"
                  description="If advisory sources aren't up to date, devices may still be affected."
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
            <h2>Advisory sources</h2>
          </CardTitle>
          <CardDescription>
            Findings are only accurate when sources and device inventory are up to date.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Button
            className="w-fit"
            variant="outline"
            disabled={feeds.isFetching}
            onClick={() => void feeds.refetch()}
          >
            Refresh sources
          </Button>
          {feeds.isPending ? (
            <div role="status" className="grid gap-3">
              <span className="text-sm text-muted-foreground">Loading advisory sources…</span>
              <Skeleton className="h-32 w-full" />
            </div>
          ) : null}
          {feeds.error ? <RpcError failure={toRpcFailure(feeds.error)} /> : null}
          {feeds.isSuccess && feeds.data.feeds.length === 0 ? (
            <EmptyState
              title="No advisory sources set up"
              description="Add sources under advisories.feeds in the server configuration, then refresh."
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
                          ? `Up to date, ${feed.rejectedRecords.length} entries skipped`
                          : "Up to date"
                        : !feed.checkedAt
                          ? "Not refreshed yet"
                          : unexpired(feed.expiresAt, now)
                            ? "Incomplete"
                            : "Out of date"}
                </StatusBadge>
              </div>
              <p className="break-all">Source: {feed.sourceUrl}</p>
              <p>
                {feed.distro} {feed.release}
                {feed.platformStream ? ` (${feed.platformStream})` : ""} ·{" "}
                {feed.advisoryCount.toString()} advisories
              </p>
              <p>
                Last refreshed: {feed.checkedAt ? formatTimestamp(feed.checkedAt).local : "Never"}
              </p>
              <p>Expires: {formatTimestamp(feed.expiresAt).local}</p>
              <p className={feed.error ? "text-destructive" : "text-muted-foreground"}>
                {feeds.error
                  ? "Couldn't load the latest status. Showing the last known details."
                  : feed.error
                    ? "The last refresh failed. Check the server logs."
                    : feed.rejectedRecords.length > 0
                      ? "Some entries couldn't be read. Counts may be incomplete."
                      : feed.fresh && unexpired(feed.expiresAt, now)
                        ? "This source is up to date."
                        : !feed.checkedAt
                          ? "This source hasn't been refreshed yet."
                          : !unexpired(feed.expiresAt, now)
                            ? "This source is out of date. Refresh it."
                            : "This source is missing some data."}
              </p>
              {feed.rejectedRecords.length > 0 ? (
                <details>
                  <summary className="cursor-pointer font-medium">
                    Skipped entries ({feed.rejectedRecords.length})
                  </summary>
                  <ul className="mt-3 grid gap-3">
                    {feed.rejectedRecords.map((record, index) => (
                      <li
                        key={`${record.id}:${index}`}
                        className="grid gap-1 break-words border-l-2 border-warning pl-3"
                      >
                        <p className="font-medium">{record.id || "Entry without an ID"}</p>
                        <p>{record.reason}</p>
                        <p className="text-muted-foreground">
                          {record.unscoped
                            ? "Affected packages unknown."
                            : `Packages: ${record.packageNames.join(", ")}`}
                        </p>
                      </li>
                    ))}
                  </ul>
                </details>
              ) : null}
              <TechnicalDetails
                items={[
                  { label: "Last attempt", value: formatTimestamp(feed.attemptedAt).local },
                  {
                    label: "Signed snapshot",
                    value: feed.snapshotAt ? formatTimestamp(feed.snapshotAt).local : undefined,
                  },
                  { label: "Reported error", value: feed.error },
                  { label: "Snapshot SHA-256", value: feed.sourceSha256 },
                ]}
              >
                {feed.artifacts.length > 0 ? (
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
                          Signer: {artifact.signerFingerprint || "Not signed"}
                        </p>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </TechnicalDetails>
            </article>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
