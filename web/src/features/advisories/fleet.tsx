import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { AdvisoryFeedStatus } from "../../../gen/lindm/admin/v1/advisories_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
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
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { CoverageBanner } from "./coverage-banner";
import {
  AdvisoryPaging,
  feedOSLabel,
  publishedSeverity,
  sourceAnchor,
  sourceGap,
  unexpired,
  useFreshnessClock,
} from "./display";
import { advisoryFeedsQueryOptions, advisorySummaryQueryOptions } from "./queries";

export function AdvisoryFleet() {
  const lifetime = useAuthLifetime();
  // Advisory sources are fleet-wide; a device-scoped reader sees findings only.
  const canReviewSources = canPermission(usePrincipal(), "fleet.read", true);
  const [pageToken, setPageToken] = useState("");
  const now = useFreshnessClock();
  const summary = useQuery(advisorySummaryQueryOptions(lifetime, pageToken));
  const feeds = useQuery({ ...advisoryFeedsQueryOptions(lifetime), enabled: canReviewSources });
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
        description={
          canReviewSources
            ? "Security advisories affecting your devices, and whether advisory sources are up to date."
            : "Security advisories affecting your devices."
        }
        actions={
          <Link to="/devices" className="text-sm underline underline-offset-4">
            View findings by device
          </Link>
        }
      />
      {summary.data ? (
        <CoverageBanner
          summary={summary.data}
          feeds={feeds.data?.feeds ?? []}
          canReviewSources={canReviewSources}
          reloading={summary.isFetching}
          onReload={() => void summary.refetch()}
        />
      ) : null}
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
          {canReviewSources && feedUnknown && !summary.data?.unknownDevices ? (
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
                  <dd
                    className="mt-1 text-2xl font-semibold tabular-nums"
                    data-advisory-unchecked-count={summary.data.unknownDevices.toString()}
                  >
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
                  {summary.data.advisories.map((advisory) => {
                    const severity = publishedSeverity(advisory.severity);
                    return (
                      <TableRow key={advisory.advisoryId}>
                        <TableCell>
                          <p>{advisory.advisoryId}</p>
                          {advisory.cves.length ? (
                            <p className="text-xs text-muted-foreground">
                              {advisory.cves.join(", ")}
                            </p>
                          ) : null}
                        </TableCell>
                        <TableCell>
                          {severity ? (
                            <StatusBadge status="neutral">{severity}</StatusBadge>
                          ) : (
                            <span className="text-xs text-muted-foreground">Not published</span>
                          )}
                        </TableCell>
                        <TableCell>{advisory.affectedDevices.toString()}</TableCell>
                        <TableCell>{advisory.acceptedDevices.toString()}</TableCell>
                        <TableCell>{advisory.unknownDevices.toString()}</TableCell>
                      </TableRow>
                    );
                  })}
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
      {canReviewSources ? (
        <Card id="advisory-sources" className="scroll-mt-4">
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
            {feeds.data?.feeds.map((feed) => {
              const status = sourceStatus(feed, now, !!feeds.error);
              return (
                <article
                  key={feed.id}
                  id={sourceAnchor(feed.id)}
                  data-advisory-source=""
                  className="grid min-w-0 scroll-mt-4 gap-2 border bg-muted/20 p-4 text-sm"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="break-words font-semibold">
                      {feedOSLabel(feed)}
                      {feed.platformStream ? ` (${feed.platformStream} stream)` : ""}
                    </h3>
                    <StatusBadge status={status.tone} data-advisory-source-badge="">
                      {status.label}
                    </StatusBadge>
                  </div>
                  <p>
                    {feed.advisoryCount === 1n
                      ? "1 advisory"
                      : `${feed.advisoryCount.toString()} advisories`}
                  </p>
                  <p>
                    Last refreshed:{" "}
                    {feed.checkedAt ? formatTimestamp(feed.checkedAt).local : "Never"}
                  </p>
                  <p>Expires: {formatTimestamp(feed.expiresAt).local}</p>
                  <p
                    data-advisory-source-status=""
                    className={feed.error ? "text-destructive" : "text-muted-foreground"}
                  >
                    {status.sentence}
                  </p>
                  {status.remedy ? <p>{status.remedy}</p> : null}
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
                      { label: "Source ID", value: feed.id },
                      { label: "Source URL", value: feed.sourceUrl },
                      { label: "Last attempt", value: formatTimestamp(feed.attemptedAt).local },
                      {
                        label: "Snapshot time",
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
              );
            })}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

// One source's badge, status sentence and remedy. Incomplete means the last
// refresh succeeded and has not expired, yet is not a complete snapshot.
function sourceStatus(
  feed: AdvisoryFeedStatus,
  now: number,
  statusFailed: boolean,
): { tone: StatusTone; label: string; sentence: string; remedy?: string } {
  if (statusFailed) {
    return {
      tone: "neutral",
      label: "Status unavailable",
      sentence: "Couldn't load the latest status. Showing the last known details.",
    };
  }
  if (feed.error) {
    return {
      tone: "destructive",
      label: "Refresh failed",
      sentence: "The last refresh failed. Check the server logs.",
    };
  }
  const skipped = feed.rejectedRecords.length;
  if (feed.fresh && unexpired(feed.expiresAt, now) && skipped > 0) {
    return {
      tone: "warning",
      label: `Up to date, ${skipped} entries skipped`,
      sentence: "Some entries couldn't be read. Counts may be incomplete.",
    };
  }
  if (feed.fresh && unexpired(feed.expiresAt, now)) {
    return {
      tone: "success",
      label: "Up to date",
      sentence: "This source is up to date.",
    };
  }
  if (!feed.checkedAt) {
    return {
      tone: "neutral",
      label: "Not refreshed yet",
      sentence: "This source hasn't been refreshed yet.",
    };
  }
  if (!unexpired(feed.expiresAt, now)) {
    return {
      tone: "warning",
      label: "Out of date",
      sentence: "This source is out of date. Refresh it.",
    };
  }
  const gap = sourceGap(feed);
  return { tone: "warning", label: "Incomplete", sentence: gap.missing, remedy: gap.remedy };
}
