// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { AdvisoryFeedStatus } from "../../../gen/lindm/admin/v1/advisories_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { ListPagination } from "@/components/ui/list-pagination";
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
import { Timestamp } from "@/components/ui/timestamp";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { CoverageBanner } from "./coverage-banner";
import {
  advisorySourcesDocsUrl,
  feedOSLabel,
  Severity,
  sourceAnchor,
  sourceGap,
  unexpired,
  useFreshnessClock,
} from "./display";
import { advisoryFeedsQueryOptions, advisorySummaryQueryOptions } from "./queries";
import { firstDownloadState } from "./initial-download";
import { InitialDownloadNotice } from "./initial-download-notice";

export function AdvisoryFleet() {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const now = useFreshnessClock();
  // Advisory sources are fleet-wide; a device-scoped reader sees findings only.
  const canReviewSources = canPermission(usePrincipal(), "fleet.read", true);
  const summary = useQuery(advisorySummaryQueryOptions(lifetime, pageToken));
  const feeds = useQuery({ ...advisoryFeedsQueryOptions(lifetime), enabled: canReviewSources });
  const firstDataPending =
    canReviewSources &&
    !feeds.error &&
    feeds.data?.feeds.some((feed) => firstDownloadState(feed, now) !== undefined);
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
            ? "Review device exposure and advisory sources."
            : "Review security advisories that affect devices."
        }
        onRefresh={() => {
          void summary.refetch();
          if (canReviewSources) void feeds.refetch();
        }}
        refreshing={summary.isFetching || feeds.isFetching}
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
          reloading={summary.isFetching}
          onReload={() => void summary.refetch()}
          canReviewSources={canReviewSources}
        />
      ) : null}
      <Card id="advisory-findings" className="scroll-mt-4">
        <CardHeader>
          <CardTitle>
            <h2>Across your devices</h2>
          </CardTitle>
          <CardDescription>
            Open an advisory to see affected devices. An accepted risk is not a package fix.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          {summary.isPending ? (
            <div role="status" className="grid gap-3">
              <span className="text-sm text-muted-foreground">Loading advisories…</span>
              <Skeleton className="h-32 w-full" />
            </div>
          ) : null}
          {summary.error ? <RpcError failure={toRpcFailure(summary.error)} /> : null}
          {canReviewSources && feedUnknown && !summary.data?.unknownDevices ? (
            <p className="text-sm text-muted-foreground">
              Counts are incomplete when advisory sources are unavailable. Check the sources below.
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
              <Table className="max-sm:block max-sm:[&_tbody]:block max-sm:[&_tr]:block max-sm:[&_td]:block max-sm:[&_td]:whitespace-normal">
                <TableHeader className="max-sm:sr-only">
                  <TableRow>
                    <TableHead>Advisory</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Affected devices</TableHead>
                    <TableHead>Devices with accepted risk</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {summary.data.advisories.map((advisory) => {
                    return (
                      <TableRow key={`${advisory.advisoryId}/${advisory.severity}`}>
                        <TableCell>
                          <Link
                            to="/devices"
                            search={{
                              pageSize: 50,
                              pageToken: "",
                              advisoryId: advisory.advisoryId,
                              advisorySeverity: advisory.severity,
                              sort: "hostname",
                              order: "asc",
                            }}
                            className="font-medium underline underline-offset-4"
                            aria-label={`View affected devices for ${advisory.advisoryId}`}
                          >
                            {advisory.advisoryId}
                          </Link>
                          {advisory.cves.length ? (
                            <p className="text-xs text-muted-foreground">
                              {advisory.cves.join(", ")}
                            </p>
                          ) : null}
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground sm:hidden">
                            Severity:{" "}
                          </span>
                          <Severity value={advisory.severity} />
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground sm:hidden">
                            Affected devices:{" "}
                          </span>
                          <AffectedDevices
                            affected={advisory.affectedDevices}
                            unconfirmed={advisory.unknownDevices}
                          />
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground sm:hidden">
                            Devices with accepted risk:{" "}
                          </span>
                          {advisory.acceptedDevices.toString()}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
              {!summary.data.advisories.length ? (
                <EmptyState
                  title={
                    firstDataPending
                      ? "First vulnerability data not ready"
                      : "No advisories on this page"
                  }
                  description={
                    firstDataPending
                      ? "Findings will appear after the first vulnerability data download and device inventory check. Exposure remains unknown."
                      : "Outdated advisory sources leave device exposure unknown."
                  }
                />
              ) : null}
            </>
          ) : null}
          <ListPagination
            label="Advisory pages"
            busy={summary.isFetching}
            onPrevious={pageToken ? () => setPageToken("") : undefined}
            onNext={
              summary.data?.nextPageToken
                ? () => setPageToken(summary.data.nextPageToken)
                : undefined
            }
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
              Keep sources and device inventory current.{" "}
              <a
                href={advisorySourcesDocsUrl}
                target="_blank"
                rel="noreferrer"
                className="underline underline-offset-4"
              >
                Configure advisory sources
              </a>
              .
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4">
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
                description="Add advisory sources to the lindm server, then refresh."
              />
            ) : null}
            {feeds.data?.feeds.map((feed) => {
              const status = sourceStatus(feed, now, !!feeds.error);
              const firstDownload = feeds.error ? undefined : firstDownloadState(feed, now);
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
                  {firstDownload ? (
                    <InitialDownloadNotice
                      state={firstDownload}
                      startedAt={feed.refreshStartedAt}
                    />
                  ) : null}
                  {feed.id.startsWith("demo-authored-critical-") ? (
                    <p className="rounded border border-warning/40 bg-warning/5 p-3">
                      <strong className="block">Authored demo supplement</strong>
                      These findings are fictional and apply only to the two synthetic demo devices.
                      This source does not prove a real vulnerability or a vendor fix.
                    </p>
                  ) : null}
                  {!firstDownload ? (
                    <p>
                      {feed.advisoryCount === 1n
                        ? "1 advisory"
                        : `${feed.advisoryCount.toString()} advisories`}
                    </p>
                  ) : null}
                  <p>
                    Last refreshed: <Timestamp value={feed.checkedAt} missing="Never" />
                  </p>
                  <p>
                    Expires: <Timestamp value={feed.expiresAt} relative={false} />
                  </p>
                  <p
                    data-advisory-source-status=""
                    className={feed.error ? "text-destructive" : "text-muted-foreground"}
                  >
                    {status.sentence}
                  </p>
                  {status.remedy ? <p>{status.remedy}</p> : null}
                  {feed.rejectedRecords.length > 0 ? (
                    <section aria-label="Skipped entries" className="grid gap-3">
                      <p className="font-medium">Skipped entries ({feed.rejectedRecords.length})</p>
                      <ul className="grid gap-3">
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
                    </section>
                  ) : null}
                  <TechnicalDetails
                    items={[
                      { label: "Source ID", value: feed.id },
                      { label: "Server setting", value: "advisories.feeds" },
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
  const firstDownload = firstDownloadState(feed, now);
  if (firstDownload) {
    return {
      tone: "neutral",
      label: firstDownload === "downloading" ? "First download" : "Waiting for first data",
      sentence: "No vulnerability data has been published for this source yet.",
    };
  }
  const skipped = feed.rejectedRecords.length;
  if (feed.fresh && unexpired(feed.expiresAt, now) && skipped > 0) {
    return {
      tone: "warning",
      label: `Up to date, ${skipped} entries skipped`,
      sentence: "lindm could not read some entries. Counts exclude these entries.",
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
      sentence: "lindm has not refreshed this source yet.",
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

// Devices with the advisory: confirmed by a current, complete check, and found
// on devices whose check is incomplete or out of date (their findings stand,
// but the device can't be shown as fully checked).
function AffectedDevices({ affected, unconfirmed }: { affected: bigint; unconfirmed: bigint }) {
  const devices = unconfirmed === 1n ? "1 device" : `${unconfirmed.toString()} devices`;
  return (
    <div className="grid gap-0.5">
      {affected > 0n || unconfirmed === 0n ? (
        <span className="tabular-nums">{affected.toString()}</span>
      ) : null}
      {unconfirmed > 0n ? (
        <span
          data-advisory-unconfirmed={unconfirmed.toString()}
          className="text-xs text-muted-foreground"
        >
          {affected > 0n ? "Also found on" : "Found on"} {devices} not fully checked
        </span>
      ) : null}
    </div>
  );
}
