// SPDX-License-Identifier: Apache-2.0

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Fragment, useDeferredValue, useMemo, useState } from "react";
import {
  AdvisoryFindingState,
  DeviceFindingSort,
  type AdvisoryFinding,
} from "../../../gen/lindm/admin/v1/advisories_pb";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { canPermission } from "@/lib/permissions";
import { formatTimestamp } from "@/lib/time";
import { deviceQueryOptions } from "@/features/devices/queries";
import { AcceptanceForm } from "./acceptance-form";
import {
  AdvisoryPaging,
  advisoryReasonText,
  findingStateLabel,
  Severity,
  unexpired,
  useFreshnessClock,
} from "./display";
import { deviceFindingsQueryOptions } from "./queries";
import { UncoveredPackages } from "./uncovered-packages";
import { firstDownloadState } from "./initial-download";
import { InitialDownloadNotice } from "./initial-download-notice";

// Debian/RPM epoch 0 is the implicit default; showing "0:" only adds noise.
function packageVersion(version: string) {
  return version.startsWith("0:") ? version.slice(2) : version;
}
export function DeviceFindings({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const device = useQuery(deviceQueryOptions(lifetime, deviceId));
  const [pageToken, setPageToken] = useState("");
  const [accepting, setAccepting] = useState<AdvisoryFinding | null>(null);
  const [sort, setSort] = useState(DeviceFindingSort.SEVERITY);
  const [packageText, setPackageText] = useState("");
  const [advisoryText, setAdvisoryText] = useState("");
  const packagePrefix = useDeferredValue(packageText.trim());
  const advisoryPrefix = useDeferredValue(advisoryText.trim());
  const now = useFreshnessClock();
  const findings = useQuery({
    ...deviceFindingsQueryOptions(lifetime, deviceId, pageToken, {
      sort,
      packagePrefix,
      advisoryPrefix,
    }),
    placeholderData: keepPreviousData,
  });
  const totals = findings.error ? undefined : findings.data?.totals;
  const filtered = packagePrefix !== "" || advisoryPrefix !== "";
  const freshness = findings.data?.freshness;
  const firstDownload =
    findings.error || !freshness?.feedId ? undefined : firstDownloadState(freshness, now);
  const awaitingEvaluation = !findings.error && freshness?.reason === "evaluation_pending";
  const cveDetails = useMemo(() => {
    const items: { label: string; value: string }[] = [];
    for (const finding of findings.data?.findings ?? []) {
      if (finding.cves.length > 3) {
        items.push({
          label: `${finding.advisoryId} CVEs`,
          value: finding.cves.join(", "),
        });
      }
    }
    return items;
  }, [findings.data?.findings]);
  const current =
    !findings.error &&
    freshness !== undefined &&
    unexpired(freshness.inventoryExpiresAt, now) &&
    unexpired(freshness.feedExpiresAt, now);
  const state = current
    ? !filtered &&
      freshness.state !== AdvisoryFindingState.PARTIAL &&
      totals?.open === 0n &&
      totals.accepted > 0n
      ? "Accepted"
      : findingStateLabel(freshness.state)
    : "Unknown";
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
        <div className="flex flex-wrap items-center justify-between gap-2">
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
          <Button
            variant="outline"
            disabled={findings.isFetching}
            onClick={() => void findings.refetch()}
          >
            {findings.isFetching ? "Refreshing…" : "Refresh"}
          </Button>
          {device.data?.callerPermissions.includes("inventory.manage") ? (
            <Link
              to="/devices/$deviceId"
              params={{ deviceId }}
              search={{ tab: "findings", action: "refreshInventory" }}
              className="text-sm underline underline-offset-4"
            >
              Request fresh inventory
            </Link>
          ) : null}
        </div>
        {firstDownload ? (
          <div className="border bg-muted/30 p-3">
            <InitialDownloadNotice state={firstDownload} startedAt={freshness?.refreshStartedAt} />
          </div>
        ) : null}
        {canPermission(principal, "profiles.manage") ? (
          <p className="text-sm text-muted-foreground">
            <Link
              to="/profiles/new"
              className="font-medium text-foreground underline underline-offset-4"
            >
              Schedule updates
            </Link>
            : choose OS update policy, set a maintenance window, then roll out the profile to the
            affected devices.
          </p>
        ) : null}
        {totals &&
        !((firstDownload || awaitingEvaluation) && findings.data?.findings.length === 0) ? (
          <p className="text-sm" data-finding-totals>
            <strong className="font-semibold tabular-nums">
              {totals.open.toLocaleString()} open {totals.open === 1n ? "finding" : "findings"}
            </strong>
            {filtered ? " matching the search" : ""}
            {" · "}
            {[
              `${totals.critical.toLocaleString()} critical`,
              `${totals.high.toLocaleString()} high`,
              `${totals.medium.toLocaleString()} medium`,
              `${totals.low.toLocaleString()} low`,
              `${totals.unrated.toLocaleString()} not rated by the vendor`,
            ].join(" · ")}
            {totals.accepted > 0n
              ? ` · ${totals.accepted.toLocaleString()} accepted ${totals.accepted === 1n ? "risk" : "risks"}`
              : ""}
          </p>
        ) : null}
        <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_12rem] sm:items-end">
          <div className="grid gap-1.5">
            <Label htmlFor={`finding-package-${deviceId}`}>Search packages</Label>
            <Input
              id={`finding-package-${deviceId}`}
              type="search"
              data-freeform="package name prefix search"
              placeholder="Package name starts with…"
              value={packageText}
              onChange={(event) => {
                setPackageText(event.target.value);
                setPageToken("");
              }}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor={`finding-advisory-${deviceId}`}>Search advisories and CVEs</Label>
            <Input
              id={`finding-advisory-${deviceId}`}
              type="search"
              data-freeform="advisory or CVE ID prefix search"
              placeholder="e.g. USN-6859 or CVE-2024"
              value={advisoryText}
              onChange={(event) => {
                setAdvisoryText(event.target.value);
                setPageToken("");
              }}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor={`finding-sort-${deviceId}`}>Sort by</Label>
            <SelectField
              id={`finding-sort-${deviceId}`}
              value={String(sort)}
              onValueChange={(value) => {
                setSort(Number(value) as DeviceFindingSort);
                setPageToken("");
              }}
              options={[
                { value: String(DeviceFindingSort.SEVERITY), label: "Severity" },
                { value: String(DeviceFindingSort.PUBLISHED), label: "Newest advisory" },
                { value: String(DeviceFindingSort.PACKAGE), label: "Package name" },
              ]}
            />
          </div>
        </div>
        {!current && !firstDownload ? (
          <p className="border bg-muted/30 p-3 text-sm">
            {freshness?.reason
              ? `This device's exposure remains unknown: ${advisoryReasonText(freshness.reason)}.`
              : "This device's exposure remains unknown. The device inventory or advisory sources are not current."}
          </p>
        ) : null}
        {partial ? (
          <div className="grid gap-4 border bg-muted/30 p-3 text-sm">
            <p className="font-medium">Partly checked: {advisoryReasonText(freshness.reason)}.</p>
            <p>
              Covered distribution packages were checked. Exposure remains unknown for{" "}
              {freshness.uncoveredPackages.toString()} installed packages. Review their causes
              below; this is not a complete assessment of this device.
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
                ...cveDetails,
              ]}
            />
          </>
        ) : null}
        {!freshness && cveDetails.length ? <TechnicalDetails items={cveDetails} /> : null}
        {findings.data?.findings.length === 0 && !firstDownload ? (
          <EmptyState
            title={awaitingEvaluation ? "Findings not ready" : "No findings on this page"}
            description={
              awaitingEvaluation
                ? "Findings will appear after lindm checks the device inventory against vulnerability data. Exposure remains unknown until that check finishes."
                : "Outdated inventory or advisory sources leave this device's exposure unknown."
            }
          />
        ) : null}
        {findings.data?.findings.length ? (
          <Table className="max-sm:block max-sm:[&_tbody]:block max-sm:[&_tr]:block max-sm:[&_td]:block max-sm:[&_td]:whitespace-normal">
            <TableCaption className="sr-only">Security findings on this device</TableCaption>
            <TableHeader className="max-sm:sr-only">
              <TableRow>
                <TableHead>Advisory</TableHead>
                <TableHead>Package</TableHead>
                <TableHead>Installed → fixed</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>State</TableHead>
                <TableHead>
                  <span className="sr-only">Risk</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.data.findings.map((finding) => {
                const accepted =
                  finding.state === AdvisoryFindingState.ACCEPTED &&
                  unexpired(finding.exception?.expiresAt, now);
                const label =
                  finding.reason === "source_record_rejected"
                    ? "Vendor document unusable"
                    : !current || freshness?.state === AdvisoryFindingState.UNKNOWN
                      ? "Unknown"
                      : finding.state === AdvisoryFindingState.ACCEPTED && !accepted
                        ? "Affected (acceptance expired)"
                        : findingStateLabel(finding.state);
                const canAccept =
                  finding.reason !== "source_record_rejected" &&
                  canPermission(principal, "advisory_exceptions.manage");
                return (
                  <Fragment key={finding.id}>
                    <TableRow data-finding-row className="align-top max-sm:py-3">
                      <TableCell className="whitespace-normal">
                        {finding.sourceUrl ? (
                          <a
                            href={finding.sourceUrl}
                            data-console-link="vendor-advisory"
                            target="_blank"
                            rel="noreferrer"
                            className="font-medium underline underline-offset-4"
                          >
                            {finding.advisoryId}
                          </a>
                        ) : (
                          <span className="font-medium">{finding.advisoryId}</span>
                        )}
                        {finding.cves.length ? (
                          <code className="block text-xs text-muted-foreground [overflow-wrap:anywhere]">
                            {finding.cves[0]}
                            {finding.cves.length > 1 ? `, ${finding.cves[1]}` : null}
                            {finding.cves.length > 2 ? `, ${finding.cves[2]}` : null}
                          </code>
                        ) : null}
                        {finding.cves.length > 3 ? (
                          <span className="block text-xs text-muted-foreground">
                            {finding.cves.length - 3} more in Details.
                          </span>
                        ) : null}
                        <span className="block text-xs text-muted-foreground">
                          Published {formatTimestamp(finding.publishedAt).local}
                        </span>
                      </TableCell>
                      <TableCell className="whitespace-normal [overflow-wrap:anywhere]">
                        <span className="text-xs text-muted-foreground sm:hidden">Package: </span>
                        {finding.packageName}
                        {finding.architecture ? (
                          <span className="text-muted-foreground"> · {finding.architecture}</span>
                        ) : null}
                      </TableCell>
                      <TableCell className="whitespace-normal font-mono text-xs [overflow-wrap:anywhere]">
                        <span className="font-sans text-xs text-muted-foreground sm:hidden">
                          Installed → fixed:{" "}
                        </span>
                        {packageVersion(finding.installedVersion) || "Unknown"} →{" "}
                        {packageVersion(finding.fixedVersion) || "no fix yet"}
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground sm:hidden">Severity: </span>
                        <Severity value={finding.severity} badge={false} />
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground sm:hidden">State: </span>
                        <StatusBadge
                          className="h-auto whitespace-normal"
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
                      </TableCell>
                      <TableCell>
                        <div className="grid gap-2">
                          {label.startsWith("Affected") &&
                          device.data?.callerPermissions.includes("remote_execution.run") ? (
                            <Link
                              to="/devices/$deviceId"
                              params={{ deviceId }}
                              search={{ tab: "findings", action: "patchNow" }}
                              className="text-sm font-medium underline underline-offset-4"
                            >
                              Patch now
                            </Link>
                          ) : null}
                          {canAccept ? (
                            <Button
                              size="sm"
                              variant="outline"
                              aria-haspopup="dialog"
                              onClick={() => setAccepting(finding)}
                            >
                              {finding.exception ? "Renew acceptance" : "Accept this risk"}
                            </Button>
                          ) : null}
                        </div>
                      </TableCell>
                    </TableRow>
                    {finding.exception ? (
                      <TableRow>
                        <TableCell colSpan={6} className="whitespace-normal pt-0 text-sm">
                          <p className="text-muted-foreground">
                            Risk accepted by{" "}
                            {!finding.exception.actorId.trim()
                              ? "the system"
                              : finding.exception.actorId === principal.id
                                ? "you"
                                : "another administrator"}{" "}
                            until {formatTimestamp(finding.exception.expiresAt).local}:{" "}
                            <span className="whitespace-pre-wrap break-words">
                              {finding.exception.reason}
                            </span>
                          </p>
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </Fragment>
                );
              })}
            </TableBody>
          </Table>
        ) : null}
        <Dialog
          open={accepting !== null}
          onOpenChange={(open) => {
            if (!open) setAccepting(null);
          }}
        >
          {accepting ? (
            <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
              <DialogHeader>
                <DialogTitle>Accept risk: {accepting.advisoryId}</DialogTitle>
                <DialogDescription>
                  {accepting.packageName} {packageVersion(accepting.installedVersion)} on{" "}
                  {device.data?.device?.hostname || "this device"}. Severity:{" "}
                  <Severity value={accepting.severity} badge={false} />.
                </DialogDescription>
              </DialogHeader>
              <AcceptanceForm
                key={`${lifetime.generation}/${accepting.id}`}
                deviceId={deviceId}
                findingId={accepting.id}
              />
            </DialogContent>
          ) : null}
        </Dialog>
        {pageToken || findings.data?.nextPageToken ? (
          <AdvisoryPaging
            token={pageToken}
            next={findings.data?.nextPageToken ?? ""}
            busy={findings.isFetching}
            onPage={setPageToken}
          />
        ) : null}
      </CardContent>
    </Card>
  );
}
