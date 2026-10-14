// SPDX-License-Identifier: Apache-2.0

import { create, toJsonString } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useLocation, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ListPagination } from "@/components/ui/list-pagination";
import { SelectField } from "@/components/ui/select-field";
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
import { adminClient, clearCsrfToken } from "@/lib/rpc";
import { synchronizeAuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { formatBytes } from "@/lib/bytes";
import {
  ReportFormat,
  ReportKind,
  ReportScheduleSchema,
  ReportSignedManifestSchema,
  type ReportArtifact,
  type ReportSchedule,
} from "../../../gen/lindm/integrations/v1/reports_pb";
import { useIntegrationAction, type IntegrationAction } from "./action";
import { reportArtifactsQueryOptions, reportSchedulesQueryOptions } from "./queries";

const KINDS: Record<ReportKind, string> = {
  [ReportKind.UNSPECIFIED]: "Unknown",
  [ReportKind.INVENTORY]: "Fleet inventory",
  [ReportKind.COMPLIANCE]: "Compliance",
  [ReportKind.FINDINGS]: "Advisory findings",
  [ReportKind.AUDIT]: "Audit log",
  [ReportKind.AUDIT_SELECTION]: "Filtered audit evidence",
};
const FORMATS: Record<ReportFormat, string> = {
  [ReportFormat.UNSPECIFIED]: "unknown",
  [ReportFormat.CSV]: "csv",
  [ReportFormat.JSON]: "json",
  [ReportFormat.JSONL]: "jsonl",
};
const FORMAT_LABELS: Record<ReportFormat, string> = {
  [ReportFormat.UNSPECIFIED]: "Unknown",
  [ReportFormat.CSV]: "CSV",
  [ReportFormat.JSON]: "JSON",
  [ReportFormat.JSONL]: "JSON Lines",
};

const HOUR = 3600;
const DAY = 24 * HOUR;
// ReportSchedule.interval_seconds allows 300 to 31536000.
const INTERVALS = [HOUR, 6 * HOUR, 12 * HOUR, DAY, 7 * DAY, 30 * DAY];

function intervalLabel(seconds: number): string {
  if (seconds % DAY === 0) {
    const days = seconds / DAY;
    return days === 1 ? "Daily" : days === 7 ? "Weekly" : `Every ${days} days`;
  }
  if (seconds % HOUR === 0) {
    const hours = seconds / HOUR;
    return hours === 1 ? "Hourly" : `Every ${hours} hours`;
  }
  const minutes = Math.round(seconds / 60);
  return `Every ${minutes} minutes`;
}

export function Reports() {
  const lifetime = useAuthLifetime();
  const [page, setPage] = useState("");
  const [adding, setAdding] = useState(false);
  const addAction = useIntegrationAction();
  const list = useQuery(reportSchedulesQueryOptions(lifetime, page));
  return (
    <section
      className="grid min-w-0 gap-4 border-t pt-6"
      aria-label="Scheduled reports"
      aria-busy={list.isFetching}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="grid gap-1">
          <h2 className="text-base font-semibold">Scheduled reports</h2>
          <p className="text-sm text-muted-foreground">
            The server builds reports on schedule. It keeps each report for its retention period.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => setAdding(true)}>
            {addAction.blocked ? "Review pending schedule" : "Add schedule"}
          </Button>
        </div>
      </div>
      <Dialog open={adding} onOpenChange={setAdding}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Add report schedule</DialogTitle>
            <DialogDescription>
              The server queues the first report when you create an enabled schedule.
            </DialogDescription>
          </DialogHeader>
          <ScheduleForm action={addAction} onDone={() => setAdding(false)} />
        </DialogContent>
      </Dialog>
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading schedules…</span>
          <Skeleton className="h-16 w-full" />
        </div>
      ) : null}
      {list.data?.schedules.length === 0 ? (
        <EmptyState
          title={page ? "No more schedules" : "No scheduled reports yet"}
          description={
            page
              ? "Return to the first page."
              : "No schedules create reports. Add a schedule for inventory, compliance or advisory findings."
          }
          action={
            page ? (
              <Button variant="outline" onClick={() => setPage("")}>
                First page
              </Button>
            ) : (
              <Button variant="outline" onClick={() => setAdding(true)}>
                Add schedule
              </Button>
            )
          }
        />
      ) : null}
      {list.data && list.data.schedules.length > 0 ? (
        <Table aria-label="Report schedules">
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Report</TableHead>
              <TableHead>Runs</TableHead>
              <TableHead>Kept for</TableHead>
              <TableHead>Next run</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.schedules.map((schedule) => (
              <ScheduleRow key={`${schedule.id}:${schedule.revision}`} schedule={schedule} />
            ))}
          </TableBody>
        </Table>
      ) : null}
      <ListPagination
        label="Schedule pages"
        previousLabel="First page"
        onPrevious={page ? () => setPage("") : undefined}
        onNext={list.data?.nextAfterId ? () => setPage(list.data?.nextAfterId ?? "") : undefined}
        busy={list.isFetching}
      />
      <Artifacts />
    </section>
  );
}

function ScheduleRow({ schedule }: { schedule: ReportSchedule }) {
  const action = useIntegrationAction();
  const [open, setOpen] = useState(false);
  const name = schedule.name.trim() || "Unnamed schedule";
  return (
    <TableRow className="align-top">
      <TableCell className="min-w-40 whitespace-normal break-words font-medium">{name}</TableCell>
      <TableCell>
        {KINDS[schedule.kind]} · {FORMAT_LABELS[schedule.format]}
      </TableCell>
      <TableCell>
        {schedule.enabled ? (
          intervalLabel(schedule.intervalSeconds)
        ) : (
          <StatusBadge status="neutral">Paused</StatusBadge>
        )}
      </TableCell>
      <TableCell className="tabular-nums">
        {schedule.retentionDays === 1 ? "1 day" : `${schedule.retentionDays} days`}
      </TableCell>
      <TableCell className="whitespace-nowrap">
        {schedule.enabled ? <Timestamp value={schedule.nextRunAt} /> : "Not scheduled"}
      </TableCell>
      <TableCell className="text-right">
        <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
          {action.blocked ? "Review pending change" : "Edit"}
        </Button>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogContent className="max-h-[90vh] overflow-y-auto text-left sm:max-w-lg">
            <DialogHeader>
              <DialogTitle className="break-words">Edit {name}</DialogTitle>
              <DialogDescription>
                Saving an enabled schedule queues a report. The server then follows the chosen
                interval. Existing reports keep their expiry.
              </DialogDescription>
            </DialogHeader>
            <ScheduleForm existing={schedule} action={action} onDone={() => setOpen(false)} />
          </DialogContent>
        </Dialog>
      </TableCell>
    </TableRow>
  );
}

function ScheduleForm({
  existing,
  action,
  onDone,
}: {
  existing?: ReportSchedule;
  action: IntegrationAction;
  onDone: () => void;
}) {
  const lifetime = useAuthLifetime();
  const [name, setName] = useState(existing?.name ?? "");
  const [kind, setKind] = useState(existing?.kind ?? ReportKind.INVENTORY);
  const [format, setFormat] = useState(existing?.format ?? ReportFormat.CSV);
  const [interval, setInterval] = useState(existing?.intervalSeconds ?? DAY);
  const [retention, setRetention] = useState(existing?.retentionDays ?? 30);
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [reason, setReason] = useState("");
  const id = existing?.id ?? "new-report";
  const intervals = INTERVALS.includes(interval) ? INTERVALS : [interval, ...INTERVALS];
  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const schedule = create(ReportScheduleSchema, {
      id: existing?.id ?? crypto.randomUUID(),
      name,
      kind,
      format,
      intervalSeconds: interval,
      retentionDays: retention,
      enabled,
      revision: existing?.revision ?? 0n,
    });
    const request = { requestId: crypto.randomUUID(), schedule, reason };
    action.perform(async () => {
      const response = await adminClient.upsertReportSchedule(request, { signal: lifetime.signal });
      lifetime.signal.throwIfAborted();
      onDone();
      return response;
    });
  }
  return (
    <form onSubmit={save} className="grid min-w-0 gap-4">
      {action.feedback}
      <fieldset disabled={action.blocked} className="grid min-w-0 gap-3">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-name`}>Name</Label>
          <Input
            id={`${id}-name`}
            data-freeform="new schedule name"
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor={`${id}-kind`}>Report</Label>
            <SelectField
              id={`${id}-kind`}
              className="h-9 min-w-0"
              value={kind}
              onValueChange={(value) => setKind(Number(value) as ReportKind)}
              options={[ReportKind.INVENTORY, ReportKind.COMPLIANCE, ReportKind.FINDINGS].map(
                (value) => ({ value, label: KINDS[value] }),
              )}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor={`${id}-format`}>Format</Label>
            <SelectField
              id={`${id}-format`}
              className="h-9 min-w-0"
              value={format}
              onValueChange={(value) => setFormat(Number(value) as ReportFormat)}
              options={[ReportFormat.CSV, ReportFormat.JSON].map((value) => ({
                value,
                label: FORMAT_LABELS[value],
              }))}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor={`${id}-interval`}>How often</Label>
            <SelectField
              id={`${id}-interval`}
              className="h-9 min-w-0"
              value={interval}
              onValueChange={(value) => setInterval(Number(value))}
              options={intervals.map((value) => ({ value, label: intervalLabel(value) }))}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor={`${id}-retention`}>Keep reports for (days, 1 to 3650)</Label>
            <Input
              id={`${id}-retention`}
              data-freeform="numeric retention period"
              required
              type="number"
              inputMode="numeric"
              min={1}
              max={3650}
              step={1}
              value={retention}
              onChange={(e) => setRetention(Number(e.target.value))}
            />
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Run on schedule
        </label>
        {existing ? (
          <TechnicalDetails
            items={[
              { label: "Schedule ID", value: existing.id },
              { label: "Revision", value: existing.revision.toString() },
            ]}
          />
        ) : null}
        <div className="grid gap-2">
          <Label htmlFor={`${id}-reason`}>Reason (audited)</Label>
          <Input
            id={`${id}-reason`}
            data-freeform="audit reason"
            required
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </div>
        <Button type="submit" className="w-fit">
          {existing ? "Save schedule" : "Create schedule"}
        </Button>
      </fieldset>
    </form>
  );
}

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function Artifacts() {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const client = useQueryClient();
  const navigate = useNavigate();
  const [page, setPage] = useState("");
  const list = useQuery(reportArtifactsQueryOptions(lifetime, page));
  const [downloading, setDownloading] = useState("");
  const [error, setError] = useState<RpcFailure | null>(null);
  // The audit export links to /integrations#report-<id>. The row renders only
  // after the list loads, so scroll to and focus it then; an export beyond this
  // page falls back to the Reports heading.
  const hash = useLocation({ select: (location) => location.hash.replace(/^#/, "") });
  const focusedHash = useRef("");
  useEffect(() => {
    if (!hash.startsWith("report-") || !list.data || focusedHash.current === hash) return;
    const target = document.getElementById(hash) ?? document.getElementById("reports-heading");
    if (!target) return;
    focusedHash.current = hash;
    target.scrollIntoView({ block: "center" });
    target.focus({ preventScroll: true });
  }, [hash, list.data]);
  async function download(artifact: ReportArtifact) {
    if (downloading || lifetime.signal.aborted) return;
    setDownloading(artifact.id);
    setError(null);
    try {
      const parts: ArrayBuffer[] = [];
      let total = 0;
      let finished = false;
      for (let index = 0; index < 128; index++) {
        const response = await adminClient.downloadReportArtifact(
          { artifactId: artifact.id, chunkIndex: index },
          { signal: lifetime.signal },
        );
        lifetime.signal.throwIfAborted();
        total += response.data.length;
        if (total > 32 * 1024 * 1024) throw new Error("This report is too large to download here.");
        parts.push(Uint8Array.from(response.data).buffer);
        if (response.finished) {
          finished = true;
          break;
        }
        if (response.nextChunkIndex !== index + 1)
          throw new Error("The report changed while downloading. Try again.");
      }
      if (!finished || BigInt(total) !== artifact.byteCount)
        throw new Error("The download didn't finish. Try again.");
      saveBlob(
        new Blob(parts, {
          type:
            artifact.format === ReportFormat.CSV ? "text/csv;charset=utf-8" : "application/json",
        }),
        `${artifact.id}.${FORMATS[artifact.format]}`,
      );
    } catch (failure) {
      if (!lifetime.signal.aborted) {
        const next = toRpcFailure(failure);
        if (next.unauthenticated) {
          synchronizeAuthLifetime(null);
          clearCsrfToken();
          client.clear();
          await navigate({ to: "/" });
          return;
        }
        setError(next);
      }
    } finally {
      if (!lifetime.signal.aborted) setDownloading("");
    }
  }
  return (
    <section
      className="grid min-w-0 gap-4 pt-2"
      aria-label="Report artifacts"
      aria-busy={list.isFetching}
    >
      <h3 id="reports-heading" tabIndex={-1} className="text-base font-semibold outline-none">
        Reports
      </h3>
      <p className="-mt-2 text-sm text-muted-foreground">
        {canPermission(principal, "audit.read", true) ? (
          <>
            To export evidence, filter the{" "}
            <Link to="/audit" className="text-foreground underline underline-offset-4">
              audit log
            </Link>
            . Select Export filtered evidence.
          </>
        ) : (
          "Scheduled runs and audit evidence exports. Exporting evidence also requires unrestricted audit access."
        )}
      </p>
      {error ? <RpcError failure={error} title="Report not downloaded" /> : null}
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading reports…</span>
          <Skeleton className="h-16 w-full" />
        </div>
      ) : null}
      {list.data?.artifacts.length === 0 ? (
        <EmptyState
          title={page ? "No more reports" : "No reports yet"}
          description={
            page
              ? "Return to the first page."
              : "Reports appear here after a scheduled run or an audit export."
          }
          action={
            page ? (
              <Button variant="outline" onClick={() => setPage("")}>
                First page
              </Button>
            ) : undefined
          }
        />
      ) : null}
      {list.data && list.data.artifacts.length > 0 ? (
        <Table aria-label="Reports">
          <TableHeader>
            <TableRow>
              <TableHead>Report</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Expires</TableHead>
              <TableHead>
                <span className="sr-only">Downloads</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.artifacts.map((artifact) => (
              <TableRow
                id={`report-${artifact.id}`}
                key={artifact.id}
                tabIndex={-1}
                className="align-top target:bg-muted/50 focus:bg-muted/50 focus:outline-2 focus:-outline-offset-2 focus:outline-ring"
              >
                <TableCell className="min-w-40 whitespace-normal">
                  {KINDS[artifact.kind]} · {FORMAT_LABELS[artifact.format]}
                  {artifact.state === "published" ? (
                    <p className="text-xs text-muted-foreground tabular-nums">
                      {artifact.rowCount.toString()} rows · {formatBytes(artifact.byteCount)}
                    </p>
                  ) : null}
                  <TechnicalDetails
                    items={[
                      { label: "Report ID", value: artifact.id },
                      { label: "Schedule ID", value: artifact.scheduleId },
                      { label: "Failure reason", value: artifact.failureReason },
                    ]}
                  />
                </TableCell>
                <TableCell className="min-w-32 max-w-sm whitespace-normal">
                  <StatusBadge
                    status={
                      artifact.state === "failed" || artifact.failureReason
                        ? "destructive"
                        : artifact.state === "published"
                          ? "success"
                          : artifact.state === "building"
                            ? "info"
                            : "neutral"
                    }
                  >
                    {artifact.state
                      ? artifact.state.charAt(0).toUpperCase() +
                        artifact.state.slice(1).replaceAll("_", " ")
                      : "Unknown"}
                  </StatusBadge>
                  {artifact.state === "queued" || artifact.state === "building" ? (
                    <p className="mt-1 text-xs text-muted-foreground">
                      Preparing report. Select Refresh to check for the download.
                    </p>
                  ) : null}
                  {artifact.failureReason ? (
                    <p role="alert" className="mt-1 break-words text-xs text-destructive">
                      {artifact.kind === ReportKind.AUDIT_SELECTION
                        ? artifact.failureReason === "report_limit_exceeded"
                          ? "The export exceeds the event or evidence limit. Narrow the audit filters or time range. Start another export. No partial evidence is available."
                          : "The export failed. Review Details before trying again."
                        : "This report failed. No partial data is available. Review the failure reason in Details."}
                    </p>
                  ) : null}
                </TableCell>
                <TableCell>
                  <Timestamp value={artifact.createdAt} />
                </TableCell>
                <TableCell>
                  {artifact.state === "published" ? <Timestamp value={artifact.expiresAt} /> : null}
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap justify-end gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={artifact.state !== "published" || !!downloading}
                      onClick={() => void download(artifact)}
                    >
                      {downloading === artifact.id ? "Downloading…" : "Download"}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={!artifact.signedManifest}
                      onClick={() => {
                        if (!artifact.signedManifest) return;
                        saveBlob(
                          new Blob(
                            [toJsonString(ReportSignedManifestSchema, artifact.signedManifest)],
                            { type: "application/json" },
                          ),
                          `${artifact.id}.manifest.json`,
                        );
                      }}
                    >
                      Download signature
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : null}
      <ListPagination
        label="Report pages"
        previousLabel="First page"
        onPrevious={page ? () => setPage("") : undefined}
        onNext={list.data?.nextAfterId ? () => setPage(list.data?.nextAfterId ?? "") : undefined}
        busy={list.isFetching}
      />
    </section>
  );
}
