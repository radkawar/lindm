import { create, toJsonString } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { adminClient, clearCsrfToken } from "@/lib/rpc";
import { synchronizeAuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import {
  ReportFormat,
  ReportKind,
  ReportScheduleSchema,
  ReportSignedManifestSchema,
  type ReportArtifact,
  type ReportSchedule,
} from "../../../gen/lindm/integrations/v1/reports_pb";
import { useIntegrationAction } from "./action";
import { reportArtifactsQueryOptions, reportSchedulesQueryOptions } from "./queries";

const KINDS: Record<ReportKind, string> = {
  [ReportKind.UNSPECIFIED]: "Unknown",
  [ReportKind.INVENTORY]: "Fleet inventory",
  [ReportKind.COMPLIANCE]: "Compliance",
  [ReportKind.FINDINGS]: "Advisory findings",
  [ReportKind.AUDIT]: "Audit log",
};
const FORMATS: Record<ReportFormat, string> = {
  [ReportFormat.UNSPECIFIED]: "unknown",
  [ReportFormat.CSV]: "csv",
  [ReportFormat.JSON]: "json",
  [ReportFormat.JSONL]: "jsonl",
};

export function Reports() {
  const lifetime = useAuthLifetime();
  const [page, setPage] = useState("");
  const list = useQuery(reportSchedulesQueryOptions(lifetime, page));
  return (
    <section
      className="grid min-w-0 gap-4 border-t pt-6"
      aria-label="Scheduled reports"
      aria-busy={list.isFetching}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-semibold">Scheduled reports</h2>
        <Button variant="outline" disabled={list.isFetching} onClick={() => void list.refetch()}>
          Refresh
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">
        Build CSV or JSON reports on a schedule. Each report is kept for its retention period.
      </p>
      <ScheduleEditor />
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading schedules…</span>
          <Skeleton className="h-32 w-full" />
        </div>
      ) : null}
      {list.data?.schedules.length === 0 ? (
        <EmptyState
          title="No scheduled reports yet"
          description="Add a schedule to build reports automatically."
        />
      ) : null}
      {list.data?.schedules.map((schedule) => (
        <ScheduleEditor key={`${schedule.id}:${schedule.revision}`} existing={schedule} />
      ))}
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" disabled={!page} onClick={() => setPage("")}>
          First page
        </Button>
        <Button
          variant="outline"
          disabled={!list.data?.nextAfterId}
          onClick={() => setPage(list.data?.nextAfterId ?? "")}
        >
          Next page
        </Button>
      </div>
      <AuditExport />
      <Artifacts />
    </section>
  );
}

function ScheduleEditor({ existing }: { existing?: ReportSchedule }) {
  const lifetime = useAuthLifetime();
  const action = useIntegrationAction();
  const [name, setName] = useState(existing?.name ?? "");
  const [kind, setKind] = useState(existing?.kind ?? ReportKind.INVENTORY);
  const [format, setFormat] = useState(existing?.format ?? ReportFormat.CSV);
  const [interval, setInterval] = useState(existing?.intervalSeconds ?? 86400);
  const [retention, setRetention] = useState(existing?.retentionDays ?? 30);
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [reason, setReason] = useState("");
  const id = existing?.id ?? "new-report";
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
      if (!existing) {
        setName("");
        setReason("");
      }
      return response;
    });
  }
  return (
    <form onSubmit={save} className="grid min-w-0 gap-4 border bg-card p-4 sm:p-6">
      <h3 className="break-words font-semibold">
        {existing ? `Edit ${existing.name}` : "Add report schedule"}
      </h3>
      {action.feedback}
      <fieldset disabled={action.blocked} className="grid min-w-0 gap-3">
        <Label htmlFor={`${id}-name`}>Name</Label>
        <Input id={`${id}-name`} required value={name} onChange={(e) => setName(e.target.value)} />
        <Label htmlFor={`${id}-kind`}>Report</Label>
        <SelectField
          id={`${id}-kind`}
          className="h-9 min-w-0"
          value={kind}
          onValueChange={(value) => setKind(Number(value) as ReportKind)}
          options={[ReportKind.INVENTORY, ReportKind.COMPLIANCE, ReportKind.FINDINGS].map(
            (value) => ({
              value,
              label: KINDS[value],
            }),
          )}
        />
        <Label htmlFor={`${id}-format`}>Format</Label>
        <SelectField
          id={`${id}-format`}
          className="h-9 min-w-0"
          value={format}
          onValueChange={(value) => setFormat(Number(value) as ReportFormat)}
          options={[
            { value: ReportFormat.CSV, label: "CSV" },
            { value: ReportFormat.JSON, label: "JSON" },
          ]}
        />
        <Label htmlFor={`${id}-interval`}>Run every (seconds)</Label>
        <Input
          id={`${id}-interval`}
          required
          type="number"
          value={interval}
          onChange={(e) => setInterval(Number(e.target.value))}
        />
        <Label htmlFor={`${id}-retention`}>Keep reports for (days)</Label>
        <Input
          id={`${id}-retention`}
          required
          type="number"
          value={retention}
          onChange={(e) => setRetention(Number(e.target.value))}
        />
        <label className="flex gap-2">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Run on schedule
        </label>
        <Label htmlFor={`${id}-reason`}>Reason</Label>
        <Input
          id={`${id}-reason`}
          required
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        {existing ? (
          <p className="text-xs">
            Revision {existing.revision.toString()} · next run{" "}
            {formatTimestamp(existing.nextRunAt).local}
          </p>
        ) : null}
        <Button type="submit" className="w-fit">
          {existing ? "Save schedule" : "Create schedule"}
        </Button>
      </fieldset>
    </form>
  );
}

function AuditExport() {
  const lifetime = useAuthLifetime();
  const action = useIntegrationAction();
  const [sequence, setSequence] = useState("0");
  const [hash, setHash] = useState("0".repeat(64));
  const [maxEvents, setMaxEvents] = useState(10000);
  const [retention, setRetention] = useState(30);
  const [reason, setReason] = useState("");
  const [inputError, setInputError] = useState("");
  function queue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setInputError("");
    if (!/^[0-9a-fA-F]{64}$/.test(hash) || !/^\d+$/.test(sequence)) {
      setInputError("Enter the last export's sequence number and its 64-character SHA-256 hash.");
      return;
    }
    const afterHash = Uint8Array.from({ length: 32 }, (_, index) =>
      Number.parseInt(hash.slice(index * 2, index * 2 + 2), 16),
    );
    const request = {
      requestId: crypto.randomUUID(),
      afterSequence: BigInt(sequence),
      afterHash,
      maxEvents,
      retentionDays: retention,
      reason,
    };
    action.perform(() => adminClient.createAuditExport(request, { signal: lifetime.signal }));
  }
  return (
    <form onSubmit={queue} className="grid min-w-0 gap-4 border bg-card p-4 sm:p-6">
      <h3 className="text-lg font-semibold">Export audit log</h3>
      <p className="text-sm">
        Continue from your last export. For the first export, use sequence 0 and a hash of 64 zeros.
      </p>
      {action.feedback}
      {inputError ? (
        <Alert variant="destructive">
          <AlertTitle>Check the export details</AlertTitle>
          <AlertDescription>{inputError}</AlertDescription>
        </Alert>
      ) : null}
      <fieldset disabled={action.blocked} className="grid min-w-0 gap-3">
        <Label htmlFor="audit-sequence">Last export sequence number</Label>
        <Input
          id="audit-sequence"
          required
          inputMode="numeric"
          value={sequence}
          onChange={(e) => setSequence(e.target.value)}
        />
        <Label htmlFor="audit-hash">Last export SHA-256 hash</Label>
        <Input id="audit-hash" required value={hash} onChange={(e) => setHash(e.target.value)} />
        <Label htmlFor="audit-events">Maximum events</Label>
        <Input
          id="audit-events"
          required
          type="number"
          value={maxEvents}
          onChange={(e) => setMaxEvents(Number(e.target.value))}
        />
        <Label htmlFor="audit-retention">Keep export for (days)</Label>
        <Input
          id="audit-retention"
          required
          type="number"
          value={retention}
          onChange={(e) => setRetention(Number(e.target.value))}
        />
        <Label htmlFor="audit-export-reason">Reason</Label>
        <Input
          id="audit-export-reason"
          required
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <Button type="submit">Start export</Button>
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
  const client = useQueryClient();
  const navigate = useNavigate();
  const [page, setPage] = useState("");
  const list = useQuery(reportArtifactsQueryOptions(lifetime, page));
  const [downloading, setDownloading] = useState("");
  const [error, setError] = useState<RpcFailure | null>(null);
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
      className="grid min-w-0 gap-4 border-t pt-6"
      aria-label="Report artifacts"
      aria-busy={list.isFetching}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-lg font-semibold">Reports</h3>
        <Button variant="outline" disabled={list.isFetching} onClick={() => void list.refetch()}>
          Refresh reports
        </Button>
      </div>
      {error ? <RpcError failure={error} /> : null}
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading reports…</span>
          <Skeleton className="h-32 w-full" />
        </div>
      ) : null}
      {list.data?.artifacts.length === 0 ? (
        <EmptyState
          title="No reports yet"
          description="Reports appear here after a scheduled run or an audit export."
        />
      ) : null}
      {list.data?.artifacts.map((artifact) => (
        <article key={artifact.id} className="grid min-w-0 gap-3 border bg-card p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h4 className="font-semibold">
              {KINDS[artifact.kind]} · {FORMATS[artifact.format]}
            </h4>
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
          </div>
          <TechnicalDetails items={[{ label: "Report ID", value: artifact.id }]} />
          <p className="text-sm">
            {artifact.rowCount.toString()} rows · {artifact.byteCount.toString()} bytes · expires{" "}
            {formatTimestamp(artifact.expiresAt).local}
          </p>
          {artifact.failureReason ? (
            <p role="alert" className="break-words text-sm text-destructive">
              {artifact.failureReason}
            </p>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              disabled={artifact.state !== "published" || !!downloading}
              onClick={() => void download(artifact)}
            >
              {downloading === artifact.id ? "Downloading…" : "Download"}
            </Button>
            <Button
              variant="outline"
              disabled={!artifact.signedManifest}
              onClick={() => {
                if (!artifact.signedManifest) return;
                saveBlob(
                  new Blob([toJsonString(ReportSignedManifestSchema, artifact.signedManifest)], {
                    type: "application/json",
                  }),
                  `${artifact.id}.manifest.json`,
                );
              }}
            >
              Download signature
            </Button>
          </div>
        </article>
      ))}
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" disabled={!page} onClick={() => setPage("")}>
          First page
        </Button>
        <Button
          variant="outline"
          disabled={!list.data?.nextAfterId}
          onClick={() => setPage(list.data?.nextAfterId ?? "")}
        >
          Next page
        </Button>
      </div>
    </section>
  );
}
