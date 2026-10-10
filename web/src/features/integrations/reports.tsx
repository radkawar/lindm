import { create, toJsonString } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
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
  [ReportKind.AUDIT]: "Audit chain",
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
        Workers publish bounded durable CSV or JSON snapshots.
      </p>
      <details className="text-xs text-muted-foreground">
        <summary className="w-fit cursor-pointer py-1">Report retention</summary>
        <p className="mt-2">
          Downloads expire at the configured retention boundary; disabling a schedule stops future
          runs, not retention of existing artifacts.
        </p>
      </details>
      <ScheduleEditor />
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading report schedules…</span>
          <Skeleton className="h-32 w-full" />
        </div>
      ) : null}
      {list.data?.schedules.length === 0 ? (
        <EmptyState
          title="No report schedules on this page"
          description="Add a schedule to generate recurring reports."
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
        <Label htmlFor={`${id}-interval`}>Interval (seconds)</Label>
        <Input
          id={`${id}-interval`}
          required
          type="number"
          value={interval}
          onChange={(e) => setInterval(Number(e.target.value))}
        />
        <Label htmlFor={`${id}-retention`}>Retention (days)</Label>
        <Input
          id={`${id}-retention`}
          required
          type="number"
          value={retention}
          onChange={(e) => setRetention(Number(e.target.value))}
        />
        <label className="flex gap-2">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Schedule enabled
        </label>
        <Label htmlFor={`${id}-reason`}>Audit reason</Label>
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
      setInputError(
        "Enter a nonnegative checkpoint sequence and its 64-character SHA-256 hexadecimal hash.",
      );
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
      <h3 className="text-lg font-semibold">Tamper-evident audit export</h3>
      <p className="text-sm">Continue from an externally retained signed checkpoint.</p>
      <details className="text-xs text-muted-foreground">
        <summary className="w-fit cursor-pointer py-1">
          Checkpoint and verification requirements
        </summary>
        <p className="mt-2">
          Genesis is sequence 0 with an all-zero hash. Verify the manifest with an independently
          pinned signer key; a key included in a download is not itself trusted. Large histories
          require multiple consecutive exports.
        </p>
      </details>
      {action.feedback}
      {inputError ? (
        <Alert variant="destructive">
          <AlertTitle>Check export details</AlertTitle>
          <AlertDescription>{inputError}</AlertDescription>
        </Alert>
      ) : null}
      <fieldset disabled={action.blocked} className="grid min-w-0 gap-3">
        <Label htmlFor="audit-sequence">Previous checkpoint sequence</Label>
        <Input
          id="audit-sequence"
          required
          inputMode="numeric"
          value={sequence}
          onChange={(e) => setSequence(e.target.value)}
        />
        <Label htmlFor="audit-hash">Previous checkpoint SHA-256 (hex)</Label>
        <Input id="audit-hash" required value={hash} onChange={(e) => setHash(e.target.value)} />
        <Label htmlFor="audit-events">Maximum events</Label>
        <Input
          id="audit-events"
          required
          type="number"
          value={maxEvents}
          onChange={(e) => setMaxEvents(Number(e.target.value))}
        />
        <Label htmlFor="audit-retention">Export retention (days)</Label>
        <Input
          id="audit-retention"
          required
          type="number"
          value={retention}
          onChange={(e) => setRetention(Number(e.target.value))}
        />
        <Label htmlFor="audit-export-reason">Audit reason</Label>
        <Input
          id="audit-export-reason"
          required
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <Button type="submit">Queue audit export</Button>
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
        if (total > 32 * 1024 * 1024)
          throw new Error("Artifact exceeds the bounded download size.");
        parts.push(Uint8Array.from(response.data).buffer);
        if (response.finished) {
          finished = true;
          break;
        }
        if (response.nextChunkIndex !== index + 1)
          throw new Error("Artifact chunk sequence changed.");
      }
      if (!finished || BigInt(total) !== artifact.byteCount)
        throw new Error("Artifact download was incomplete.");
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
        <h3 className="text-lg font-semibold">Durable report artifacts</h3>
        <Button variant="outline" disabled={list.isFetching} onClick={() => void list.refetch()}>
          Refresh artifacts
        </Button>
      </div>
      {error ? <RpcError failure={error} /> : null}
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading artifacts…</span>
          <Skeleton className="h-32 w-full" />
        </div>
      ) : null}
      {list.data?.artifacts.length === 0 ? (
        <EmptyState
          title="No report artifacts on this page"
          description="Generated reports appear here after a scheduled run or audit export."
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
          <p className="break-all font-mono text-xs">{artifact.id}</p>
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
              {downloading === artifact.id ? "Downloading…" : "Download artifact"}
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
              Download signed manifest
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
