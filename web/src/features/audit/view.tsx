import { useQuery } from "@tanstack/react-query";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
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
import { toRpcFailure } from "@/lib/errors";
import { PAGE_SIZES, type PageSize } from "@/lib/list-search";
import { formatTimestamp, freshnessLabel } from "@/lib/time";
import { auditQueryOptions } from "./queries";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useListPagination } from "@/hooks/use-list-pagination";

export function AuditView({
  pageSize,
  pageToken,
  onSearch,
}: {
  pageSize: PageSize;
  pageToken: string;
  onSearch: (next: { pageSize: PageSize; pageToken: string }) => void;
}) {
  const lifetime = useAuthLifetime();
  const list = useQuery(auditQueryOptions(lifetime, pageSize, pageToken));
  const pagination = useListPagination({ pageSize, pageToken }, onSearch);
  const failure = list.error ? toRpcFailure(list.error) : null;
  const now = new Date();

  return (
    <section className="flex min-w-0 flex-col gap-6" aria-busy={list.isFetching}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">Audit</h1>
          <p className="max-w-3xl text-sm text-muted-foreground">
            Local append history for this deployment.
          </p>
          <details className="text-xs text-muted-foreground">
            <summary className="w-fit cursor-pointer py-1">Audit limitations</summary>
            <p className="mt-2">
              It is not an external tamper-proof trail. Secrets are not recorded here.
            </p>
          </details>
        </div>
        <Button variant="outline" onClick={() => void list.refetch()} disabled={list.isFetching}>
          Refresh
        </Button>
      </div>
      {failure ? (
        <Alert variant="destructive">
          <AlertTitle>{failure.denied ? "Not authorized" : "Audit list failed"}</AlertTitle>
          <AlertDescription>
            {failure.codeName}: {failure.message}
          </AlertDescription>
        </Alert>
      ) : null}
      <div className="flex flex-wrap items-center gap-2 border-y py-3 text-sm">
        <Label htmlFor="audit-page-size">Page size</Label>
        <SelectField
          id="audit-page-size"
          className="h-9"
          value={pageSize}
          onValueChange={(value) => {
            const next = Number(value);
            if (next === 50 || next === 100 || next === 200) {
              onSearch({ pageSize: next, pageToken: "" });
            }
          }}
          options={PAGE_SIZES.map((size) => ({ value: size, label: size }))}
        />
      </div>
      {list.isPending ? (
        <div role="status" className="grid gap-3 border p-4">
          <span className="text-sm text-muted-foreground">Loading audit events…</span>
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : null}
      {list.isSuccess && list.data.events.length === 0 ? (
        <p
          role="status"
          className="border border-dashed bg-muted/30 px-6 py-10 text-center text-sm text-muted-foreground"
        >
          {pageToken === "" ? "No audit events are recorded." : "This page has no audit events."}
        </p>
      ) : null}
      {list.data && list.data.events.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Occurred</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Resource</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Reason</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.events.map((event) => {
              const occurred = formatTimestamp(event.occurredAt);
              return (
                <TableRow key={event.id}>
                  <TableCell>
                    {occurred.date ? (
                      <time dateTime={occurred.utc}>
                        {occurred.local} ({freshnessLabel(occurred.date, now)})
                      </time>
                    ) : (
                      "Not recorded"
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {event.action.trim() || "Not recorded"}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {event.resourceId.trim() || "Not recorded"}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {event.actorId.trim() || "Unknown actor"}
                  </TableCell>
                  <TableCell className="min-w-48 max-w-md whitespace-normal break-words">
                    {event.reason.trim() || "—"}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" disabled={pageToken === ""} onClick={pagination.previous}>
          {pagination.previousLabel}
        </Button>
        <Button
          variant="outline"
          disabled={!list.data?.nextPageToken}
          onClick={() => pagination.next(list.data?.nextPageToken ?? "")}
        >
          Next page
        </Button>
      </div>
    </section>
  );
}
