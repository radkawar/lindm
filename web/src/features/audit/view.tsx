import { useQuery } from "@tanstack/react-query";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
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
      <PageHeader
        title="Audit"
        description="Local append history for this deployment."
        actions={
          <Button variant="outline" onClick={() => void list.refetch()} disabled={list.isFetching}>
            Refresh
          </Button>
        }
      />
      <details className="text-xs text-muted-foreground">
        <summary className="w-fit cursor-pointer py-1">Audit limitations</summary>
        <p className="mt-2">
          This is not an external tamper-proof trail. Secrets are not recorded here.
        </p>
      </details>
      {failure ? <RpcError failure={failure} /> : null}
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
        <EmptyState
          title={pageToken === "" ? "No audit events recorded" : "No audit events on this page"}
        />
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
                    {event.reason.trim() || "Not recorded"}
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
