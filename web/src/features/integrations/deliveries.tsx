// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";
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
import { toRpcFailure } from "@/lib/errors";
import { reasonError } from "@/lib/reason";
import { adminClient } from "@/lib/rpc";
import {
  DeliveryStatus,
  type Delivery,
  type DeliverySummary,
} from "../../../gen/lindm/integrations/v1/delivery_pb";
import { useIntegrationAction } from "./action";
import { deliveryFailureText, plural } from "./health";
import {
  deliveredQueryOptions,
  deliverySummaryQueryOptions,
  destinationsQueryOptions,
  failedDeliveriesQueryOptions,
} from "./queries";

/**
 * Failures first; delivered events are only counted per destination (server
 * summary over the last 24 hours) and listed on request.
 */
export function Deliveries() {
  const lifetime = useAuthLifetime();
  const [page, setPage] = useState("");
  const failures = useQuery(failedDeliveriesQueryOptions(lifetime, page));
  const summary = useQuery(deliverySummaryQueryOptions(lifetime));
  const destinations = useQuery(destinationsQueryOptions(lifetime, ""));
  const names: Record<string, string> = {};
  for (const destination of destinations.data?.destinations ?? []) {
    names[destination.id] = destination.config?.displayName.trim() || "Unnamed destination";
  }
  const nameOf = (id: string) => names[id] ?? "Destination name unavailable";
  return (
    <section
      className="grid min-w-0 gap-3 border-t pt-6"
      aria-labelledby="deliveries-heading"
      aria-busy={failures.isFetching || summary.isFetching}
    >
      <div className="grid gap-1">
        <h2 id="deliveries-heading" className="text-base font-semibold">
          Delivery log
        </h2>
        <p className="text-sm text-muted-foreground">
          This list shows failed deliveries. Each destination shows its successful delivery count.
        </p>
      </div>
      {failures.error ? <RpcError failure={toRpcFailure(failures.error)} /> : null}
      {failures.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading failed deliveries…</span>
          <Skeleton className="h-16 w-full" />
        </div>
      ) : null}
      {failures.data?.deliveries.length === 0 ? (
        <EmptyState
          title={page ? "No more failed deliveries" : "No failed deliveries"}
          description={
            page
              ? "Return to the first page."
              : "No delivery is failing or waiting to retry after an error."
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
      {failures.data && failures.data.deliveries.length > 0 ? (
        <Table aria-label="Failed deliveries">
          <TableHeader>
            <TableRow>
              <TableHead>Destination</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Attempts</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {failures.data.deliveries.map((delivery) => (
              <FailureRow
                key={delivery.id}
                delivery={delivery}
                destinationName={nameOf(delivery.destinationId)}
              />
            ))}
          </TableBody>
        </Table>
      ) : null}
      <ListPagination
        label="Failed delivery pages"
        previousLabel="First page"
        onPrevious={page ? () => setPage("") : undefined}
        onNext={
          failures.data?.nextPageToken
            ? () => setPage(failures.data?.nextPageToken ?? "")
            : undefined
        }
        busy={failures.isFetching}
      />
      {summary.error ? (
        <RpcError failure={toRpcFailure(summary.error)} title="Delivery counts unavailable" />
      ) : null}
      {summary.data && summary.data.summaries.length > 0 ? (
        <ul className="grid border-y" aria-label="Delivered events per destination">
          {summary.data.summaries.map((row) => (
            <DeliveredGroup
              key={row.destinationId}
              summary={row}
              destinationName={nameOf(row.destinationId)}
            />
          ))}
        </ul>
      ) : null}
    </section>
  );
}

function DeliveredGroup({
  summary,
  destinationName,
}: {
  summary: DeliverySummary;
  destinationName: string;
}) {
  const [open, setOpen] = useState(false);
  const panel = `delivered-${summary.destinationId}`;
  const Icon = open ? ChevronDown : ChevronRight;
  return (
    <li className="grid min-w-0 gap-2 border-b py-2 last:border-b-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="min-w-0 break-words text-sm">
          <span className="font-medium">{destinationName}</span>
          {" · "}
          {plural(summary.delivered, "event")} delivered in the last 24 h
          {summary.queued > 0n ? ` · ${plural(summary.queued, "event")} waiting to send` : null}
          {summary.lastDeliveredAt ? (
            <span className="text-muted-foreground">
              {" · last "}
              <Timestamp value={summary.lastDeliveredAt} />
            </span>
          ) : null}
        </p>
        {summary.lastDeliveredAt ? (
          <Button
            variant="ghost"
            size="sm"
            aria-expanded={open}
            aria-controls={panel}
            onClick={() => setOpen(!open)}
          >
            <Icon aria-hidden="true" />
            {open ? "Hide delivered" : "Show delivered"}
          </Button>
        ) : null}
      </div>
      {open ? (
        <div id={panel}>
          <DeliveredList destinationId={summary.destinationId} />
        </div>
      ) : null}
    </li>
  );
}

function DeliveredList({ destinationId }: { destinationId: string }) {
  const lifetime = useAuthLifetime();
  const [page, setPage] = useState("");
  const list = useQuery(deliveredQueryOptions(lifetime, destinationId, page));
  if (list.error) return <RpcError failure={toRpcFailure(list.error)} />;
  if (list.isPending) return <Skeleton className="h-16 w-full" />;
  return (
    <div className="grid gap-2">
      <Table aria-label="Delivered events">
        <TableHeader>
          <TableRow>
            <TableHead>Delivered</TableHead>
            <TableHead>Attempts</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {list.data.deliveries.map((delivery) => (
            <TableRow key={delivery.id} className="align-top">
              <TableCell>
                <Timestamp value={delivery.deliveredAt} />
                <TechnicalDetails
                  items={[
                    { label: "Delivery ID", value: delivery.id },
                    { label: "Event ID", value: delivery.eventId },
                    { label: "Resource", value: delivery.resourceId },
                  ]}
                />
              </TableCell>
              <TableCell className="tabular-nums">
                {delivery.attempts}
                {delivery.replayCount > 0 ? ` · retried ${delivery.replayCount}×` : null}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <ListPagination
        label="Delivered event pages"
        previousLabel="Newest"
        onPrevious={page ? () => setPage("") : undefined}
        onNext={list.data.nextPageToken ? () => setPage(list.data.nextPageToken) : undefined}
        busy={list.isFetching}
      />
    </div>
  );
}

function FailureRow({
  delivery,
  destinationName,
}: {
  delivery: Delivery;
  destinationName: string;
}) {
  const lifetime = useAuthLifetime();
  const action = useIntegrationAction();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [attempted, setAttempted] = useState(false);
  const failed = delivery.status === DeliveryStatus.DEAD_LETTER;
  const error = reasonError(reason);
  return (
    <TableRow className="align-top">
      <TableCell className="min-w-40 whitespace-normal break-words">
        {destinationName}
        <TechnicalDetails
          items={[
            { label: "Reason code", value: delivery.lastError },
            { label: "Delivery ID", value: delivery.id },
            { label: "Event ID", value: delivery.eventId },
            { label: "Destination ID", value: delivery.destinationId },
            { label: "Resource", value: delivery.resourceId },
          ]}
        />
      </TableCell>
      <TableCell className="min-w-56 max-w-md whitespace-normal break-words">
        <StatusBadge status={failed ? "destructive" : "warning"}>
          {failed ? "Failed" : "Retrying"}
        </StatusBadge>
        <p className="mt-1 text-sm">{deliveryFailureText(delivery.lastError)}</p>
        {failed ? null : (
          <p className="mt-1 text-xs text-muted-foreground">
            Next try <Timestamp value={delivery.nextAttemptAt} />
          </p>
        )}
      </TableCell>
      <TableCell className="tabular-nums">
        {delivery.attempts}
        {delivery.replayCount > 0 ? (
          <span className="text-muted-foreground"> · retried {delivery.replayCount}×</span>
        ) : null}
      </TableCell>
      <TableCell className="text-right">
        {failed || action.blocked ? (
          <>
            <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
              {action.blocked ? "Review retry" : "Retry…"}
            </Button>
            <Dialog open={open} onOpenChange={setOpen}>
              <DialogContent className="text-left sm:max-w-md">
                <DialogHeader>
                  <DialogTitle>Retry delivery to {destinationName}</DialogTitle>
                  <DialogDescription>
                    The server queues this event for this destination only. The receiver can already
                    have this event. It must ignore duplicates.
                  </DialogDescription>
                </DialogHeader>
                {action.feedback}
                <form
                  className="grid gap-3"
                  noValidate
                  onSubmit={(event) => {
                    event.preventDefault();
                    setAttempted(true);
                    if (error) return;
                    const request = {
                      requestId: crypto.randomUUID(),
                      deliveryId: delivery.id,
                      reason,
                    };
                    action.perform(async () => {
                      const response = await adminClient.replayDelivery(request, {
                        signal: lifetime.signal,
                      });
                      lifetime.signal.throwIfAborted();
                      setOpen(false);
                      return response;
                    });
                  }}
                >
                  <fieldset className="grid gap-3" disabled={action.blocked}>
                    <Label htmlFor={`${delivery.id}-reason`}>Reason (audited)</Label>
                    <Input
                      id={`${delivery.id}-reason`}
                      data-freeform="audit reason"
                      aria-invalid={attempted && error ? true : undefined}
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                    />
                    {attempted && error ? (
                      <p className="text-xs text-destructive">{error}</p>
                    ) : null}
                    <Button type="submit" className="w-fit">
                      Retry delivery
                    </Button>
                  </fieldset>
                </form>
              </DialogContent>
            </Dialog>
          </>
        ) : null}
      </TableCell>
    </TableRow>
  );
}
