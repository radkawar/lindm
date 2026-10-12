import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
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
import { adminClient } from "@/lib/rpc";
import { DeliveryStatus, type Delivery } from "../../../gen/lindm/integrations/v1/delivery_pb";
import { useIntegrationAction } from "./action";
import { deliveriesQueryOptions, destinationsQueryOptions } from "./queries";

const STATUS: Record<DeliveryStatus, string> = {
  [DeliveryStatus.UNSPECIFIED]: "Unknown",
  [DeliveryStatus.PENDING]: "Pending",
  [DeliveryStatus.LEASED]: "Delivering",
  [DeliveryStatus.DELIVERED]: "Delivered",
  [DeliveryStatus.DEAD_LETTER]: "Failed",
  [DeliveryStatus.CANCELLED]: "Cancelled",
};

export function Deliveries() {
  const lifetime = useAuthLifetime();
  const [page, setPage] = useState("");
  const [deadLetters, setDeadLetters] = useState(false);
  const list = useQuery(deliveriesQueryOptions(lifetime, page, deadLetters));
  const destinations = useQuery(destinationsQueryOptions(lifetime, ""));
  const destinationNames = useMemo(
    () =>
      new Map(
        destinations.data?.destinations.map((d) => [d.id, d.config?.displayName.trim() ?? ""]) ??
          [],
      ),
    [destinations.data],
  );
  function show(failedOnly: boolean) {
    setDeadLetters(failedOnly);
    setPage("");
  }
  return (
    <section
      className="grid min-w-0 gap-4 border-t pt-6"
      aria-label="Delivery history"
      aria-busy={list.isFetching}
    >
      <div className="grid gap-1">
        <h2 className="text-base font-semibold">Deliveries</h2>
        <p className="text-sm text-muted-foreground">
          Receivers may get the same event more than once and should ignore repeats.
        </p>
      </div>
      <div className="flex flex-wrap gap-2" role="group" aria-label="Show deliveries">
        <Button
          size="sm"
          variant={deadLetters ? "outline" : "default"}
          aria-pressed={!deadLetters}
          onClick={() => show(false)}
        >
          All deliveries
        </Button>
        <Button
          size="sm"
          variant={deadLetters ? "default" : "outline"}
          aria-pressed={deadLetters}
          onClick={() => show(true)}
        >
          Failed only
        </Button>
      </div>
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading deliveries…</span>
          <Skeleton className="h-32 w-full" />
        </div>
      ) : null}
      {list.data?.deliveries.length === 0 ? (
        <EmptyState
          title={deadLetters ? "No failed deliveries" : "No deliveries yet"}
          description={
            page
              ? "No more deliveries on this page. Return to the first page."
              : deadLetters
                ? "Every delivery either succeeded or is still being retried."
                : "Events are listed here once a destination is sending."
          }
          action={
            page ? (
              <Button variant="outline" onClick={() => setPage("")}>
                First page
              </Button>
            ) : deadLetters ? (
              <Button variant="outline" onClick={() => show(false)}>
                Show all deliveries
              </Button>
            ) : undefined
          }
        />
      ) : null}
      {list.data && list.data.deliveries.length > 0 ? (
        <Table aria-label="Deliveries">
          <TableHeader>
            <TableRow>
              <TableHead>Destination</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>When</TableHead>
              <TableHead>Attempts</TableHead>
              <TableHead>Last error</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.deliveries.map((delivery) => (
              <DeliveryRow
                key={delivery.id}
                delivery={delivery}
                destinationName={
                  destinationNames.get(delivery.destinationId) || "Destination name unavailable"
                }
              />
            ))}
          </TableBody>
        </Table>
      ) : null}
      <ListPagination
        label="Delivery pages"
        previousLabel="First page"
        onPrevious={page ? () => setPage("") : undefined}
        onNext={
          list.data?.nextPageToken ? () => setPage(list.data?.nextPageToken ?? "") : undefined
        }
        busy={list.isFetching}
      />
    </section>
  );
}

function DeliveryRow({
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
  const failed = delivery.status === DeliveryStatus.DEAD_LETTER;
  return (
    <TableRow className="align-top">
      <TableCell className="min-w-40 whitespace-normal break-words">
        {destinationName}
        <TechnicalDetails
          items={[
            { label: "Delivery ID", value: delivery.id },
            { label: "Event ID", value: delivery.eventId },
            { label: "Destination ID", value: delivery.destinationId },
            { label: "Resource", value: delivery.resourceId },
          ]}
        />
      </TableCell>
      <TableCell>
        <StatusBadge
          status={
            failed
              ? "destructive"
              : delivery.status === DeliveryStatus.DELIVERED
                ? "success"
                : delivery.status === DeliveryStatus.LEASED
                  ? "info"
                  : delivery.lastError
                    ? "warning"
                    : "neutral"
          }
        >
          {STATUS[delivery.status]}
        </StatusBadge>
      </TableCell>
      <TableCell className="whitespace-nowrap">
        {delivery.status === DeliveryStatus.DELIVERED ? (
          <Timestamp value={delivery.deliveredAt} />
        ) : delivery.status === DeliveryStatus.PENDING ||
          delivery.status === DeliveryStatus.LEASED ? (
          <>
            Next try <Timestamp value={delivery.nextAttemptAt} />
          </>
        ) : null}
      </TableCell>
      <TableCell className="tabular-nums">
        {delivery.attempts}
        {delivery.replayCount > 0 ? (
          <span className="text-muted-foreground"> · retried {delivery.replayCount}×</span>
        ) : null}
      </TableCell>
      <TableCell className="min-w-48 max-w-md whitespace-normal break-words">
        {delivery.lastError ? (
          <span className="font-mono text-xs">{delivery.lastError}</span>
        ) : (
          <span className="text-muted-foreground">None</span>
        )}
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
                    The event is queued again for this destination only. The receiver may already
                    have it and should ignore a repeat.
                  </DialogDescription>
                </DialogHeader>
                {action.feedback}
                <form
                  className="grid gap-3"
                  onSubmit={(event) => {
                    event.preventDefault();
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
                      required
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                    />
                    <Button type="submit" className="w-fit" disabled={!reason.trim()}>
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
