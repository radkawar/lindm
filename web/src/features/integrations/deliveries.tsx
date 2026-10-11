import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { EmptyState } from "@/components/ui/empty-state";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { toRpcFailure } from "@/lib/errors";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { DeliveryStatus } from "../../../gen/lindm/integrations/v1/delivery_pb";
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
  const [reason, setReason] = useState("");
  const list = useQuery(deliveriesQueryOptions(lifetime, page, deadLetters));
  const action = useIntegrationAction();
  const destinations = useQuery(destinationsQueryOptions(lifetime, ""));
  const destinationNames = useMemo(
    () =>
      new Map(
        destinations.data?.destinations.map((d) => [d.id, d.config?.displayName.trim() ?? ""]) ??
          [],
      ),
    [destinations.data],
  );
  return (
    <section
      className="grid min-w-0 gap-4 border-t pt-6"
      aria-label="Delivery history"
      aria-busy={list.isFetching}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-semibold">Deliveries</h2>
        <Button variant="outline" disabled={list.isFetching} onClick={() => void list.refetch()}>
          Refresh
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">
        Receivers may get the same event more than once and should ignore repeats.
      </p>
      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={deadLetters}
          onChange={(e) => {
            setDeadLetters(e.target.checked);
            setPage("");
          }}
        />
        Show failed deliveries only
      </label>
      <Label htmlFor="replay-reason">Reason for retrying</Label>
      <Input
        id="replay-reason"
        value={reason}
        disabled={action.blocked}
        onChange={(e) => setReason(e.target.value)}
      />
      {action.feedback}
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading deliveries…</span>
          <Skeleton className="h-32 w-full" />
        </div>
      ) : null}
      {list.data?.deliveries.length === 0 ? <EmptyState title="No deliveries" /> : null}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Destination</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Attempts</TableHead>
            <TableHead>Next attempt</TableHead>
            <TableHead>Last error</TableHead>
            <TableHead>Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {list.data?.deliveries.map((delivery) => (
            <TableRow key={delivery.id}>
              <TableCell className="whitespace-normal break-words">
                {destinationNames.get(delivery.destinationId) || "Destination"}
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
                    delivery.status === DeliveryStatus.DEAD_LETTER
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
              <TableCell>
                {delivery.attempts}
                {delivery.replayCount > 0 ? ` (${delivery.replayCount} retried)` : ""}
              </TableCell>
              <TableCell>{formatTimestamp(delivery.nextAttemptAt).local}</TableCell>
              <TableCell className="min-w-48 max-w-md whitespace-normal break-words">
                {delivery.lastError || "None"}
              </TableCell>
              <TableCell>
                {delivery.status === DeliveryStatus.DEAD_LETTER ? (
                  <Button
                    variant="outline"
                    disabled={action.blocked || !reason.trim()}
                    onClick={() => {
                      const request = {
                        requestId: crypto.randomUUID(),
                        deliveryId: delivery.id,
                        reason,
                      };
                      action.perform(() =>
                        adminClient.replayDelivery(request, { signal: lifetime.signal }),
                      );
                    }}
                  >
                    Retry
                  </Button>
                ) : null}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" disabled={!page} onClick={() => setPage("")}>
          First page
        </Button>
        <Button
          variant="outline"
          disabled={!list.data?.nextPageToken}
          onClick={() => setPage(list.data?.nextPageToken ?? "")}
        >
          Next page
        </Button>
      </div>
    </section>
  );
}
