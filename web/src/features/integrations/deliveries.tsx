import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
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
import { deliveriesQueryOptions } from "./queries";

const STATUS: Record<DeliveryStatus, string> = {
  [DeliveryStatus.UNSPECIFIED]: "Unknown",
  [DeliveryStatus.PENDING]: "Pending",
  [DeliveryStatus.LEASED]: "Delivering",
  [DeliveryStatus.DELIVERED]: "Delivered",
  [DeliveryStatus.DEAD_LETTER]: "Dead letter",
  [DeliveryStatus.CANCELLED]: "Cancelled",
};

export function Deliveries() {
  const lifetime = useAuthLifetime();
  const [page, setPage] = useState("");
  const [deadLetters, setDeadLetters] = useState(false);
  const [reason, setReason] = useState("");
  const list = useQuery(deliveriesQueryOptions(lifetime, page, deadLetters));
  const action = useIntegrationAction();
  return (
    <section
      className="grid min-w-0 gap-4 border-t pt-6"
      aria-label="Delivery history"
      aria-busy={list.isFetching}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-semibold">Delivery history and dead letters</h2>
        <Button variant="outline" disabled={list.isFetching} onClick={() => void list.refetch()}>
          Refresh
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">
        At-least-once delivery can produce duplicates. Receivers must deduplicate the authenticated
        body event ID for their destination, not unsigned delivery headers. A replay may deliver an
        event already received before its acknowledgement was lost.
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
        Show dead letters only
      </label>
      <Label htmlFor="replay-reason">Audit reason for manual replay</Label>
      <Input
        id="replay-reason"
        value={reason}
        disabled={action.blocked}
        onChange={(e) => setReason(e.target.value)}
      />
      {action.feedback}
      {list.error ? (
        <Alert variant="destructive">
          <AlertTitle>Deliveries unavailable</AlertTitle>
          <AlertDescription>{toRpcFailure(list.error).message}</AlertDescription>
        </Alert>
      ) : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading deliveries…</span>
          <Skeleton className="h-32 w-full" />
        </div>
      ) : null}
      {list.data?.deliveries.length === 0 ? (
        <p
          role="status"
          className="border border-dashed bg-muted/30 px-6 py-10 text-center text-sm text-muted-foreground"
        >
          No deliveries on this page.
        </p>
      ) : null}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Delivery / event</TableHead>
            <TableHead>Destination / ordering key</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Attempts / replays</TableHead>
            <TableHead>Next attempt</TableHead>
            <TableHead>Failure</TableHead>
            <TableHead>Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {list.data?.deliveries.map((delivery) => (
            <TableRow key={delivery.id}>
              <TableCell className="font-mono text-xs">
                {delivery.id}
                <br />
                {delivery.eventId}
              </TableCell>
              <TableCell className="font-mono text-xs">
                {delivery.destinationId}
                <br />
                {delivery.resourceId}
              </TableCell>
              <TableCell>
                <Badge
                  variant={
                    delivery.status === DeliveryStatus.DEAD_LETTER
                      ? "destructive"
                      : delivery.status === DeliveryStatus.DELIVERED
                        ? "secondary"
                        : "outline"
                  }
                >
                  {STATUS[delivery.status]}
                </Badge>
              </TableCell>
              <TableCell>
                {delivery.attempts} / {delivery.replayCount}
              </TableCell>
              <TableCell>{formatTimestamp(delivery.nextAttemptAt).local}</TableCell>
              <TableCell className="min-w-48 max-w-md whitespace-normal break-words">
                {delivery.lastError || "—"}
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
                    Replay
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
