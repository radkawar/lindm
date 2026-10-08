import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import type { Device } from "../../../gen/lindm/admin/v1/admin_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { newRequestId } from "@/lib/ids";
import { PAGE_SIZES, type PageSize } from "@/lib/list-search";
import { toRpcFailure, type RpcFailure } from "@/lib/errors";
import { reasonError } from "@/lib/reason";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp, freshnessLabel } from "@/lib/time";
import { devicesQueryOptions } from "./queries";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useListPagination } from "@/hooks/use-list-pagination";

export function DevicesView({
  pageSize,
  pageToken,
  onSearch,
}: {
  pageSize: PageSize;
  pageToken: string;
  onSearch: (next: { pageSize: PageSize; pageToken: string }) => void;
}) {
  const queryClient = useQueryClient();
  const lifetime = useAuthLifetime();
  const list = useQuery(devicesQueryOptions(lifetime, pageSize, pageToken));
  const pagination = useListPagination({ pageSize, pageToken }, onSearch);
  const [target, setTarget] = useState<Device | null>(null);
  const [notice, setNotice] = useState("");
  const now = new Date();
  const failure = list.error ? toRpcFailure(list.error) : null;

  return (
    <section className="flex flex-col gap-4" aria-busy={list.isFetching}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Devices</h1>
          <p className="max-w-3xl text-sm text-muted-foreground">
            Last contact is the server time of the last accepted inventory report. It is not a live
            presence claim. Revocation is enforced on the next request this server receives.
          </p>
        </div>
        <Button variant="outline" onClick={() => void list.refetch()} disabled={list.isFetching}>
          Refresh
        </Button>
      </div>
      {notice !== "" ? (
        <Alert>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}
      {failure ? (
        <Alert variant="destructive">
          <AlertTitle>{failure.denied ? "Not authorized" : "Device list failed"}</AlertTitle>
          <AlertDescription>
            {failure.codeName}: {failure.message}
          </AlertDescription>
        </Alert>
      ) : null}
      <div className="flex items-center gap-2 text-sm">
        <Label htmlFor="device-page-size">Page size</Label>
        <select
          id="device-page-size"
          className="h-8 rounded-lg border border-input bg-background px-2"
          value={pageSize}
          onChange={(event) => {
            const next = Number(event.target.value);
            if (next === 50 || next === 100 || next === 200) {
              onSearch({ pageSize: next, pageToken: "" });
            }
          }}
        >
          {PAGE_SIZES.map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </select>
      </div>
      {list.isPending ? <p role="status">Loading devices…</p> : null}
      {list.isSuccess && list.data.devices.length === 0 ? (
        <p role="status">
          {pageToken === "" ? "No devices are enrolled." : "This page has no devices."}
        </p>
      ) : null}
      {list.data && list.data.devices.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Hostname</TableHead>
              <TableHead>State</TableHead>
              <TableHead>Last contact</TableHead>
              <TableHead>OS</TableHead>
              <TableHead>Sequence</TableHead>
              <TableHead>Device ID</TableHead>
              <TableHead>Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.devices.map((device) => {
              const seen = formatTimestamp(device.lastSeenAt);
              return (
                <TableRow key={device.id}>
                  <TableCell>{device.hostname.trim() || "Hostname not reported"}</TableCell>
                  <TableCell>
                    <Badge variant={device.state === "revoked" ? "destructive" : "outline"}>
                      {device.state.trim() || "Not reported"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {seen.date ? (
                      <time dateTime={seen.utc}>
                        {seen.local} ({freshnessLabel(seen.date, now)})
                      </time>
                    ) : (
                      "No accepted inventory"
                    )}
                  </TableCell>
                  <TableCell>
                    {[device.osId, device.osVersion]
                      .filter((part) => part.trim() !== "")
                      .join(" ") || "Not reported"}
                  </TableCell>
                  <TableCell>{device.inventorySequence.toString()}</TableCell>
                  <TableCell className="font-mono text-xs">{device.id}</TableCell>
                  <TableCell>
                    <Button
                      variant="destructive"
                      size="sm"
                      aria-label={`Revoke device ${device.id}`}
                      onClick={() => setTarget(device)}
                    >
                      Revoke
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      ) : null}
      <div className="flex items-center gap-2">
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
      {target ? (
        <RevokeDeviceDialog
          device={target}
          onClose={() => setTarget(null)}
          onAccepted={(deviceId, requestId) => {
            setTarget(null);
            setNotice(
              `Revoke request ${requestId} was accepted for ${deviceId}. The list is refreshing.`,
            );
            void queryClient.invalidateQueries({ queryKey: ["devices", lifetime.generation] });
          }}
        />
      ) : null}
    </section>
  );
}

function RevokeDeviceDialog({
  device,
  onClose,
  onAccepted,
}: {
  device: Device;
  onClose: () => void;
  onAccepted: (deviceId: string, requestId: string) => void;
}) {
  const inFlight = useRef(false);
  const lifetime = useAuthLifetime();
  const submitted = useRef<{ requestId: string; reason: string } | null>(null);
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [requestId, setRequestId] = useState(newRequestId);
  const [fieldError, setFieldError] = useState("");
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const revoke = useMutation({
    retry: false,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (payload: { requestId: string; reason: string }) => {
      await adminClient.revokeDevice(
        {
          requestId: payload.requestId,
          deviceId: device.id,
          reason: payload.reason,
        },
        { signal: lifetime.signal },
      );
      lifetime.signal.throwIfAborted();
      return payload;
    },
    onSuccess: (payload) => onAccepted(device.id, payload.requestId),
    onError: (error) => setFailure(toRpcFailure(error)),
    onSettled: () => {
      inFlight.current = false;
    },
  });

  return (
    <Dialog open onOpenChange={(open) => !open && !inFlight.current && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Revoke device</DialogTitle>
          <DialogDescription>
            This revokes {device.id} and its active certificates on this server. It does not wipe
            the machine or prove a disconnected device has applied the revocation.
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (inFlight.current) return;
            if (submitted.current) {
              inFlight.current = true;
              revoke.mutate(submitted.current);
              return;
            }
            const nextReason = reasonError(reason);
            const matches = confirmation.trim().toLowerCase() === device.id.trim().toLowerCase();
            if (nextReason !== "" || !matches) {
              setFieldError(nextReason || "Type the device ID to confirm.");
              return;
            }
            inFlight.current = true;
            setFailure(null);
            submitted.current = { requestId, reason: reason.trim() };
            revoke.mutate(submitted.current);
          }}
        >
          <div className="grid gap-1.5">
            <Label htmlFor="revoke-reason">Reason</Label>
            <Textarea
              id="revoke-reason"
              required
              maxLength={512}
              value={reason}
              readOnly={revoke.isPending || submitted.current !== null}
              onChange={(event) => setReason(event.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="revoke-confirm">Type the device ID to confirm</Label>
            <Input
              id="revoke-confirm"
              required
              autoComplete="off"
              value={confirmation}
              readOnly={revoke.isPending || submitted.current !== null}
              onChange={(event) => setConfirmation(event.target.value)}
            />
          </div>
          <p className="font-mono text-xs text-muted-foreground">Request ID {requestId}</p>
          {fieldError !== "" ? <p className="text-sm text-destructive">{fieldError}</p> : null}
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>
                {failure.ambiguous ? "No result came back. Retry the same request ID. " : ""}
                {failure.codeName}: {failure.message}
              </AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={revoke.isPending} onClick={onClose}>
              Cancel
            </Button>
            {failure ? (
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  submitted.current = null;
                  setRequestId(newRequestId());
                  setFailure(null);
                }}
              >
                Start a different request
              </Button>
            ) : null}
            <Button type="submit" variant="destructive" disabled={revoke.isPending}>
              {revoke.isPending ? "Revoking…" : failure ? "Retry same request" : "Revoke device"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
