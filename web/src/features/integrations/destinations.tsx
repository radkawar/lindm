import { create } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { EmptyState } from "@/components/ui/empty-state";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { RpcError } from "@/components/ui/rpc-error";
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
import { StatusBadge } from "@/components/ui/status-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { Timestamp } from "@/components/ui/timestamp";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { adminClient } from "@/lib/rpc";
import { toRpcFailure } from "@/lib/errors";
import {
  DestinationConfigSchema,
  DestinationKind,
  type Destination,
} from "../../../gen/lindm/integrations/v1/delivery_pb";
import { useIntegrationAction, type IntegrationAction } from "./action";
import { destinationsQueryOptions } from "./queries";

const KIND_LABELS: Record<DestinationKind, string> = {
  [DestinationKind.UNSPECIFIED]: "Unknown",
  [DestinationKind.WEBHOOK]: "HTTPS webhook",
  [DestinationKind.SYSLOG_TLS]: "Syslog over TLS",
};

// RotateDestinationSecretRequest.overlap_seconds allows 0 to 86400.
const OVERLAP_OPTIONS = [
  { value: 0, label: "Stop immediately" },
  { value: 3600, label: "1 hour" },
  { value: 6 * 3600, label: "6 hours" },
  { value: 86400, label: "24 hours" },
];

export function Destinations() {
  const lifetime = useAuthLifetime();
  const [page, setPage] = useState("");
  const [adding, setAdding] = useState(false);
  const addAction = useIntegrationAction();
  const list = useQuery(destinationsQueryOptions(lifetime, page));
  return (
    <section
      className="grid min-w-0 gap-4 border-t pt-6"
      aria-label="Delivery destinations"
      aria-busy={list.isFetching}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="grid gap-1">
          <h2 className="text-base font-semibold">Destinations</h2>
          <p className="text-sm text-muted-foreground">
            New audit events go to every destination that is sending. A destination that is off does
            not receive events recorded while it is off.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => setAdding(true)}>
            {addAction.blocked ? "Review pending destination" : "Add destination"}
          </Button>
        </div>
      </div>
      <Dialog open={adding} onOpenChange={setAdding}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Add destination</DialogTitle>
            <DialogDescription>
              Only audit events recorded after it is created are sent; earlier events are not.
            </DialogDescription>
          </DialogHeader>
          <DestinationForm action={addAction} onDone={() => setAdding(false)} />
        </DialogContent>
      </Dialog>
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading destinations…</span>
          <Skeleton className="h-16 w-full" />
        </div>
      ) : null}
      {list.data?.destinations.length === 0 ? (
        <EmptyState
          title={page ? "No more destinations" : "No destinations yet"}
          description={
            page
              ? "Return to the first page."
              : "Audit events are not sent anywhere. Add a webhook or syslog server to start sending them."
          }
          action={
            page ? (
              <Button variant="outline" onClick={() => setPage("")}>
                First page
              </Button>
            ) : (
              <Button variant="outline" onClick={() => setAdding(true)}>
                Add destination
              </Button>
            )
          }
        />
      ) : null}
      {list.data && list.data.destinations.length > 0 ? (
        <Table aria-label="Destinations">
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Address</TableHead>
              <TableHead>Delivery</TableHead>
              <TableHead>Changed</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.destinations.map((destination) => (
              <DestinationRow
                key={`${destination.id}:${destination.version}`}
                destination={destination}
              />
            ))}
          </TableBody>
        </Table>
      ) : null}
      <ListPagination
        label="Destination pages"
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

function DestinationRow({ destination }: { destination: Destination }) {
  const action = useIntegrationAction();
  const [open, setOpen] = useState(false);
  const config = destination.config;
  const name = config?.displayName.trim() || "Unnamed destination";
  const overlapEnds = destination.previousSecretExpiresAt
    ? timestampDate(destination.previousSecretExpiresAt)
    : null;
  return (
    <TableRow className="align-top">
      <TableCell className="min-w-40 whitespace-normal break-words">
        <span className="font-medium">{name}</span>
        <TechnicalDetails
          items={[
            { label: "Destination ID", value: destination.id },
            { label: "Revision", value: destination.version.toString() },
          ]}
        />
      </TableCell>
      <TableCell>{KIND_LABELS[config?.kind ?? DestinationKind.UNSPECIFIED]}</TableCell>
      <TableCell className="min-w-48 max-w-md whitespace-normal break-all font-mono text-xs">
        {config?.endpoint}
      </TableCell>
      <TableCell className="whitespace-normal">
        <StatusBadge status={config?.enabled ? "success" : "neutral"}>
          {config?.enabled ? "Sending" : "Paused"}
        </StatusBadge>
        {overlapEnds && overlapEnds.getTime() > Date.now() ? (
          <p className="mt-1 text-xs text-muted-foreground">
            Old signing secret works until <Timestamp value={destination.previousSecretExpiresAt} />
          </p>
        ) : null}
      </TableCell>
      <TableCell>
        <Timestamp value={destination.updatedAt} />
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
                Changes apply to events sent after you save. The type can't be changed.
              </DialogDescription>
            </DialogHeader>
            <DestinationForm
              destination={destination}
              action={action}
              onDone={() => setOpen(false)}
            />
          </DialogContent>
        </Dialog>
      </TableCell>
    </TableRow>
  );
}

function DestinationForm({
  destination,
  action,
  onDone,
}: {
  destination?: Destination;
  action: IntegrationAction;
  onDone: () => void;
}) {
  const lifetime = useAuthLifetime();
  const [name, setName] = useState(destination?.config?.displayName ?? "");
  const [kind, setKind] = useState(destination?.config?.kind ?? DestinationKind.WEBHOOK);
  const [endpoint, setEndpoint] = useState(destination?.config?.endpoint ?? "");
  const [ca, setCa] = useState(destination?.config?.pinnedCaPem ?? "");
  const [enabled, setEnabled] = useState(destination?.config?.enabled ?? true);
  const [secret, setSecret] = useState("");
  const [overlap, setOverlap] = useState(3600);
  const [reason, setReason] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const id = destination?.id ?? "new";
  const callOptions = { signal: lifetime.signal };

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const config = create(DestinationConfigSchema, {
      displayName: name,
      kind,
      endpoint,
      pinnedCaPem: ca,
      enabled,
    });
    const requestId = crypto.randomUUID();
    if (destination) {
      const request = {
        requestId,
        destinationId: destination.id,
        expectedVersion: destination.version,
        config,
        reason,
      };
      action.perform(async () => {
        const response = await adminClient.updateDestination(request, callOptions);
        lifetime.signal.throwIfAborted();
        onDone();
        return response;
      });
    } else {
      const request = {
        requestId,
        config,
        reason,
        signingSecret:
          kind === DestinationKind.WEBHOOK ? new TextEncoder().encode(secret) : new Uint8Array(),
      };
      action.perform(async () => {
        const response = await adminClient.createDestination(request, callOptions);
        lifetime.signal.throwIfAborted();
        setSecret("");
        onDone();
        return response;
      });
    }
  }

  function rotate() {
    if (!destination) return;
    const request = {
      requestId: crypto.randomUUID(),
      destinationId: destination.id,
      expectedVersion: destination.version,
      signingSecret: new TextEncoder().encode(secret),
      overlapSeconds: overlap,
      reason,
    };
    action.perform(async () => {
      const response = await adminClient.rotateDestinationSecret(request, callOptions);
      lifetime.signal.throwIfAborted();
      setSecret("");
      onDone();
      return response;
    });
  }

  function remove() {
    if (!destination) return;
    const request = {
      requestId: crypto.randomUUID(),
      destinationId: destination.id,
      expectedVersion: destination.version,
      reason,
    };
    action.perform(async () => {
      const response = await adminClient.deleteDestination(request, callOptions);
      lifetime.signal.throwIfAborted();
      onDone();
      return response;
    });
  }

  return (
    <form onSubmit={save} className="grid min-w-0 gap-4">
      {action.feedback}
      <fieldset className="grid min-w-0 gap-3" disabled={action.blocked}>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-name`}>Name</Label>
          <Input
            id={`${id}-name`}
            data-freeform="new destination name"
            required
            maxLength={128}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-kind`}>Type</Label>
          <SelectField
            id={`${id}-kind`}
            className="h-9 min-w-0"
            value={kind}
            disabled={!!destination}
            onValueChange={(value) => setKind(Number(value) as DestinationKind)}
            options={[DestinationKind.WEBHOOK, DestinationKind.SYSLOG_TLS].map((value) => ({
              value,
              label: KIND_LABELS[value],
            }))}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-endpoint`}>Address</Label>
          <Input
            id={`${id}-endpoint`}
            data-freeform="external receiver URL"
            type="url"
            required
            maxLength={2048}
            className="font-mono"
            placeholder={
              kind === DestinationKind.WEBHOOK
                ? "https://receiver.example/events"
                : "tls://siem.example:6514"
            }
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-ca`}>
            CA certificate {kind === DestinationKind.SYSLOG_TLS ? "(required)" : "(optional)"}
          </Label>
          <Textarea
            id={`${id}-ca`}
            data-freeform="pasted PEM certificate"
            rows={3}
            className="max-h-40 font-mono text-xs"
            placeholder="-----BEGIN CERTIFICATE-----"
            value={ca}
            required={kind === DestinationKind.SYSLOG_TLS}
            onChange={(e) => setCa(e.target.value)}
          />
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Send events
        </label>
        {!destination && kind === DestinationKind.WEBHOOK ? (
          <div className="grid gap-2">
            <Label htmlFor={`${id}-secret`}>Signing secret</Label>
            <Input
              id={`${id}-secret`}
              type="password"
              autoComplete="new-password"
              required
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              A random 32 to 64 character secret shared with your receiver. It's never shown again.
            </p>
          </div>
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
          {destination ? "Save changes" : "Create destination"}
        </Button>
        {destination && kind === DestinationKind.WEBHOOK ? (
          <div className="grid gap-3 border-t pt-4">
            <h3 className="font-semibold">Rotate signing secret</h3>
            <div className="grid gap-2">
              <Label htmlFor={`${id}-secret`}>New signing secret</Label>
              <Input
                id={`${id}-secret`}
                type="password"
                autoComplete="new-password"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor={`${id}-overlap`}>Keep the old secret working for</Label>
              <SelectField
                id={`${id}-overlap`}
                className="h-9 w-48"
                value={overlap}
                onValueChange={(value) => setOverlap(Number(value))}
                options={OVERLAP_OPTIONS}
              />
            </div>
            <Button
              type="button"
              variant="outline"
              className="w-fit"
              disabled={!secret || !reason.trim()}
              onClick={rotate}
            >
              Rotate signing secret
            </Button>
            {!secret || !reason.trim() ? (
              <p className="text-xs text-muted-foreground">
                Enter a new secret and a reason to rotate.
              </p>
            ) : null}
          </div>
        ) : null}
        {destination ? (
          <div className="grid gap-3 border-t pt-4">
            <h3 className="font-semibold">Delete destination</h3>
            <p className="text-sm text-muted-foreground">
              Events not yet delivered to {name || "this destination"} are dropped, and new events
              are no longer sent. This can't be undone.
            </p>
            {confirmDelete ? (
              <div className="flex flex-wrap gap-2">
                <Button type="button" variant="destructive" onClick={remove}>
                  Delete {name || "destination"}
                </Button>
                <Button type="button" variant="ghost" onClick={() => setConfirmDelete(false)}>
                  Keep destination
                </Button>
              </div>
            ) : (
              <Button
                type="button"
                variant="outline"
                className="w-fit"
                disabled={!reason.trim()}
                onClick={() => setConfirmDelete(true)}
              >
                Delete destination…
              </Button>
            )}
            {!reason.trim() ? (
              <p className="text-xs text-muted-foreground">Enter a reason to delete.</p>
            ) : null}
          </div>
        ) : null}
      </fieldset>
    </form>
  );
}
