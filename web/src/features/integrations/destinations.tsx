import { create } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { EmptyState } from "@/components/ui/empty-state";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { adminClient } from "@/lib/rpc";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import {
  DestinationConfigSchema,
  DestinationKind,
  type Destination,
} from "../../../gen/lindm/integrations/v1/delivery_pb";
import { useIntegrationAction } from "./action";
import { destinationsQueryOptions } from "./queries";

export function Destinations() {
  const lifetime = useAuthLifetime();
  const [page, setPage] = useState("");
  const list = useQuery(destinationsQueryOptions(lifetime, page));
  return (
    <section
      className="grid min-w-0 gap-4 border-t pt-6"
      aria-label="Delivery destinations"
      aria-busy={list.isFetching}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-semibold">Destinations</h2>
        <Button variant="outline" disabled={list.isFetching} onClick={() => void list.refetch()}>
          Refresh
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">
        Send audit events to a webhook or a syslog server. Turning a destination off pauses
        delivery.
      </p>
      <DestinationEditor />
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading destinations…</span>
          <Skeleton className="h-32 w-full" />
        </div>
      ) : null}
      {list.data?.destinations.length === 0 ? (
        <EmptyState
          title="No destinations yet"
          description="Add one to start sending audit events."
        />
      ) : null}
      {list.data?.destinations.map((destination) => (
        <DestinationEditor
          key={`${destination.id}:${destination.version}`}
          destination={destination}
        />
      ))}
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

function DestinationEditor({ destination }: { destination?: Destination }) {
  const lifetime = useAuthLifetime();
  const action = useIntegrationAction();
  const [name, setName] = useState(destination?.config?.displayName ?? "");
  const [kind, setKind] = useState(destination?.config?.kind ?? DestinationKind.WEBHOOK);
  const [endpoint, setEndpoint] = useState(destination?.config?.endpoint ?? "");
  const [ca, setCa] = useState(destination?.config?.pinnedCaPem ?? "");
  const [enabled, setEnabled] = useState(destination?.config?.enabled ?? true);
  const [secret, setSecret] = useState("");
  const [overlap, setOverlap] = useState(3600);
  const [reason, setReason] = useState("");
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
      action.perform(() => adminClient.updateDestination(request, callOptions));
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
        setName("");
        setEndpoint("");
        setCa("");
        setReason("");
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
      return response;
    });
  }

  return (
    <form onSubmit={save} className="grid min-w-0 gap-4 border bg-card p-4 sm:p-6">
      <h3 className="break-words font-semibold">
        {destination
          ? `Edit ${destination.config?.displayName || "destination"}`
          : "Add destination"}
      </h3>
      {destination ? (
        <TechnicalDetails
          items={[
            { label: "Destination ID", value: destination.id },
            { label: "Revision", value: destination.version.toString() },
          ]}
        />
      ) : null}
      {action.feedback}
      <fieldset className="grid min-w-0 gap-3" disabled={action.blocked}>
        <Label htmlFor={`${id}-name`}>Name</Label>
        <Input id={`${id}-name`} required value={name} onChange={(e) => setName(e.target.value)} />
        <Label htmlFor={`${id}-kind`}>Type</Label>
        <SelectField
          id={`${id}-kind`}
          className="h-9 min-w-0"
          value={kind}
          disabled={!!destination}
          onValueChange={(value) => setKind(Number(value) as DestinationKind)}
          options={[
            { value: DestinationKind.WEBHOOK, label: "HTTPS webhook" },
            { value: DestinationKind.SYSLOG_TLS, label: "Syslog over TLS" },
          ]}
        />
        <Label htmlFor={`${id}-endpoint`}>Address</Label>
        <Input
          id={`${id}-endpoint`}
          required
          placeholder={
            kind === DestinationKind.WEBHOOK
              ? "https://receiver.example/events"
              : "tls://siem.example:6514"
          }
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
        />
        <Label htmlFor={`${id}-ca`}>
          CA certificate {kind === DestinationKind.SYSLOG_TLS ? "(required)" : "(optional)"}
        </Label>
        <Textarea
          id={`${id}-ca`}
          rows={3}
          className="font-mono text-xs"
          value={ca}
          required={kind === DestinationKind.SYSLOG_TLS}
          onChange={(e) => setCa(e.target.value)}
        />
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Send events
        </label>
        <Label htmlFor={`${id}-reason`}>Reason</Label>
        <Input
          id={`${id}-reason`}
          required
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        {kind === DestinationKind.WEBHOOK ? (
          <>
            <Label htmlFor={`${id}-secret`}>
              {destination ? "New signing secret (to rotate)" : "Signing secret"}
            </Label>
            <Input
              id={`${id}-secret`}
              type="password"
              autoComplete="new-password"
              required={!destination}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              A random 32 to 64 character secret shared with your receiver. It's never shown again.
            </p>
          </>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button type="submit">{destination ? "Save" : "Create destination"}</Button>
          {destination ? (
            <Button
              type="button"
              variant="destructive"
              disabled={!reason.trim()}
              onClick={() => {
                if (!window.confirm(`Delete ${name}? Undelivered events will be dropped.`)) return;
                const request = {
                  requestId: crypto.randomUUID(),
                  destinationId: destination.id,
                  expectedVersion: destination.version,
                  reason,
                };
                action.perform(() => adminClient.deleteDestination(request, callOptions));
              }}
            >
              Delete destination
            </Button>
          ) : null}
        </div>
        {destination && kind === DestinationKind.WEBHOOK ? (
          <>
            <Label htmlFor={`${id}-overlap`}>Keep old secret working for (seconds)</Label>
            <Input
              id={`${id}-overlap`}
              type="number"
              value={overlap}
              onChange={(e) => setOverlap(Number(e.target.value))}
            />
            <Button
              type="button"
              variant="outline"
              disabled={!secret || !reason.trim()}
              onClick={rotate}
            >
              Rotate signing secret
            </Button>
            <p className="text-xs">
              Old secret stops working: {formatTimestamp(destination.previousSecretExpiresAt).local}
            </p>
          </>
        ) : null}
      </fieldset>
    </form>
  );
}
