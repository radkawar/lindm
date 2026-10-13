import { create } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import { useQuery } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
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
import { reasonError } from "@/lib/reason";
import {
  DestinationConfigSchema,
  DestinationKind,
  type CertificateSummary,
  type DeliverySummary,
  type Destination,
} from "../../../gen/lindm/integrations/v1/delivery_pb";
import { useIntegrationAction, type IntegrationAction } from "./action";
import { destinationHealth, plural } from "./health";
import { deliverySummaryQueryOptions, destinationsQueryOptions } from "./queries";

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

// The same rules the server enforces (DestinationConfig and request CEL), checked
// before submit so each field explains itself.
const WEBHOOK_ENDPOINT = /^https:\/\/[^/@?#]+(\/[^?#]*)?$/;
const SYSLOG_ENDPOINT = /^tls:\/\/[^/@?#]+:[0-9]+$/;

function secretError(secret: string): string {
  const size = new TextEncoder().encode(secret).length;
  if (size === 0) return "Enter a signing secret, or generate one.";
  if (size < 32 || size > 64) {
    return `Use 32 to 64 characters. This secret has ${size}. Select Generate to create a secret.`;
  }
  return "";
}

// Shown only when a certificate must be supplied: syslog trust or an explicit
// pin/replace; an empty value there would silently drop pinning.
function caError(ca: string): string {
  const text = ca.trim();
  if (text === "") return "Paste the CA certificate that signed the receiver's certificate.";
  if (!text.startsWith("-----BEGIN CERTIFICATE-----") || /PRIVATE KEY/.test(text)) {
    return "Paste only PEM certificates starting with -----BEGIN CERTIFICATE-----, never a key.";
  }
  return "";
}

/** 48 random URL-safe characters (288 bits) for a new signing secret. */
function generateSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(36));
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_");
}

export function Destinations() {
  const lifetime = useAuthLifetime();
  const [page, setPage] = useState("");
  const [adding, setAdding] = useState(false);
  const addAction = useIntegrationAction();
  const list = useQuery(destinationsQueryOptions(lifetime, page));
  const summary = useQuery(deliverySummaryQueryOptions(lifetime));
  const summaries = new Map(summary.data?.summaries.map((row) => [row.destinationId, row]) ?? []);
  return (
    <section
      className="grid min-w-0 gap-3"
      aria-labelledby="destinations-heading"
      aria-busy={list.isFetching}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="grid gap-1">
          <h2 id="destinations-heading" className="text-base font-semibold">
            Destinations
          </h2>
          <p className="text-sm text-muted-foreground">
            New audit events go to every destination that is sending.
          </p>
        </div>
        <Button onClick={() => setAdding(true)}>
          {addAction.blocked ? "Review pending destination" : "Add destination"}
        </Button>
      </div>
      <Dialog open={adding} onOpenChange={setAdding}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Add destination</DialogTitle>
            <DialogDescription>
              The server sends only audit events recorded after creation.
            </DialogDescription>
          </DialogHeader>
          <DestinationForm action={addAction} onDone={() => setAdding(false)} />
        </DialogContent>
      </Dialog>
      {list.error ? <RpcError failure={toRpcFailure(list.error)} /> : null}
      {summary.error ? (
        <RpcError failure={toRpcFailure(summary.error)} title="Delivery health unavailable" />
      ) : null}
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
              : "The server sends no audit events. Add a webhook or syslog server to start sending."
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
              <TableHead>Health</TableHead>
              <TableHead>Address</TableHead>
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
                summary={summaries.get(destination.id)}
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

function destinationName(destination: Destination) {
  return destination.config?.displayName.trim() || "Unnamed destination";
}

function overlapEnd(destination: Destination): Date | null {
  if (!destination.previousSecretExpiresAt) return null;
  const end = timestampDate(destination.previousSecretExpiresAt);
  return end.getTime() > Date.now() ? end : null;
}

function DestinationRow({
  destination,
  summary,
}: {
  destination: Destination;
  summary: DeliverySummary | undefined;
}) {
  const editAction = useIntegrationAction();
  const rotateAction = useIntegrationAction();
  const deleteAction = useIntegrationAction();
  const [open, setOpen] = useState<"" | "edit" | "rotate" | "delete">("");
  const name = destinationName(destination);
  const health = destinationHealth(destination, summary);
  const webhook = destination.config?.kind === DestinationKind.WEBHOOK;
  const overlap = overlapEnd(destination);
  return (
    <TableRow className="align-top">
      <TableCell className="min-w-40 whitespace-normal break-words">
        <span className="font-medium">{name}</span>
        <p className="text-xs text-muted-foreground">
          {KIND_LABELS[destination.config?.kind ?? DestinationKind.UNSPECIFIED]}
        </p>
        <TechnicalDetails
          items={[
            { label: "Destination ID", value: destination.id },
            { label: "Revision", value: destination.version.toString() },
            { label: "Delivery reason", value: summary?.lastError },
          ]}
        />
      </TableCell>
      <TableCell className="min-w-48 max-w-sm whitespace-normal">
        <StatusBadge status={health.tone}>{health.label}</StatusBadge>
        {health.detail ? <p className="mt-1 text-xs">{health.detail}</p> : null}
        {summary?.lastDeliveredAt && destination.config?.enabled ? (
          <p className="mt-1 text-xs text-muted-foreground">
            Last delivered <Timestamp value={summary.lastDeliveredAt} />
          </p>
        ) : null}
        {overlap ? (
          <p className="mt-1 text-xs text-muted-foreground">
            Old signing secret works until <Timestamp value={destination.previousSecretExpiresAt} />
          </p>
        ) : null}
      </TableCell>
      <TableCell className="min-w-48 max-w-md whitespace-normal break-all font-mono text-xs">
        {destination.config?.endpoint}
      </TableCell>
      <TableCell>
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="outline" size="sm" onClick={() => setOpen("edit")}>
            {editAction.blocked ? "Review pending change" : "Edit"}
          </Button>
          {webhook ? (
            <Button variant="outline" size="sm" onClick={() => setOpen("rotate")}>
              {rotateAction.blocked ? "Review pending rotation" : "Rotate secret"}
            </Button>
          ) : null}
          <Button
            variant="ghost"
            size="sm"
            aria-label={`Remove ${name}`}
            title={`Remove ${name}`}
            onClick={() => setOpen("delete")}
          >
            <Trash2 aria-hidden="true" />
          </Button>
        </div>
        <RowDialog
          open={open === "edit"}
          onClose={() => setOpen("")}
          title={`Edit ${name}`}
          description="Changes affect events sent after you save. You cannot change the destination type."
        >
          <DestinationForm
            destination={destination}
            action={editAction}
            onDone={() => setOpen("")}
          />
        </RowDialog>
        <RowDialog
          open={open === "rotate"}
          onClose={() => setOpen("")}
          title={`Rotate signing secret for ${name}`}
          description="The receiver checks each event's signature with this secret."
        >
          <RotateForm destination={destination} action={rotateAction} onDone={() => setOpen("")} />
        </RowDialog>
        <RowDialog
          open={open === "delete"}
          onClose={() => setOpen("")}
          title={`Remove ${name}`}
          description="You cannot undo this removal."
        >
          <DeleteForm
            destination={destination}
            summary={summary}
            action={deleteAction}
            onDone={() => setOpen("")}
          />
        </RowDialog>
      </TableCell>
    </TableRow>
  );
}

function RowDialog({
  open,
  onClose,
  title,
  description,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <Dialog open={open} onOpenChange={(next) => (next ? undefined : onClose())}>
      <DialogContent className="max-h-[90vh] overflow-y-auto text-left sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="break-words">{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        {children}
      </DialogContent>
    </Dialog>
  );
}

function FieldError({ id, message }: { id: string; message: string }) {
  if (!message) return null;
  return (
    <p id={id} className="text-xs text-destructive">
      {message}
    </p>
  );
}

function ReasonField({
  id,
  value,
  onChange,
  error,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  error: string;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={`${id}-reason`}>Reason (audited)</Label>
      <Input
        id={`${id}-reason`}
        data-freeform="audit reason"
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${id}-reason-error` : undefined}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <FieldError id={`${id}-reason-error`} message={error} />
    </div>
  );
}

function CertificateLine({ certificate }: { certificate: CertificateSummary }) {
  const expired = certificate.notAfter && timestampDate(certificate.notAfter) < new Date();
  return (
    <li className="grid gap-1">
      <span className="break-words font-medium">{certificate.subject}</span>
      <span className="text-xs">
        {expired ? "Expired " : "Expires "}
        <Timestamp value={certificate.notAfter} relative={false} />
      </span>
      <span className="break-all font-mono text-xs text-muted-foreground">
        SHA-256 {certificate.sha256Fingerprint}
      </span>
    </li>
  );
}

type FieldKey = "name" | "endpoint" | "ca" | "secret" | "reason";

// Proto field names of a server violation → the form input it belongs under.
const SERVER_FIELDS: Record<string, FieldKey> = {
  display_name: "name",
  endpoint: "endpoint",
  pinned_ca_pem: "ca",
  signing_secret: "secret",
  reason: "reason",
};

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
  // The stored PEM is never shown; it is sent back unchanged unless replaced.
  const [replacingCa, setReplacingCa] = useState(false);
  const [ca, setCa] = useState("");
  const [enabled, setEnabled] = useState(destination?.config?.enabled ?? true);
  const [secret, setSecret] = useState("");
  const [shownSecret, setShownSecret] = useState(false);
  const [reason, setReason] = useState("");
  const [attempted, setAttempted] = useState(false);
  // Server refusals with buf.validate violations, placed under their inputs.
  const [serverErrors, setServerErrors] = useState<Partial<Record<FieldKey, string>>>({});
  const id = destination?.id ?? "new";
  const syslog = kind === DestinationKind.SYSLOG_TLS;
  const storedCertificates = destination?.pinnedCaCertificates ?? [];
  const storedPem = destination?.config?.pinnedCaPem ?? "";
  // Syslog without stored trust must take a PEM; otherwise PEM input is opt-in.
  const editingCa = replacingCa || (syslog && !storedPem);
  const errors = {
    name: name.trim() === "" ? "Enter a name, for example SOC webhook." : "",
    endpoint: syslog
      ? SYSLOG_ENDPOINT.test(endpoint.trim())
        ? ""
        : "Use a TLS address, such as tls://siem.example:6514."
      : WEBHOOK_ENDPOINT.test(endpoint.trim())
        ? ""
        : "Use an https:// address, for example https://receiver.example/events. Plain http:// isn't allowed.",
    ca: editingCa ? caError(ca) : "",
    secret: !destination && !syslog ? secretError(secret) : "",
    reason: reasonError(reason),
  };
  const shown = (key: FieldKey) => serverErrors[key] || (attempted ? errors[key] : "");

  async function placeServerErrors<T>(send: () => Promise<T>): Promise<T> {
    try {
      return await send();
    } catch (error) {
      const placed: Partial<Record<FieldKey, string>> = {};
      for (const field of toRpcFailure(error).fields ?? []) {
        const key = SERVER_FIELDS[field.field];
        if (key && !placed[key]) placed[key] = field.message;
      }
      setServerErrors(placed);
      throw error;
    }
  }

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAttempted(true);
    setServerErrors({});
    if (Object.values(errors).some(Boolean)) return;
    const config = create(DestinationConfigSchema, {
      displayName: name.trim(),
      kind,
      endpoint: endpoint.trim(),
      pinnedCaPem: editingCa ? ca.trim() : storedPem,
      enabled,
    });
    const requestId = crypto.randomUUID();
    const callOptions = { signal: lifetime.signal };
    if (destination) {
      const request = {
        requestId,
        destinationId: destination.id,
        expectedVersion: destination.version,
        config,
        reason,
      };
      action.perform(async () => {
        const response = await placeServerErrors(() =>
          adminClient.updateDestination(request, callOptions),
        );
        lifetime.signal.throwIfAborted();
        onDone();
        return response;
      });
      return;
    }
    const request = {
      requestId,
      config,
      reason,
      signingSecret: syslog ? new Uint8Array() : new TextEncoder().encode(secret),
    };
    action.perform(async () => {
      const response = await placeServerErrors(() =>
        adminClient.createDestination(request, callOptions),
      );
      lifetime.signal.throwIfAborted();
      setSecret("");
      onDone();
      return response;
    });
  }

  return (
    <form onSubmit={save} noValidate className="grid min-w-0 gap-4">
      {action.feedback}
      <fieldset className="grid min-w-0 gap-3" disabled={action.blocked}>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-name`}>Name</Label>
          <Input
            id={`${id}-name`}
            data-freeform="new destination name"
            maxLength={128}
            aria-invalid={shown("name") ? true : undefined}
            aria-describedby={shown("name") ? `${id}-name-error` : undefined}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <FieldError id={`${id}-name-error`} message={shown("name")} />
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
            maxLength={2048}
            className="font-mono"
            placeholder={syslog ? "tls://siem.example:6514" : "https://receiver.example/events"}
            aria-invalid={shown("endpoint") ? true : undefined}
            aria-describedby={shown("endpoint") ? `${id}-endpoint-error` : undefined}
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
          />
          <FieldError id={`${id}-endpoint-error`} message={shown("endpoint")} />
        </div>
        <div className="grid gap-2" role="group" aria-labelledby={`${id}-ca-heading`}>
          <span id={`${id}-ca-heading`} className="text-sm font-medium">
            CA certificate {syslog ? "(required)" : "(optional)"}
          </span>
          {storedCertificates.length > 0 && !replacingCa ? (
            <ul className="grid gap-2 border p-3" aria-label="Pinned CA certificate">
              {storedCertificates.map((certificate) => (
                <CertificateLine key={certificate.sha256Fingerprint} certificate={certificate} />
              ))}
            </ul>
          ) : null}
          {!editingCa && !storedPem ? (
            <p className="text-xs text-muted-foreground">
              Trusts the receiver's public certificate authorities.
            </p>
          ) : null}
          {editingCa ? (
            <>
              <Label htmlFor={`${id}-ca`} className="sr-only">
                {storedPem ? "Replacement CA certificate (PEM)" : "CA certificate (PEM)"}
              </Label>
              <Textarea
                id={`${id}-ca`}
                data-freeform="pasted PEM certificate"
                rows={3}
                className="max-h-40 font-mono text-xs"
                placeholder="-----BEGIN CERTIFICATE-----"
                aria-invalid={shown("ca") ? true : undefined}
                aria-describedby={shown("ca") ? `${id}-ca-error` : undefined}
                value={ca}
                onChange={(e) => setCa(e.target.value)}
              />
              <FieldError id={`${id}-ca-error`} message={shown("ca")} />
            </>
          ) : null}
          {storedPem ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="w-fit"
              onClick={() => {
                setReplacingCa(!replacingCa);
                setCa("");
              }}
            >
              {replacingCa ? "Keep current certificate" : "Replace certificate"}
            </Button>
          ) : !syslog ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="w-fit"
              onClick={() => {
                setReplacingCa(!replacingCa);
                setCa("");
              }}
            >
              {replacingCa ? "Use public certificate authorities" : "Pin a CA certificate"}
            </Button>
          ) : null}
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Send events
        </label>
        {!destination && !syslog ? (
          <div className="grid gap-2">
            <Label htmlFor={`${id}-secret`}>Signing secret</Label>
            <div className="flex gap-2">
              <Input
                id={`${id}-secret`}
                type={shownSecret ? "text" : "password"}
                autoComplete="new-password"
                className={shownSecret ? "font-mono" : undefined}
                aria-invalid={shown("secret") ? true : undefined}
                aria-describedby={`${id}-secret-hint`}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                data-freeform="new signing secret shared with the receiver"
              />
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setSecret(generateSecret());
                  setShownSecret(true);
                }}
              >
                Generate
              </Button>
            </div>
            <p id={`${id}-secret-hint`} className="text-xs text-muted-foreground">
              32 to 64 characters, shared with your receiver. It's never shown again after creation.
            </p>
            <FieldError id={`${id}-secret-error`} message={shown("secret")} />
          </div>
        ) : null}
        <ReasonField id={id} value={reason} onChange={setReason} error={shown("reason")} />
        <Button type="submit" className="w-fit">
          {destination ? "Save changes" : "Create destination"}
        </Button>
      </fieldset>
    </form>
  );
}

function RotateForm({
  destination,
  action,
  onDone,
}: {
  destination: Destination;
  action: IntegrationAction;
  onDone: () => void;
}) {
  const lifetime = useAuthLifetime();
  const [secret, setSecret] = useState("");
  const [shownSecret, setShownSecret] = useState(false);
  const [overlap, setOverlap] = useState(3600);
  const [reason, setReason] = useState("");
  const [attempted, setAttempted] = useState(false);
  const id = `${destination.id}-rotate`;
  const active = overlapEnd(destination);
  if (active && !action.blocked) {
    return (
      <p className="text-sm">
        The secret replaced by the last rotation still works until{" "}
        <Timestamp value={destination.previousSecretExpiresAt} />. You can rotate again after that.
      </p>
    );
  }
  const errors = { secret: secretError(secret), reason: reasonError(reason) };
  const label = OVERLAP_OPTIONS.find((option) => option.value === overlap)?.label ?? "";
  const deadline = timestampFromDate(new Date(Date.now() + overlap * 1000));

  function rotate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAttempted(true);
    if (errors.secret || errors.reason) return;
    const request = {
      requestId: crypto.randomUUID(),
      destinationId: destination.id,
      expectedVersion: destination.version,
      signingSecret: new TextEncoder().encode(secret),
      overlapSeconds: overlap,
      reason,
    };
    action.perform(async () => {
      const response = await adminClient.rotateDestinationSecret(request, {
        signal: lifetime.signal,
      });
      lifetime.signal.throwIfAborted();
      setSecret("");
      onDone();
      return response;
    });
  }

  return (
    <form onSubmit={rotate} noValidate className="grid min-w-0 gap-4">
      {action.feedback}
      <fieldset className="grid min-w-0 gap-3" disabled={action.blocked}>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-secret`}>New signing secret</Label>
          <div className="flex gap-2">
            <Input
              id={`${id}-secret`}
              type={shownSecret ? "text" : "password"}
              autoComplete="new-password"
              className={shownSecret ? "font-mono" : undefined}
              aria-invalid={attempted && errors.secret ? true : undefined}
              aria-describedby={`${id}-secret-hint`}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              data-freeform="new signing secret shared with the receiver"
            />
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setSecret(generateSecret());
                setShownSecret(true);
              }}
            >
              Generate
            </Button>
          </div>
          <p id={`${id}-secret-hint`} className="text-xs text-muted-foreground">
            32 to 64 characters. Copy it to the receiver. The console never shows it again.
          </p>
          <FieldError id={`${id}-secret-error`} message={attempted ? errors.secret : ""} />
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
        <p className="border-l-2 border-warning pl-3 text-sm" aria-live="polite">
          {overlap > 0 ? (
            <>
              The old secret works for {label}. Update the receiver before{" "}
              <Timestamp value={deadline} relative={false} />.
            </>
          ) : (
            <>
              The old secret stops working immediately. The receiver rejects events until it has the
              new secret.
            </>
          )}
        </p>
        <ReasonField
          id={id}
          value={reason}
          onChange={setReason}
          error={attempted ? errors.reason : ""}
        />
        <Button type="submit" className="w-fit">
          Rotate secret
        </Button>
      </fieldset>
    </form>
  );
}

function DeleteForm({
  destination,
  summary,
  action,
  onDone,
}: {
  destination: Destination;
  summary: DeliverySummary | undefined;
  action: IntegrationAction;
  onDone: () => void;
}) {
  const lifetime = useAuthLifetime();
  const [reason, setReason] = useState("");
  const [attempted, setAttempted] = useState(false);
  const name = destinationName(destination);
  const pending = summary ? summary.failed + summary.retrying + summary.queued : undefined;
  const error = reasonError(reason);

  function remove(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAttempted(true);
    if (error) return;
    const request = {
      requestId: crypto.randomUUID(),
      destinationId: destination.id,
      expectedVersion: destination.version,
      reason,
    };
    action.perform(async () => {
      const response = await adminClient.deleteDestination(request, { signal: lifetime.signal });
      lifetime.signal.throwIfAborted();
      onDone();
      return response;
    });
  }

  return (
    <form onSubmit={remove} noValidate className="grid min-w-0 gap-4">
      {action.feedback}
      <p className="border-l-2 border-destructive pl-3 text-sm">
        {name} stops receiving events.{" "}
        {pending === undefined
          ? "The server removes events that have not reached this destination."
          : pending > 0n
            ? `The server removes ${plural(pending, "event")} that have not reached this destination.`
            : "No events are waiting for this destination."}
      </p>
      <fieldset className="grid min-w-0 gap-3" disabled={action.blocked}>
        <ReasonField
          id={`${destination.id}-delete`}
          value={reason}
          onChange={setReason}
          error={attempted ? error : ""}
        />
        <Button type="submit" variant="destructive" className="w-fit">
          Remove destination
        </Button>
      </fieldset>
    </form>
  );
}
