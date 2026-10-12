import type { Timestamp } from "@bufbuild/protobuf/wkt";
import type { ReactNode } from "react";
import {
  CollectionStatus,
  type ObservedString,
} from "../../../gen/lindm/inventory/v1/observation_pb";
import { formatTimestamp, freshnessLabel } from "@/lib/time";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { StatusBadge } from "@/components/ui/status-badge";
import { useUnprotectedToolPath } from "./tool-custody";

export const collectionLabels: Record<CollectionStatus, string> = {
  [CollectionStatus.UNSPECIFIED]: "Not reported",
  [CollectionStatus.SUCCESS]: "Collected",
  [CollectionStatus.UNAVAILABLE]: "Not available",
  [CollectionStatus.PERMISSION_DENIED]: "Permission denied",
  [CollectionStatus.TIMEOUT]: "Timed out",
  [CollectionStatus.INVALID_OUTPUT]: "Unreadable output",
  [CollectionStatus.CAPACITY_EXCEEDED]: "Too much data",
  [CollectionStatus.NATIVE_COMMAND_FAILURE]: "Command failed",
  [CollectionStatus.NOT_APPLICABLE]: "Not applicable",
};

export function isOptionalCollectionAbsence(status: CollectionStatus | undefined) {
  return (
    status === undefined ||
    status === CollectionStatus.UNSPECIFIED ||
    status === CollectionStatus.UNAVAILABLE ||
    status === CollectionStatus.NOT_APPLICABLE
  );
}

/** A native command failure on a device with unprotected tool ancestry is the
 * agent's refusal; name the path instead of a generic failure. */
function useCollectionLabel(status: CollectionStatus | undefined) {
  const unprotected = useUnprotectedToolPath();
  return status === CollectionStatus.NATIVE_COMMAND_FAILURE && unprotected
    ? `Refused: ${unprotected.unprotectedPath} is writable by group or other`
    : (collectionLabels[status ?? CollectionStatus.UNSPECIFIED] ?? "Unknown collection status");
}

export function CollectionStatusText({
  status,
  unavailableLabel,
}: {
  status: CollectionStatus | undefined;
  unavailableLabel?: string;
}) {
  const label = useCollectionLabel(status);
  return (
    <span
      className={
        isOptionalCollectionAbsence(status) || status === CollectionStatus.SUCCESS
          ? "text-muted-foreground"
          : "text-warning"
      }
      title={CollectionStatus[status ?? CollectionStatus.UNSPECIFIED]}
    >
      {status === CollectionStatus.UNAVAILABLE && unavailableLabel ? unavailableLabel : label}
    </span>
  );
}

export function CollectionStatusBadge({ status }: { status: CollectionStatus | undefined }) {
  const label = useCollectionLabel(status);
  if (isOptionalCollectionAbsence(status)) return <CollectionStatusText status={status} />;
  return (
    <StatusBadge
      status={
        status === CollectionStatus.SUCCESS
          ? "success"
          : status === CollectionStatus.PERMISSION_DENIED ||
              status === CollectionStatus.CAPACITY_EXCEEDED
            ? "warning"
            : "destructive"
      }
    >
      {label}
    </StatusBadge>
  );
}

export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="mb-1 text-sm text-muted-foreground">{label}</dt>
      <dd className="break-words text-sm">{children}</dd>
    </div>
  );
}

export function ObservedValue({
  field,
  unavailableLabel,
}: {
  field: ObservedString | undefined;
  unavailableLabel?: string;
}) {
  return field?.status === CollectionStatus.SUCCESS ? (
    <span>{field.value}</span>
  ) : (
    <CollectionStatusText status={field?.status} unavailableLabel={unavailableLabel} />
  );
}

export function ObservedTime({
  value,
  server = false,
  relative = false,
}: {
  value: Timestamp | undefined;
  server?: boolean;
  relative?: boolean;
}) {
  const formatted = formatTimestamp(value);
  if (relative && formatted.date) {
    const age = freshnessLabel(formatted.date, new Date())
      .replace(/ seconds? ago$/, " sec ago")
      .replace(/ minutes? ago$/, " min ago")
      .replace(/ hours? ago$/, " hr ago");
    return (
      <Tooltip>
        <TooltipTrigger render={<time dateTime={formatted.utc} tabIndex={0} />}>
          {age}
        </TooltipTrigger>
        <TooltipContent>
          {formatted.local} · {formatted.utc}
          {server ? " · When the server received it." : ""}
        </TooltipContent>
      </Tooltip>
    );
  }
  return formatted.date ? (
    <time dateTime={formatted.utc} title={formatted.utc}>
      {formatted.local}
      {server ? ` (${freshnessLabel(formatted.date, new Date())})` : ""}
    </time>
  ) : (
    <span className="text-muted-foreground">{formatted.local}</span>
  );
}

const clockTime = new Intl.DateTimeFormat(undefined, { timeStyle: "short" });
const clockDateTime = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
});

// Short "since" time for current state: time of day today, otherwise date and time.
export function ObservedClock({ value }: { value: Timestamp | undefined }) {
  const formatted = formatTimestamp(value);
  if (!formatted.date) return <span>{formatted.local}</span>;
  const today = formatted.date.toDateString() === new Date().toDateString();
  return (
    <time dateTime={formatted.utc} title={`${formatted.local} · ${formatted.utc}`}>
      {(today ? clockTime : clockDateTime).format(formatted.date)}
    </time>
  );
}
