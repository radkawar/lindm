import type { Timestamp } from "@bufbuild/protobuf/wkt";
import type { ReactNode } from "react";
import {
  CollectionStatus,
  type ObservedString,
} from "../../../gen/lindm/inventory/v1/observation_pb";
import { formatTimestamp, freshnessLabel } from "@/lib/time";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { StatusBadge } from "@/components/ui/status-badge";

export const collectionLabels: Record<CollectionStatus, string> = {
  [CollectionStatus.UNSPECIFIED]: "Not reported",
  [CollectionStatus.SUCCESS]: "Successful collection",
  [CollectionStatus.UNAVAILABLE]: "Not available",
  [CollectionStatus.PERMISSION_DENIED]: "Permission denied",
  [CollectionStatus.TIMEOUT]: "Collection timed out",
  [CollectionStatus.INVALID_OUTPUT]: "Invalid native output",
  [CollectionStatus.CAPACITY_EXCEEDED]: "Collection capacity exceeded",
  [CollectionStatus.NATIVE_COMMAND_FAILURE]: "Native command failed",
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

export function CollectionStatusText({
  status,
  unavailableLabel,
}: {
  status: CollectionStatus | undefined;
  unavailableLabel?: string;
}) {
  const label =
    collectionLabels[status ?? CollectionStatus.UNSPECIFIED] ?? "Unknown collection status";
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
      {collectionLabels[status ?? CollectionStatus.UNSPECIFIED] ?? "Unknown collection status"}
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
          {server ? " · Server receipt time, not live presence or inventory freshness." : ""}
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
