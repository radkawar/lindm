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
  [CollectionStatus.UNAVAILABLE]: "Unavailable",
  [CollectionStatus.PERMISSION_DENIED]: "Permission denied",
  [CollectionStatus.TIMEOUT]: "Collection timed out",
  [CollectionStatus.INVALID_OUTPUT]: "Invalid native output",
  [CollectionStatus.CAPACITY_EXCEEDED]: "Collection capacity exceeded",
  [CollectionStatus.NATIVE_COMMAND_FAILURE]: "Native command failed",
};

export function CollectionStatusBadge({ status }: { status: CollectionStatus | undefined }) {
  return (
    <StatusBadge
      status={
        status === CollectionStatus.SUCCESS
          ? "success"
          : status === undefined ||
              status === CollectionStatus.UNSPECIFIED ||
              status === CollectionStatus.UNAVAILABLE
            ? "neutral"
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

export function ObservedValue({ field }: { field: ObservedString | undefined }) {
  if (!field) return <CollectionStatusBadge status={undefined} />;
  return field.status === CollectionStatus.SUCCESS ? (
    <span>{field.value}</span>
  ) : (
    <CollectionStatusBadge status={field.status} />
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
