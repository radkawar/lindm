import type { Timestamp as ProtoTimestamp } from "@bufbuild/protobuf/wkt";
import { cn } from "cn";
import { formatTimestamp, shortAgeLabel } from "@/lib/time";

// One console-wide time presentation: "Oct 12, 10:18 AM BST · 4 min ago", with
// the exact local time and UTC in the title.
export function Timestamp({
  value,
  relative = true,
  missing = "Not recorded",
  className,
}: {
  value: ProtoTimestamp | undefined;
  relative?: boolean;
  missing?: string;
  className?: string;
}) {
  const formatted = formatTimestamp(value);
  if (!formatted.date) {
    return (
      <span className={cn("text-muted-foreground", className)}>
        {value === undefined ? missing : formatted.local}
      </span>
    );
  }
  return (
    <time
      dateTime={formatted.utc}
      title={`${formatted.full} · ${formatted.utc}`}
      className={cn("tabular-nums", className)}
    >
      <span className="whitespace-nowrap">{formatted.local}</span>
      {relative ? (
        <span className="whitespace-nowrap text-muted-foreground">
          {" · "}
          {shortAgeLabel(formatted.date, new Date())}
        </span>
      ) : null}
    </time>
  );
}
