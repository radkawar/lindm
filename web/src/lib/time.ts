import { timestampDate, type Timestamp } from "@bufbuild/protobuf/wkt";

const localTime = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "long",
});

export function formatTimestamp(value: Timestamp | undefined): {
  local: string;
  utc: string;
  date: Date | null;
} {
  if (value === undefined) return { local: "Not recorded", utc: "", date: null };
  const date = timestampDate(value);
  if (Number.isNaN(date.getTime())) return { local: "Invalid time", utc: "", date: null };
  return { local: localTime.format(date), utc: date.toISOString(), date };
}

// Relative age for past times and "in ..." for future ones such as expiry. A
// future time is not clock skew: expiries and deadlines are legitimately ahead.
export function freshnessLabel(date: Date, now: Date): string {
  const deltaMs = now.getTime() - date.getTime();
  const future = deltaMs < 0;
  const seconds = Math.floor(Math.abs(deltaMs) / 1000);
  if (seconds < 5) return "just now";
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  const span =
    seconds < 60
      ? `${seconds} seconds`
      : minutes < 60
        ? minutes === 1
          ? "1 minute"
          : `${minutes} minutes`
        : hours < 48
          ? hours === 1
            ? "1 hour"
            : `${hours} hours`
          : days === 1
            ? "1 day"
            : `${days} days`;
  return future ? `in ${span}` : `${span} ago`;
}
