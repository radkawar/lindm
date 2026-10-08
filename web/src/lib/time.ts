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

export function freshnessLabel(date: Date, now: Date): string {
  const deltaMs = now.getTime() - date.getTime();
  if (deltaMs < 0) return "browser clock is behind this server time";
  const seconds = Math.floor(deltaMs / 1000);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds} seconds ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
  const days = Math.floor(hours / 24);
  return days === 1 ? "1 day ago" : `${days} days ago`;
}
