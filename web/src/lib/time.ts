import { timestampDate, type Timestamp } from "@bufbuild/protobuf/wkt";

// The console has one time format: "Oct 12, 10:18 AM BST" (the year only when it
// differs from the current one), with the full local time and UTC in a title.

const shortDateTime = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
});
const shortDateTimeWithYear = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
});
const fullDateTime = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "medium",
});
const zoneFormats = (["short", "long", "longGeneric"] as const).map(
  (timeZoneName) => new Intl.DateTimeFormat(undefined, { timeZoneName }),
);
const offsetName = /^(?:GMT|UTC)[+\-\u2212]\d/;

// The viewer's zone as people name it ("BST", "EDT"). Some locales only have an
// offset such as "GMT+1" for a zone, which hides daylight saving: then the long
// name ("British Summer Time"), plain "GMT" for a zero offset, or the generic
// region name ("United Kingdom Time").
export function timeZoneLabel(date: Date): string {
  const [short, long, generic] = zoneFormats.map(
    (format) =>
      format.formatToParts(date).find((part) => part.type === "timeZoneName")?.value ?? "",
  );
  if (short && !offsetName.test(short)) return short;
  if (long && !offsetName.test(long)) return long;
  if (date.getTimezoneOffset() === 0) return "GMT";
  return generic && !offsetName.test(generic) ? generic : short;
}

export function formatShortDateTime(date: Date, now: Date): string {
  const format = date.getFullYear() === now.getFullYear() ? shortDateTime : shortDateTimeWithYear;
  return `${format.format(date)} ${timeZoneLabel(date)}`;
}

export function formatTimestamp(value: Timestamp | undefined): {
  // Primary text: "Oct 12, 10:18 AM BST".
  local: string;
  // Exact local time with seconds, for titles and details.
  full: string;
  utc: string;
  date: Date | null;
} {
  if (value === undefined) return { local: "Not recorded", full: "", utc: "", date: null };
  const date = timestampDate(value);
  if (Number.isNaN(date.getTime())) return { local: "Invalid time", full: "", utc: "", date: null };
  return {
    local: formatShortDateTime(date, new Date()),
    full: `${fullDateTime.format(date)} ${timeZoneLabel(date)}`,
    utc: date.toISOString(),
    date,
  };
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

// Compact relative age beside a short date: "4 min ago", "in 2 hr", "3 days ago".
export function shortAgeLabel(date: Date, now: Date): string {
  return freshnessLabel(date, now)
    .replace(/ seconds?\b/, " sec")
    .replace(/ minutes?\b/, " min")
    .replace(/ hours?\b/, " hr");
}
