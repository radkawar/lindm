// Human sizes for primary text (docs/design.md, "Numbers and units"): binary
// units, three significant figures at most. Exact byte counts belong in a
// technical-details disclosure, never in primary text.
const units = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"] as const;

export function formatBytes(value: bigint | number): string {
  const bytes = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isFinite(bytes) || bytes < 0) return "Size not reported";
  if (bytes < 1024) return bytes === 1 ? "1 byte" : `${Math.round(bytes)} bytes`;
  let scaled = bytes;
  let unit = -1;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  // 1023.6 KiB rounds to "1024 KiB"; promote so the figure stays below 1024.
  if (Math.round(scaled) >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  const figure =
    scaled < 10 ? (Math.round(scaled * 10) / 10).toString() : Math.round(scaled).toString();
  return `${figure} ${units[unit]}`;
}

// Exact count with grouping, for technical details next to formatBytes.
export function exactBytes(value: bigint | number): string {
  return `${value.toLocaleString("en-US")} bytes`;
}
