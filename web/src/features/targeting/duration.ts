// Exact whole-unit durations for saved rollout settings: "90 seconds" → "1 minute 30 seconds".
export function formatSeconds(total: number) {
  const units: [number, string][] = [
    [86400, "day"],
    [3600, "hour"],
    [60, "minute"],
    [1, "second"],
  ];
  const parts: string[] = [];
  let rest = Math.max(0, Math.floor(total));
  for (const [size, name] of units) {
    const count = Math.floor(rest / size);
    if (count === 0) continue;
    parts.push(`${count} ${name}${count === 1 ? "" : "s"}`);
    rest -= count * size;
  }
  return parts.join(" ") || "0 seconds";
}
