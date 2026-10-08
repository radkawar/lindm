export const REASON_MAX_UNITS = 512;

export function reasonError(value: string): string {
  const trimmed = value.trim();
  if (trimmed === "" || !/\S/.test(trimmed)) {
    return "Reason must contain non-whitespace text.";
  }
  if ([...trimmed].length > REASON_MAX_UNITS) {
    return `Reason must be at most ${REASON_MAX_UNITS} characters.`;
  }
  return "";
}
