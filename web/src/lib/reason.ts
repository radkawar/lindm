// SPDX-License-Identifier: Apache-2.0

export const REASON_MAX_UNITS = 512;

export function reasonError(value: string): string {
  const trimmed = value.trim();
  if (trimmed === "" || !/\S/.test(trimmed)) {
    return "Enter a reason that contains visible text.";
  }
  if ([...trimmed].length > REASON_MAX_UNITS) {
    return `Enter a reason with no more than ${REASON_MAX_UNITS} characters.`;
  }
  return "";
}
