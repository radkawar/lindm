// SPDX-License-Identifier: Apache-2.0

export function sourceRetrySummary(count: bigint): string {
  return `Retries for latest refresh: ${count.toString()}`;
}

export function sourceVendorRaceRefetchSummary(count: bigint): string {
  return `Vendor publication race refetches for latest refresh: ${count.toString()}`;
}
