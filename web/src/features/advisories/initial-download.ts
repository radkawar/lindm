// SPDX-License-Identifier: Apache-2.0

import type { Timestamp } from "@bufbuild/protobuf/wkt";

// Both the fleet source and scoped device freshness carry the live publisher lease.
// A retained publication must keep its stale/partial/error interpretation instead.
type DownloadStatus = {
  refreshEnabled: boolean;
  refreshing: boolean;
  refreshStartedAt?: Timestamp;
  refreshLeaseExpiresAt?: Timestamp;
  checkedAt?: Timestamp;
  feedCheckedAt?: Timestamp;
  sourceSha256: string;
  error?: string;
  refreshFailed?: boolean;
};
export function firstDownloadState(status: DownloadStatus | undefined, now: number) {
  if (
    status === undefined ||
    !status.refreshEnabled ||
    status.checkedAt !== undefined ||
    status.feedCheckedAt !== undefined ||
    status.sourceSha256 !== "" ||
    status.error ||
    status.refreshFailed
  ) {
    return undefined;
  }
  const live =
    status.refreshing &&
    status.refreshStartedAt !== undefined &&
    status.refreshLeaseExpiresAt !== undefined &&
    Number(status.refreshLeaseExpiresAt.seconds) * 1000 +
      status.refreshLeaseExpiresAt.nanos / 1_000_000 >
      now;
  return live ? "downloading" : "waiting";
}
