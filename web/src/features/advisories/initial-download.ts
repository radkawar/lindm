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

// This is source preparation for the same OS, not proof that the source covers
// every unchecked device's architecture or stream. Only evaluation can prove that.
export function initialSourceForOS<T extends DownloadStatus & { distro: string; release: string }>(
  sources: readonly T[],
  osId: string,
  osVersion: string,
  now: number,
) {
  if (osId === "" || osVersion === "") return undefined;
  let waiting: T | undefined;
  for (const source of sources) {
    if (source.distro !== osId || source.release !== osVersion) continue;
    const state = firstDownloadState(source, now);
    if (state === "downloading") return source;
    if (state === "waiting") waiting ??= source;
  }
  return waiting;
}

export function unavailableSourceDescription(
  os: string,
  source: DownloadStatus | undefined,
  now: number,
) {
  const state = firstDownloadState(source, now);
  if (state) {
    return {
      title:
        state === "downloading"
          ? `Downloading first vulnerability data for ${os}`
          : `Waiting for first vulnerability data for ${os}`,
      detail:
        (state === "downloading"
          ? `A source for ${os} is downloading and checking its first vulnerability data.`
          : `Automatic download is enabled for a source for ${os}.`) +
        " No source was applied to these devices at the last check. Exposure remains unknown until a matching source is ready and the inventory check finishes.",
      fix: "source" as const,
    };
  }
  return {
    title: `No source applied for ${os}`,
    detail: `No ${os} source was applied at the last device check. Review the current advisory sources and wait for the next check.`,
    fix: "sources" as const,
  };
}
