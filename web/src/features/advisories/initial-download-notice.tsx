// SPDX-License-Identifier: Apache-2.0

import type { Timestamp as ProtoTimestamp } from "@bufbuild/protobuf/wkt";
import { Timestamp } from "@/components/ui/timestamp";

export function InitialDownloadNotice({
  state,
  startedAt,
}: {
  state: "downloading" | "waiting";
  startedAt?: ProtoTimestamp;
}) {
  return (
    <div role="status" data-advisory-initial-download={state} className="grid gap-2 text-sm">
      <p className="font-medium">
        {state === "downloading"
          ? "Downloading first vulnerability data"
          : "Waiting for first vulnerability data"}
      </p>
      <p>
        {state === "downloading"
          ? "lindm is downloading and checking the first vulnerability data."
          : "Automatic download is enabled. The first vulnerability data is not ready yet."}{" "}
        Findings will appear after the download and device inventory check. Exposure remains unknown
        until that check finishes.
      </p>
      {state === "downloading" && startedAt ? (
        <p className="text-xs text-muted-foreground">
          Started: <Timestamp value={startedAt} relative={false} />. Download progress is not
          reported.
        </p>
      ) : null}
    </div>
  );
}
