// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { firstDownloadState } from "../src/features/advisories/initial-download.ts";

const now = 1_000_000;
const stamp = (milliseconds) => ({
  seconds: BigInt(Math.floor(milliseconds / 1000)),
  nanos: (milliseconds % 1000) * 1_000_000,
});
const pending = { refreshEnabled: true, refreshing: false, sourceSha256: "" };
const downloading = {
  ...pending,
  refreshing: true,
  refreshStartedAt: stamp(now - 1_000),
  refreshLeaseExpiresAt: stamp(now + 1_000),
};

test("enabled first download waits without claiming active work", () => {
  assert.equal(firstDownloadState(pending, now), "waiting");
  assert.equal(firstDownloadState(undefined, now), undefined);
});

test("first download requires a live publisher lease and real start", () => {
  assert.equal(firstDownloadState(downloading, now), "downloading");
  for (const change of [
    { refreshing: false },
    { refreshStartedAt: undefined },
    { refreshLeaseExpiresAt: undefined },
    { refreshLeaseExpiresAt: stamp(now) },
    { refreshLeaseExpiresAt: stamp(now - 1) },
  ]) {
    assert.equal(firstDownloadState({ ...downloading, ...change }, now), "waiting");
  }
});

test("lease expiry stops a cached downloading claim without a new response", () => {
  assert.equal(firstDownloadState(downloading, now + 1_000), "waiting");
});

test("disabled automatic refresh never claims a first download", () => {
  assert.equal(firstDownloadState({ ...pending, refreshEnabled: false }, now), undefined);
  assert.equal(firstDownloadState({ ...downloading, refreshEnabled: false }, now), undefined);
});

test("published fleet and scoped device data keep their normal evidence state", () => {
  for (const published of [
    { checkedAt: stamp(now - 10_000) },
    { feedCheckedAt: stamp(now - 10_000) },
    { sourceSha256: "published-source-proof" },
  ]) {
    assert.equal(firstDownloadState({ ...downloading, ...published }, now), undefined);
  }
});

test("failed refresh remains an error, not a waiting or downloading message", () => {
  assert.equal(firstDownloadState({ ...downloading, error: "source failed" }, now), undefined);
  assert.equal(firstDownloadState({ ...downloading, refreshFailed: true }, now), undefined);
  assert.equal(firstDownloadState({ ...pending, refreshFailed: true }, now), undefined);
});
