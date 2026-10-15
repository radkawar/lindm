// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import {
  firstDownloadState,
  initialSourceForOS,
  unavailableSourceDescription,
} from "../src/features/advisories/initial-download.ts";

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

test("a newly downloading OS source supersedes old global absence copy, not the device assessment", () => {
  const source = { ...downloading, distro: "ubuntu", release: "24.04" };
  assert.equal(initialSourceForOS([source], "ubuntu", "24.04", now), source);
  const copy = unavailableSourceDescription("Ubuntu 24.04 LTS", source, now);
  assert.match(copy.title, /^Downloading first vulnerability data/);
  assert.match(copy.detail, /No source was applied.*last check/);
  assert.match(copy.detail, /Exposure remains unknown until a matching source is ready/);
  assert.doesNotMatch(copy.detail, /server has no|devices are covered|exposure is clear/i);
  assert.equal(copy.fix, "source");
});

test("OS source preparation requires exact known OS identity and real first-publication metadata", () => {
  const source = { ...downloading, distro: "ubuntu", release: "24.04" };
  for (const [osId, osVersion] of [
    ["debian", "24.04"],
    ["ubuntu", "22.04"],
    ["", "24.04"],
    ["ubuntu", ""],
  ]) {
    assert.equal(initialSourceForOS([source], osId, osVersion, now), undefined);
  }
  for (const retained of [
    { checkedAt: stamp(now - 10_000) },
    { sourceSha256: "published-proof" },
    { error: "refresh failed" },
    { refreshEnabled: false },
  ]) {
    assert.equal(
      initialSourceForOS([{ ...source, ...retained }], "ubuntu", "24.04", now),
      undefined,
    );
  }
  assert.equal(initialSourceForOS([], "ubuntu", "24.04", now), undefined);
});

test("live OS preparation takes priority over waiting without asserting architecture or stream coverage", () => {
  const waiting = { ...pending, distro: "rhel", release: "9", platformStream: "eus" };
  const live = { ...downloading, distro: "rhel", release: "9", platformStream: "standard" };
  assert.equal(initialSourceForOS([waiting, live], "rhel", "9", now), live);
  assert.equal(initialSourceForOS([waiting], "rhel", "9", now), waiting);
  const copy = unavailableSourceDescription("RHEL 9", waiting, now);
  assert.match(copy.title, /^Waiting/);
  assert.doesNotMatch(copy.detail, /is downloading/);
  assert.match(copy.detail, /matching source/);
});

test("unconfigured, failed, retained or disabled source keeps absence at the last check, not a global claim", () => {
  for (const source of [
    undefined,
    { ...downloading, error: "failed" },
    { ...downloading, refreshEnabled: false },
    { ...downloading, checkedAt: stamp(now - 10_000) },
  ]) {
    const copy = unavailableSourceDescription("Ubuntu 24.04 LTS", source, now);
    assert.equal(copy.title, "No source applied for Ubuntu 24.04 LTS");
    assert.match(copy.detail, /last device check/);
    assert.doesNotMatch(copy.detail, /is downloading|server has no/);
    assert.equal(copy.fix, "sources");
  }
});
