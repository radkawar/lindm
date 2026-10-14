// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import {
  cursorVisibilityNote,
  DisplayPresentationFence,
  parseDisplayFrameMarker,
  rtpAtOrAfter,
} from "../src/features/assistance/presentation.ts";

const marker = { t: "display-frame", display: "shared-two", generation: 2, rtpTimestamp: 9000 };

for (const order of ["smf", "sfm", "msf", "mfs", "fsm", "fms"]) {
  test(`display readiness requires session, marker and actual presentation (${order})`, () => {
    const fence = new DisplayPresentationFence();
    fence.select("shared-one", 1);
    fence.receive({ ...marker, display: "shared-one", generation: 1, rtpTimestamp: 6000 });
    // The last old-display frame has the same dimensions as the new display.
    fence.present(8999);
    assert.equal(fence.ready, true);
    for (const [index, event] of [...order].entries()) {
      if (event === "s") fence.select(marker.display, marker.generation);
      if (event === "m") fence.receive(marker);
      if (event === "f") fence.present(marker.rtpTimestamp);
      // Before the new selection/marker is known the native old-generation
      // input fence still applies; once either arrives it must remain blocked
      // until all three agree, regardless of network/RPC arrival order.
      const observed = order.slice(0, index + 1);
      if (observed.includes("s") || observed.includes("m")) assert.equal(fence.ready, index === 2);
    }
    assert.equal(fence.ready, true);
  });
}

test("a newer marker immediately blocks an old session even if frames advanced", () => {
  const fence = new DisplayPresentationFence();
  fence.select("shared-one", 1);
  fence.receive({ ...marker, display: "shared-one", generation: 1, rtpTimestamp: 6000 });
  fence.present(12000);
  assert.equal(fence.ready, true);
  fence.receive(marker);
  assert.equal(fence.ready, false);
  fence.select(marker.display, marker.generation);
  assert.equal(fence.ready, true);
  // An obsolete duplicate must not roll the marker fence back.
  fence.receive({ ...marker, display: "shared-one", generation: 1, rtpTimestamp: 6000 });
  assert.equal(fence.ready, true);
});

test("neither display ID alone nor generation alone can qualify a frame", () => {
  const fence = new DisplayPresentationFence();
  fence.receive(marker);
  fence.present(marker.rtpTimestamp);
  for (const [display, generation] of [
    [marker.display, 0],
    [marker.display, 1],
    ["shared-one", 2],
  ]) {
    fence.select(display, generation);
    assert.equal(fence.ready, false);
  }
  fence.select(marker.display, marker.generation);
  assert.equal(fence.ready, true);
});

test("RTP wrap accepts a newer presentation and rejects a just-before-switch frame", () => {
  assert.equal(rtpAtOrAfter(0x20, 0xfffffff0), true);
  assert.equal(rtpAtOrAfter(0xfffffff0, 0x20), false);
  assert.equal(rtpAtOrAfter(0x80000000, 0), false);
  assert.equal(rtpAtOrAfter(0, 0), true);
  const fence = new DisplayPresentationFence();
  fence.select(marker.display, marker.generation);
  fence.receive({ ...marker, rtpTimestamp: 0x20 });
  fence.present(0xfffffff0);
  assert.equal(fence.ready, false);
  fence.present(0x20);
  assert.equal(fence.ready, true);
  fence.present(0x21);
  assert.equal(fence.ready, true);
});

test("interruption clears presented evidence, not the marker identity", () => {
  const fence = new DisplayPresentationFence();
  fence.select(marker.display, marker.generation);
  fence.receive(marker);
  fence.present(marker.rtpTimestamp);
  assert.equal(fence.ready, true);
  fence.clearPresentation();
  assert.equal(fence.ready, false);
  fence.present(marker.rtpTimestamp + 1);
  assert.equal(fence.ready, true);
  // Even after recovery, presenting a stale frame must hide it again.
  fence.present(marker.rtpTimestamp - 1);
  assert.equal(fence.ready, false);
});

test("missing RTP metadata never becomes readiness", () => {
  const fence = new DisplayPresentationFence();
  fence.select(marker.display, marker.generation);
  fence.receive(marker);
  assert.equal(fence.metadataAvailable, null);
  for (const timestamp of [undefined, null, NaN, -1, 0x100000000, 1.5, "9000"]) {
    fence.present(timestamp);
    assert.equal(fence.metadataAvailable, false);
    assert.equal(fence.ready, false);
  }
  fence.present(marker.rtpTimestamp);
  assert.equal(fence.ready, true);
  fence.present(undefined);
  assert.equal(fence.ready, false);
});

test("marker wire parsing enforces uint32 identity and the 256-byte bound", () => {
  assert.deepEqual(parseDisplayFrameMarker(JSON.stringify(marker)), marker);
  assert.deepEqual(parseDisplayFrameMarker(JSON.stringify({ ...marker, rtpTimestamp: 0 })), {
    ...marker,
    rtpTimestamp: 0,
  });
  for (const data of [null, new Uint8Array(), "{", "null", "[]", " ".repeat(257)])
    assert.equal(parseDisplayFrameMarker(data), null);
  for (const override of [
    { t: "frame" },
    { display: "" },
    { generation: 0 },
    { generation: -1 },
    { generation: 1.5 },
    { generation: "2" },
    { generation: 0x100000000 },
    { rtpTimestamp: -1 },
    { rtpTimestamp: 0x100000000 },
    { rtpTimestamp: "9000" },
    { rtpTimestamp: undefined },
    { display: "é".repeat(100) },
  ])
    assert.equal(parseDisplayFrameMarker(JSON.stringify({ ...marker, ...override })), null);
});

test("default typed session marker values never establish readiness", () => {
  const fence = new DisplayPresentationFence();
  fence.select("", 0);
  fence.present(0);
  fence.receive({ t: "display-frame", display: "", generation: 0, rtpTimestamp: 0 });
  assert.equal(fence.ready, false);
  fence.select(marker.display, 0);
  fence.receive({ ...marker, generation: 0 });
  assert.equal(fence.ready, false);
});

test("cursor omission is explicit only for a reported live capture limitation", () => {
  assert.equal(cursorVisibilityNote(false, true), "Cursor isn't shown on this desktop version");
  assert.equal(cursorVisibilityNote(false, false), null);
  assert.equal(cursorVisibilityNote(false, undefined), null);
  assert.equal(cursorVisibilityNote(true, true), null);
});
