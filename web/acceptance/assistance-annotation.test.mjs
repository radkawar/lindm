// SPDX-License-Identifier: Apache-2.0

// Runs the production annotation sender with Node's built-in TypeScript stripping.
import assert from "node:assert/strict";
import test from "node:test";

import {
  ANNOTATION_INTERVAL_MS,
  AnnotationSender,
  MAX_STROKE_POINTS,
} from "../src/features/assistance/annotation.ts";

function sender(drawing = true) {
  const messages = [];
  let now = 1_000;
  const channel = { readyState: "open", send: (data) => messages.push(JSON.parse(data)) };
  const annotations = new AnnotationSender(channel, "monitor-2", 4, drawing, () => now);
  return {
    annotations,
    channel,
    messages,
    advance: (ms) => {
      now += ms;
    },
  };
}

test("pointer frames are bound to the shared display generation and rate-limited", () => {
  const { annotations, messages, advance } = sender();
  assert.equal(annotations.pointer({ x: 0.25, y: 0.5 }), true);
  assert.equal(annotations.pointer({ x: 0.3, y: 0.5 }), false, "a frame inside the interval");
  advance(ANNOTATION_INTERVAL_MS);
  assert.equal(annotations.pointer({ x: 0.3, y: 0.5 }), true);
  assert.deepEqual(messages, [
    { t: "p", d: "monitor-2", g: 4, x: 0.25, y: 0.5 },
    { t: "p", d: "monitor-2", g: 4, x: 0.3, y: 0.5 },
  ]);
});

test("frames outside the shared frame or non-finite are never sent", () => {
  const { annotations, messages } = sender();
  for (const point of [
    { x: -0.01, y: 0.5 },
    { x: 1.01, y: 0.5 },
    { x: Number.NaN, y: 0.5 },
    { x: 0.5, y: Number.POSITIVE_INFINITY },
  ]) {
    assert.equal(annotations.pointer(point), false);
    assert.equal(annotations.beginStroke(point), false);
  }
  assert.deepEqual(messages, []);
});

test("pointer-only policy never draws marks", () => {
  const { annotations, messages } = sender(false);
  assert.equal(annotations.beginStroke({ x: 0.1, y: 0.1 }), false);
  assert.equal(annotations.extendStroke({ x: 0.2, y: 0.2 }), false);
  assert.equal(annotations.endStroke(), false);
  assert.deepEqual(messages, []);
});

test("strokes are bounded and split into continuing strokes", () => {
  const { annotations, messages, advance } = sender();
  assert.equal(annotations.beginStroke({ x: 0, y: 0 }), true);
  for (let i = 1; i < MAX_STROKE_POINTS + 10; i++) {
    advance(1);
    annotations.extendStroke({ x: i / 200, y: i / 200 });
  }
  annotations.endStroke();
  const strokes = messages.filter((message) => message.t === "s");
  assert.ok(strokes.length >= 2);
  for (const stroke of strokes) {
    assert.ok(stroke.p.length >= 2 && stroke.p.length <= MAX_STROKE_POINTS);
    assert.equal(stroke.d, "monitor-2");
    assert.equal(stroke.g, 4);
  }
  const first = strokes.find((stroke) => stroke.p.length === MAX_STROKE_POINTS);
  const next = strokes.find((stroke) => stroke.id !== first.id);
  assert.ok(first && next, "a full stroke continues under a new identity");
  assert.deepEqual(next.p[0], first.p[first.p.length - 1], "the continuation starts at the split");
});

test("only pointer, stroke and clear frames exist; nothing is sent after dispose", () => {
  const { annotations, channel, messages, advance } = sender();
  annotations.pointer({ x: 0.5, y: 0.5 });
  advance(ANNOTATION_INTERVAL_MS);
  annotations.beginStroke({ x: 0.1, y: 0.1 });
  annotations.extendStroke({ x: 0.2, y: 0.2 });
  annotations.endStroke();
  annotations.clear();
  for (const message of messages) {
    assert.ok(["p", "s", "c"].includes(message.t));
    for (const key of Object.keys(message))
      assert.ok(["t", "d", "g", "x", "y", "id", "p"].includes(key));
  }
  assert.deepEqual(messages.at(-1), { t: "c" });
  const count = messages.length;
  channel.readyState = "closing";
  advance(ANNOTATION_INTERVAL_MS);
  assert.equal(annotations.pointer({ x: 0.5, y: 0.5 }), false);
  channel.readyState = "open";
  annotations.dispose();
  advance(ANNOTATION_INTERVAL_MS);
  assert.equal(annotations.pointer({ x: 0.5, y: 0.5 }), false);
  assert.equal(annotations.clear(), false);
  assert.equal(messages.length, count);
});
