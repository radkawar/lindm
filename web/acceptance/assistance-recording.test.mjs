// SPDX-License-Identifier: Apache-2.0

// Production recording-retrieval assembly only. These do not qualify playback in a
// browser, native recording disclosure or server decryption.
import assert from "node:assert/strict";
import test from "node:test";
import {
  RECORDING_SEGMENT_BYTES,
  RecordingAssembly,
  RecordingContractError,
  readRecording,
} from "../src/features/assistance/recording-stream.ts";

const bytes = (length, fill = 1) => new Uint8Array(length).fill(fill);
const segment = (sequence, last, complete = true, data = bytes(4, sequence + 1)) => ({
  data,
  sequence,
  last,
  complete,
});

test("a complete retrieval is assembled in order", async () => {
  const served = [segment(0, false), segment(1, false), segment(2, true)];
  const requested = [];
  const loaded = [];
  const playback = await readRecording(
    3,
    1024,
    async (sequence) => {
      requested.push(sequence);
      return served[sequence];
    },
    new AbortController().signal,
    (count) => loaded.push(count),
  );
  assert.deepEqual(requested, [0, 1, 2]);
  assert.deepEqual(loaded, [1, 2, 3]);
  assert.equal(playback.bytes, 12);
  assert.equal(playback.complete, true);
  assert.deepEqual(
    playback.parts.map((part) => part[0]),
    [1, 2, 3],
  );
});

test("an incomplete archive is labelled incomplete, never complete", () => {
  const assembly = new RecordingAssembly(2, 1024);
  assembly.accept(segment(0, false, false));
  assert.throws(() => assembly.accept(segment(1, true, true)), RecordingContractError);
  const prefix = new RecordingAssembly(1, 1024);
  prefix.accept(segment(0, true, false));
  assert.equal(prefix.result().complete, false);
});

test("reordered, short, overlong and oversized retrievals are refused", () => {
  assert.throws(() => new RecordingAssembly(2, 1024).accept(segment(1, false)), /out of order/);
  const early = new RecordingAssembly(3, 1024);
  early.accept(segment(0, false));
  assert.throws(() => early.accept(segment(1, true)), /unexpected segment/);
  const late = new RecordingAssembly(1, 1024);
  assert.throws(() => late.accept(segment(0, false)), /unexpected segment/);
  const finished = new RecordingAssembly(1, 1024);
  finished.accept(segment(0, true));
  assert.throws(() => finished.accept(segment(1, true)), /already ended/);
  assert.throws(
    () =>
      new RecordingAssembly(1, 1 << 30).accept(
        segment(0, true, true, bytes(RECORDING_SEGMENT_BYTES + 1)),
      ),
    /larger than allowed/,
  );
  assert.throws(
    () => new RecordingAssembly(1, 3).accept(segment(0, true)),
    /larger than its limit/,
  );
  const unfinished = new RecordingAssembly(2, 1024);
  unfinished.accept(segment(0, false));
  assert.throws(() => unfinished.result(), /not fully loaded/);
  assert.throws(() => new RecordingAssembly(0, 1024), /no stored segments/);
});

test("an aborted retrieval presents no prefix", async () => {
  const controller = new AbortController();
  await assert.rejects(
    readRecording(
      2,
      1024,
      async (sequence) => {
        controller.abort();
        return segment(sequence, false);
      },
      controller.signal,
    ),
  );
});
