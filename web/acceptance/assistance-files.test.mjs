// SPDX-License-Identifier: Apache-2.0

// Production protobuf/stream state tests only. These do not qualify a browser picker or native desktop.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { create } from "@bufbuild/protobuf";
import {
  AssistanceFileDirection,
  AssistanceFileFrameSchema,
  AssistanceFileMetadataSchema,
  AssistanceFilePolicySchema,
} from "../gen/lindm/agent/v1/assistance_files_pb.ts";
import {
  FILE_BUFFER_BYTES,
  FILE_CHUNK_BYTES,
  FILE_FRAME_BYTES,
  FileTransferStream,
  FileCleanupError,
  FileRemoteCancellationError,
  awaitFileOperation,
  checkFilePolicy,
  decodeFileFrame,
  encodeFileFrame,
  prepareFile,
  retireFileRequest,
  sendFileFrame,
  sniffFileType,
} from "../src/features/assistance/files-stream.ts";

const requestId = "a7260418-6429-45cc-9029-5c428de2f0f7";
const otherId = "b7260418-6429-45cc-9029-5c428de2f0f7";
const policy = create(AssistanceFilePolicySchema, {
  maxFileBytes: 16777216n,
  maxSessionBytes: 67108864n,
  allowedMimeTypes: ["text/plain", "application/pdf", "image/png", "image/jpeg"],
  allowedExtensions: [".txt", ".log", ".pdf", ".png", ".jpg", ".jpeg"],
});
const text = new TextEncoder().encode("independently verified text\n");
const digest = new Uint8Array(createHash("sha256").update(text).digest());
const metadata = create(AssistanceFileMetadataSchema, {
  name: "support.txt",
  size: BigInt(text.length),
  mimeType: "text/plain",
  sha256: digest,
});

function frame(kind, value = {}, id = requestId) {
  return create(AssistanceFileFrameSchema, { requestId: id, body: { case: kind, value } });
}

class Channel extends EventTarget {
  readyState = "open";
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  sent = [];
  onSend = null;
  send(bytes) {
    const decoded = decodeFileFrame(bytes.slice().buffer);
    this.sent.push(decoded);
    this.dispatchEvent(new Event("sent"));
    this.onSend?.(decoded);
  }
  close() {
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
  }
  receive(message) {
    this.dispatchEvent(new MessageEvent("message", { data: encodeFileFrame(message).buffer }));
  }
  async sentFrame(kind) {
    const existing = this.sent.find((message) => message.body.case === kind);
    if (existing) return existing;
    return new Promise((resolve) => {
      const listener = () => {
        const found = this.sent.find((message) => message.body.case === kind);
        if (found) {
          this.removeEventListener("sent", listener);
          resolve(found);
        }
      };
      this.addEventListener("sent", listener);
    });
  }
}

function receiver() {
  const channel = new Channel();
  const controller = new AbortController();
  const stream = new FileTransferStream(channel, requestId, controller.signal);
  const writes = [];
  const state = { closed: 0, aborted: 0 };
  const destination = {
    async write(data) {
      writes.push(data.slice());
    },
    async close() {
      state.closed++;
    },
    async abort() {
      state.aborted++;
    },
  };
  return { channel, controller, stream, writes, state, destination };
}

async function beginReceiver(target, file = metadata) {
  const done = target.stream.transfer(
    AssistanceFileDirection.FROM_USER,
    policy,
    null,
    target.destination,
    () => {},
  );
  target.channel.receive(frame("start", file));
  assert.equal(target.channel.sent.length, 0, "Start cannot authorize its own Ready");
  target.stream.authorize();
  await target.channel.sentFrame("ready");
  return { done };
}

test("file protobuf framing rejects text, missing body and hard size violations", () => {
  const message = frame("chunk", { offset: 0n, data: new Uint8Array(FILE_CHUNK_BYTES) });
  assert.deepEqual(decodeFileFrame(encodeFileFrame(message).buffer), message);
  for (const data of [
    "{}",
    new Uint8Array(1),
    new ArrayBuffer(0),
    new ArrayBuffer(FILE_FRAME_BYTES + 1),
  ])
    assert.throws(() => decodeFileFrame(data));
  assert.throws(() =>
    encodeFileFrame(frame("chunk", { offset: 0n, data: new Uint8Array(FILE_CHUNK_BYTES + 1) })),
  );
  assert.throws(() => encodeFileFrame(create(AssistanceFileFrameSchema, { requestId })));
  assert.throws(() => encodeFileFrame(frame("end", { size: 0n, sha256: new Uint8Array(31) })));
});

test("prehash reads bounded slices and matches an independent SHA-256 implementation", async () => {
  class Source extends File {
    reads = [];
    arrayBuffer() {
      throw new Error("unbounded read");
    }
    slice(start, end) {
      this.reads.push(end - start);
      return super.slice(start, end);
    }
  }
  const contents = "a".repeat(FILE_CHUNK_BYTES * 3 + 7);
  const source = new Source([contents], "support.txt", { type: "application/octet-stream" });
  const prepared = await prepareFile(source, policy, new AbortController().signal, () => {});
  assert.equal(prepared.mimeType, "text/plain", "browser-reported MIME is not authority");
  assert.equal(prepared.size, BigInt(contents.length));
  assert.equal(
    Buffer.from(prepared.sha256).toString("hex"),
    createHash("sha256").update(contents).digest("hex"),
  );
  assert.ok(source.reads.every((length) => length <= FILE_CHUNK_BYTES));
  const cancelled = new AbortController();
  cancelled.abort();
  await assert.rejects(prepareFile(source, policy, cancelled.signal, () => {}));
});

test("type and extension limits apply independently with safe metadata names", () => {
  assert.equal(sniffFileType(new TextEncoder().encode("%PDF-1.7\n")), "application/pdf");
  assert.equal(
    sniffFileType(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 13, 10, 26, 10])),
    "image/png",
  );
  assert.equal(sniffFileType(new Uint8Array([255, 216, 255])), "image/jpeg");
  for (const contents of ["<html>evil", '<?xml version="1.0"?>', "GIF89a", "\x7fELF\0"])
    assert.throws(() => sniffFileType(new TextEncoder().encode(contents)));
  for (const override of [
    { name: "../secret.txt" },
    { name: "secret.exe" },
    { mimeType: "application/zip" },
    { size: policy.maxFileBytes + 1n },
    { name: "file\n.txt" },
  ])
    assert.throws(() =>
      checkFilePolicy(create(AssistanceFileMetadataSchema, { ...metadata, ...override }), policy),
    );
});

test("sender waits for local authorization and Ready, then sends bounded offsets and verifies receipt", async () => {
  const channel = new Channel();
  const controller = new AbortController();
  const stream = new FileTransferStream(channel, requestId, controller.signal);
  const source = new File([text], metadata.name);
  const done = stream.transfer(
    AssistanceFileDirection.TO_USER,
    policy,
    { file: source, metadata },
    null,
    () => {},
  );
  assert.equal(channel.sent.length, 0);
  stream.authorize();
  await channel.sentFrame("start");
  assert.deepEqual(
    channel.sent.map((message) => message.body.case),
    ["start"],
  );
  channel.receive(frame("ready"));
  const end = await channel.sentFrame("end");
  const chunk = channel.sent.find((message) => message.body.case === "chunk").body.value;
  assert.equal(chunk.offset, 0n);
  assert.deepEqual(chunk.data, text);
  assert.deepEqual(end.body.value.sha256, digest);
  channel.receive(frame("receipt", { file: metadata }));
  assert.deepEqual(await done, metadata);
  stream.dispose();
});

test("backpressure waits for bufferedamountlow and cancellation releases the waiter", async () => {
  const channel = new Channel();
  channel.bufferedAmount = FILE_BUFFER_BYTES;
  const controller = new AbortController();
  const send = sendFileFrame(channel, frame("ready"), controller.signal);
  assert.equal(channel.sent.length, 0);
  channel.bufferedAmount = FILE_BUFFER_BYTES / 2;
  channel.dispatchEvent(new Event("bufferedamountlow"));
  await send;
  assert.equal(channel.sent.length, 1);
  channel.bufferedAmount = FILE_BUFFER_BYTES;
  const blocked = sendFileFrame(channel, frame("ready"), controller.signal);
  controller.abort(new Error("authority lost"));
  await assert.rejects(blocked, /authority lost/);
  assert.equal(channel.sent.length, 1);
});

test("receiver hashes its own sequential writes, closes only after verification and then acknowledges", async () => {
  const target = receiver();
  const { done } = await beginReceiver(
    target,
    create(AssistanceFileMetadataSchema, { ...metadata, sha256: new Uint8Array() }),
  );
  target.channel.receive(frame("chunk", { offset: 0n, data: text }));
  target.channel.receive(frame("end", { size: BigInt(text.length), sha256: digest }));
  const result = await done;
  assert.deepEqual(Buffer.concat(target.writes), Buffer.from(text));
  assert.deepEqual(result, metadata);
  assert.deepEqual(target.state, { closed: 1, aborted: 0 });
  assert.deepEqual(
    target.channel.sent.map((message) => message.body.case),
    ["ready", "receipt"],
  );
  target.stream.dispose();
});

for (const failure of [
  "digest",
  "offset",
  "early end",
  "wrong id",
  "wrong direction",
  "extra chunk",
]) {
  test(`receiver aborts rather than publishing on ${failure}`, async () => {
    const target = receiver();
    const { done } = await beginReceiver(target);
    const rejected = assert.rejects(done);
    if (failure === "wrong id")
      target.channel.receive(frame("chunk", { offset: 0n, data: text }, otherId));
    else if (failure === "wrong direction")
      target.channel.receive(frame("receipt", { file: metadata }));
    else if (failure === "early end")
      target.channel.receive(frame("end", { size: BigInt(text.length), sha256: digest }));
    else {
      target.channel.receive(
        frame("chunk", { offset: failure === "offset" ? 1n : 0n, data: text }),
      );
      if (failure === "extra chunk")
        target.channel.receive(frame("chunk", { offset: BigInt(text.length), data: text }));
      else
        target.channel.receive(
          frame("end", {
            size: BigInt(text.length),
            sha256: failure === "digest" ? new Uint8Array(32) : digest,
          }),
        );
    }
    await rejected;
    assert.deepEqual(target.state, { closed: 0, aborted: 1 });
    assert.equal(
      target.channel.sent.some((message) => message.body.case === "receipt"),
      false,
    );
    target.stream.dispose();
  });
}

test("receiver rejects data sent before authorized Ready and never writes it", async () => {
  const target = receiver();
  const done = target.stream.transfer(
    AssistanceFileDirection.FROM_USER,
    policy,
    null,
    target.destination,
    () => {},
  );
  const rejected = assert.rejects(done);
  target.channel.receive(frame("start", metadata));
  target.channel.receive(frame("chunk", { offset: 0n, data: text }));
  await rejected;
  assert.equal(target.writes.length, 0);
  assert.deepEqual(target.state, { closed: 0, aborted: 1 });
  target.stream.dispose();
});

test("receiver queue is bounded even if a peer ignores writable backpressure", async () => {
  const target = receiver();
  const large = create(AssistanceFileMetadataSchema, { ...metadata, size: 1000n });
  const { done } = await beginReceiver(target, large);
  const rejected = assert.rejects(done);
  for (let offset = 0; offset < 9; offset++)
    target.channel.receive(frame("chunk", { offset: BigInt(offset), data: new Uint8Array([65]) }));
  await rejected;
  assert.equal(target.channel.readyState, "closed");
  assert.equal(target.state.aborted, 1);
  target.stream.dispose();
});

test("authority cancellation aborts a writable immediately even while a write is pending", async () => {
  const target = receiver();
  const pending = Promise.withResolvers();
  const writing = Promise.withResolvers();
  target.destination.write = async () => {
    writing.resolve();
    await pending.promise;
  };
  const { done } = await beginReceiver(target);
  const rejected = assert.rejects(done, /authority lost/);
  target.channel.receive(frame("chunk", { offset: 0n, data: text }));
  await writing.promise;
  target.controller.abort(new Error("authority lost"));
  assert.equal(target.state.aborted, 1);
  pending.resolve();
  await rejected;
  assert.equal(target.state.closed, 0);
  target.stream.dispose();
});

test("destination close failure cannot emit a completion receipt", async () => {
  const target = receiver();
  target.destination.close = async () => {
    throw new Error("disk full");
  };
  const { done } = await beginReceiver(target);
  const rejected = assert.rejects(done, /disk full/);
  target.channel.receive(frame("chunk", { offset: 0n, data: text }));
  target.channel.receive(frame("end", { size: BigInt(text.length), sha256: digest }));
  await rejected;
  assert.equal(target.state.aborted, 1);
  assert.equal(
    target.channel.sent.some((message) => message.body.case === "receipt"),
    false,
  );
  target.stream.dispose();
});

test("a cancelled browser picker wait cannot continue work after late selection", async () => {
  const picker = Promise.withResolvers();
  const controller = new AbortController();
  let continued = false;
  const waiting = awaitFileOperation(picker.promise, controller.signal).then(() => {
    continued = true;
  });
  const rejected = assert.rejects(waiting, /session ended/);
  controller.abort(new Error("session ended"));
  await rejected;
  picker.resolve({ name: "late destination" });
  await Promise.resolve();
  assert.equal(continued, false);
});

test("sender rejects a changed selected file and never sends End", async () => {
  const channel = new Channel();
  const stream = new FileTransferStream(channel, requestId, new AbortController().signal);
  const source = new File([new Uint8Array(text.length).fill(65)], metadata.name);
  const done = stream.transfer(
    AssistanceFileDirection.TO_USER,
    policy,
    { file: source, metadata },
    null,
    () => {},
  );
  const rejected = assert.rejects(done, /changed/);
  stream.authorize();
  await channel.sentFrame("start");
  channel.receive(frame("ready"));
  await rejected;
  assert.equal(
    channel.sent.some((message) => message.body.case === "end"),
    false,
  );
  stream.dispose();
});

test("a mismatched receiver receipt is not sender completion", async () => {
  const channel = new Channel();
  const stream = new FileTransferStream(channel, requestId, new AbortController().signal);
  const done = stream.transfer(
    AssistanceFileDirection.TO_USER,
    policy,
    { file: new File([text], metadata.name), metadata },
    null,
    () => {},
  );
  const rejected = assert.rejects(done, /confirm/);
  stream.authorize();
  await channel.sentFrame("start");
  channel.receive(frame("ready"));
  await channel.sentFrame("end");
  channel.receive(
    frame("receipt", {
      file: create(AssistanceFileMetadataSchema, { ...metadata, sha256: new Uint8Array(32) }),
    }),
  );
  await rejected;
  stream.dispose();
});

test("empty files still require independently verified End before closing", async () => {
  const target = receiver();
  const hash = new Uint8Array(createHash("sha256").digest());
  const empty = create(AssistanceFileMetadataSchema, { ...metadata, size: 0n, sha256: hash });
  const { done } = await beginReceiver(target, empty);
  assert.equal(target.state.closed, 0);
  target.channel.receive(frame("end", { size: 0n, sha256: hash }));
  assert.deepEqual(await done, empty);
  assert.deepEqual(target.state, { closed: 1, aborted: 0 });
  target.stream.dispose();
});

test("failed download cleanup remains distinct from ordinary cancellation", async () => {
  const target = receiver();
  target.destination.abort = async () => {
    throw new Error("storage unavailable");
  };
  const { done } = await beginReceiver(target);
  const rejected = assert.rejects(done, FileCleanupError);
  target.controller.abort();
  await rejected;
  assert.equal(target.state.closed, 0);
  target.stream.dispose();
});

test("unknown protobuf fields fail closed at frame and nested metadata boundaries", () => {
  const top = frame("ready");
  top.$unknown = [{ no: 90, wireType: 0, data: new Uint8Array([1]) }];
  const nested = frame("start", {
    name: metadata.name,
    size: metadata.size,
    mimeType: metadata.mimeType,
    sha256: metadata.sha256,
  });
  nested.body.value.$unknown = [{ no: 90, wireType: 0, data: new Uint8Array([1]) }];
  assert.throws(() => encodeFileFrame(top), /unrecognized/);
  assert.throws(() => encodeFileFrame(nested), /unrecognized/);
});

test("text detection follows byte offsets and does not misclassify recognized printable signatures", () => {
  assert.equal(sniffFileType(new TextEncoder().encode("\x1b[32mtext log")), "text/plain");
  assert.equal(sniffFileType(new Uint8Array([0xff, 0xfe, 0x41, 0])), "text/plain");
  for (const prefix of [
    new TextEncoder().encode("BM"),
    new TextEncoder().encode("ttcf"),
    new TextEncoder().encode("x".repeat(34) + "LP"),
    new Uint8Array([82, 73, 70, 70, 0xc3, 0xa9, 0xc3, 0xa9, 87, 69, 66, 80, 86, 80]),
  ])
    assert.throws(() => sniffFileType(prefix));
});

test("a valid local cancellation aborts only its transfer and preserves support", async () => {
  const target = receiver();
  const { done } = await beginReceiver(target);
  const rejected = assert.rejects(done, FileRemoteCancellationError);
  target.channel.receive(frame("cancel", { reason: "local_user_declined" }));
  await rejected;
  assert.equal(target.channel.readyState, "open");
  assert.deepEqual(target.state, { closed: 0, aborted: 1 });
  assert.equal(target.writes.length, 0);
  assert.equal(
    target.channel.sent.some((message) => message.body.case === "receipt"),
    false,
  );
  target.stream.dispose();
});

test("late revoked operation frames never write into a later real stream", async () => {
  const target = receiver();
  target.stream.dispose();
  const completed = new Set([otherId]);
  target.stream = new FileTransferStream(
    target.channel,
    requestId,
    target.controller.signal,
    completed,
  );
  const { done } = await beginReceiver(target);
  target.channel.receive(frame("cancel", { reason: "file_cancelled" }, otherId));
  target.channel.receive(frame("chunk", { offset: 0n, data: text }, otherId));
  target.channel.receive(frame("end", { size: metadata.size, sha256: digest }, otherId));
  assert.equal(target.channel.readyState, "open");
  assert.equal(target.writes.length, 0);
  target.channel.receive(frame("chunk", { offset: 0n, data: text }));
  target.channel.receive(frame("end", { size: metadata.size, sha256: digest }));
  assert.deepEqual(await done, metadata);
  assert.equal(target.writes.length, 1);
  assert.deepEqual(target.writes[0], text);
  target.stream.dispose();
});

test("cancellation does not make unknown or malformed late traffic acceptable", async () => {
  for (const malformed of [false, true]) {
    const target = receiver();
    const { done } = await beginReceiver(target);
    const rejected = assert.rejects(done);
    target.channel.receive(frame("cancel", { reason: "local_user_declined" }));
    await rejected;
    if (malformed)
      target.channel.dispatchEvent(new MessageEvent("message", { data: new ArrayBuffer(0) }));
    else target.channel.receive(frame("cancel", { reason: "file_cancelled" }, otherId));
    assert.equal(target.channel.readyState, "closed");
    assert.equal(target.writes.length, 0);
    target.stream.dispose();
  }
});

test("local revocation tombstones before delayed completion without eviction", () => {
  const retired = new Set();
  for (let index = 0; index < 32; index++) {
    const id = `${index.toString(16).padStart(8, "0")}-6429-45cc-9029-5c428de2f0f7`;
    retireFileRequest(retired, id);
    retireFileRequest(retired, id);
    assert.equal(retired.size, index + 1);
  }
  const first = [...retired][0];
  assert.throws(() => retireFileRequest(retired, requestId), /limit/);
  assert.equal(retired.size, 32);
  assert.equal(retired.has(first), true);
  assert.equal(retired.has(requestId), false);
});

test("locally aborted request is revoked before its server cancellation report", async () => {
  const target = receiver();
  target.stream.dispose();
  const retired = new Set();
  target.stream = new FileTransferStream(
    target.channel,
    requestId,
    target.controller.signal,
    retired,
  );
  const { done } = await beginReceiver(target);
  const rejected = assert.rejects(done);
  retireFileRequest(retired, requestId);
  target.controller.abort(new Error("Operator cancelled"));
  target.channel.receive(frame("cancel", { reason: "file_cancelled" }));
  target.channel.receive(frame("chunk", { offset: 0n, data: text }));
  await rejected;
  assert.equal(target.channel.readyState, "open");
  assert.equal(target.writes.length, 0);
  assert.deepEqual(target.state, { closed: 0, aborted: 1 });
  target.stream.dispose();
});
