// SPDX-License-Identifier: Apache-2.0

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  AssistanceFileDirection,
  AssistanceFileFrameSchema,
  AssistanceFileMetadataSchema,
  AssistanceFilePolicySchema,
  type AssistanceFileFrame,
  type AssistanceFileMetadata,
  type AssistanceFilePolicy,
} from "../../../gen/lindm/agent/v1/assistance_files_pb.ts";

export const FILE_CHANNEL_LABEL = "lindm-files";
export const FILE_CHUNK_BYTES = 16 * 1024;
export const FILE_FRAME_BYTES = 17 * 1024;
export const FILE_BUFFER_BYTES = 128 * 1024;
const FILE_QUEUE_FRAMES = 8;
const validator = createValidator();

// A real FileSystemWritableFileStream satisfies this boundary. No Blob or download fallback.
export type FileDestination = {
  write: (data: Uint8Array) => Promise<void>;
  close: () => Promise<void>;
  abort: (reason?: unknown) => Promise<void>;
};

export class FileCleanupError extends Error {
  constructor(cause?: unknown) {
    super(
      "Couldn't confirm removal of the unfinished download. Check the destination and stop the session.",
      { cause },
    );
  }
}

export class FileRemoteCancellationError extends Error {
  constructor() {
    super("The transfer was cancelled on the device.");
  }
}

// Browser pickers have no programmatic dismiss operation. Cancelling this wait
// revokes all subsequent work; a late picker response cannot start an RPC.
export function awaitFileOperation<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const aborted = () => reject(signal.reason);
    signal.addEventListener("abort", aborted, { once: true });
    pending.then(
      (value) => {
        signal.removeEventListener("abort", aborted);
        if (!signal.aborted) resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", aborted);
        reject(error);
      },
    );
    if (signal.aborted) aborted();
  });
}

function checkFrame(frame: AssistanceFileFrame) {
  if (
    frame.$unknown?.length ||
    frame.body.value?.$unknown?.length ||
    (frame.body.case === "receipt" && frame.body.value.file?.$unknown?.length)
  )
    throw new Error("The file connection sent unrecognized fields. Stop the session.");
  if (validator.validate(AssistanceFileFrameSchema, frame).kind !== "valid")
    throw new Error("The file connection sent invalid data. Stop the session and reconnect.");
}

export function encodeFileFrame(frame: AssistanceFileFrame): Uint8Array<ArrayBuffer> {
  checkFrame(frame);
  const bytes = toBinary(AssistanceFileFrameSchema, frame);
  if (bytes.byteLength > FILE_FRAME_BYTES) throw new Error("The file message is too large.");
  return bytes;
}

export function decodeFileFrame(data: unknown): AssistanceFileFrame {
  if (!(data instanceof ArrayBuffer) || data.byteLength > FILE_FRAME_BYTES || !data.byteLength)
    throw new Error("The file connection sent an unsupported message.");
  const frame = fromBinary(AssistanceFileFrameSchema, new Uint8Array(data));
  checkFrame(frame);
  return frame;
}

// Session-local, add-only revocations cover terminal reports and local aborts.
// Their bound matches server admission; never evict an ID to admit late traffic.
export function retireFileRequest(requests: Set<string>, requestId: string): void {
  if (!requests.has(requestId) && requests.size >= 32)
    throw new Error("The session file-operation limit was exceeded. Stop the session.");
  requests.add(requestId);
}

export function sameFile(a: AssistanceFileMetadata, b: AssistanceFileMetadata): boolean {
  return (
    a.name === b.name &&
    a.size === b.size &&
    a.mimeType === b.mimeType &&
    sameDigest(a.sha256, b.sha256)
  );
}

function sameDigest(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

// Match the supported subset of Go net/http.DetectContentType over its first 512 bytes.
// Unknown or ambiguous content is rejected, not inferred from File.type or the extension.
export function sniffFileType(prefix: Uint8Array): string {
  const starts = (signature: number[]) => signature.every((byte, index) => prefix[index] === byte);
  if (starts([0x25, 0x50, 0x44, 0x46, 0x2d])) return "application/pdf";
  if (starts([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "image/png";
  if (starts([0xff, 0xd8, 0xff])) return "image/jpeg";
  if (
    starts([0xef, 0xbb, 0xbf]) ||
    (prefix.length >= 4 && (starts([0xfe, 0xff]) || starts([0xff, 0xfe])))
  )
    return "text/plain";
  // These printable prefixes are recognized by DetectContentType before its text fallback.
  const text = new TextDecoder("latin1").decode(prefix);
  if (
    /^[\t\n\f\r ]*(?:<!DOCTYPE HTML[ >]|<HTML[ >]|<HEAD[ >]|<SCRIPT[ >]|<IFRAME[ >]|<H1[ >]|<DIV[ >]|<FONT[ >]|<TABLE[ >]|<A[ >]|<STYLE[ >]|<TITLE[ >]|<B[ >]|<BODY[ >]|<BR[ >]|<P[ >]|<!--[ >])/i.test(
      text,
    ) ||
    /^[\t\n\f\r ]*<\?xml/.test(text) ||
    /^(?:%!PS-Adobe-|BM|GIF87a|GIF89a|ID3|wOFF|wOF2|OTTO|ttcf)/.test(text) ||
    /^RIFF[\s\S]{4}(?:WEBPVP|AVI |WAVE)/.test(text) ||
    /^FORM[\s\S]{4}AIFF/.test(text) ||
    (prefix.length >= 36 && prefix[34] === 0x4c && prefix[35] === 0x50)
  )
    throw new Error("This file type is not supported. Choose plain text, PDF, PNG or JPEG.");
  if (
    prefix.some(
      (byte) =>
        byte <= 8 || byte === 11 || (byte >= 14 && byte <= 26) || (byte >= 28 && byte <= 31),
    )
  )
    throw new Error("This file type is not supported. Choose plain text, PDF, PNG or JPEG.");
  return "text/plain";
}

export function checkFilePolicy(file: AssistanceFileMetadata, policy: AssistanceFilePolicy) {
  if (
    validator.validate(AssistanceFilePolicySchema, policy).kind !== "valid" ||
    validator.validate(AssistanceFileMetadataSchema, file).kind !== "valid"
  )
    throw new Error("File limits are unavailable. Refresh the assistance policy.");
  const extension = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
  if (file.size > policy.maxFileBytes || file.size > policy.maxSessionBytes)
    throw new Error("This file exceeds the allowed size. Choose a smaller file.");
  if (
    !policy.allowedMimeTypes.includes(file.mimeType) ||
    !policy.allowedExtensions.includes(extension)
  )
    throw new Error(
      "This file type is not allowed. Review the file limits and choose another file.",
    );
}

// Explicit slices cap every allocation independently of the browser's stream chunk size.
export async function prepareFile(
  file: File,
  policy: AssistanceFilePolicy,
  signal: AbortSignal,
  progress: (bytes: number) => void,
): Promise<AssistanceFileMetadata> {
  signal.throwIfAborted();
  const metadata = create(AssistanceFileMetadataSchema, {
    name: file.name,
    size: BigInt(file.size),
    mimeType: "text/plain",
  });
  if (
    !Number.isSafeInteger(file.size) ||
    file.size > Number(policy.maxFileBytes) ||
    file.size > 16 * 1024 * 1024
  )
    throw new Error("This file exceeds the allowed size. Choose a smaller file.");
  const hash = sha256.create();
  try {
    metadata.mimeType = sniffFileType(
      new Uint8Array(await awaitFileOperation(file.slice(0, 512).arrayBuffer(), signal)),
    );
    signal.throwIfAborted();
    checkFilePolicy(metadata, policy);
    for (let offset = 0; offset < file.size; offset += FILE_CHUNK_BYTES) {
      signal.throwIfAborted();
      const bytes = new Uint8Array(
        await awaitFileOperation(
          file.slice(offset, offset + FILE_CHUNK_BYTES).arrayBuffer(),
          signal,
        ),
      );
      signal.throwIfAborted();
      if (bytes.length !== Math.min(FILE_CHUNK_BYTES, file.size - offset))
        throw new Error("The selected file changed. Select it again.");
      hash.update(bytes);
      progress(offset + bytes.length);
    }
    metadata.sha256 = hash.digest();
    return metadata;
  } finally {
    hash.destroy();
  }
}

export async function sendFileFrame(
  channel: RTCDataChannel,
  frame: AssistanceFileFrame,
  signal: AbortSignal,
) {
  const bytes = encodeFileFrame(frame);
  signal.throwIfAborted();
  if (channel.readyState !== "open") throw new Error("The file connection closed.");
  if (channel.bufferedAmount + bytes.length > FILE_BUFFER_BYTES) {
    channel.bufferedAmountLowThreshold = FILE_BUFFER_BYTES / 2;
    await new Promise<void>((resolve, reject) => {
      const clean = () => {
        channel.removeEventListener("bufferedamountlow", low);
        channel.removeEventListener("close", closed);
        channel.removeEventListener("error", closed);
        signal.removeEventListener("abort", aborted);
      };
      const low = () => {
        if (channel.bufferedAmount + bytes.length <= FILE_BUFFER_BYTES) {
          clean();
          resolve();
        }
      };
      const closed = () => {
        clean();
        reject(new Error("The file connection closed."));
      };
      const aborted = () => {
        clean();
        reject(signal.reason);
      };
      channel.addEventListener("bufferedamountlow", low);
      channel.addEventListener("close", closed);
      channel.addEventListener("error", closed);
      signal.addEventListener("abort", aborted, { once: true });
      if (signal.aborted) aborted();
      else if (channel.readyState !== "open") closed();
      else low();
    });
  }
  signal.throwIfAborted();
  if (channel.readyState !== "open") throw new Error("The file connection closed.");
  channel.send(bytes);
}

// One mailbox per exact server operation. The listener is installed before Start RPC,
// but no frame can cause a write or Ready before authorize() observes TRANSFERRING.
export class FileTransferStream {
  private readonly controller = new AbortController();
  readonly signal: AbortSignal;
  private readonly channel: RTCDataChannel;
  private readonly requestId: string;
  private readonly queue: AssistanceFileFrame[] = [];
  private wake: (() => void) | null = null;
  private authorized = false;
  private started = false;
  private disposed = false;
  private expected: "start" | "ready" | "data" | "receipt" | null = null;
  private readonly retiredRequests: ReadonlySet<string> | undefined;

  constructor(
    channel: RTCDataChannel,
    requestId: string,
    signal: AbortSignal,
    retiredRequests?: ReadonlySet<string>,
  ) {
    this.channel = channel;
    this.requestId = requestId;
    this.signal = AbortSignal.any([signal, this.controller.signal]);
    this.retiredRequests = retiredRequests;
    channel.binaryType = "arraybuffer";
    channel.addEventListener("message", this.message);
    channel.addEventListener("close", this.closed);
    channel.addEventListener("error", this.closed);
    this.signal.addEventListener("abort", this.aborted, { once: true });
  }

  private message = (event: MessageEvent<unknown>) => {
    try {
      const frame = decodeFileFrame(event.data);
      // RPC completion can overtake reliable SCTP delivery. Known completed
      // identities are permanently revoked: valid late frames are discarded,
      // never queued, written or interpreted as a new transfer.
      if (this.retiredRequests?.has(frame.requestId)) return;
      if (
        frame.requestId !== this.requestId ||
        this.queue.length >= FILE_QUEUE_FRAMES ||
        this.disposed
      )
        throw new Error("The file connection no longer matches this transfer. Stop the session.");
      if (this.signal.aborted) return;
      if (frame.body.case === "cancel") {
        this.controller.abort(new FileRemoteCancellationError());
        return;
      }
      const kind = frame.body.case;
      if (this.expected === "data" ? kind !== "chunk" && kind !== "end" : kind !== this.expected)
        throw new Error("The file connection sent data before it was accepted or after it ended.");
      if (kind !== "chunk") this.expected = null;
      this.queue.push(frame);
      this.wake?.();
    } catch (error) {
      this.controller.abort(error);
      this.channel.close();
    }
  };
  private closed = () =>
    this.controller.abort(
      new Error("The file connection closed. Stop the session before trying again."),
    );
  private aborted = () => {
    this.queue.length = 0;
    this.wake?.();
  };

  authorize() {
    this.signal.throwIfAborted();
    this.authorized = true;
    this.wake?.();
  }

  private async waitFor(condition: () => boolean) {
    while (!condition()) {
      this.signal.throwIfAborted();
      await new Promise<void>((resolve) => {
        this.wake = resolve;
      });
      this.wake = null;
    }
    this.signal.throwIfAborted();
  }

  private async next(): Promise<AssistanceFileFrame> {
    await this.waitFor(() => this.queue.length > 0);
    return this.queue.shift()!;
  }

  private send(body: AssistanceFileFrame["body"]) {
    return sendFileFrame(
      this.channel,
      create(AssistanceFileFrameSchema, { requestId: this.requestId, body }),
      this.signal,
    );
  }

  async transfer(
    direction: AssistanceFileDirection,
    policy: AssistanceFilePolicy,
    source: { file: File; metadata: AssistanceFileMetadata } | null,
    destination: FileDestination | null,
    progress: (bytes: number) => void,
  ): Promise<AssistanceFileMetadata> {
    if (this.started) throw new Error("This transfer has already started.");
    this.started = true;
    this.expected = direction === AssistanceFileDirection.FROM_USER ? "start" : null;
    let closed = false;
    const hash = sha256.create();
    let aborting: Promise<void> | null = null;
    const abortDestination = () => {
      if (!destination || closed || aborting) return;
      // Initiate abort immediately, even while an asynchronous disk write is pending.
      aborting = destination.abort(this.signal.reason);
      // The same promise is awaited below; attach rejection handling now.
      void aborting.catch(() => {});
    };
    this.signal.addEventListener("abort", abortDestination, { once: true });
    try {
      await this.waitFor(() => this.authorized);
      if (direction === AssistanceFileDirection.TO_USER && source && !destination) {
        checkFilePolicy(source.metadata, policy);
        if (
          source.metadata.sha256.length !== 32 ||
          BigInt(source.file.size) !== source.metadata.size
        )
          throw new Error("The selected file no longer matches this transfer.");
        this.expected = "ready";
        await this.send({ case: "start", value: source.metadata });
        if ((await this.next()).body.case !== "ready")
          throw new Error("The device did not accept this transfer.");
        for (let offset = 0; offset < source.file.size; offset += FILE_CHUNK_BYTES) {
          this.signal.throwIfAborted();
          const data = new Uint8Array(
            await awaitFileOperation(
              source.file.slice(offset, offset + FILE_CHUNK_BYTES).arrayBuffer(),
              this.signal,
            ),
          );
          this.signal.throwIfAborted();
          if (data.length !== Math.min(FILE_CHUNK_BYTES, source.file.size - offset))
            throw new Error("The selected file changed. Select it again.");
          hash.update(data);
          await this.send({
            case: "chunk",
            value: {
              $typeName: "lindm.agent.v1.AssistanceFileChunk",
              offset: BigInt(offset),
              data,
            },
          });
          progress(offset + data.length);
        }
        const digest = hash.digest();
        if (
          !sameDigest(digest, source.metadata.sha256) ||
          BigInt(source.file.size) !== source.metadata.size
        )
          throw new Error("The selected file changed. Select it again.");
        this.expected = "receipt";
        await this.send({
          case: "end",
          value: {
            $typeName: "lindm.agent.v1.AssistanceFileEnd",
            size: source.metadata.size,
            sha256: digest,
          },
        });
        const receipt = (await this.next()).body;
        if (
          receipt.case !== "receipt" ||
          !receipt.value.file ||
          !sameFile(source.metadata, receipt.value.file)
        )
          throw new Error(
            "The device could not confirm the saved file. Check the device before sending again.",
          );
        if (this.queue.length) throw new Error("Unexpected data after file completion.");
        return receipt.value.file;
      }
      if (direction !== AssistanceFileDirection.FROM_USER || !destination || source)
        throw new Error("The file direction does not match this transfer.");
      const start = (await this.next()).body;
      if (start.case !== "start") throw new Error("The device did not identify its selected file.");
      const metadata = start.value;
      checkFilePolicy(metadata, policy);
      this.expected = "data";
      await this.send({
        case: "ready",
        value: { $typeName: "lindm.agent.v1.AssistanceFileReady" },
      });
      let offset = 0n;
      const prefix = new Uint8Array(512);
      let prefixSize = 0;
      for (;;) {
        const body = (await this.next()).body;
        if (body.case === "chunk") {
          const { data } = body.value;
          if (body.value.offset !== offset || offset + BigInt(data.length) > metadata.size)
            throw new Error("The file arrived out of order or exceeded its declared size.");
          const take = Math.min(512 - prefixSize, data.length);
          prefix.set(data.subarray(0, take), prefixSize);
          prefixSize += take;
          hash.update(data);
          this.signal.throwIfAborted();
          await awaitFileOperation(destination.write(data), this.signal);
          this.signal.throwIfAborted();
          offset += BigInt(data.length);
          progress(Number(offset));
          continue;
        }
        if (body.case !== "end" || body.value.size !== offset || offset !== metadata.size)
          throw new Error("The file ended before its full size could be verified.");
        const digest = hash.digest();
        if (
          !sameDigest(digest, body.value.sha256) ||
          (metadata.sha256.length !== 0 && !sameDigest(digest, metadata.sha256)) ||
          sniffFileType(prefix.subarray(0, prefixSize)) !== metadata.mimeType
        )
          throw new Error(
            "The file contents could not be verified. The partial download was discarded.",
          );
        if (this.queue.length) throw new Error("Unexpected data after the end of the file.");
        this.signal.throwIfAborted();
        await awaitFileOperation(destination.close(), this.signal);
        closed = true;
        this.signal.throwIfAborted();
        const verified = create(AssistanceFileMetadataSchema, { ...metadata, sha256: digest });
        await this.send({
          case: "receipt",
          value: { $typeName: "lindm.agent.v1.AssistanceFileReceipt", file: verified },
        });
        return verified;
      }
    } catch (cause) {
      if (destination && !closed) {
        abortDestination();
        try {
          await awaitFileOperation(aborting!, AbortSignal.timeout(10_000));
        } catch (cleanupError) {
          throw new FileCleanupError(new AggregateError([cause, cleanupError]));
        }
      }
      throw cause;
    } finally {
      hash.destroy();
      this.signal.removeEventListener("abort", abortDestination);
    }
  }

  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.controller.abort(new Error("The transfer ended."));
    this.channel.removeEventListener("message", this.message);
    this.channel.removeEventListener("close", this.closed);
    this.channel.removeEventListener("error", this.closed);
    this.signal.removeEventListener("abort", this.aborted);
    this.queue.length = 0;
  }
}
