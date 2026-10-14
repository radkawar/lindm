// SPDX-License-Identifier: Apache-2.0

// Assembles one authorized recording retrieval in browser memory. The server
// authenticates every segment; this enforces the retrieval contract so a short,
// reordered or oversized response is never presented as the recording.

export const RECORDING_SEGMENT_BYTES = 192 * 1024;
export const RECORDING_MEDIA_TYPE = "video/webm";

export type RecordingSegment = {
  data: Uint8Array;
  sequence: number;
  last: boolean;
  complete: boolean;
};

export type RecordingPlayback = {
  parts: Uint8Array[];
  bytes: number;
  complete: boolean;
};

export class RecordingContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RecordingContractError";
  }
}

export class RecordingAssembly {
  private readonly parts: Uint8Array[] = [];
  private bytes = 0;
  private finished = false;
  private complete = false;

  constructor(
    private readonly segments: number,
    private readonly maxBytes: number,
  ) {
    if (!Number.isInteger(segments) || segments < 1 || segments > 65536)
      throw new RecordingContractError("The recording has no stored segments.");
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1)
      throw new RecordingContractError("The recording size limit is invalid.");
  }

  get next(): number {
    return this.parts.length;
  }

  get done(): boolean {
    return this.finished;
  }

  accept(segment: RecordingSegment) {
    if (this.finished) throw new RecordingContractError("The recording already ended.");
    if (segment.sequence !== this.parts.length)
      throw new RecordingContractError("A recording segment arrived out of order.");
    if (segment.data.byteLength > RECORDING_SEGMENT_BYTES)
      throw new RecordingContractError("A recording segment is larger than allowed.");
    if (this.bytes + segment.data.byteLength > this.maxBytes)
      throw new RecordingContractError("The recording is larger than its limit.");
    const last = segment.sequence === this.segments - 1;
    if (segment.last !== last)
      throw new RecordingContractError("The recording ended at an unexpected segment.");
    if (this.parts.length > 0 && segment.complete !== this.complete)
      throw new RecordingContractError("The recording completeness changed during playback.");
    this.complete = segment.complete;
    this.parts.push(segment.data);
    this.bytes += segment.data.byteLength;
    this.finished = last;
  }

  result(): RecordingPlayback {
    if (!this.finished) throw new RecordingContractError("The recording is not fully loaded.");
    return { parts: [...this.parts], bytes: this.bytes, complete: this.complete };
  }
}

// readRecording fetches every segment in order. Retrieval authority expires
// server-side; an abort stops the download without presenting a prefix.
export async function readRecording(
  segments: number,
  maxBytes: number,
  read: (sequence: number, signal: AbortSignal) => Promise<RecordingSegment>,
  signal: AbortSignal,
  progress?: (loaded: number) => void,
): Promise<RecordingPlayback> {
  const assembly = new RecordingAssembly(segments, maxBytes);
  while (!assembly.done) {
    signal.throwIfAborted();
    assembly.accept(await read(assembly.next, signal));
    progress?.(assembly.next);
  }
  return assembly.result();
}
