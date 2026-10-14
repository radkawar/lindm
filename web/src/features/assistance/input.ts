// SPDX-License-Identifier: Apache-2.0

// Input capture for the authenticated "lindm-input" data channel. Every press
// carries the selected display and its generation so queued coordinates AND
// keyboard events cannot cross a switch. Release remains safe across generations.
// Semantic keys follow KeyboardEvent.key; physical keys follow code.

import { unicodeLegacyKeysyms } from "./keysym-table.generated.ts";

const MOVE_INTERVAL_MS = 1000 / 60;
const MAX_WHEEL_STEPS = 10;
const MAX_CODE_LENGTH = 64;
// Pointer motion is dropped instead of queued once the channel is this far behind.
const MAX_BUFFERED_BYTES = 64 * 1024;
const WHEEL_PIXELS_PER_STEP = 100;
const WHEEL_LINES_PER_STEP = 3;
const PRINTABLE_KEY = /^[\p{L}\p{M}\p{N}\p{P}\p{S} ]$/u;

const buttonNames: Record<number, "left" | "middle" | "right"> = {
  0: "left",
  1: "middle",
  2: "right",
};

export type KeyboardMode = "text" | "physical";

type InputMessage =
  | { t: "move"; x: number; y: number; display: string; generation: number }
  | {
      t: "button";
      b: "left" | "middle" | "right";
      down: boolean;
      display: string;
      generation: number;
    }
  | { t: "wheel"; dx: number; dy: number; display: string; generation: number }
  | { t: "key"; code: string; down: boolean; display: string; generation: number }
  | { t: "keysym"; keysym: number; down: boolean; display: string; generation: number }
  | { t: "release" };

export function printableKeysym(key: string): number | null {
  const point = key.codePointAt(0);
  if (point === undefined || key.length !== (point > 0xffff ? 2 : 1)) return null;
  // Match the native printable categories, not merely "not a control". Format,
  // surrogate, private-use and unassigned characters are not printable input.
  if (!PRINTABLE_KEY.test(key)) return null;
  // Mutter matches exact XKB symbols in its active keymap. Prefer maintained
  // legacy symbols (Euro, Cyrillic, Greek, etc.), as xkb_utf32_to_keysym does.
  return point <= 0xff ? point : (unicodeLegacyKeysyms[point] ?? 0x01000000 | point);
}

// Maps a client point to the displayed frame of an object-fit: contain video, excluding
// the letterbox bars. Returns null outside the frame unless clamping (during a drag).
export function videoFramePoint(
  video: HTMLVideoElement,
  clientX: number,
  clientY: number,
  clamp: boolean,
): { x: number; y: number } | null {
  const rect = video.getBoundingClientRect();
  const sourceWidth = video.videoWidth;
  const sourceHeight = video.videoHeight;
  if (!sourceWidth || !sourceHeight || !rect.width || !rect.height) return null;
  const scale = Math.min(rect.width / sourceWidth, rect.height / sourceHeight);
  const width = sourceWidth * scale;
  const height = sourceHeight * scale;
  let x = (clientX - rect.left - (rect.width - width) / 2) / width;
  let y = (clientY - rect.top - (rect.height - height) / 2) / height;
  if (x < 0 || x > 1 || y < 0 || y > 1) {
    if (!clamp) return null;
    x = Math.min(1, Math.max(0, x));
    y = Math.min(1, Math.max(0, y));
  }
  return { x: Math.round(x * 10_000) / 10_000, y: Math.round(y * 10_000) / 10_000 };
}

export class InputCapture {
  private readonly channel: RTCDataChannel;
  private readonly display: string;
  private readonly generation: number;
  private readonly epoch: number;
  private disposed = false;
  private readonly pressedKeys = new Map<string, Extract<InputMessage, { t: "key" | "keysym" }>>();
  private readonly pressedButtons = new Set<"left" | "middle" | "right">();
  private pendingMove: { x: number; y: number } | null = null;
  private moveTimer: number | undefined;
  private lastMoveAt = Number.NEGATIVE_INFINITY;
  private wheelX = 0;
  private wheelY = 0;

  constructor(channel: RTCDataChannel, display: string, generation: number, epoch: number) {
    if (!Number.isInteger(epoch) || epoch < 1 || epoch > 0xffffffff)
      throw new Error("Remote input requires a current input epoch.");
    this.channel = channel;
    this.display = display;
    this.generation = generation;
    this.epoch = epoch;
  }

  get dragging(): boolean {
    return this.pressedButtons.size > 0;
  }

  move(point: { x: number; y: number }) {
    if (this.disposed) return;
    this.pendingMove = point;
    if (this.moveTimer !== undefined) return;
    const wait = this.lastMoveAt + MOVE_INTERVAL_MS - performance.now();
    if (wait <= 0) {
      this.flushMove();
      return;
    }
    this.moveTimer = window.setTimeout(() => {
      this.moveTimer = undefined;
      this.flushMove();
    }, wait);
  }

  button(domButton: number, down: boolean): boolean {
    if (this.disposed) return false;
    const name = buttonNames[domButton];
    if (!name) return false;
    if (down === this.pressedButtons.has(name)) return true;
    this.flushMove();
    if (down) this.pressedButtons.add(name);
    else this.pressedButtons.delete(name);
    this.send({ t: "button", b: name, down, display: this.display, generation: this.generation });
    return true;
  }

  wheel(event: WheelEvent) {
    if (this.disposed) return;
    const perStep =
      event.deltaMode === WheelEvent.DOM_DELTA_LINE
        ? WHEEL_LINES_PER_STEP
        : event.deltaMode === WheelEvent.DOM_DELTA_PAGE
          ? 1
          : WHEEL_PIXELS_PER_STEP;
    this.wheelX += event.deltaX / perStep;
    this.wheelY += event.deltaY / perStep;
    const dx = Math.max(-MAX_WHEEL_STEPS, Math.min(MAX_WHEEL_STEPS, Math.trunc(this.wheelX)));
    const dy = Math.max(-MAX_WHEEL_STEPS, Math.min(MAX_WHEEL_STEPS, Math.trunc(this.wheelY)));
    if (dx === 0 && dy === 0) return;
    // Keep the sub-step remainder; discard anything beyond the per-message clamp.
    this.wheelX = Math.abs(this.wheelX - dx) < 1 ? this.wheelX - dx : 0;
    this.wheelY = Math.abs(this.wheelY - dy) < 1 ? this.wheelY - dy : 0;
    this.flushMove();
    this.send({ t: "wheel", dx, dy, display: this.display, generation: this.generation });
  }

  key(event: KeyboardEvent, mode: KeyboardMode): boolean {
    if (this.disposed) return false;
    const { code } = event;
    const down = event.type === "keydown";
    if (code === "" || code === "Unidentified" || code.length > MAX_CODE_LENGTH) return false;
    const held = this.pressedKeys.get(code);
    if (!down) {
      if (!held) return false;
      this.pressedKeys.delete(code);
      this.send({ ...held, down: false });
      return true;
    }
    if (event.isComposing) return false;
    if (held) {
      this.send(held);
      return true;
    }
    let message: Extract<InputMessage, { t: "key" | "keysym" }>;
    if (mode === "physical") {
      message = { t: "key", code, down: true, display: this.display, generation: this.generation };
    } else {
      // AltGraph may produce a printable symbol; ordinary shortcuts stay physical.
      if (event.metaKey || ((event.ctrlKey || event.altKey) && !event.getModifierState("AltGraph")))
        return false;
      const keysym = printableKeysym(event.key);
      if (keysym === null) return false;
      message = {
        t: "keysym",
        keysym,
        down: true,
        display: this.display,
        generation: this.generation,
      };
    }
    this.pressedKeys.set(code, message);
    this.send(message);
    return true;
  }

  // Releases every key and button this page pressed, e.g. on blur or when control stops.
  releaseAll() {
    clearTimeout(this.moveTimer);
    this.moveTimer = undefined;
    this.pendingMove = null;
    this.send({ t: "release" });
    this.pressedKeys.clear();
    this.pressedButtons.clear();
    this.wheelX = 0;
    this.wheelY = 0;
  }

  dispose() {
    this.releaseAll();
    clearTimeout(this.moveTimer);
    this.moveTimer = undefined;
    this.pendingMove = null;
    this.disposed = true;
  }

  private flushMove() {
    clearTimeout(this.moveTimer);
    this.moveTimer = undefined;
    const point = this.pendingMove;
    this.pendingMove = null;
    if (!point) return;
    this.lastMoveAt = performance.now();
    if (this.channel.bufferedAmount > MAX_BUFFERED_BYTES) return;
    this.send({
      t: "move",
      x: point.x,
      y: point.y,
      display: this.display,
      generation: this.generation,
    });
  }

  private send(message: InputMessage) {
    if (this.disposed || this.channel.readyState !== "open") return;
    this.channel.send(
      JSON.stringify(message.t === "release" ? message : { ...message, epoch: this.epoch }),
    );
  }
}

// This authority clock is independent of the displayed media generation. A stale
// poll or a changed pause flag without a new epoch can never resume remote input.
export class InputEpochFence {
  private epoch = 0;
  private paused = true;
  private valid = false;

  receive(state: { epoch: number; paused: boolean } | undefined): boolean {
    if (
      !state ||
      !Number.isInteger(state.epoch) ||
      state.epoch < 1 ||
      state.epoch > 0xffffffff ||
      state.epoch < this.epoch ||
      (state.epoch === this.epoch && state.paused !== this.paused)
    ) {
      this.valid = false;
      return false;
    }
    if (state.epoch > this.epoch) {
      this.epoch = state.epoch;
      this.paused = state.paused;
      this.valid = true;
    }
    return this.valid && !this.paused;
  }
}
