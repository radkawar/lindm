// Input capture for the "lindm-input" data channel. Messages follow the assistance
// contract: {"t":"move","x","y"} with coordinates normalized to the video frame,
// {"t":"button","b","down"}, {"t":"wheel","dx","dy"} in discrete steps (DOM sign:
// positive is down/right) and {"t":"key","code","down"} with KeyboardEvent.code.

const MOVE_INTERVAL_MS = 1000 / 60;
const MAX_WHEEL_STEPS = 10;
const MAX_CODE_LENGTH = 64;
// Pointer motion is dropped instead of queued once the channel is this far behind.
const MAX_BUFFERED_BYTES = 64 * 1024;
const WHEEL_PIXELS_PER_STEP = 100;
const WHEEL_LINES_PER_STEP = 3;

const buttonNames: Record<number, "left" | "middle" | "right"> = {
  0: "left",
  1: "middle",
  2: "right",
};

type InputMessage =
  | { t: "move"; x: number; y: number }
  | { t: "button"; b: "left" | "middle" | "right"; down: boolean }
  | { t: "wheel"; dx: number; dy: number }
  | { t: "key"; code: string; down: boolean };

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
  private readonly pressedKeys = new Set<string>();
  private readonly pressedButtons = new Set<"left" | "middle" | "right">();
  private pendingMove: { x: number; y: number } | null = null;
  private moveTimer: number | undefined;
  private lastMoveAt = Number.NEGATIVE_INFINITY;
  private wheelX = 0;
  private wheelY = 0;

  constructor(private readonly channel: RTCDataChannel) {}

  get dragging(): boolean {
    return this.pressedButtons.size > 0;
  }

  move(point: { x: number; y: number }) {
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
    const name = buttonNames[domButton];
    if (!name) return false;
    if (down === this.pressedButtons.has(name)) return true;
    this.flushMove();
    if (down) this.pressedButtons.add(name);
    else this.pressedButtons.delete(name);
    this.send({ t: "button", b: name, down });
    return true;
  }

  wheel(event: WheelEvent) {
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
    this.send({ t: "wheel", dx, dy });
  }

  key(code: string, down: boolean): boolean {
    if (code === "" || code === "Unidentified" || code.length > MAX_CODE_LENGTH) return false;
    if (!down && !this.pressedKeys.has(code)) return true;
    if (down) this.pressedKeys.add(code);
    else this.pressedKeys.delete(code);
    this.send({ t: "key", code, down });
    return true;
  }

  // Releases every key and button this page pressed, e.g. on blur or when control stops.
  releaseAll() {
    for (const code of this.pressedKeys) this.send({ t: "key", code, down: false });
    this.pressedKeys.clear();
    for (const name of this.pressedButtons) this.send({ t: "button", b: name, down: false });
    this.pressedButtons.clear();
    this.wheelX = 0;
    this.wheelY = 0;
  }

  dispose() {
    this.releaseAll();
    clearTimeout(this.moveTimer);
    this.moveTimer = undefined;
    this.pendingMove = null;
  }

  private flushMove() {
    clearTimeout(this.moveTimer);
    this.moveTimer = undefined;
    const point = this.pendingMove;
    this.pendingMove = null;
    if (!point) return;
    this.lastMoveAt = performance.now();
    if (this.channel.bufferedAmount > MAX_BUFFERED_BYTES) return;
    this.send({ t: "move", x: point.x, y: point.y });
  }

  private send(message: InputMessage) {
    if (this.channel.readyState !== "open") return;
    this.channel.send(JSON.stringify(message));
  }
}
