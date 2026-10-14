// SPDX-License-Identifier: Apache-2.0

// Operator pointer and annotation frames for the "lindm-annotate" channel.
// The vocabulary is pointer position, bounded strokes and clear: it carries no
// clicks, keys or other input, so annotation never acts on the device.

export const ANNOTATION_CHANNEL_LABEL = "lindm-annotate";
export const MAX_STROKE_POINTS = 64;
// The device admits at most 60 frames per second; stay well below it.
export const ANNOTATION_INTERVAL_MS = 50;
const MAX_STROKE_ID = 0x7fffffff;

export type AnnotationPoint = { x: number; y: number };

export type AnnotationMessage =
  | { t: "p"; d: string; g: number; x: number; y: number }
  | { t: "s"; d: string; g: number; id: number; p: [number, number][] }
  | { t: "c" };

type Channel = { readyState: string; send: (data: string) => void };

function normalized(point: AnnotationPoint): boolean {
  return (
    Number.isFinite(point.x) &&
    Number.isFinite(point.y) &&
    point.x >= 0 &&
    point.x <= 1 &&
    point.y >= 0 &&
    point.y <= 1
  );
}

// AnnotationSender binds frames to one shared display generation. A display
// switch needs a new sender, so marks never land on another monitor.
export class AnnotationSender {
  private readonly channel: Channel;
  private readonly display: string;
  private readonly generation: number;
  private readonly drawing: boolean;
  private readonly now: () => number;
  private lastSent = Number.NEGATIVE_INFINITY;
  private nextId = 1;
  private stroke: { id: number; points: [number, number][] } | null = null;
  private disposed = false;

  constructor(
    channel: Channel,
    display: string,
    generation: number,
    drawing: boolean,
    now: () => number = () => Date.now(),
  ) {
    this.channel = channel;
    this.display = display;
    this.generation = generation;
    this.drawing = drawing;
    this.now = now;
  }

  private send(message: AnnotationMessage): boolean {
    if (this.disposed || this.channel.readyState !== "open") return false;
    this.channel.send(JSON.stringify(message));
    this.lastSent = this.now();
    return true;
  }

  // pointer moves the ephemeral pointer; frames inside the interval are dropped.
  pointer(point: AnnotationPoint): boolean {
    if (!normalized(point) || this.now() - this.lastSent < ANNOTATION_INTERVAL_MS) return false;
    return this.send({ t: "p", d: this.display, g: this.generation, x: point.x, y: point.y });
  }

  beginStroke(point: AnnotationPoint): boolean {
    if (!this.drawing || !normalized(point)) return false;
    this.stroke = { id: this.takeId(), points: [[point.x, point.y]] };
    return true;
  }

  // extendStroke adds a point and sends the stroke so far. A stroke at the
  // point bound is sent whole and continues as a new stroke.
  extendStroke(point: AnnotationPoint): boolean {
    const stroke = this.stroke;
    if (!stroke || !normalized(point)) return false;
    const last = stroke.points[stroke.points.length - 1];
    if (last && last[0] === point.x && last[1] === point.y) return false;
    stroke.points.push([point.x, point.y]);
    if (stroke.points.length >= MAX_STROKE_POINTS) {
      const sent = this.sendStroke(stroke);
      this.stroke = { id: this.takeId(), points: [[point.x, point.y]] };
      return sent;
    }
    return this.now() - this.lastSent >= ANNOTATION_INTERVAL_MS ? this.sendStroke(stroke) : false;
  }

  endStroke(): boolean {
    const stroke = this.stroke;
    this.stroke = null;
    return stroke ? this.sendStroke(stroke) : false;
  }

  clear(): boolean {
    this.stroke = null;
    return this.send({ t: "c" });
  }

  dispose(): void {
    this.disposed = true;
    this.stroke = null;
  }

  private sendStroke(stroke: { id: number; points: [number, number][] }): boolean {
    if (stroke.points.length < 2) return false;
    return this.send({
      t: "s",
      d: this.display,
      g: this.generation,
      id: stroke.id,
      p: stroke.points.slice(0, MAX_STROKE_POINTS),
    });
  }

  private takeId(): number {
    const id = this.nextId;
    this.nextId = id >= MAX_STROKE_ID ? 1 : id + 1;
    return id;
  }
}
