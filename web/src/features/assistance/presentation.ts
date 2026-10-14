// SPDX-License-Identifier: Apache-2.0

export type DisplayFrameMarker = {
  t: "display-frame";
  display: string;
  generation: number;
  rtpTimestamp: number;
};

function uint32(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

export function parseDisplayFrameMarker(data: unknown): DisplayFrameMarker | null {
  if (typeof data !== "string" || data.length > 256 || new TextEncoder().encode(data).length > 256)
    return null;
  try {
    const value: unknown = JSON.parse(data);
    if (typeof value !== "object" || value === null) return null;
    const marker = value as Record<string, unknown>;
    if (
      marker.t !== "display-frame" ||
      typeof marker.display !== "string" ||
      marker.display === "" ||
      !uint32(marker.generation) ||
      marker.generation === 0 ||
      !uint32(marker.rtpTimestamp)
    )
      return null;
    return {
      t: "display-frame",
      display: marker.display,
      generation: marker.generation,
      rtpTimestamp: marker.rtpTimestamp,
    };
  } catch {
    return null;
  }
}

// A session is at most 30 minutes: its 90 kHz video timeline spans less than
// half the uint32 range. Modular ordering therefore survives RTP timestamp wrap
// without mistaking a just-before-switch frame for a post-switch presentation.
export function rtpAtOrAfter(presented: number, first: number): boolean {
  return uint32(presented) && uint32(first) && (presented - first) >>> 0 < 0x80000000;
}

// Stores metadata only. Session, marker and presentation can arrive in any order.
// Generations increase once per actual switch and never wrap within a session.
export class DisplayPresentationFence {
  private display = "";
  private generation = 0;
  private marker: DisplayFrameMarker | null = null;
  private presented: number | null = null;
  metadataAvailable: boolean | null = null;

  select(display: string, generation: number) {
    this.display = display;
    this.generation = generation;
  }

  receive(marker: DisplayFrameMarker) {
    // Also used by the typed session projection, whose absent/default values
    // must not accidentally establish an initial generation.
    if (
      !marker.display ||
      !uint32(marker.generation) ||
      marker.generation === 0 ||
      !uint32(marker.rtpTimestamp)
    )
      return;
    if (this.marker && marker.generation <= this.marker.generation) return;
    this.marker = marker;
  }

  present(rtpTimestamp: unknown) {
    this.metadataAvailable = uint32(rtpTimestamp);
    this.presented = this.metadataAvailable ? (rtpTimestamp as number) : null;
  }

  clearPresentation() {
    this.presented = null;
  }

  get ready(): boolean {
    return (
      this.marker !== null &&
      this.presented !== null &&
      this.marker.display === this.display &&
      this.marker.generation === this.generation &&
      rtpAtOrAfter(this.presented, this.marker.rtpTimestamp)
    );
  }
}

// An ended record or an older agent without a cursor report is not a live
// cursor limitation. The device reports this independently of input authority.
export function cursorVisibilityNote(ended: boolean, hidden: boolean | undefined): string | null {
  return !ended && hidden === true ? "Cursor isn't shown on this desktop version" : null;
}
