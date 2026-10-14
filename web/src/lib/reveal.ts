// SPDX-License-Identifier: Apache-2.0

// Decodes revealed bytes only for rendering. Text that is not valid UTF-8 is shown as
// hexadecimal instead of being silently altered by replacement characters.
export function revealedText(bytes: Uint8Array): { text: string; hex: boolean } {
  try {
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes), hex: false };
  } catch {
    return {
      text: Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""),
      hex: true,
    };
  }
}
