// SPDX-License-Identifier: Apache-2.0

// Native GTK marker contract (internal/vmlab/assistance_fixture.py): 14 bytes,
// MSB first, row-major in 8 rows of 14 bits. Bytes are 0xa7, head (0 or 1),
// then the 12-byte fixture nonce. Each bit occupies two horizontal cells:
// black/white for zero, white/black for one. Every pair must be complementary.
// RGB samples are central 3x3 averages, one triplet per cell. Neutral dark
// (all channels <= 80) and light (all >= 175) tolerate codec error, but neither
// colored wallpaper nor ambiguous/corrupt samples can establish readiness.
export function decodeNativeMarker(samples, expectedNonce) {
  if (
    typeof expectedNonce !== "string" ||
    !/^[a-f0-9]{24}$/.test(expectedNonce) ||
    !Array.isArray(samples) ||
    samples.length !== 8 * 28 * 3
  )
    return null;
  const bytes = new Uint8Array(14);
  for (let bit = 0; bit < 112; bit++) {
    let first;
    for (let half = 0; half < 2; half++) {
      const offset = (bit * 2 + half) * 3;
      let dark = true;
      let light = true;
      for (let channel = 0; channel < 3; channel++) {
        const value = samples[offset + channel];
        if (!Number.isInteger(value) || value < 0 || value > 255) return null;
        dark &&= value <= 80;
        light &&= value >= 175;
      }
      if (!dark && !light) return null;
      const value = light ? 1 : 0;
      if (half === 0) first = value;
      else if (value === first) return null;
    }
    bytes[bit >> 3] |= first << (7 - (bit % 8));
  }
  if (bytes[0] !== 0xa7 || bytes[1] > 1) return null;
  let nonce = "";
  for (let index = 2; index < bytes.length; index++)
    nonce += bytes[index].toString(16).padStart(2, "0");
  return nonce === expectedNonce ? { head: bytes[1], nonce } : null;
}

// Passed directly to Playwright evaluate: no module closures or synthetic media.
// Read only the bounded marker region of the console's actual video, independent
// of CSS fitting/fullscreen. GTK draws at the same normalized coordinates.
export function sampleNativeMarker(surface) {
  const video = document.querySelector(`${surface} video`);
  if (
    !video ||
    video.readyState < 2 ||
    (video.videoWidth * 0.8) / 28 < 8 ||
    (video.videoHeight * 0.28) / 8 < 8
  )
    return null;
  const canvas = document.createElement("canvas");
  canvas.width = 140;
  canvas.height = 40;
  const context = canvas.getContext("2d");
  if (!context) return null;
  context.imageSmoothingEnabled = false;
  context.drawImage(
    video,
    video.videoWidth * 0.1,
    video.videoHeight * 0.65,
    video.videoWidth * 0.8,
    video.videoHeight * 0.28,
    0,
    0,
    canvas.width,
    canvas.height,
  );
  const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
  const samples = [];
  for (let row = 0; row < 8; row++) {
    for (let column = 0; column < 28; column++) {
      for (let channel = 0; channel < 3; channel++) {
        let sum = 0;
        for (let y = 1; y <= 3; y++) {
          for (let x = 1; x <= 3; x++)
            sum += pixels[((row * 5 + y) * canvas.width + column * 5 + x) * 4 + channel];
        }
        samples.push(Math.round(sum / 9));
      }
    }
  }
  return samples;
}
