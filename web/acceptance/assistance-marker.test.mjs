import assert from "node:assert/strict";
import test from "node:test";
import { decodeNativeMarker } from "./assistance-marker.mjs";

const nonce = "0123456789abcdef10325476";
const staleNonce = "fedcba987654321001234567";

// Fixed wire payload, independently specified from the GTK rendering code.
// These are decoder samples only, not a native/codec qualification witness.
function markerSamples(head, dark = [0, 0, 0], light = [255, 255, 255]) {
  const payload = [
    0xa7,
    head,
    0x01,
    0x23,
    0x45,
    0x67,
    0x89,
    0xab,
    0xcd,
    0xef,
    0x10,
    0x32,
    0x54,
    0x76,
  ];
  const samples = [];
  for (const byte of payload) {
    for (let shift = 7; shift >= 0; shift--) {
      const one = (byte >> shift) & 1;
      samples.push(...(one ? light : dark), ...(one ? dark : light));
    }
  }
  return samples;
}

for (const head of [0, 1]) {
  test(`current native head ${head} decodes only with its exact nonce`, () => {
    assert.deepEqual(decodeNativeMarker(markerSamples(head), nonce), { head, nonce });
    assert.equal(decodeNativeMarker(markerSamples(head), staleNonce), null);
  });

  test(`head ${head} tolerates bounded codec channel shifts`, () => {
    assert.deepEqual(
      decodeNativeMarker(markerSamples(head, [25, 43, 61], [199, 217, 235]), nonce),
      { head, nonce },
    );
    assert.deepEqual(
      decodeNativeMarker(markerSamples(head, [80, 80, 80], [175, 175, 175]), nonce),
      {
        head,
        nonce,
      },
    );
  });
}

test("solid Fedora blue, fixture red/blue and neutral backgrounds are not markers", () => {
  for (const rgb of [
    [30, 55, 180],
    [13, 13, 204],
    [204, 13, 13],
    [0, 0, 0],
    [255, 255, 255],
    [128, 128, 128],
  ]) {
    const samples = Array.from({ length: 224 }, () => rgb).flat();
    assert.equal(decodeNativeMarker(samples, nonce), null);
  }
});

test("unbound, wrong and stale fixture nonces never establish readiness", () => {
  for (const expected of [
    undefined,
    null,
    "",
    staleNonce,
    nonce.slice(1),
    `${nonce}0`,
    nonce.toUpperCase(),
  ])
    assert.equal(decodeNativeMarker(markerSamples(0), expected), null);
  // A complete, valid old marker cannot pass after the current nonce is bound.
  const currentNonce = "1123456789abcdef10325476";
  assert.equal(decodeNativeMarker(markerSamples(1), currentNonce), null);
});

test("missing, truncated, oversized and malformed sample buffers fail closed", () => {
  const valid = markerSamples(0);
  for (const samples of [
    null,
    undefined,
    {},
    [],
    valid.slice(0, -1),
    [...valid, 0],
    new Array(672),
  ])
    assert.equal(decodeNativeMarker(samples, nonce), null);
  for (const value of [NaN, Infinity, -1, 256, 0.5, "0", null, undefined]) {
    const samples = [...valid];
    samples[100] = value;
    assert.equal(decodeNativeMarker(samples, nonce), null);
  }
});

test("ambiguous brightness and saturated channels cannot masquerade as bits", () => {
  for (const rgb of [
    [81, 0, 0],
    [174, 255, 255],
    [0, 0, 200],
    [200, 0, 0],
    [128, 128, 128],
  ]) {
    const samples = markerSamples(0);
    samples.splice(0, 3, ...rgb);
    assert.equal(decodeNativeMarker(samples, nonce), null);
  }
});

test("malformed framing, head identity and complementary cells fail closed", () => {
  assert.equal(decodeNativeMarker(markerSamples(2), nonce), null);
  const brokenPair = markerSamples(0);
  brokenPair.splice(3, 3, ...brokenPair.slice(0, 3));
  assert.equal(decodeNativeMarker(brokenPair, nonce), null);
  // Inverting both cells retains valid contrast/complement but changes the magic.
  const wrongMagic = markerSamples(0);
  for (let index = 0; index < 6; index++) wrongMagic[index] = 255 - wrongMagic[index];
  assert.equal(decodeNativeMarker(wrongMagic, nonce), null);
  // Likewise, a well-formed changed nonce bit must not be corrected or ignored.
  const wrongNonce = markerSamples(1);
  for (let index = 16 * 6; index < 17 * 6; index++) wrongNonce[index] = 255 - wrongNonce[index];
  assert.equal(decodeNativeMarker(wrongNonce, nonce), null);
});
