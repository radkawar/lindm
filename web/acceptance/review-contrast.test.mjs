import assert from "node:assert/strict";
import { test } from "node:test";
import {
  checkPaletteContrast,
  contrastPairs,
  contrastRatio,
  opaqueRGB,
} from "./review-contrast.mjs";

function palette(dark = false) {
  const surface = dark ? "rgb(17, 17, 17)" : "rgb(255, 255, 255)";
  const ink = dark ? "rgb(255, 255, 255)" : "rgb(17, 17, 17)";
  const result = {};
  for (const pair of contrastPairs) {
    result[pair.foreground] = ink;
    result[pair.background] = surface;
  }
  for (const token of ["primary", "accent", "destructive"]) result[token] = ink;
  for (const token of ["primary-foreground", "accent-foreground", "destructive-foreground"])
    result[token] = surface;
  result.foreground = ink;
  result["brand-eye"] = "#767676";
  return result;
}

test("WCAG sRGB relative luminance and contrast are symmetric", () => {
  assert.equal(contrastRatio([0, 0, 0], [255, 255, 255]), 21);
  assert.equal(contrastRatio([255, 255, 255], [0, 0, 0]), 21);
  assert.equal(contrastRatio([17, 17, 17], [17, 17, 17]), 1);
  assert.ok(Math.abs(contrastRatio([255, 0, 0], [255, 255, 255]) - 3.99847677) < 0.000001);
  assert.ok(contrastRatio([118, 118, 118], [255, 255, 255]) > 4.5);
  assert.ok(contrastRatio([119, 119, 119], [255, 255, 255]) < 4.5);
});

test("accepts opaque computed RGB and rejects missing/transparent/unresolved colours", () => {
  assert.deepEqual(opaqueRGB("rgb(1, 2, 3)"), [1, 2, 3]);
  assert.deepEqual(opaqueRGB("rgb(0 0 0 / 100%)"), [0, 0, 0]);
  assert.deepEqual(opaqueRGB("rgb(100% 0% 0%)").map(Math.round), [255, 0, 0]);
  assert.deepEqual(opaqueRGB("#abc"), [170, 187, 204]);
  for (const value of ["", "var(--foreground)", "transparent", "rgba(1, 2, 3, .5)", "rgb(300 0 0)"])
    assert.throws(() => opaqueRGB(value));
});

test("checks all normal, button, selection, ring, chart and tinted status pairs in both themes", () => {
  for (const dark of [false, true]) {
    const theme = dark ? "dark" : "light";
    const result = checkPaletteContrast(palette(dark), theme);
    assert.deepEqual(result.findings, []);
    assert.equal(
      result.pairs.length,
      contrastPairs.filter((pair) => !pair.theme || pair.theme === theme).length,
    );
  }
  assert.ok(
    contrastPairs.some(
      (pair) => pair.foreground === "destructive-foreground" && pair.minimum === 4.5,
    ),
  );
  assert.ok(
    contrastPairs.some(
      (pair) => pair.foreground === "selection-foreground" && pair.minimum === 4.5,
    ),
  );
  assert.equal(
    contrastPairs.filter((pair) => pair.foreground.startsWith("chart-") && pair.minimum === 3)
      .length,
    5,
  );
  assert.ok(
    contrastPairs.some(
      (pair) => pair.foreground === "ring" && pair.background === "card" && pair.minimum === 3,
    ),
  );
  for (const token of ["border", "input"])
    assert.deepEqual(
      contrastPairs
        .filter((pair) => pair.foreground === token && pair.minimum === 3)
        .map((pair) => pair.background),
      ["background", "card", "popover", "muted", "secondary", "sidebar"],
    );
  assert.equal(
    contrastPairs.filter((pair) => pair.foreground === "brand-eye" && pair.minimum === 3).length,
    2,
  );
});

test("fails actual weak text, button, ring and chart pairs instead of skipping", () => {
  for (const token of [
    "foreground",
    "neutral",
    "primary-foreground",
    "destructive-foreground",
    "ring",
    "border",
    "input",
    "chart-1",
    "brand-eye",
  ]) {
    const values = palette();
    const pair = contrastPairs.find((pair) => pair.foreground === token);
    values[token] = values[pair.background];
    const result = checkPaletteContrast(values);
    assert.ok(
      result.findings.some((finding) => finding.elements[0].startsWith(`--${token} /`)),
      token,
    );
  }
});

test("checks status text on the composited 10% tinted background", () => {
  const values = palette();
  values.success = "rgb(118, 118, 118)";
  const result = checkPaletteContrast(values);
  assert.ok(result.findings.some((finding) => finding.elements[0].includes("--success/10")));
  assert.ok(!result.findings.some((finding) => finding.elements[0] === "--success / --card"));
});

test("checks destructive text on the dark 30% hover surface", () => {
  const values = palette(true);
  values.background = "#101826";
  values.card = "#172235";
  values.destructive = "#ff98a2";
  const weak = checkPaletteContrast(values, "dark");
  const hover = "--destructive / --card tinted with --destructive/30";
  assert.ok(weak.findings.some((finding) => finding.elements[0] === hover));
  assert.ok(!checkPaletteContrast(values, "light").pairs.some((pair) => pair.tint === 0.3));
  values.destructive = "#ffb3bb";
  assert.ok(
    !checkPaletteContrast(values, "dark").findings.some((finding) => finding.elements[0] === hover),
  );
});

test("missing tokens and nonopaque palettes are blocking findings", () => {
  const values = palette();
  delete values["chart-3"];
  delete values.input;
  values.ring = "rgba(0, 0, 0, .5)";
  const result = checkPaletteContrast(values);
  assert.ok(result.findings.some((finding) => finding.elements[0] === "--chart-3 / --card"));
  assert.ok(result.findings.some((finding) => finding.elements[0] === "--input / --muted"));
  assert.ok(result.findings.some((finding) => finding.message.includes("must be opaque")));
});
