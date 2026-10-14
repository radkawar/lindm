// SPDX-License-Identifier: Apache-2.0

// Palette contrast complements axe's rendered-text checks. Read the browser's
// resolved semantic variables in the active theme, not a copied palette fixture.
const surfaces = ["background", "card", "popover", "muted", "secondary", "sidebar"];
const tones = ["success", "warning", "destructive", "info", "neutral"];

export const contrastPairs = [
  ...["background", "card"].flatMap((background) =>
    ["foreground", "muted-foreground", "primary", "accent", ...tones].map((foreground) => ({
      foreground,
      background,
      minimum: 4.5,
    })),
  ),
  ...[
    ["card-foreground", "card"],
    ["popover-foreground", "popover"],
    ["muted-foreground", "muted"],
    ["secondary-foreground", "secondary"],
    ["sidebar-foreground", "sidebar"],
    ["primary-foreground", "primary"],
    ["accent-foreground", "accent"],
    ["selection-foreground", "selection"],
    ["destructive-foreground", "destructive"],
  ].map(([foreground, background]) => ({ foreground, background, minimum: 4.5 })),
  ...["ring", "border", "input"].flatMap((foreground) =>
    surfaces.map((background) => ({ foreground, background, minimum: 3 })),
  ),
  ...Array.from({ length: 5 }, (_, index) => ({
    foreground: `chart-${index + 1}`,
    background: "card",
    minimum: 3,
  })),
  ...["background", "foreground"].map((background) => ({
    foreground: "brand-eye",
    background,
    minimum: 3,
  })),
  // Status badges/notices use bg-tone/10 on both the page and card surfaces.
  ...tones.flatMap((foreground) =>
    ["background", "card"].map((background) => ({
      foreground,
      background,
      tint: 0.1,
      minimum: 4.5,
    })),
  ),
  ...[0.2, 0.3].flatMap((tint) =>
    ["background", "card"].map((background) => ({
      foreground: "destructive",
      background,
      tint,
      minimum: 4.5,
      ...(tint === 0.3 ? { theme: "dark" } : {}),
    })),
  ),
];

export function opaqueRGB(value) {
  const hex = value.trim().match(/^#([\da-f]{3}|[\da-f]{6})$/i);
  if (hex) {
    const expanded =
      hex[1].length === 3 ? [...hex[1]].map((digit) => digit + digit).join("") : hex[1];
    return [0, 2, 4].map((index) => parseInt(expanded.slice(index, index + 2), 16));
  }
  const rgb = value.trim().match(/^rgba?\(([^)]+)\)$/i);
  if (!rgb) throw new Error(`Unsupported or unresolved colour: ${value || "(missing)"}`);
  const channels = rgb[1].split(/[\s,/]+/).filter(Boolean);
  if (channels.length !== 3 && channels.length !== 4) throw new Error(`Invalid colour: ${value}`);
  const alpha =
    channels.length === 4 ? parseFloat(channels[3]) / (channels[3].endsWith("%") ? 100 : 1) : 1;
  if (alpha !== 1) throw new Error(`Palette colour must be opaque: ${value}`);
  const result = channels
    .slice(0, 3)
    .map((channel) => Number(channel.replace(/%$/, "")) * (channel.endsWith("%") ? 2.55 : 1));
  if (result.some((channel) => !Number.isFinite(channel) || channel < 0 || channel > 255))
    throw new Error(`Invalid colour: ${value}`);
  return result;
}

export function contrastRatio(foreground, background) {
  const luminance = (rgb) => {
    const linear = rgb.map((channel) => {
      const value = channel / 255;
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
    });
    return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722;
  };
  const a = luminance(foreground);
  const b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

export function checkPaletteContrast(palette, theme = "light") {
  const pairs = [];
  const findings = [];
  for (const pair of contrastPairs) {
    if (pair.theme && pair.theme !== theme) continue;
    const label = `--${pair.foreground} / --${pair.background}${pair.tint ? ` tinted with --${pair.foreground}/${pair.tint * 100}` : ""}`;
    try {
      const foreground = opaqueRGB(palette[pair.foreground] ?? "");
      let background = opaqueRGB(palette[pair.background] ?? "");
      if (pair.tint)
        background = background.map(
          (channel, index) => channel * (1 - pair.tint) + foreground[index] * pair.tint,
        );
      const ratio = contrastRatio(foreground, background);
      pairs.push({ ...pair, ratio });
      // Do not round before comparing: 4.499:1 is not 4.5:1.
      if (ratio < pair.minimum)
        findings.push({
          message: `${label}: ${ratio.toFixed(3)}:1 is below ${pair.minimum}:1`,
          elements: [label],
        });
    } catch (error) {
      findings.push({ message: `${label}: ${error.message}`, elements: [label] });
    }
  }
  return { palette, pairs, findings };
}

export async function reviewContrast(page, theme) {
  const tokens = [
    ...new Set(contrastPairs.flatMap(({ foreground, background }) => [foreground, background])),
  ];
  const resolved = await page.evaluate((tokens) => {
    const root = document.documentElement;
    const style = getComputedStyle(root);
    const sample = document.createElement("span");
    sample.setAttribute("aria-hidden", "true");
    root.append(sample);
    const palette = {};
    try {
      for (const token of tokens) {
        const value = style.getPropertyValue(`--${token}`).trim();
        if (!value || !CSS.supports("color", value)) {
          palette[token] = value;
          continue;
        }
        sample.style.color = `var(--${token})`;
        palette[token] = getComputedStyle(sample).color;
      }
    } finally {
      sample.remove();
    }
    return { palette, theme: root.classList.contains("dark") ? "dark" : "light" };
  }, tokens);
  const result = checkPaletteContrast(resolved.palette, resolved.theme);
  if (resolved.theme !== theme)
    result.findings.push({
      message: `Expected ${theme} palette, but the document resolved ${resolved.theme}`,
      elements: ["html"],
    });
  return result;
}
