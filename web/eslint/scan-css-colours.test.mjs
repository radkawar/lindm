import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { scanCSSColours, scanCSSDirectory } from "./scan-css-colours.mjs";

for (const declaration of [
  "color: #abc",
  "stroke: #1234",
  "background: #123456",
  "fill: #12345678",
  "color: rgb(1 2 3)",
  "color: rgba(1, 2, 3, .5)",
  "color: hsl(20 30% 40%)",
  "color: hsla(20, 30%, 40%, .5)",
  "--local: oklch(.5 .2 200)",
  "color: red",
  "border: 1px solid rebeccapurple",
  "box-shadow: 0 0 3px navy",
  "filter: drop-shadow(0 0 3px red)",
  "-webkit-text-fill-color: blue",
  "background-image: linear-gradient(white, transparent)",
  "color: color-mix(in srgb, red, var(--foreground))",
  "color: var(--foreground, blue)",
  String.raw`color: r\65 d`,
  "@apply dark:hover:bg-blue-600/50",
  "@apply bg-neutral-950",
  "@apply text-[rgb(1_2_3)]",
  "@apply text-[red]",
  "@apply [color:#abc]",
]) {
  test(`rejects CSS ${declaration}`, () => {
    assert.equal(scanCSSColours(`@layer components { .sample { ${declaration}; } }`).length, 1);
  });
}

for (const selector of [
  '[stroke="#abc"]',
  '[fill="red"]',
  "[stroke='rgb(1 2 3)']",
  '[style*="color:red"]',
  ".bg-red-500",
  String.raw`.fill-\[\#abc\]`,
]) {
  test(`rejects raw selector ${selector}`, () => {
    assert.equal(scanCSSColours(`${selector} { stroke: var(--neutral); }`).length, 1);
  });
}

test("rejects raw-colour Tailwind custom variants and support queries", () => {
  assert.equal(scanCSSColours('@custom-variant ink (& [stroke="#abc"]);').length, 1);
  assert.equal(
    scanCSSColours("@supports (color: red) { .a { color: var(--foreground); } }").length,
    1,
  );
});

test("permits semantic CSS, neutral keywords, names, prose and URLs", () => {
  assert.deepEqual(
    scanCSSColours(`
      /* red, #abc and oklch(.5 .2 20) here are documentation. */
      @import "red.css";
      #abc [data-label="red"] {
        color: var(--foreground);
        --local-ink: var(--neutral);
        background: color-mix(in srgb, var(--primary) 10%, transparent);
        border: 1px solid currentColor;
        stroke: none;
        content: "red; #abc { rgb(1 2 3) }";
        font-family: "red", sans-serif;
        animation-name: red;
        background-image: url("red.svg#abc");
        mask-image: linear-gradient(var(--mask-ink), var(--mask-ink));
        @apply bg-neutral/10 text-neutral dark:bg-card ring-ring/50;
        @apply w-[3px] text-[length:14px] text-[var(--foreground)];
      }
    `),
    [],
  );
});

test("reports each violation within nested blocks and its source line", () => {
  const findings = scanCSSColours(
    "@media (width > 2px) {\n  .a {\n    color: red;\n    background: #abc\n  }\n}",
  );
  assert.deepEqual(findings, [
    { line: 3, column: 5, colour: "red" },
    { line: 4, column: 5, colour: "#abc" },
  ]);
});

test("the only CSS palette exemption is src/styles/globals.css", async () => {
  const directory = await mkdtemp(join(tmpdir(), "lindm-css-colours-"));
  try {
    await mkdir(join(directory, "styles"));
    await mkdir(join(directory, "feature"));
    await writeFile(join(directory, "styles/globals.css"), ":root { --foreground: #111; }");
    await writeFile(join(directory, "styles/components.css"), ".bad { color: red; }");
    await writeFile(join(directory, "feature/globals.css"), ".bad { color: #abc; }");
    const findings = await scanCSSDirectory(directory);
    assert.deepEqual(findings.map(({ colour }) => colour).sort(), ["#abc", "red"]);
    assert.equal(findings.length, 2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
