import assert from "node:assert/strict";
import test from "node:test";
import { chromium } from "playwright";
import { captureHelpDocument } from "./review-help.mjs";
import { contactSheet } from "./review-report.mjs";

// Exercise real Chromium rasterization: one enormous full-page image timed out
// and prevented later display variants from reaching the owner report.
test("help evidence covers a long document in bounded images and exposes every part", async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    const captures = [];
    for (const theme of ["light", "dark"]) {
      for (const viewport of [
        { name: "desktop", width: 1440, height: 900 },
        { name: "mobile", width: 390, height: 844 },
      ]) {
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await page.emulateMedia({ colorScheme: theme });
        await page.setContent(`<style>
          html, body { margin: 0; }
          main { position: relative; height: 40017px; overflow: hidden; background: white; }
          h1 { margin: 0; }
          footer { position: absolute; bottom: 0; height: 17px; width: 100%; background: red; }
        </style><main><h1>Long reference</h1><footer></footer></main>`);
        const images = new Map();
        const evidence = await captureHelpDocument({
          page,
          prefix: `reference-${theme}-${viewport.name}`,
          async screenshot(page, name, fullPage) {
            const image = await page.screenshot({ fullPage, timeout: 30_000 });
            images.set(name, image);
            return name;
          },
        });
        assert.deepEqual(page.viewportSize(), { width: viewport.width, height: viewport.height });
        assert.equal(await page.evaluate(() => window.scrollY), 0);
        assert.deepEqual(evidence.dimensions, { width: viewport.width, height: 40017 });
        let covered = 0;
        for (const part of evidence.fullScreenshots) {
          const image = images.get(part.screenshot);
          assert.equal(image.readUInt32BE(16), viewport.width);
          assert.equal(image.readUInt32BE(20), part.height);
          assert.equal(part.y, covered);
          assert.ok(part.height > 0 && part.height <= 8192);
          covered += part.height;
        }
        assert.equal(covered, evidence.dimensions.height);
        const last = images.get(evidence.fullScreenshots.at(-1).screenshot);
        // Decode the actual final raster. The red footer is at the document's
        // end, not in its first viewport; empty or repeated top clips fail here.
        const finalPixel = await page.evaluate(async (encoded) => {
          const image = new Image();
          image.src = `data:image/png;base64,${encoded}`;
          await image.decode();
          const canvas = document.createElement("canvas");
          canvas.width = 1;
          canvas.height = 1;
          const context = canvas.getContext("2d");
          context.drawImage(image, 0, image.height - 1, 1, 1, 0, 0, 1, 1);
          return Array.from(context.getImageData(0, 0, 1, 1).data);
        }, last.toString("base64"));
        assert.deepEqual(finalPixel, [255, 0, 0, 255]);
        captures.push({ path: "/help/reference.md", theme, viewport: viewport.name, ...evidence });
      }
    }
    const sheet = contactSheet({
      results: [],
      sessions: [],
      failures: [],
      helpScreenshots: captures,
    });
    await page.setContent(sheet);
    for (const capture of captures) {
      for (const part of capture.fullScreenshots) {
        assert.equal(await page.locator(`a[href="${part.screenshot}"]`).count(), 1);
      }
    }
  } finally {
    await browser.close();
  }
});
