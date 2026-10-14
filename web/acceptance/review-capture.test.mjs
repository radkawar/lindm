// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 lindm contributors

import assert from "node:assert/strict";
import { test } from "node:test";
import { ChromiumDriver } from "./drivers.mjs";
import { captureReviewPNG } from "./review-capture.mjs";

test("PNG captures restore classic viewport and horizontal table scrollbars", async () => {
  const driver = new ChromiumDriver();
  await driver.open({ classicScrollbars: true, actionTimeoutMs: 30_000 });
  try {
    const page = driver.page;
    await page.setViewportSize({ width: 390, height: 844 });
    await page.setContent(`<!doctype html><html><head><style>
      html, body { margin: 0; }
      body { min-height: 1600px; }
      #table { width: 300px; overflow-x: auto; }
      #columns { width: 700px; height: 100px; }
    </style></head><body>
      <div id="table"><div id="columns">Wide table columns</div></div>
      <div id="following">Following page content</div>
    </body></html>`);
    const geometry = () =>
      page.evaluate(() => {
        const table = document.getElementById("table");
        return {
          viewportWidth: document.documentElement.clientWidth,
          tableHeight: table.getBoundingClientRect().height,
          scrollbarHeight: table.offsetHeight - table.clientHeight,
          followingY: document.getElementById("following").getBoundingClientRect().y,
        };
      });
    const before = await geometry();
    assert.ok(before.viewportWidth < 390, "The fixture must have a classic viewport scrollbar");
    assert.ok(before.scrollbarHeight > 0, "The fixture must have a classic horizontal scrollbar");
    for (const fullPage of [true, false]) {
      const image = await captureReviewPNG(page, { fullPage, animations: "disabled" });
      assert.equal(image.subarray(0, 8).toString("hex"), "89504e470d0a1a0a");
      assert.deepEqual(
        await geometry(),
        before,
        "Capture must not change the next layout baseline",
      );
    }
  } finally {
    await driver.close();
  }
});
