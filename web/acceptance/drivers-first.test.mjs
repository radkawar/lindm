// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { ChromiumDriver, UI } from "./drivers.mjs";

test("an explicit first action handles matching toolbar and empty-state controls", async () => {
  const driver = new ChromiumDriver();
  try {
    await driver.open({ origin: "http://127.0.0.1", headless: true });
    await driver.page.setContent(`
      <main>
        <header><button onclick="document.body.dataset.selected='toolbar'">Add destination</button></header>
        <section><button onclick="document.body.dataset.selected='empty-state'">Add destination</button></section>
      </main>
    `);
    const ui = new UI(driver, 1000);
    await assert.rejects(
      ui.wait({ role: "button", text: "Add destination" }),
      /ambiguous_ui_locator/,
    );
    await ui.click({ role: "button", text: "Add destination", first: true });
    assert.equal(await driver.observe(() => document.body.dataset.selected), "toolbar");
    const element = await ui.wait({ role: "button", text: "Add destination", first: true });
    await element.dispose();
  } finally {
    await driver.browser?.close();
  }
});
