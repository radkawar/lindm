// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { ChromiumDriver, UI } from "./drivers.mjs";
import { submitReviewedDeviceAction, waitForSettledActionHistory } from "./deploy-actions.mjs";

async function browser(run) {
  const driver = new ChromiumDriver();
  try {
    await driver.open({ origin: "http://127.0.0.1", headless: true });
    await run(driver);
  } finally {
    await driver.browser?.close();
  }
}

test("a Send action click without an acknowledgement cannot admit navigation", async () => {
  await browser(async (driver) => {
    await driver.page.setContent(`
      <div role="dialog">
        <button>Review action</button>
        <button onclick="document.body.dataset.submission='pending'">Send action</button>
      </div>
    `);
    await assert.rejects(submitReviewedDeviceAction(new UI(driver, 300)), /ui_condition_timeout/);
    assert.equal(await driver.observe(() => document.body.dataset.submission), "pending");
  });
});

test("submission admits navigation only after visible asynchronous acknowledgement", async () => {
  await browser(async (driver) => {
    await driver.page.setContent(`
      <div role="dialog">
        <button>Review action</button>
        <button onclick="setTimeout(() => {
          document.body.dataset.submission='accepted';
          const acknowledgement = document.createElement('p');
          acknowledgement.textContent='Action sent to device';
          document.body.append(acknowledgement);
        }, 100)">Send action</button>
      </div>
    `);
    await submitReviewedDeviceAction(new UI(driver, 2_000));
    assert.equal(await driver.observe(() => document.body.dataset.submission), "accepted");
  });
});

test("old-row and empty history snapshots wait for settled asynchronous rendering", async () => {
  await browser(async (driver) => {
    await driver.page.setContent(`
      <p role="status">Loading action history…</p>
      <script>setTimeout(() => {
        document.body.innerHTML='<details data-device-action-row data-action-id="restored-old-action"></details>';
      }, 100);</script>
    `);
    await waitForSettledActionHistory(driver);
    assert.deepEqual(
      await driver.observe(() =>
        [...document.querySelectorAll("[data-device-action-row]")].map(
          (row) => row.dataset.actionId,
        ),
      ),
      ["restored-old-action"],
    );
    await driver.page.setContent(`
      <p role="status">Loading action history…</p>
      <script>setTimeout(() => { document.body.innerHTML='<h3>No actions yet</h3>'; }, 100);</script>
    `);
    await waitForSettledActionHistory(driver);
    assert.equal(await driver.observe(() => document.body.innerText.trim()), "No actions yet");
  });
});
