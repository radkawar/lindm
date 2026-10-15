// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { ChromiumDriver, UI } from "./drivers.mjs";
import {
  deviceActionFailureIsTerminal,
  openDeviceActionResult,
  submitReviewedDeviceAction,
  waitForSettledActionHistory,
} from "./deploy-actions.mjs";

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

test("disconnected pre-send readiness is checked again before exactly one accepted Send", async () => {
  await browser(async (driver) => {
    await driver.page.setContent(`
      <div role="dialog">
        <button onclick="document.body.dataset.reviews='1'">Review action</button>
        <p id="readiness">Device is not connected</p>
        <button onclick="
          document.body.dataset.probes=String(Number(document.body.dataset.probes || 0)+1);
          if (document.body.dataset.probes === '2') {
            document.getElementById('readiness').textContent='Ready to send';
            document.getElementById('send').disabled=false;
            this.disabled=true;
          }
        ">Check again</button>
        <button id="send" disabled onclick="
          document.body.dataset.sends=String(Number(document.body.dataset.sends || 0)+1);
          const acknowledgement=document.createElement('ol');
          acknowledgement.innerHTML='<li data-sonner-toast data-type=success data-visible=true><div data-title>Action sent to device</div></li>';
          document.body.append(acknowledgement);
        ">Send action</button>
      </div>
    `);
    await submitReviewedDeviceAction(new UI(driver, 2_000));
    assert.deepEqual(
      await driver.observe(() => ({
        reviews: document.body.dataset.reviews,
        probes: document.body.dataset.probes,
        sends: document.body.dataset.sends,
      })),
      { reviews: "1", probes: "2", sends: "1" },
    );
  });
});

test("permanent disconnection times out without sending or recreating the action form", async () => {
  await browser(async (driver) => {
    await driver.page.setContent(`
      <div role="dialog">
        <button onclick="document.body.dataset.reviews='1'">Review action</button>
        <p>Device is not connected</p>
        <button onclick="document.body.dataset.probes=String(Number(document.body.dataset.probes || 0)+1)">Check again</button>
        <button disabled onclick="document.body.dataset.sent='yes'">Send action</button>
      </div>
    `);
    await assert.rejects(submitReviewedDeviceAction(new UI(driver, 300)), /ui_condition_timeout/);
    assert.equal(await driver.observe(() => document.body.dataset.reviews), "1");
    assert.ok(Number(await driver.observe(() => document.body.dataset.probes)) > 0);
    assert.equal(await driver.observe(() => document.body.dataset.sent), undefined);
  });
});

test("an unrelated pre-send policy refusal is not retried or sent", async () => {
  await browser(async (driver) => {
    await driver.page.setContent(`
      <div role="dialog">
        <button>Review action</button>
        <p>Execution permission is unavailable</p>
        <button onclick="document.body.dataset.probed='yes'">Check again</button>
        <button disabled onclick="document.body.dataset.sent='yes'">Send action</button>
      </div>
    `);
    await assert.rejects(
      submitReviewedDeviceAction(new UI(driver, 300)),
      /device_action_pre_send_blocked/,
    );
    assert.equal(await driver.observe(() => document.body.dataset.probed), undefined);
    assert.equal(await driver.observe(() => document.body.dataset.sent), undefined);
  });
});

test("submission waits for the visible Sonner title without matching its text-bearing ancestors", async () => {
  await browser(async (driver) => {
    await driver.page.setContent(`
      <div role="dialog">
        <button>Review action</button>
        <button onclick="setTimeout(() => {
          document.body.dataset.submission='accepted';
          const acknowledgement = document.createElement('ol');
          acknowledgement.innerHTML='<li data-sonner-toast data-type=success data-visible=true><div data-content><div data-title>Action sent to device</div></div></li>';
          document.body.append(acknowledgement);
        }, 100)">Send action</button>
      </div>
    `);
    await submitReviewedDeviceAction(new UI(driver, 2_000));
    assert.equal(await driver.observe(() => document.body.dataset.submission), "accepted");
    await assert.rejects(driver.find({ text: "Action sent to device" }), /ambiguous_ui_locator/);
  });
});

test("multiple visible success acknowledgements remain ambiguous", async () => {
  await browser(async (driver) => {
    await driver.page.setContent(`
      <div role="dialog"><button>Review action</button><button>Send action</button></div>
      <ol>
        <li data-sonner-toast data-type="success" data-visible="true"><div data-content><div data-title>Action sent to device</div></div></li>
        <li data-sonner-toast data-type="success" data-visible="true"><div data-content><div data-title>Action sent to device</div></div></li>
      </ol>
    `);
    await assert.rejects(submitReviewedDeviceAction(new UI(driver, 300)), /ambiguous_ui_locator/);
  });
});

test("unrelated or removed acknowledgements cannot admit navigation", async () => {
  await browser(async (driver) => {
    await driver.page.setContent(`
      <div role="dialog"><button>Review action</button><button>Send action</button></div>
      <p role="status">Action sent to device</p>
      <ol>
        <li data-sonner-toast data-type="success" data-visible="true" data-removed="true"><div data-title>Action sent to device</div></li>
      </ol>
    `);
    await assert.rejects(submitReviewedDeviceAction(new UI(driver, 300)), /ui_condition_timeout/);
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

test("action evidence expands only its existing result and never retries", async () => {
  await browser(async (driver) => {
    await driver.page.setContent(`
      <details data-device-action-row data-action-id="other-action">
        <summary>Other action</summary><p>Other result</p>
      </details>
      <details data-device-action-row data-action-id="failed-action">
        <summary>Refresh inventory: Outcome unknown, don't retry</summary>
        <dl><dt>Failure</dt><dd>Interrupted</dd></dl>
        <details data-slot="technical-details">
          <summary>Details</summary><dl><dt>Action ID</dt><dd>failed-action</dd></dl>
        </details>
      </details>
      <button onclick="document.body.dataset.submitted='yes'">Send action</button>
    `);
    await openDeviceActionResult(driver.page, "failed-action");
    await openDeviceActionResult(driver.page, "failed-action");
    const failed = driver.page.locator('[data-action-id="failed-action"]');
    assert.equal(await failed.locator("summary").count(), 2);
    assert.equal(await failed.locator(":scope > dl > dd").isVisible(), true);
    assert.equal(
      await failed.locator('[data-slot="technical-details"]').getAttribute("open"),
      null,
    );
    assert.equal(
      await driver.page.locator('[data-action-id="other-action"]').getAttribute("open"),
      null,
    );
    assert.equal(await driver.observe(() => document.body.dataset.submitted), undefined);
  });
});

test("unknown remains bounded observation, not terminal failure or retry authority", () => {
  for (const state of [
    "Queued",
    "Running",
    "Completed",
    "Outcome unknown, don't retry",
    "",
    undefined,
  ])
    assert.equal(deviceActionFailureIsTerminal(state), false, state);
  for (const state of ["Failed", "Expired"])
    assert.equal(deviceActionFailureIsTerminal(state), true, state);
});
