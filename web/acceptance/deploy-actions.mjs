// SPDX-License-Identifier: Apache-2.0

import { setTimeout as delay } from "node:timers/promises";

// A click is not a server acknowledgement. Do not unload the real action form
// until it reports an accepted action ID through its visible success message.
export async function submitReviewedDeviceAction(ui) {
  await ui.click({ role: "button", text: "Review action", dialog: true });
  await waitForReadyDeviceAction(ui);
  await ui.click({ role: "button", text: "Send action", dialog: true });
  // Sonner nests the same text in its list item, content and title. An unscoped
  // text query is ambiguous even with one toast; keep duplicate-toast rejection.
  await ui.wait({
    css: '[data-sonner-toast][data-type="success"][data-visible="true"]:not([data-removed="true"]) [data-title]',
    text: "Action sent to device",
  });
}

// Reconnection after an upgrade can outlive the first read-only preparation.
// Refresh only that disconnected pre-send check, never a sent action or denial.
async function waitForReadyDeviceAction(ui) {
  const send = { role: "button", text: "Send action", dialog: true, enabled: true };
  const checkAgain = { role: "button", text: "Check again", dialog: true, enabled: true };
  const disconnected = { text: "Device is not connected", dialog: true };
  const deadline = Date.now() + ui.timeoutMs;
  while (!(await ui.driver.find(send))) {
    if (Date.now() >= deadline) throw new Error("ui_condition_timeout");
    if (await ui.driver.find(checkAgain)) {
      if (!(await ui.driver.find(disconnected))) throw new Error("device_action_pre_send_blocked");
      await ui.click(checkAgain);
    }
    await delay(100);
  }
}

// Navigation resolves at DOMContentLoaded, before React's history query. Taking
// either snapshot early could admit an older restored action or miss a new one.
export async function waitForSettledActionHistory(driver) {
  await driver.page.waitForFunction(
    () =>
      document.querySelector("[data-device-action-row]") !== null ||
      document.body.innerText.includes("No actions yet"),
    undefined,
    { timeout: 30_000 },
  );
}

export function deviceActionFailureIsTerminal(state) {
  // A start grant already projects unknown while its same action can complete.
  // Continue bounded read-only observation; unknown never authorizes a retry.
  return state === "Failed" || state === "Expired";
}

// Expanding an existing result is read-only; never submit or retry failed work.
export async function openDeviceActionResult(page, actionId) {
  const row = page.locator(`[data-device-action-row][data-action-id="${actionId}"]`);
  if ((await row.getAttribute("open")) === null) await row.locator(":scope > summary").click();
}
