// SPDX-License-Identifier: Apache-2.0

// A click is not a server acknowledgement. Do not unload the real action form
// until it reports an accepted action ID through its visible success message.
export async function submitReviewedDeviceAction(ui) {
  await ui.click({ role: "button", text: "Review action", dialog: true });
  await ui.click({ role: "button", text: "Send action", dialog: true });
  // Sonner nests the same text in its list item, content and title. An unscoped
  // text query is ambiguous even with one toast; keep duplicate-toast rejection.
  await ui.wait({
    css: '[data-sonner-toast][data-type="success"][data-visible="true"]:not([data-removed="true"]) [data-title]',
    text: "Action sent to device",
  });
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

// Expanding an existing result is read-only; never submit or retry failed work.
export async function openDeviceActionResult(page, actionId) {
  const row = page.locator(`[data-device-action-row][data-action-id="${actionId}"]`);
  if ((await row.getAttribute("open")) === null) await row.locator("summary").click();
}
