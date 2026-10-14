// SPDX-License-Identifier: Apache-2.0

// A click is not a server acknowledgement. Do not unload the real action form
// until it reports an accepted action ID through its visible success message.
export async function submitReviewedDeviceAction(ui) {
  await ui.click({ role: "button", text: "Review action", dialog: true });
  await ui.click({ role: "button", text: "Send action", dialog: true });
  await ui.wait({ text: "Action sent to device" });
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
