// SPDX-License-Identifier: Apache-2.0

// Owner pass 2 (safety): Overview "Undo" next to Accounts locked opens a
// confirmation naming the device and the effect, asks for a reason, and sends
// nothing until the admin reviews and sends. Read-only: the dialog is reviewed
// and cancelled; the check fails if any device action is created.
export const task = {
  name: "Undo account lock confirms first",
  screenId: "owner-pass2-safety-undo",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "Clicking Undo next to Accounts locked opens a confirmation naming the device and that it restores the locked accounts while screen locks stay in place, with a reason; nothing is sent until confirmed; cancel leaves the lock in place.",
};

export async function check({ page, demo, visit, require, capture, step }) {
  const { DeviceID } = demo.Routes;
  const hostname = demo.Devices.find((device) => device.ID === DeviceID)?.Hostname ?? DeviceID;
  const main = page.getByRole("main");
  const sent = [];
  const watch = (request) => {
    if (/\/(CreateDeviceAction|CreateApproval)$/.test(new URL(request.url()).pathname))
      sent.push(request.url());
  };
  page.on("request", watch);
  try {
    step(`open ${hostname} overview`);
    await visit(`/devices/${DeviceID}`);
    const lock = main.locator('[data-device-restriction="lock"][data-confirmed="true"]');
    await lock.waitFor({ timeout: 30_000 });
    const undo = lock.getByRole("button", { name: /^Undo/ });
    require((await undo.count()) === 1, "Accounts locked has no single Undo button");

    step("Undo opens a confirmation naming device and effect");
    await undo.click();
    const dialog = page.getByRole("dialog");
    await dialog.waitFor({ timeout: 30_000 });
    const description = (
      await dialog.locator('[data-slot="dialog-description"], p').first().innerText()
    ).trim();
    const text = await dialog.innerText();
    require(text.includes(hostname), `Confirmation does not name the device ${hostname}`);
    require(text.includes(`Restores the local accounts lindm locked on ${hostname}.`) &&
      text.includes(
        "Users must unlock their screens.",
      ), `Confirmation does not state the effect (got ${JSON.stringify(description)})`);
    require(sent.length === 0, "Opening Undo sent a request");
    const reason = dialog.getByLabel("Reason", { exact: true });
    require(await reason.isVisible(), "Confirmation asks for no reason");

    step("review without sending");
    await reason.fill("Owner pass 2 check: review only");
    await dialog.getByRole("button", { name: "Review action" }).click();
    await dialog.getByText("Before you send", { exact: true }).waitFor({ timeout: 30_000 });
    require((await dialog.innerText()).includes(
      "Restores accounts locked by lindm. Screen locks stay in place.",
    ), "Review step does not restate the account and screen-lock effects");
    await capture("pass2-safety-undo");
    require(sent.length === 0, `Reviewing sent a request: ${sent.join(", ")}`);

    step("cancel leaves the lock");
    await dialog.getByRole("button", { name: "Edit action" }).click();
    await page.keyboard.press("Escape");
    await dialog.waitFor({ state: "hidden", timeout: 30_000 });
    require(sent.length === 0, `Cancelling sent a request: ${sent.join(", ")}`);
    require(await lock.isVisible(), "Lock disappeared after cancelling Undo");
  } finally {
    page.off("request", watch);
  }
}
