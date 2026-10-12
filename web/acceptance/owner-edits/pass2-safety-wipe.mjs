// Owner pass 2 (Safety → Wipe): the wipe mode follows the chosen target, so an
// in-use volume is never paired with offline mode; the review names the
// hostname, device path and size; and Request approval is the primary action
// because a wipe always needs a second admin. Read-only: the review is a local
// draft, discarded with Edit action; nothing is sent or requested. Runs after
// wipe-form.mjs, whose inventory refresh leaves fresh storage info.
export const task = {
  name: "Wipe mode, review and approval",
  screenId: "owner-pass2-safety-wipe",
  route: "/devices/$deviceId/actions/new/cryptoErase",
  priority: "high",
  acceptance:
    "Choosing the in-use root volume selects 'While running' and offline mode is not offered; the review names the hostname, /dev path and size in binary units; the primary button is 'Request approval' and Send action is not offered before approval.",
};

const OFFLINE = "Offline: one volume that isn't in use";
const LIVE = "While running: all encrypted volumes, then power off";

export async function check({ page, demo, visit, require, capture, step }) {
  const deviceId = demo.Routes.DeviceID;
  const hostname = demo.Devices.find((device) => device.ID === deviceId)?.Hostname;
  if (!deviceId || !hostname) throw new Error("demo route device or its hostname is missing");

  step("open wipe form and choose the target");
  await visit(`/devices/${encodeURIComponent(deviceId)}/actions/new/cryptoErase`);
  const main = page.getByRole("main");
  const picker = main.getByRole("region", { name: "Observed storage target" });
  const target = picker.getByRole("combobox", { name: "Target", exact: true });
  await target.waitFor({ timeout: 90_000 });
  await target.click();
  const options = page.getByRole("option").filter({ hasNotText: "Select observed storage" });
  await page.getByRole("option").first().waitFor({ timeout: 30_000 });
  require((await options.count()) > 0, "no storage target is offered");
  await options.first().click();

  step("mode matches the target");
  const mode = main.getByRole("combobox", { name: "Wipe mode", exact: true });
  await mode.waitFor({ timeout: 30_000 });
  const modeText = (await mode.innerText()).trim();
  const inUse = await main
    .getByText("This volume is in use, so it can only be wiped while the device is running.")
    .isVisible();
  // The demo device reports only its root volume, which is in use.
  require(inUse, "the in-use root volume is not marked as in use");
  require(modeText.includes(LIVE), `in-use volume defaults to '${modeText}', not '${LIVE}'`);
  await mode.click();
  await page.getByRole("option", { name: LIVE, exact: true }).waitFor({ timeout: 30_000 });
  const offered = (await page.getByRole("option").allInnerTexts()).map((text) => text.trim());
  await page.keyboard.press("Escape");
  require(!offered.includes(OFFLINE), "offline mode is still offered for an in-use volume");
  await capture("mode-follows-target");

  step("review names host, path and size");
  await main
    .getByRole("textbox", { name: new RegExp(`^Type hostname ${hostname} to confirm$`) })
    .fill(hostname);
  await main
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("Owner acceptance check: review only, discarded");
  await main.getByRole("button", { name: "Review action", exact: true }).click();
  const review = main.locator('[data-slot="review-targets"]');
  await review.waitFor({ timeout: 30_000 });
  const text = (await review.innerText()).replace(/\s+/g, " ");
  require(text.includes(hostname), `review does not name ${hostname}: ${text}`);
  require(/\/dev\/\S+/.test(text), `review does not name a /dev path: ${text}`);
  require(/\d (KiB|MiB|GiB|TiB)\b/.test(text), `review does not give a binary size: ${text}`);
  const clipped = await review.evaluate((node) => node.scrollWidth > node.clientWidth + 1);
  require(!clipped, "review target text is cut off");

  step("request approval is primary");
  const request = main.getByRole("button", { name: "Request approval", exact: true });
  require(await request.isVisible(), "no Request approval button in the review");
  require(await request.evaluate((node) =>
    node.classList.contains("bg-primary"),
  ), "Request approval is not the primary button");
  require(!(await main
    .getByRole("button", { name: "Send action", exact: true })
    .count()), "Send action is offered before approval");
  await capture("review-request-approval");

  step("discard the draft");
  await main.getByRole("button", { name: "Edit action", exact: true }).click();
  await mode.waitFor({ timeout: 30_000 });
}
