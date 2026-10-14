// SPDX-License-Identifier: Apache-2.0

// Owner pass 2, bug 3: a restart was refused with "Inventory needs refreshing"
// only after Send, although the device had checked in a minute earlier, and Send
// stayed enabled beside the refusal. The review now runs the server's create
// checks: on the route device (online, inventory older than 5 minutes) it names
// the blocker with check-in and inventory times and offers Refresh inventory
// before Send; Send is disabled with its reason. After a real server refusal at
// Send, Send stays disabled with the reason shown.
//
// It never requests inventory (the wipe check, which runs later, needs it stale)
// and never sends work the server accepts: the only Send happens after the real
// review check reported stale inventory, so the server refuses it.
export const task = {
  name: "Restart review runs server checks",
  screenId: "owner-pass2-bug3-review-preflight",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "Reviewing a restart on a device whose inventory is older than 5 minutes shows 'Inventory needs refreshing' with when it last checked in and when inventory arrived, a Refresh inventory button, and a disabled Send action with its reason, before anything is sent; after a server refusal at Send, Send action stays disabled with the reason shown.",
};

const STATUS = /^(Ready to send|Not ready to send)$/;
const EVIDENCE =
  /last checked in .+\. Its latest inventory arrived .+ ago\. This action needs inventory from the last 5 minutes\. Check-ins do not include inventory\./;
const SEND_OFF =
  "Send and approval requests are unavailable. Resolve this problem: inventory needs refreshing.";
// A restart needs no approval, so the fix sends the same request once inventory is fresh.
const REFRESH = { name: "Refresh inventory and send when ready", exact: true };

export async function check({ page, demo, visit, require, capture, step }) {
  const deviceId = demo.Routes.DeviceID;
  if (!deviceId) throw new Error("demo route device is missing");
  const main = page.getByRole("main");

  step("open restart form");
  await visit(`/devices/${encodeURIComponent(deviceId)}`);
  await main.getByRole("button", { name: "Actions", exact: true }).click();
  await page.getByRole("menuitem", { name: "Restart device", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Restart device", exact: true });
  await dialog.waitFor({ timeout: 30_000 });
  await dialog
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("Owner acceptance check: review a restart; the server refuses it");
  const send = dialog.getByRole("button", { name: "Send action", exact: true });
  const edit = dialog.getByRole("button", { name: "Edit action", exact: true });

  step("review runs the server checks");
  await dialog.getByRole("button", { name: "Review action", exact: true }).click();
  await dialog.getByText(STATUS).waitFor({ timeout: 30_000 });
  if (await dialog.getByText("Ready to send", { exact: true }).isVisible()) {
    require(false, "the route device's inventory was fresh, so the stale-inventory review could not be checked; run before any inventory refresh");
    await edit.click();
    return;
  }

  step("blocker and fix before Send");
  const blocker = dialog.locator('[data-slot="action-blocker"]');
  require(await blocker.isVisible(), "the review shows no blocker before Send");
  const text = (await blocker.innerText()).replace(/\s+/g, " ");
  require(text.includes(
    "Inventory needs refreshing",
  ), `the blocker is not 'Inventory needs refreshing': ${text}`);
  require(EVIDENCE.test(
    text,
  ), `the blocker does not separate the check-in from the inventory age: ${text}`);
  const refresh = blocker.getByRole("button", REFRESH);
  require((await refresh.isVisible()) &&
    (await refresh.isEnabled()), "the blocker offers no enabled Refresh inventory button");
  require(await send.isDisabled(), "Send action is enabled while the review is blocked");
  require(await dialog
    .getByText(SEND_OFF, { exact: true })
    .isVisible(), "the disabled Send action does not state why");
  await capture("review-blocked-before-send");

  // The device's inventory can age between review and Send. Emulate that race
  // by letting one review check pass in the browser; the server then refuses
  // the real Send exactly as the owner saw.
  step("refusal after Send");
  const preflight = "**/lindm.admin.v1.AdminService/PreflightDeviceAction";
  await page.route(preflight, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ checkedAt: new Date().toISOString() }),
    }),
  );
  try {
    await blocker.getByRole("button", { name: "Check again", exact: true }).click();
    await dialog.getByText("Ready to send", { exact: true }).waitFor({ timeout: 30_000 });
  } finally {
    await page.unroute(preflight);
  }
  require(await send.isEnabled(), "Send action stayed disabled after the review check passed");
  await send.click();
  await dialog.getByText("Not accepted", { exact: true }).waitFor({ timeout: 30_000 });
  require(await send.isDisabled(), "Send action is enabled next to the refusal");
  require(await dialog
    .getByText(SEND_OFF, { exact: true })
    .isVisible(), "the disabled Send action does not state the refusal reason");
  require(await blocker.isVisible(), "the refusal does not show the blocker and its fix");
  // The refusal reruns the real check, so its evidence names current times again.
  await blocker.getByText(EVIDENCE).waitFor({ timeout: 30_000 });
  require(await blocker
    .getByRole("button", REFRESH)
    .isEnabled(), "the refusal offers no Refresh inventory fix");
  require(!(await dialog
    .getByText("Something went wrong", { exact: true })
    .count()), "the refusal is presented as an unknown failure");
  await capture("refused-send-disabled");

  step("discard");
  await edit.click();
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden", timeout: 10_000 });
}
