// Owner pass 2 finding #6: a new action refused because another is still open
// read "Something went wrong". The server now names the blocking action
// (kind, send time, expiry) and the review says so in plain words.
//
// The route device's inventory must stay stale for later checks and its open
// work must not change, so no action is sent: the review's server check is
// answered in the browser with the refusal the server gives while the seeded
// "Undo account lock" is still open (the server side is covered by
// TestDeviceActionPendingDetailAndUnstartedExpiry). Read-only.
export const task = {
  name: "Pending action refusal names the blocker",
  screenId: "owner-pass2-p2-6-action-pending",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "When another action is still open, reviewing a new one says 'Another action is still running on this device (Undo account lock, sent <time>). Wait for it to finish or let it expire at <time>.' with a link to that action, Send is disabled with its reason, and nothing reads 'Something went wrong'.",
};

const EVIDENCE =
  /Another action is still running on this device \(Undo account lock, sent \d{1,2}:\d{2}.*\)\. Wait for it to finish or let it expire at \d{1,2}:\d{2}.*\./;

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const deviceId = demo.Routes.DeviceID;
  const main = page.getByRole("main");

  step("find the seeded Undo account lock");
  await visit(`/devices/${encodeURIComponent(deviceId)}`);
  await main.getByRole("tab", { name: "Actions", exact: true }).click();
  const panel = main.locator('[role="tabpanel"]:not([hidden])');
  const undo = panel
    .locator("[data-device-action-row]")
    .filter({ hasText: "Undo account lock" })
    .first();
  await undo.waitFor({ timeout: 30_000 });
  const undoId = await undo.getAttribute("data-action-id");
  require(undoId, "The Undo account lock row has no action ID");
  await settle();

  step("review a restart while that undo is open");
  const preflight = "**/lindm.admin.v1.AdminService/PreflightDeviceAction";
  const sent = new Date(Date.now() - 2 * 60_000);
  const expires = new Date(Date.now() + 3 * 60_000);
  await page.route(preflight, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        checkedAt: new Date().toISOString(),
        blockedReason: "device_action_pending",
        blockingAction: {
          actionId: undoId,
          deviceId,
          spec: { releaseLock: { lockActionId: undoId } },
          createdAt: sent.toISOString(),
          expiresAt: expires.toISOString(),
        },
      }),
    }),
  );
  try {
    await main.getByRole("button", { name: "Actions", exact: true }).click();
    await page.getByRole("menuitem", { name: "Restart device", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Restart device", exact: true });
    await dialog.waitFor({ timeout: 30_000 });
    await dialog
      .getByRole("textbox", { name: "Reason", exact: true })
      .fill("Owner acceptance check: review only, never sent");
    await dialog.getByRole("button", { name: "Review action", exact: true }).click();
    const blocker = dialog.locator('[data-slot="action-blocker"]');
    await blocker.waitFor({ timeout: 30_000 });

    step("blocker names the open action in plain words");
    const text = (await blocker.innerText()).replace(/\s+/g, " ");
    require(EVIDENCE.test(text), `Pending blocker reads ${JSON.stringify(text)}`);
    const link = blocker.getByRole("link", { name: "View action", exact: true });
    require((await link.getAttribute("href"))?.endsWith(
      `/actions/${undoId}`,
    ), "The blocker does not link to the blocking action");
    require(await dialog
      .getByRole("button", { name: "Send action", exact: true })
      .isDisabled(), "Send action is enabled while another action is open");
    require(!(await dialog
      .getByText("Something went wrong", { exact: true })
      .count()), "The pending refusal reads 'Something went wrong'");
    await capture("pending-action-blocker");

    step("discard");
    await dialog.getByRole("button", { name: "Edit action", exact: true }).click();
    await page.keyboard.press("Escape");
    await dialog.waitFor({ state: "hidden", timeout: 10_000 });
  } finally {
    await page.unroute(preflight);
  }
}
