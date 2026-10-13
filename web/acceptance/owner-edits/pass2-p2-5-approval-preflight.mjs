// Owner pass 2 finding 5: the freshness refusal arrived only after Send, and an
// approved restart was refused for stale inventory, wasting the approval. The
// review's server checks now gate the approval request too, and the fix offers
// to refresh inventory and send the same request when the checks pass. Read-only:
// it never requests approval or inventory (the wipe check needs it stale).
export const task = {
  name: "Approval waits for the server's checks",
  screenId: "owner-pass2-p2-5-approval-preflight",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "On a device whose inventory is too old, a reviewed restart disables Request approval as well as Send and says why, and offers 'Refresh inventory and send when ready', which states that the same request is sent only once fresh inventory passes the server's checks.",
};

const REASON =
  "Send and approval requests are unavailable. Resolve this problem: inventory needs refreshing.";
const PROMISE =
  "Uses the reason above. The console sends this exact request after fresh inventory passes server checks. Failed checks prevent sending.";

export async function check({ page, demo, visit, require, capture, step }) {
  const deviceId = demo.Routes.DeviceID;
  if (!deviceId) throw new Error("demo route device is missing");
  const main = page.getByRole("main");

  step("review a restart");
  await visit(`/devices/${encodeURIComponent(deviceId)}`);
  await main.getByRole("button", { name: "Actions", exact: true }).click();
  await page.getByRole("menuitem", { name: "Restart device", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Restart device", exact: true });
  await dialog.waitFor({ timeout: 30_000 });
  await dialog
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("Owner acceptance check: approval waits for the server's checks; never sent");
  await dialog.getByRole("button", { name: "Review action", exact: true }).click();
  await dialog.getByText(/^(Ready to send|Not ready to send)$/).waitFor({ timeout: 30_000 });
  const edit = dialog.getByRole("button", { name: "Edit action", exact: true });
  if (await dialog.getByText("Ready to send", { exact: true }).isVisible()) {
    require(false, "the route device's inventory was fresh, so the blocked approval could not be checked; run before any inventory refresh");
    await edit.click();
    return;
  }

  step("approval gated with its reason");
  const approval = dialog.getByRole("button", { name: "Request approval", exact: true });
  require(await approval.isDisabled(), "Request approval is enabled while the server's checks refuse the request");
  require(await dialog
    .getByText(REASON, { exact: true })
    .isVisible(), "the disabled Request approval does not state why");
  require((await approval.getAttribute("aria-describedby")) !==
    null, "Request approval is not described by its reason");
  require(await dialog
    .getByRole("button", { name: "Send action", exact: true })
    .isDisabled(), "Send action is enabled while blocked");

  step("refresh and send when ready");
  const blocker = dialog.locator('[data-slot="action-blocker"]');
  require(await blocker
    .getByRole("button", { name: "Refresh inventory and send when ready", exact: true })
    .isEnabled(), "the blocker does not offer 'Refresh inventory and send when ready'");
  require(await blocker
    .getByText(PROMISE, { exact: true })
    .isVisible(), "the send-when-ready fix does not say it sends only after the checks pass");
  await capture("approval-gated-send-when-ready");

  step("discard");
  await edit.click();
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden", timeout: 10_000 });
}
