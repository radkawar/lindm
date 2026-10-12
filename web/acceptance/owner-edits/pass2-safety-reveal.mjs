// Owner pass 2 (safety): the recovery-key reveal page leads with the reveal,
// not an unrelated rotation history card, and a revealed key reads aloud in
// 4-character groups while Copy yields the raw key, with a visible countdown
// to auto-hide.
//
// The demo has another admin, so the reveal needs approval: the check creates
// an admin who approves in its own browser, then reveals on the review page,
// completing the in-page "Verify it's you" when the server asks for it.
// State (registered late): one new admin account, one approved and consumed
// recovery-key reveal approval (audited).
import { createAdmin, revealAfterApproval } from "./second-admin.mjs";

export const task = {
  name: "Recovery key reveal leads with the key",
  screenId: "owner-pass2-safety-reveal",
  route: "/devices/$deviceId/recovery/$actionId",
  priority: "high",
  acceptance:
    "Reveal page opens with the reveal form/result; no 'Rotate escrow recovery key' card or its expiry; a revealed key shows as 20f4-a061-… groups with a visible 'Hides in N s' countdown and Copy copies the raw 64-character key.",
};

const grouped = /^([0-9a-f]{4}-){15}[0-9a-f]{4}$/;

export async function check({ page, config, demo, visit, require, capture, step }) {
  const { DeviceID, RecoveryActionID } = demo.Routes;
  if (!RecoveryActionID) throw new Error("Demo seed has no recovery action");
  const hostname = demo.Devices.find((device) => device.ID === DeviceID)?.Hostname ?? DeviceID;
  const main = page.getByRole("main");

  step("create a second admin to approve");
  const admin = await createAdmin({ page, visit });

  step("open reveal page");
  await visit(`/devices/${DeviceID}/recovery/${RecoveryActionID}`);
  await main.getByText("Recovery access", { exact: true }).waitFor({ timeout: 30_000 });

  step("reveal leads; no rotation history card");
  const text = await main.innerText();
  require(!/Rotate escrow recovery key/.test(text), "Reveal page still shows the rotation card");
  require(!/\(in \d+ (second|minute|hour)s?\)/.test(
    text,
  ), "Reveal page still shows the rotation action's expiry");
  // The device context card (hostname, OS) may precede; the reveal is the first task card.
  const titles = (await main.locator('[data-slot="card-title"]').allInnerTexts())
    .map((title) => title.trim())
    .filter((title) => title !== "Device");
  require(titles[0] ===
    "Recovery access", `First card is not the reveal (got ${JSON.stringify(titles[0])})`);

  step("request approval, approve as the second admin, reveal");
  await main.getByLabel("Reason", { exact: true }).fill("Owner pass 2 check: read key to user");
  await main.getByLabel("Type the device name to confirm").fill(hostname);
  const { value: key, refusal } = await revealAfterApproval({
    page,
    config,
    admin,
    refreshName: "Refresh approval status",
    revealName: "Reveal recovery key",
    valueLabel: "Recovery key",
    failureTitle: "Couldn't reveal recovery key",
  });
  if (!key) throw new Error(`The approved reveal did not show the key: ${refusal}`);

  step("grouped key, countdown, raw copy");
  const shown = (await key.innerText()).trim();
  require(grouped.test(
    shown,
  ), `Key is not shown in 4-character groups (got ${shown.length} characters)`);
  const countdown = (await main.locator("[data-reveal-countdown]").innerText()).trim();
  require(/^Hides in \d+ s\b/.test(
    countdown,
  ), `No visible auto-hide countdown (got ${JSON.stringify(countdown)})`);
  await main.getByRole("button", { name: "Copy", exact: true }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  require(/^[0-9a-f]{64}$/.test(copied) &&
    copied === shown.replaceAll("-", ""), "Copy did not copy the raw ungrouped key");
  // The demo fixture's disposable key; the owner asked to see the revealed state.
  await capture("pass2-safety-reveal");

  step("hide now");
  await main.getByRole("button", { name: "Hide now", exact: true }).click();
  require(!(await key.isVisible()), "Hide now left the key visible");
}
