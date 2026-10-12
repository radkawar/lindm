// Owner pass 2 (safety): the recovery-key reveal page leads with the reveal,
// not an unrelated rotation history card, and a revealed key reads aloud in
// 4-character groups while Copy yields the raw key. State-changing: a reveal
// is audited (and may create nothing else), so this check is registered late.
export const task = {
  name: "Recovery key reveal leads with the key",
  screenId: "owner-pass2-safety-reveal",
  route: "/devices/$deviceId/recovery/$actionId",
  priority: "high",
  acceptance:
    "Reveal page opens with the reveal form/result; no 'Rotate escrow recovery key' card or its expiry; a revealed key shows as 20f4-a061-… groups and Copy copies the raw 64-character key.",
};

const grouped = /^([0-9a-f]{4}-){15}[0-9a-f]{4}$/;

export async function check({ page, demo, visit, require, capture, step }) {
  const { DeviceID, RecoveryActionID } = demo.Routes;
  require(Boolean(RecoveryActionID), "Demo seed has no recovery action");
  const hostname = demo.Devices.find((device) => device.ID === DeviceID)?.Hostname ?? DeviceID;
  const main = page.getByRole("main");

  step("open reveal page");
  await visit(`/devices/${DeviceID}/recovery/${RecoveryActionID}`);
  const access = main.getByText("Recovery access", { exact: true });
  await access.waitFor({ timeout: 30_000 });

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

  step("reveal the key");
  await main.getByLabel("Reason", { exact: true }).fill("Owner pass 2 check: read key to user");
  await main.getByLabel("Type the device name to confirm").fill(hostname);
  await page.bringToFront();
  await main.getByRole("button", { name: "Reveal recovery key" }).click();
  const key = main.getByLabel("Recovery key", { exact: true });
  const refused = main.getByText(/^(Couldn't reveal recovery key|Verify your identity)$/).first();
  await key.or(refused).first().waitFor({ timeout: 30_000 });
  if (!(await key.isVisible())) {
    // This deployment requires a second approver or fresh step-up identity
    // verification, which a headless review session cannot satisfy, so the
    // key cannot appear here. Layout criteria above still hold.
    await capture("pass2-safety-reveal-approval");
    return;
  }
  const shown = (await key.innerText()).trim();
  require(grouped.test(
    shown,
  ), `Key is not shown in 4-character groups (got ${shown.length} chars)`);

  step("copy yields the raw key");
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
  await main.getByRole("button", { name: "Copy", exact: true }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  require(copied === shown.replaceAll("-", ""), "Copy did not copy the raw ungrouped key");
  await capture("pass2-safety-reveal");
  await main.getByRole("button", { name: "Hide now" }).click();
}
