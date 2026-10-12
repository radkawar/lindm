// Owner pass 2 finding 14: a reveal refused with "Verify your identity —
// Complete step-up verification before submitting again" and offered no way
// to do it; only signing out and in again worked. The refusal now carries an
// in-page "Verify it's you" check (password, then passkey) on the same session,
// after which the same request is sent again automatically.
//
// The demo has another admin, so a reveal needs approval first. The check runs
// the real job end to end: the review account requests approval to reveal the
// route device's recovery key; a new admin account is created in Accounts,
// enrolled and signed in with its own passkey in a separate browser, and
// approves; the review account then runs the approved reveal from the inbox.
// Its session signed in well over five minutes earlier, so the reveal needs
// the step-up.
//
// State (registered late): one new admin account, one approved and consumed
// recovery-key reveal approval (audited), one step-up on the review session.
import {
  approveAs,
  cardIndex,
  completeStepUp,
  createAdmin,
  requestedApprovalId,
} from "./second-admin.mjs";

export const task = {
  name: "Reveal offers in-page identity check",
  screenId: "owner-pass2-p2-14-step-up",
  route: "/approvals",
  priority: "high",
  acceptance:
    "Running an approved recovery-key reveal on an older session shows 'Verify it's you' with a password field and 'Verify with passkey'; after verifying, the key is revealed without pressing Run now again and without signing out.",
};

const timeout = 30_000;

export async function check({ page, config, demo, visit, settle, require, capture, step }) {
  const { DeviceID, RecoveryActionID } = demo.Routes;
  if (!RecoveryActionID) throw new Error("Demo seed has no recovery action");
  const hostname = demo.Devices.find((device) => device.ID === DeviceID)?.Hostname ?? DeviceID;
  const main = page.getByRole("main");

  step("request approval to reveal");
  await visit(`/devices/${DeviceID}/recovery/${RecoveryActionID}`);
  await main.getByLabel("Reason", { exact: true }).waitFor({ timeout });
  await main.getByLabel("Reason", { exact: true }).fill("Owner pass 2 check: in-page step-up");
  await main.getByLabel("Type the device name to confirm").fill(hostname);
  await main.getByRole("button", { name: "Request approval", exact: true }).click();
  const approvalId = await requestedApprovalId(page);

  step("create a second admin");
  const admin = await createAdmin({ page, visit });

  step("second admin approves in its own browser");
  await approveAs({
    config,
    admin,
    approvalId,
    reason: "Owner pass 2 check: approve the step-up reveal",
  });

  step("run the approved reveal");
  await visit("/approvals");
  const articles = main.locator("article");
  await articles.first().waitFor({ timeout });
  const index = await cardIndex(articles, approvalId);
  if (index < 0) throw new Error("The approved reveal is not listed for the requester");
  const card = articles.nth(index);
  await card.getByRole("button", { name: "Run now", exact: true }).click();
  const revealed = main.getByRole("region", { name: "Revealed recovery key" });
  const verifyTitle = card.getByText("Verify it's you", { exact: true });
  await revealed.or(verifyTitle).first().waitFor({ timeout });
  if (await revealed.isVisible()) {
    require(false, "The reveal did not need a step-up (the session is under five minutes old), so the in-page check was not exercised");
    await revealed.getByRole("button", { name: "Dismiss recovery key" }).click();
    return;
  }
  require((await card.getByText("Complete step-up verification").count()) ===
    0, "The refusal still only says to complete step-up verification");
  await card.scrollIntoViewIfNeeded();
  await settle();
  await capture("verify-its-you");

  step("verify with password and passkey");
  await completeStepUp(card, config);
  // The same approved reveal runs again; no second press of Run now.
  await revealed.waitFor({ timeout });
  require(new URL(page.url()).pathname === "/approvals", "Verification left the approvals page");
  // No capture here: the revealed key is plaintext on the page.
  await revealed.getByRole("button", { name: "Dismiss recovery key" }).click();
}
