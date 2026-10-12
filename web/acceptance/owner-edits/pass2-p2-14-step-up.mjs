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
import { ChromiumDriver, UI } from "../drivers.mjs";
import { enroll, signIn } from "../journey.mjs";

export const task = {
  name: "Reveal offers in-page identity check",
  screenId: "owner-pass2-p2-14-step-up",
  route: "/approvals",
  priority: "high",
  acceptance:
    "Running an approved recovery-key reveal on an older session shows 'Verify it's you' with a password field and 'Verify with passkey'; after verifying, the key is revealed without pressing Run now again and without signing out.",
};

const timeout = 30_000;

// Index of the approval card whose DOM text (including collapsed Details)
// contains the approval ID.
function cardIndex(articles, approvalId) {
  return articles.evaluateAll(
    (nodes, id) => nodes.findIndex((node) => node.textContent?.includes(id)),
    approvalId,
  );
}

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
  const approvalItem = main
    .locator('[data-slot="technical-details"] div')
    .filter({ hasText: /^Approval ID:/ })
    .first();
  await page.waitForFunction(
    () =>
      [...document.querySelectorAll('main [data-slot="technical-details"] div')].some((node) =>
        /^Approval ID:\s*[0-9a-f-]{36}/.test(node.textContent ?? ""),
      ),
    undefined,
    { timeout },
  );
  const approvalId = ((await approvalItem.locator("dd").textContent()) ?? "").trim();
  if (!/^[0-9a-f-]{36}$/.test(approvalId)) throw new Error("The new approval ID was not shown");

  step("create a second admin");
  const username = `stepup-approver-${Date.now().toString(36)}`;
  const password = `${crypto.randomUUID()}!Aa`;
  await visit("/accounts");
  await main.getByRole("button", { name: "Create account", exact: true }).first().click();
  const dialog = page.getByRole("dialog", { name: "Create account", exact: true });
  await dialog.waitFor({ timeout });
  await dialog.getByLabel("Username", { exact: true }).fill(username);
  await dialog.locator("#new-role").click();
  await page.getByRole("option", { name: "Admin", exact: true }).click();
  await dialog.getByRole("button", { name: "Create account", exact: true }).click();
  const secretSection = main.getByRole("region", { name: "One-time enrollment secret" });
  await secretSection.waitFor({ timeout });
  const enrollmentSecret = ((await secretSection.locator("code").textContent()) ?? "").trim();
  await secretSection.getByRole("button", { name: "Dismiss secret", exact: true }).click();
  if (!enrollmentSecret) throw new Error("No enrollment secret was shown for the new admin");

  step("second admin approves in its own browser");
  const approver = new ChromiumDriver();
  await approver.open({ ignoreHTTPSErrors: true, actionTimeoutMs: timeout, origin: config.origin });
  try {
    await approver.authenticator([]);
    await approver.goto(config.origin);
    const ui = new UI(approver, timeout);
    await enroll(ui, { enrollmentSecret, password });
    await signIn(ui, { username, password, origin: config.origin });
    const inbox = approver.page;
    await inbox.goto(`${config.origin}/approvals`);
    const articles = inbox.getByRole("main").locator("article");
    await articles.first().waitFor({ timeout });
    const index = await cardIndex(articles, approvalId);
    if (index < 0) throw new Error("The second admin does not see the reveal request");
    const card = articles.nth(index);
    await card
      .getByRole("textbox", { name: "Approval decision reason" })
      .fill("Owner pass 2 check: approve the step-up reveal");
    await card.getByRole("button", { name: "Approve", exact: true }).click();
    // The inbox refetches and may reorder; find the card again by its ID.
    await inbox.waitForFunction(
      (id) =>
        [...document.querySelectorAll("main article")].some(
          (node) =>
            node.textContent?.includes(id) &&
            node.querySelector("h3")?.nextElementSibling?.textContent?.trim() === "Approved",
        ),
      approvalId,
      { timeout },
    );
  } finally {
    await approver.close();
  }

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
  await card.getByLabel("Your password", { exact: true }).fill(config.password);
  await card.getByRole("button", { name: "Verify with passkey", exact: true }).click();
  // The same approved reveal runs again; no second press of Run now.
  await revealed.waitFor({ timeout });
  require(new URL(page.url()).pathname === "/approvals", "Verification left the approvals page");
  // No capture here: the revealed key is plaintext on the page.
  await revealed.getByRole("button", { name: "Dismiss recovery key" }).click();
}
