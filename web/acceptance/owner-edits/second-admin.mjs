// Shared steps for owner-edit checks that need a real second approver or an
// in-page step-up: create an Admin in Accounts, approve one request as that
// admin in its own browser (own virtual passkey), read the approval ID a reveal
// form shows, and complete "Verify it's you" on the review session.
import { ChromiumDriver, UI } from "../drivers.mjs";
import { enroll, signIn } from "../journey.mjs";

const timeout = 30_000;

// Creates a new Admin account through the console and returns its one-time
// enrollment secret with a fresh password for enrolling it.
export async function createAdmin({ page, visit }) {
  const main = page.getByRole("main");
  const username = `approver-${Date.now().toString(36)}`;
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
  return { username, password, enrollmentSecret };
}

// Index of the approval card whose DOM text (including collapsed Details)
// contains the approval ID.
export function cardIndex(articles, approvalId) {
  return articles.evaluateAll(
    (nodes, id) => nodes.findIndex((node) => node.textContent?.includes(id)),
    approvalId,
  );
}

// The approval ID a reveal form shows in its Details after "Request approval".
export async function requestedApprovalId(page) {
  await page.waitForFunction(
    () =>
      [...document.querySelectorAll('main [data-slot="technical-details"] div')].some((node) =>
        /^Approval ID:\s*[0-9a-f-]{36}/.test(node.textContent ?? ""),
      ),
    undefined,
    { timeout },
  );
  const item = page
    .getByRole("main")
    .locator('[data-slot="technical-details"] div')
    .filter({ hasText: /^Approval ID:/ })
    .first();
  const approvalId = ((await item.locator("dd").textContent()) ?? "").trim();
  if (!/^[0-9a-f-]{36}$/.test(approvalId)) throw new Error("The new approval ID was not shown");
  return approvalId;
}

// Enrolls and signs in the admin from createAdmin in a separate browser and
// approves one request in its inbox. The review page's session is untouched.
export async function approveAs({ config, admin, approvalId, reason }) {
  const approver = new ChromiumDriver();
  await approver.open({ ignoreHTTPSErrors: true, actionTimeoutMs: timeout, origin: config.origin });
  try {
    await approver.authenticator([]);
    await approver.goto(config.origin);
    const ui = new UI(approver, timeout);
    await enroll(ui, { enrollmentSecret: admin.enrollmentSecret, password: admin.password });
    await signIn(ui, { username: admin.username, password: admin.password, origin: config.origin });
    const inbox = approver.page;
    await inbox.goto(`${config.origin}/approvals`);
    const articles = inbox.getByRole("main").locator("article");
    await articles.first().waitFor({ timeout });
    const index = await cardIndex(articles, approvalId);
    if (index < 0) throw new Error("The second admin does not see the request");
    const card = articles.nth(index);
    await card.getByRole("textbox", { name: "Approval decision reason" }).fill(reason);
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
}

// Completes the in-page "Verify it's you" (password, then the review page's
// virtual passkey) inside scope. The caller's onRetry resends the request.
export async function completeStepUp(scope, config) {
  await scope.getByLabel("Your password", { exact: true }).fill(config.password);
  await scope.getByRole("button", { name: "Verify with passkey", exact: true }).click();
}

// Runs a two-person reveal end to end on a reveal form already filled in on the
// review page: Request approval, approval by `admin` in its own browser, the
// form's own approval refresh, then Reveal, completing "Verify it's you" if the
// server asks for it. Returns the revealed value's locator, or null with the
// refusal text when the server refused.
export async function revealAfterApproval({
  page,
  config,
  admin,
  refreshName,
  revealName,
  valueLabel,
  failureTitle,
}) {
  const main = page.getByRole("main");
  await main.getByRole("button", { name: "Request approval", exact: true }).click();
  const approvalId = await requestedApprovalId(page);
  await approveAs({
    config,
    admin,
    approvalId,
    reason: "Owner pass 2 check: approve a reveal for review",
  });
  await page.bringToFront();
  await main.getByRole("button", { name: refreshName, exact: true }).click();
  const reveal = main.getByRole("button", { name: revealName, exact: true });
  await page.waitForFunction(
    (name) =>
      [...document.querySelectorAll("main button")].some(
        (node) => node.textContent?.trim() === name && !node.disabled,
      ),
    revealName,
    { timeout },
  );
  // Clipboard access must exist before the key arrives: granting later can
  // blur the page, and the reveal hides on blur.
  await page
    .context()
    .grantPermissions(["clipboard-read", "clipboard-write"], { origin: config.origin });
  await reveal.click();
  const value = main.getByLabel(valueLabel, { exact: true });
  const verify = main.getByText("Verify it's you", { exact: true }).first();
  const refused = main.getByText(failureTitle, { exact: true }).first();
  await value.or(verify).or(refused).first().waitFor({ timeout });
  if (await verify.isVisible()) {
    // The refusal panel (same title) stays until the resent request answers,
    // so wait for the value itself.
    await completeStepUp(main, config);
    await value.waitFor({ timeout }).catch(() => {});
  }
  if (await value.isVisible()) return { value, refusal: "" };
  const panel = (await refused.count()) ? refused.locator("xpath=..") : main;
  return {
    value: null,
    refusal: (await panel.innerText()).trim().split("\n").slice(0, 3).join(" "),
  };
}
