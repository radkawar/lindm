// Owner pass 2 findings 20-24 (two-person approvals): the risk form takes a
// duration from now, so no past expiry can be proposed (the server also
// refuses one); after proposing, the form offers the approval inbox, not
// "Accept again"; a requested revocation is shown on the device page; the
// requester can withdraw their own pending request, which then reads
// Withdrawn under Recent decisions; a request another admin approved leads the
// inbox under "Ready for you to run" and is counted on the dashboard.
//
// State: proposes one risk acceptance and one revocation as the review account
// on the route device, then withdraws both, so neither can be approved or run.
// For the ready group it requests to reveal the demo secret (the least-impact
// approval: it changes nothing and reveals nothing unless the requester runs
// it) with a five-minute lifetime, and a fresh admin account approves it in its
// own browser. The check never clicks Run now; the approval expires unused.
import { ChromiumDriver, UI } from "../drivers.mjs";
import { enroll, signIn } from "../journey.mjs";

export const task = {
  name: "Approvals requester flow",
  screenId: "owner-pass2-p2-approvals",
  route: "/approvals",
  priority: "high",
  acceptance:
    "The risk form offers no free past date; a proposal shows its status and an approval inbox link, never 'Accept again'; the device page names the open revocation request; the requester's own pending request offers Withdraw request (disabled with a reason hint until a reason is typed) and, once withdrawn, reads Withdrawn under Recent decisions; a request another admin approved is listed first under 'Ready for you to run (N)' with Run now, and the dashboard says 'N approved request(s) ready for you to run' beside its link to the inbox.",
};

const timeout = 30_000;
const HINT = /^Enter a reason to withdraw\./;
const READY = /^\d+ approved requests? ready for you to run\.$/;

// One AdminService call through the signed-in page's own cookie and CSRF token.
async function rpc(page, method, body) {
  return page.evaluate(
    async ({ method, body }) => {
      const session = await (await fetch("/auth/session", { cache: "no-store" })).json();
      const response = await fetch(`/lindm.admin.v1.AdminService/${method}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrfToken },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(`${method}_${response.status}`);
      return response.json();
    },
    { method, body },
  );
}

// A fresh admin, created through the owner's real session, approves approvalId
// from its own browser; the review account can never approve its own request.
async function approveAsSecondAdmin({ page, config, protectSecret, approvalId }) {
  const username = `review-approver-${crypto.randomUUID().slice(0, 8)}`;
  const enrollmentSecret = await page.evaluate(async (username) => {
    const current = await (await fetch("/auth/session", { cache: "no-store" })).json();
    const response = await fetch("/auth/accounts/create", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-CSRF-Token": current.csrfToken,
      },
      body: JSON.stringify({ username, role: "admin", scopes: [] }),
    });
    if (!response.ok) throw new Error(`create_account_${response.status}`);
    return (await response.json()).secret;
  }, username);
  protectSecret?.(enrollmentSecret);
  const password = `review-${crypto.randomUUID()}`;
  protectSecret?.(password);
  const driver = new ChromiumDriver();
  try {
    await driver.open({ ignoreHTTPSErrors: true, actionTimeoutMs: 30_000 });
    await driver.authenticator([]);
    const ui = new UI(driver, 30_000);
    const account = { origin: config.origin, username, password, enrollmentSecret };
    await driver.goto(config.origin);
    await enroll(ui, account);
    await signIn(ui, account);
    await rpc(driver.page, "ApproveApproval", {
      approvalId,
      reason: "Owner pass 2 acceptance: independent approval left unused",
    });
  } finally {
    await driver.close().catch(() => {});
  }
}

async function withdraw({ page, main, visit, require, title, reason }) {
  await visit("/approvals");
  await main.getByRole("heading", { name: "Approval inbox", exact: true }).waitFor({ timeout });
  const own = main
    .locator("article")
    .filter({ has: page.locator("h3", { hasText: title }) })
    .filter({ hasText: reason })
    .filter({ has: page.getByRole("button", { name: "Withdraw request", exact: true }) });
  await own.first().waitFor({ timeout });
  require((await own.count()) === 1, `Expected one withdrawable "${title}" request`);
  const card = own.first();
  const button = card.getByRole("button", { name: "Withdraw request", exact: true });
  require(await button.isDisabled(), "Withdraw request is enabled with an empty reason");
  const ids = ((await button.getAttribute("aria-describedby")) ?? "").split(/\s+/).filter(Boolean);
  const described = await Promise.all(
    ids.map(async (id) => ((await card.locator(`[id="${id}"]`).textContent()) ?? "").trim()),
  );
  require(described.some((text) =>
    HINT.test(text),
  ), "Disabled Withdraw request is not described by its hint");
  const hint = card.getByText(HINT);
  require((await hint.count()) === 1 &&
    (await hint.isVisible()), "The withdrawal hint is not visible with an empty reason");
  await card
    .getByRole("textbox", { name: "Withdrawal reason" })
    .fill("Owner pass 2 acceptance: withdraw own request");
  await button.click();
  await page.getByText("Request withdrawn").first().waitFor({ timeout });
  const recent = main.locator("details").filter({
    has: page.locator("summary", { hasText: "Recent decisions" }),
  });
  await recent.first().locator(":scope > summary").click();
  const withdrawn = recent
    .first()
    .locator("article")
    .filter({ has: page.locator("h3", { hasText: title }) })
    .filter({ hasText: reason })
    .filter({ has: page.locator('[data-slot="badge"]', { hasText: /^Withdrawn$/ }) });
  await withdrawn.first().waitFor({ timeout });
  require((await withdrawn.count()) === 1, `Withdrawn "${title}" is not under Recent decisions`);
}

export async function check({ page, config, demo, visit, require, protectSecret, capture, step }) {
  const main = page.getByRole("main");
  const deviceId = demo.Routes.DeviceID;
  const hostname = demo.Devices.find((device) => device.ID === deviceId)?.Hostname;
  if (!deviceId || !hostname) throw new Error("demo route device or its hostname is missing");
  const riskReason = `Owner pass 2 acceptance: proposal to withdraw ${Date.now()}`;
  const revokeReason = `Owner pass 2 acceptance: revocation to withdraw ${Date.now()}`;

  step("open findings");
  await visit(`/devices/${encodeURIComponent(deviceId)}`);
  await main.getByRole("tab", { name: "Findings", exact: true }).click();
  const panel = main.locator('[role="tabpanel"]:not([hidden])');
  const accept = panel.getByRole("button", { name: "Accept this risk", exact: true }).first();
  await accept.waitFor({ timeout });
  await accept.click();
  const form = page.getByRole("dialog").locator("form");
  await form.waitFor({ timeout });

  step("no past expiry can be entered");
  await form.getByRole("textbox", { name: "Reason" }).fill(riskReason);
  require((await form.locator('input[type="date"], input[type="datetime-local"]').count()) ===
    0, "The risk form still takes a free date that can be in the past");
  require((await form.getByText("Accept the risk for").count()) ===
    1, "The risk form does not offer a duration from now");

  step("propose");
  await form.getByRole("button", { name: "Propose risk acceptance", exact: true }).click();
  await form
    .getByRole("status")
    .filter({
      hasText:
        "Proposal saved. Another administrator must approve it before lindm accepts this risk.",
    })
    .waitFor({ timeout });
  require((await form.getByRole("button", { name: "Accept again" }).count()) ===
    0, "'Accept again' is offered after proposing");
  require((await form.getByRole("link", { name: "Open approval inbox" }).count()) ===
    1, "The proposal does not link to the approval inbox");
  await capture("proposed");
  await page.keyboard.press("Escape");

  step("request revocation");
  await main.getByRole("button", { name: "Actions", exact: true }).click();
  await page.getByRole("menuitem", { name: "Revoke device", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("textbox", { name: "Revocation reason" }).fill(revokeReason);
  await dialog.getByRole("button", { name: "Request revocation approval", exact: true }).click();
  await dialog.getByText("Approval requested.").waitFor({ timeout });
  await page.keyboard.press("Escape");

  step("device page shows the open revocation");
  await visit(`/devices/${encodeURIComponent(deviceId)}`);
  const notice = main.locator('[data-slot="revocation-status"]');
  await notice.first().waitFor({ timeout });
  require((await notice.getByText("Revocation requested by you.").count()) ===
    1, "The device page does not name the open revocation request");
  await page.evaluate(() => window.scrollTo(0, 0));
  await capture("device-revocation-requested");

  step("withdraw the risk acceptance");
  await withdraw({
    page,
    main,
    visit,
    require,
    title: /^Accept advisory risk/,
    reason: riskReason,
  });
  step("withdraw the revocation");
  await withdraw({
    page,
    main,
    visit,
    require,
    title: /^Revoke device access/,
    reason: revokeReason,
  });
  await page.evaluate(() => window.scrollTo(0, 0));
  await capture("withdrawn");

  step("device page clears the withdrawn revocation");
  await visit(`/devices/${encodeURIComponent(deviceId)}`);
  await main.getByRole("tab", { name: "Findings", exact: true }).waitFor({ timeout });
  require((await main.locator('[data-slot="revocation-status"]').count()) ===
    0, "The device page still shows a withdrawn revocation");

  step("request a reveal another admin approves");
  const { secret } = await rpc(page, "GetSecret", { secretId: demo.Routes.SecretID });
  const revealReason = `Owner pass 2 acceptance: approved request left to expire ${Date.now()}`;
  const created = await rpc(page, "CreateApproval", {
    lifetimeSeconds: 300,
    revealSecret: {
      requestId: crypto.randomUUID(),
      secretId: demo.Routes.SecretID,
      version: secret?.currentVersion,
      reason: revealReason,
    },
  });
  const approvalId = created.approval?.id;
  if (!approvalId) throw new Error("The reveal approval was not created");
  await approveAsSecondAdmin({ page, config, protectSecret, approvalId });

  step("ready group leads the inbox");
  await visit("/approvals");
  const readyHeading = main.getByRole("heading", { name: /^Ready for you to run/ });
  await readyHeading.waitFor({ timeout });
  const headingText = ((await readyHeading.textContent()) ?? "").trim();
  require(/\(\d+\)$/.test(headingText), `The ready group has no count: "${headingText}"`);
  const order = await main
    .locator("h2")
    .evaluateAll((headings) => headings.map((heading) => (heading.textContent ?? "").trim()));
  const readyIndex = order.findIndex((text) => text.startsWith("Ready for you to run"));
  const openIndex = order.findIndex((text) => text.startsWith("Open requests"));
  require(readyIndex >= 0 &&
    readyIndex <
      openIndex, `Ready for you to run does not precede Open requests: ${order.join(" | ")}`);
  // The ID is only in the card's collapsed Details, so match on DOM text.
  const readyCards = main.locator('section[aria-labelledby="approvals-ready"] article');
  const index = await readyCards.evaluateAll(
    (nodes, id) => nodes.findIndex((node) => node.textContent?.includes(id)),
    approvalId,
  );
  require(index >= 0, "The approved request is not listed under Ready for you to run");
  if (index >= 0) {
    const card = readyCards.nth(index);
    require((await card.locator('[data-slot="badge"]').first().textContent())?.trim() ===
      "Approved", "The ready request is not badged Approved");
    require((await card.getByRole("button", { name: "Run now", exact: true }).count()) ===
      1, "The ready request offers no Run now");
  }
  const mixed = await main
    .locator('section[aria-labelledby="approvals-open"] article')
    .evaluateAll((nodes, id) => nodes.some((node) => node.textContent?.includes(id)), approvalId);
  require(!mixed, "The approved request is still mixed into Open requests");
  await page.evaluate(() => window.scrollTo(0, 0));
  await capture("ready-for-you-to-run");

  step("dashboard counts it");
  await visit("/dashboard");
  const line = main.locator('[data-slot="approvals-ready"]');
  await line.waitFor({ timeout });
  const lineText = ((await line.textContent()) ?? "").replace(/\s+/g, " ").trim();
  require(READY.test(lineText), `Dashboard ready line reads "${lineText}"`);
  // The work item (dashboard WorkItem, data-review-metric) holding the line.
  const item = line
    .locator("xpath=ancestor::*[@data-review-metric][1]")
    .getByRole("link", { name: /Review approvals/ });
  require((await item.count()) === 1 &&
    (await item.getAttribute("href")) ===
      "/approvals", "The ready line is not beside a link to the approval inbox");
  await page.evaluate(() => window.scrollTo(0, 0));
  await capture("dashboard-ready-count");
}
