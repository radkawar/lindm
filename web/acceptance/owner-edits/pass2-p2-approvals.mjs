// Owner pass 2 findings 20, 22-24 (two-person approvals): the risk form takes
// a duration from now, so no past expiry can be proposed (the server also
// refuses one); after proposing, the form offers the approval inbox, not
// "Accept again"; a requested revocation is shown on the device page; the
// requester can withdraw their own pending request, which then reads
// Withdrawn under Recent decisions.
//
// State: proposes one risk acceptance and one revocation as the review account
// on the route device, then withdraws both. Neither can be approved afterwards;
// nothing is accepted or revoked.
export const task = {
  name: "Approvals requester flow",
  screenId: "owner-pass2-p2-approvals",
  route: "/approvals",
  priority: "high",
  acceptance:
    "The risk form offers no free past date; a proposal shows its status and an approval inbox link, never 'Accept again'; the device page names the open revocation request; the requester's own pending request offers Withdraw request (disabled with a reason hint until a reason is typed) and, once withdrawn, reads Withdrawn under Recent decisions.",
};

const timeout = 30_000;
const HINT = /^Enter a reason to withdraw\./;

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

export async function check({ page, demo, visit, require, capture, step }) {
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
  await form.getByText(/^Proposed\./).waitFor({ timeout });
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
}
