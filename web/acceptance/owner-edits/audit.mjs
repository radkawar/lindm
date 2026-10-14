// SPDX-License-Identifier: Apache-2.0

// Owner task: /audit opens on human decisions, not read-only or system churn.
// Read-only: switches quick views and restores the default view afterwards.
export const task = {
  name: "Audit human actions default",
  screenId: "46b6bf9bc6535ff5a64d6c69",
  route: "/audit",
  priority: "normal",
  acceptance:
    "Opening /audit shows no approvals-inbox or advisory-findings rows unless 'All actions' is selected; empty reason/device cells are blank.",
};

// Human names from web/src/features/audit/action-names.json.
const CHURN = ["Opened approvals inbox", "Updated advisory findings"];

async function rows(main) {
  // `has:` locators resolve relative to the row, so a main-anchored one never matched.
  const body = main.locator("table tbody tr");
  const result = [];
  for (const row of await body.all()) {
    const cells = row.getByRole("cell");
    result.push({
      action: (await cells.nth(1).innerText()).trim(),
      reason: (await cells.nth(3).innerText()).trim(),
      device: (await cells.nth(4).innerText()).trim(),
    });
  }
  return result;
}

// The view keeps the previous page visible while the new selection loads.
async function idle(main) {
  await main.locator('section[aria-busy="false"]').first().waitFor({ timeout: 30_000 });
  await main.locator("table tbody tr").first().waitFor({ timeout: 30_000 });
}

function churnIn(list) {
  return list.filter((row) => CHURN.some((label) => row.action.startsWith(label)));
}

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  // Opening the approvals inbox records a read-only event, so one sits on the
  // first All actions page even after bulk seed edits.
  step("open approvals inbox");
  await visit("/approvals");
  await settle();
  step("open default audit view");
  await visit("/audit");
  await main.getByRole("heading", { name: "Audit log", exact: true }).waitFor({ timeout: 30_000 });
  const human = main.getByRole("button", { name: "Human actions", exact: true });
  const all = main.getByRole("button", { name: "All actions", exact: true });
  await human.waitFor({ timeout: 30_000 });
  require((await human.getAttribute("aria-pressed")) ===
    "true", "Human actions is not the default view");
  require((await all.count()) === 1, "All actions quick view is missing");
  await idle(main);
  const defaults = await rows(main);
  require(defaults.length > 0, "Default Human actions view shows no rows to assess");
  require(churnIn(defaults).length === 0, `Default view shows read-only/system rows: ${churnIn(
    defaults,
  )
    .map((row) => row.action)
    .join(", ")}`);
  require(!defaults.some(
    (row) => row.reason === "Not recorded" || row.device === "Not recorded",
  ), "Default view prints 'Not recorded' in Reason/Device cells");
  await capture("audit-human-actions");

  step("switch to all actions");
  await all.click();
  await settle();
  await page.waitForURL(/[?&]view=all/, { timeout: 30_000 });
  await idle(main);
  require((await all.getAttribute("aria-pressed")) ===
    "true", "All actions did not become selected");
  const everything = await rows(main);
  require(churnIn(everything).length > 0, "All actions does not show read-only/system events");
  require(!everything.some(
    (row) => row.reason === "Not recorded" || row.device === "Not recorded",
  ), "All actions prints 'Not recorded' in Reason/Device cells");
  require(everything.some((row) => row.reason === "") ||
    everything.some(
      (row) => row.device === "",
    ), "No blank Reason/Device cell observed for events without them");
  await capture("audit-all-actions");

  step("restore default view");
  await human.click();
  await settle();
}
