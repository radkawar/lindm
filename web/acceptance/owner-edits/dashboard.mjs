// SPDX-License-Identifier: Apache-2.0

// Dashboard decision queue: grouped activity with real outcome words, a
// dedicated vulnerability-coverage item linking to /advisories, and no
// supporting-evidence accordion. Read-only.
export const task = {
  name: "Dashboard decision queue",
  screenId: "54f6ab9e9730f694718bc6de",
  route: "/dashboard",
  priority: "high",
  acceptance:
    "With the seeded demo fleet: activity shows at most one row per action kind with counts and outcome words; a needs-review item counts devices with unknown exposure and links to its coverage explanation and remedy; no 'Supporting fleet evidence' section remains.",
};

const outcomeWord = /\b\d+ (succeeded|failed|unknown|expired|running|waiting|cancelled)\b/;
const coverageTitle = /^\d+ devices? (has|have) unknown exposure$/;

export async function check({ page, visit, settle, require, capture, step }) {
  step("open dashboard");
  await visit("/dashboard");
  const queue = page.getByRole("heading", { name: "Needs review", exact: true });
  await queue.waitFor({ timeout: 30_000 });

  step("activity grouped by kind");
  // The activity section is labelled by its own heading; the page section also contains it.
  const activity = page.locator('section[aria-labelledby="recent-activity-title"]');
  await page
    .getByRole("heading", { name: "Latest recorded activity", exact: true })
    .waitFor({ timeout: 30_000 });
  await activity.waitFor({ timeout: 30_000 });
  const rows = activity.locator("li");
  const rowCount = await rows.count();
  require(rowCount > 0, "Latest recorded activity has no rows on the seeded fleet");
  const kinds = new Set();
  const labels = new Set();
  const failedRows = [];
  for (let index = 0; index < rowCount; index += 1) {
    const row = rows.nth(index);
    const kind = await row.getAttribute("data-activity-kind");
    const text = (await row.innerText()).replace(/\s+/g, " ").trim();
    const label = text.split(" · ")[0];
    require(!kinds.has(kind), `activity kind repeated: ${kind}`);
    require(!labels.has(label), `activity label repeated: ${label}`);
    kinds.add(kind);
    labels.add(label);
    require(/· \d+ actions?\b/.test(text), `activity row has no count: ${text}`);
    require(outcomeWord.test(text), `activity row has no outcome word: ${text}`);
    failedRows.push(/\b\d+ failed\b/.test(text));
  }
  if (failedRows.includes(true)) {
    require(failedRows.indexOf(false) === -1 ||
      failedRows.indexOf(false) >
        failedRows.lastIndexOf(true), "activity rows with failures are not listed first");
  }
  const activityText = await activity.innerText();
  require(!/\bClosed\b/.test(activityText), "activity still shows 'Closed'");

  step("supporting evidence removed");
  require((await page.getByText("Supporting fleet evidence").count()) ===
    0, "'Supporting fleet evidence' is still on the dashboard");

  step("coverage needs-review item");
  const heading = page.getByRole("heading", { level: 3, name: coverageTitle });
  const headingCount = await heading.count();
  require(headingCount === 1, `expected one coverage item matching ${coverageTitle}`);
  if (headingCount !== 1) {
    await capture("dashboard-decision-queue");
    return;
  }
  const title = (await heading.innerText()).trim();
  const dashboardCount = Number(title.match(/^\d+/)[0]);
  const item = heading.locator("xpath=ancestor::*[@data-review-metric][1]");
  const link = item.getByRole("link", { name: /fix coverage/i });
  require((await link.count()) === 1, "coverage item has no 'fix coverage' link");
  await capture("dashboard-decision-queue");

  step("coverage link opens advisories");
  await link.click();
  await page.waitForURL(/\/advisories(\?|$)/, { timeout: 30_000 });
  await settle();
  require(new URL(page.url()).pathname === "/advisories", `link opened ${page.url()}`);
  // Marker agreed with the Advisories slice: the visible "Devices not checked" count.
  const notChecked = page.locator("[data-advisory-unchecked-count]").first();
  await notChecked.waitFor({ timeout: 30_000 });
  const marked = Number(await notChecked.getAttribute("data-advisory-unchecked-count"));
  const advisoriesCount = Number((await notChecked.innerText()).trim());
  require(marked === advisoriesCount, "advisories unchecked marker disagrees with visible count");
  require(advisoriesCount ===
    dashboardCount, `dashboard says ${dashboardCount} uncovered devices; /advisories shows ${advisoriesCount} not checked`);
  await capture("dashboard-coverage-advisories");
}
