// SPDX-License-Identifier: Apache-2.0

// Owner task (pass 2 findings 49): "View export and download evidence" from the
// audit export dialog landed at the top of /integrations. The link now lands on
// the export's report row and focuses it. Moves state: queues one audit export.
export const task = {
  name: "Integrations audit export deep link",
  screenId: "",
  route: "/audit",
  priority: "normal",
  acceptance:
    "After exporting filtered evidence on /audit, View export and download evidence opens /integrations#report-<id> with that report's row focused and on screen.",
};

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  step("export filtered evidence");
  await visit("/audit");
  await main.getByRole("button", { name: "Export filtered evidence", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Export filtered evidence" });
  await dialog.waitFor({ timeout: 30_000 });
  await dialog
    .getByLabel("Reason for export", { exact: true })
    .fill("Owner check: export deep link");
  await dialog.getByRole("button", { name: "Start export", exact: true }).click();
  const link = dialog.getByRole("link", { name: "View export and download evidence" });
  await link.waitFor({ timeout: 30_000 });

  step("follow the link");
  await link.click();
  await page.waitForURL(/\/integrations#report-/, { timeout: 30_000 });
  const id = new URL(page.url()).hash.slice(1);
  await page.locator(`[id="${id}"]`).waitFor({ timeout: 30_000 });
  await page.waitForFunction((target) => document.activeElement?.id === target, id, {
    timeout: 10_000,
  });
  await settle();
  const placement = await page.evaluate((target) => {
    const box = document.getElementById(target).getBoundingClientRect();
    return { top: box.top, bottom: box.bottom, height: window.innerHeight };
  }, id);
  require(placement.top >= 0 &&
    placement.bottom <=
      placement.height, `the report row is off screen (top ${Math.round(placement.top)})`);
  await capture("integrations-report-deep-link");
}
