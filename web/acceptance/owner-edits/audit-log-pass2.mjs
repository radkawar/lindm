// Owner pass 2 (2026-10-12), Audit log: compact filters, one time-range
// control, Details reachable at desktop and phone widths, human event names for
// every kind (device actions name their kind), no sign-out in Human actions.
// Read-only: switches views and viewport, then restores both.
import { readFile } from "node:fs/promises";

export const task = {
  name: "Audit log compact and named",
  screenId: "",
  route: "/audit",
  priority: "normal",
  acceptance:
    "At 1440x900 the first audit row starts within 250 px of the filters' top; no stray 'All time' text outside the time-range control; every row's Details control lies inside the viewport at 1440 and 390 px; at 390x844 the page does not scroll sideways and a row is visible on the first screen; every action caption is a human name from action-names.json (no 'Device action create'/'Identity local enrolled'); device-action rows name their kind ('Requested device action: Restart'); 'Changed device details' rows name the device; Human actions shows no 'Signed out'/'Signed in' rows; with a long hostname selected the Actor, Device and Time range labels stay in one line.",
};

const names = Object.values(
  JSON.parse(
    await readFile(new URL("../../src/features/audit/action-names.json", import.meta.url), "utf8"),
  ),
);
const DEVICE_ACTION_NAMES = ["Requested device action", "Started device action"];
const SESSION_NAMES = ["Signed in", "Signed out", "Signed in from the command line"];

async function idle(main) {
  await main.locator('section[aria-busy="false"]').first().waitFor({ timeout: 30_000 });
  await main.getByRole("table").first().getByRole("row").nth(1).waitFor({
    timeout: 30_000,
  });
}

async function captions(main) {
  const rows = main.getByRole("table").first().locator("tbody tr");
  const result = [];
  for (const row of await rows.all()) {
    const text = await row.getByRole("cell").nth(1).innerText();
    result.push(text.split("\n")[0].trim());
  }
  return result;
}

async function detailsInView(page, main, width) {
  const viewport = page.viewportSize();
  const rows = main.getByRole("table").first().locator("tbody tr");
  const outside = [];
  const count = Math.min(await rows.count(), 5);
  for (let i = 0; i < count; i++) {
    const details = rows.nth(i).getByText("Details", { exact: true }).first();
    if (!(await details.count())) {
      outside.push(`row ${i + 1} has no Details control`);
      continue;
    }
    const box = await details.boundingBox();
    if (!box || box.x < 0 || box.x + box.width > viewport.width) {
      outside.push(
        `row ${i + 1} Details at x=${box ? Math.round(box.x) : "hidden"} (width ${width})`,
      );
    }
  }
  return outside;
}

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  const original = page.viewportSize();
  try {
    step("open audit log at 1440x900");
    await page.setViewportSize({ width: 1440, height: 900 });
    await visit("/audit");
    await main
      .getByRole("heading", { name: "Audit log", exact: true })
      .waitFor({ timeout: 30_000 });
    await idle(main);
    const filters = main.getByRole("region", { name: "Audit filters" });
    const top = (await filters.boundingBox())?.y;
    const firstRow = (
      await main.getByRole("table").first().locator("tbody tr").first().boundingBox()
    )?.y;
    require(top !== undefined &&
      firstRow !== undefined &&
      firstRow - top <=
        250, `first audit row starts ${firstRow !== undefined && top !== undefined ? Math.round(firstRow - top) : "?"} px below the filters' top (limit 250)`);

    step("time range is one control");
    const stray = await main.getByText("All time", { exact: true }).evaluateAll((nodes) =>
      nodes
        .filter((node) => node.getClientRects().length > 0)
        .filter((node) => !node.closest('[role="combobox"], [role="option"], [role="listbox"]'))
        .map((node) => node.tagName.toLowerCase()),
    );
    require(stray.length ===
      0, `'All time' appears outside the time-range control: ${stray.join(", ")}`);

    step("human actions: names and no session bookkeeping");
    const human = await captions(main);
    const sessions = human.filter((caption) => SESSION_NAMES.includes(caption));
    require(sessions.length ===
      0, `Human actions lists session bookkeeping: ${sessions.join(", ")}`);
    const outside = await detailsInView(page, main, 1440);
    require(outside.length === 0, `Details not fully visible at 1440: ${outside.join("; ")}`);
    await capture("audit-pass2-human-desktop");

    step("all actions: every caption is a human name");
    await main.getByRole("button", { name: "All actions", exact: true }).click();
    await settle();
    await page.waitForURL(/[?&]view=all/, { timeout: 30_000 });
    await idle(main);
    const isDeviceAction = (caption) =>
      DEVICE_ACTION_NAMES.some((name) => caption.startsWith(name));
    const all = await captions(main);
    // The seed's bulk device-details edits are each about one device, so their
    // Device cell (When, Action, Who, Device, Reason) names it. Events recorded
    // after the seed (inbox reads, sign-ins, earlier review checks) can push
    // them past the first page, so page back as an operator would.
    const details = main
      .getByRole("table")
      .first()
      .locator("tbody tr")
      .filter({ hasText: "Changed device details" });
    for (let turned = 0; (await details.count()) === 0 && turned < 40; turned += 1) {
      const next = main
        .getByRole("navigation", { name: "Audit log pages", exact: true })
        .getByRole("button", { name: "Next page", exact: true });
      if (!(await next.isVisible()) || (await next.isDisabled())) break;
      await Promise.all([
        page.waitForResponse((response) =>
          response.url().endsWith("/lindm.admin.v1.AdminService/ListAuditEvents"),
        ),
        next.click(),
      ]);
      await idle(main);
      all.push(...(await captions(main)));
    }
    const detailCount = await details.count();
    require(detailCount > 0, "All actions shows no 'Changed device details' rows to assess");
    const unnamedDevices = [];
    for (const row of await details.all()) {
      if (!(await row.getByRole("cell").nth(3).innerText()).trim()) {
        unnamedDevices.push((await row.getByRole("cell").nth(4).innerText()).trim());
      }
    }
    require(unnamedDevices.length ===
      0, `${unnamedDevices.length} of ${detailCount} 'Changed device details' rows name no device (e.g. ${unnamedDevices.slice(0, 2).join("; ")})`);
    await capture("audit-pass2-all-desktop");

    // Bulk seed edits can fill the first All actions pages, so device actions
    // are read on the route device, where the seed requests them.
    step("device actions name their kind");
    await visit(`/audit?view=all&deviceId=${encodeURIComponent(demo.Routes.DeviceID)}`);
    await idle(main);
    all.push(...(await captions(main)));
    const raw = all.filter((caption) => !names.some((name) => caption.startsWith(name)));
    require(raw.length === 0, `actions without a human name: ${[...new Set(raw)].join(", ")}`);
    const deviceActions = all.filter(isDeviceAction);
    require(deviceActions.length > 0, "the route device's audit shows no device-action rows");
    const unnamed = deviceActions.filter((caption) => !/^[^:]+: \S/.test(caption));
    require(unnamed.length ===
      0, `device-action rows without their kind: ${[...new Set(unnamed)].join(", ")}`);
    await capture("audit-pass2-device-actions-desktop");

    // A long selected hostname wraps its picker trigger (design.md: hostnames
    // wrap, never truncate); the other filters' labels must stay in one line.
    step("long hostname keeps the filter bar aligned");
    const bar = main.getByRole("region", { name: "Audit filters" });
    await bar.getByRole("button", { name: /^Device\b/ }).click();
    await page.getByRole("combobox", { name: "Search device" }).pressSequentially("fedora-ci-gpu");
    await page
      .getByRole("option", { name: /^fedora-ci-gpu-runner/ })
      .first()
      .click({ timeout: 15_000 });
    await page.waitForURL(/[?&]deviceId=/, { timeout: 30_000 });
    await settle();
    const labelTops = {};
    for (const name of ["Actor", "Device", "Time range"]) {
      labelTops[name] = Math.round(
        (await bar.getByText(name, { exact: true }).first().boundingBox())?.y ?? -1,
      );
    }
    const tops = Object.values(labelTops);
    require(Math.max(...tops) - Math.min(...tops) <= 2 &&
      !tops.includes(
        -1,
      ), `filter labels out of line with a long hostname selected: ${JSON.stringify(labelTops)}`);
    await capture("audit-pass2-long-hostname-desktop");
    await visit("/audit?view=all");
    await idle(main);

    step("phone width: rows on the first screen, Details reachable");
    await page.setViewportSize({ width: 390, height: 844 });
    await settle();
    await page.evaluate(() => window.scrollTo(0, 0));
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth);
    require(overflow <= 390, `the page scrolls sideways at 390 px (${overflow} px wide)`);
    const phoneRow = await main
      .getByRole("table")
      .first()
      .locator("tbody tr")
      .first()
      .boundingBox();
    require(phoneRow !== null &&
      phoneRow.y + 40 <=
        844, `no audit row visible on the first 390x844 screen (first row at ${phoneRow ? Math.round(phoneRow.y) : "?"} px)`);
    const phone = await detailsInView(page, main, 390);
    require(phone.length === 0, `Details not fully visible at 390: ${phone.join("; ")}`);
    await capture("audit-pass2-all-mobile");
  } finally {
    step("restore default view and viewport");
    if (original) await page.setViewportSize(original);
    const human = main.getByRole("button", { name: "Human actions", exact: true });
    if (await human.count()) {
      await human.click();
      await settle();
    }
  }
}
