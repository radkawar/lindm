// Owner task (UI pass 2, items 36–38): device list search is case-insensitive
// and matches any part of a hostname; sorting is server-side across all pages
// with devices lacking the value last; the CSV export uses human values.
// Read-only: searches, sorts and downloads one export page.
import { readFile } from "node:fs/promises";

export const task = {
  name: "Device list search, sort and export",
  screenId: "owner-pass-2-devices-36-38",
  route: "/devices",
  priority: "normal",
  acceptance:
    "Typing any case or any part of a hostname finds it; sorting by last contact orders all devices with never-seen ones last in both directions and never says 'current page only'; the CSV export has human column names and values (no DEVICE_* enums or JSON) and the console confirms the download.",
};

async function column(table, name) {
  const headers = (await table.locator("thead th").allInnerTexts()).map((text) => text.trim());
  const index = headers.indexOf(name);
  const rows = await table.locator("tbody tr").all();
  const cells = [];
  for (const row of rows) cells.push((await row.locator("td").nth(index).innerText()).trim());
  return cells;
}

const hostnames = (table) => column(table, "Device");
export async function check({ page, demo, visit, settle, require, capture, step }) {
  const devices = (demo?.Devices ?? []).filter((device) => device.Hostname);
  const target = devices.find((device) => /-/.test(device.Hostname)) ?? devices[0];
  require(target, "the seed has no named device to search for");
  if (!target) return;

  step("case-insensitive part-of-hostname search");
  await visit("/devices");
  const table = page.getByRole("table", { name: /Enrolled devices/ });
  await table.waitFor({ state: "visible", timeout: 30_000 });
  const part = target.Hostname.split("-")[1] ?? target.Hostname;
  const query = part.toUpperCase();
  await page.getByLabel("Search devices", { exact: true }).fill(query);
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await settle();
  const found = await hostnames(table);
  const expected = devices
    .filter((device) => device.Hostname.toLowerCase().includes(part.toLowerCase()))
    .map((device) => device.Hostname);
  for (const name of expected)
    require(found.some((cell) => cell.includes(name)), `searching "${query}" did not find ${name}`);
  for (const cell of found)
    require(cell.toLowerCase().includes(part.toLowerCase()), `searching "${query}" listed ${cell}`);
  await capture("case-insensitive hostname search");
  await page.getByRole("button", { name: "Clear", exact: true }).click();
  await settle();

  step("server-side sort by last contact");
  const caption = await table.locator("caption").innerText();
  require(!/current page/i.test(caption), `the table still says "${caption}"`);
  const sortButton = page.getByRole("button", { name: "Sort all devices by Last contact" });
  for (const direction of ["ascending", "descending"]) {
    await sortButton.click();
    await settle();
    const header = page.locator("thead th", { has: sortButton });
    require((await header.getAttribute("aria-sort")) ===
      direction, `Last contact header is not ${direction} after clicking`);
    // Never-seen devices (pending enrollment) read "Not recorded": always last.
    const contacts = await column(table, "Last contact");
    const firstNever = contacts.findIndex((cell) => /not recorded|never/i.test(cell));
    if (firstNever >= 0)
      require(contacts
        .slice(firstNever)
        .every((cell) =>
          /not recorded|never/i.test(cell),
        ), `${direction}: a never-seen device is listed before devices with contact (${contacts.join(", ")})`);
    const note = page.getByText(/across all pages/);
    require(await note.isVisible(), `${direction}: no note that the sort spans all pages`);
    await capture(`sorted by last contact ${direction}`);
  }
  step("CSV export uses human values");
  const exportSummary = page.locator("summary", { hasText: /^Export devices$/ });
  if (await exportSummary.count()) await exportSummary.click();
  const download = page.waitForEvent("download", { timeout: 30_000 });
  await page.getByRole("button", { name: "Download", exact: true }).click();
  const file = await download;
  const content = await readFile(await file.path(), "utf8");
  const header = content.split("\n")[0];
  require(header.startsWith("Device ID,Hostname,Operating system"), `CSV header is "${header}"`);
  require(!/DEVICE_[A-Z_]+/.test(content), "CSV contains raw DEVICE_* enum values");
  require(!/[{}]/.test(content), "CSV contains JSON");
  const toast = page
    .locator("[data-sonner-toast]")
    .filter({ hasText: /Downloaded devices-page-1/ });
  await toast.waitFor({ state: "visible", timeout: 10_000 }).catch(() => {});
  require(await toast.isVisible(), "the console did not confirm the download");
  await capture("device export confirmation");
}
