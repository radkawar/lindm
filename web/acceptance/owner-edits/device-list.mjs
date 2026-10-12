// Owner task: /devices shows encryption, pending updates and open findings for
// every row, a relative "Last inventory" without sequence numbers, the paging
// explanation in a focusable pager tooltip, and no Custom attributes accordion
// (managed in Settings instead). Read-only: toggles a column off and back on and
// opens/closes a tooltip; nothing is created or changed on the server.
export const task = {
  name: "Device list posture columns",
  screenId: "b8a865903d16786380d0b956",
  route: "/devices",
  priority: "normal",
  acceptance:
    "Device list shows Encryption (Encrypted / Not encrypted / Unknown), Updates (n pending / Up to date / Unknown) and Findings (critical/high counts or Not checked) for every row; no '#1' text; no paragraph under the table; no Custom attributes accordion on /devices.",
};

const ENCRYPTION = new Set(["Encrypted", "Not encrypted", "Unknown"]);
const UPDATES = /^(\d+ pending|Up to date|Unknown)$/;
const FINDINGS = /^(\d+ critical · \d+ high( · partial)?|Not checked)$/;
const POSTURE = ["Encryption", "Updates", "Findings", "Last inventory"];

async function headerTexts(table) {
  return (await table.locator("thead th").allInnerTexts()).map((text) => text.trim());
}

export async function check({ page, demo, visit, settle, require, capture, step }) {
  step("open device list");
  await visit("/devices");
  const table = page.getByRole("table", { name: /Enrolled devices/ });
  await table.waitFor({ state: "visible", timeout: 30_000 });

  step("posture column headers");
  const headers = await headerTexts(table);
  for (const name of POSTURE) {
    require(headers.includes(name), `column header "${name}" missing (${headers.join(", ")})`);
  }
  require(!headers.includes("Inventory"), "the old 'Inventory' column header is still shown");

  step("posture cells on every row");
  const rows = table.locator("tbody tr");
  const rowCount = await rows.count();
  require(rowCount > 0, "the device list shows no rows");
  const tableText = await table.innerText();
  for (const device of demo?.Devices ?? []) {
    if (device.Hostname?.trim()) {
      require(tableText.includes(device.Hostname), `${device.Hostname} is not listed`);
    }
  }
  const column = Object.fromEntries(POSTURE.map((name) => [name, headers.indexOf(name)]));
  for (let index = 0; index < rowCount; index += 1) {
    const cells = (await rows.nth(index).locator("td").allInnerTexts()).map((text) => text.trim());
    const name = cells[headers.indexOf("Device")] || `row ${index + 1}`;
    const encryption = cells[column.Encryption];
    const updates = cells[column.Updates];
    const findings = cells[column.Findings];
    require(ENCRYPTION.has(encryption), `${name}: Encryption cell reads "${encryption}"`);
    require(UPDATES.test(updates ?? ""), `${name}: Updates cell reads "${updates}"`);
    require(FINDINGS.test(findings ?? ""), `${name}: Findings cell reads "${findings}"`);
  }
  // The route device carries an escrowed LUKS recovery key in the seed: its root
  // is reported encrypted, so the column reflects stored data, not a blanket Unknown.
  const routeID = demo?.Routes?.DeviceID;
  if (routeID) {
    const routeRow = rows.filter({ has: page.locator(`a[href*="${routeID}"]`) });
    require((await routeRow.count()) === 1, "route device row not found in the list");
    if ((await routeRow.count()) === 1) {
      const cells = (await routeRow.locator("td").allInnerTexts()).map((text) => text.trim());
      require(cells[column.Encryption] ===
        "Encrypted", `route device (escrowed LUKS key) shows Encryption "${cells[column.Encryption]}"`);
    }
  }

  step("no sequence numbers");
  require(!/#\d/.test(tableText), "the device table still shows a '#N' sequence number");
  await capture("device list posture columns");

  step("columns control removes and restores a posture column");
  const columns = page.locator("summary", { hasText: /^Columns$/ });
  await columns.click();
  const findingsToggle = page.getByRole("checkbox", { name: "Findings", exact: true });
  await findingsToggle.waitFor({ state: "visible", timeout: 10_000 });
  require(await findingsToggle.isChecked(), "Findings is not visible by default");
  await findingsToggle.uncheck();
  require(!(await headerTexts(table)).includes(
    "Findings",
  ), "unchecking Findings in Columns kept the column");
  await findingsToggle.check();
  require((await headerTexts(table)).includes("Findings"), "re-checking Findings kept it hidden");
  await columns.click();

  step("nothing below the table but disclosures");
  const below = await table.evaluate((node) => {
    let card = node;
    while (card.parentElement && card.parentElement.tagName !== "SECTION") {
      card = card.parentElement;
    }
    const found = [];
    for (let sibling = card.nextElementSibling; sibling; sibling = sibling.nextElementSibling) {
      const paragraphs = sibling.matches("p") ? [sibling] : [...sibling.querySelectorAll("p")];
      for (const paragraph of paragraphs) {
        if (paragraph.checkVisibility()) found.push(paragraph.innerText.trim().slice(0, 80));
      }
    }
    return found;
  });
  require(below.length === 0, `paragraphs remain under the table: ${below.join(" | ")}`);

  step("paging explanation is a keyboard-reachable pager tooltip");
  const help = page.getByRole("button", { name: "About paging this search" });
  require(await help.isVisible(), "no paging help control on the pager");
  if (await help.isVisible()) {
    await page.getByRole("button", { name: "New search / latest devices" }).focus();
    await page.keyboard.press("Tab");
    require(await help.evaluate(
      (node) => node === document.activeElement,
    ), "the paging help control is not reached by keyboard from the pager");
    const tip = page
      .locator('[data-slot="tooltip-content"]')
      .filter({ hasText: "page through this search" });
    await tip.waitFor({ state: "visible", timeout: 5_000 }).catch(() => {});
    require(await tip.isVisible(), "focusing the paging help did not explain paging");
    if (await tip.isVisible()) await capture("pager paging tooltip");
    await page.keyboard.press("Escape");
    await settle();
  }

  step("custom attributes moved to Settings");
  // Management (the definitions card or its accordion) must be gone; the
  // attribute-value filter under More filters stays, labelled as a filter.
  const leftovers = [];
  if ((await page.locator("main summary", { hasText: "Custom attributes" }).count()) > 0) {
    leftovers.push("accordion");
  }
  if ((await page.getByText("Custom attributes", { exact: true }).count()) > 0) {
    leftovers.push("'Custom attributes' title");
  }
  if ((await page.getByRole("button", { name: "Add attribute" }).count()) > 0) {
    leftovers.push("'Add attribute' button");
  }
  require(leftovers.length === 0, `Custom attributes management still on /devices: ${leftovers}`);
  await visit("/settings");
  const attributes = page.getByText("Custom attributes", { exact: true });
  await attributes.waitFor({ state: "visible", timeout: 30_000 }).catch(() => {});
  require(await attributes.isVisible(), "Settings does not show Custom attributes");
  require(await page
    .getByRole("button", { name: "Add attribute" })
    .isVisible(), "Settings does not offer Custom attributes management (Add attribute)");
  await capture("settings custom attributes");
}
