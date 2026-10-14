// SPDX-License-Identifier: Apache-2.0

// Owner task (pass 2 findings 48): an http:// address and a 5-character secret
// gave no visible error; a failing destination showed a raw reason code and no
// health. Each field explains its rule before submit, and every destination
// shows a health state in words. Read-only: the invalid form is never sent.
export const task = {
  name: "Integrations destination validation and health",
  screenId: "",
  route: "/integrations",
  priority: "high",
  acceptance:
    "Submitting Add destination with http://, a 5-character secret and no reason shows field errors naming https://, '32 to 64 characters' and the reason, and creates nothing; each destination row has a Health state in words; no raw reason code (snake_case) is visible in Health or the failed deliveries list.",
};

const RAW_CODE = /\b[a-z]+(?:_[a-z0-9]+)+\b/;

export async function check({ page, visit, require, capture, step }) {
  const main = page.getByRole("main");
  step("health column");
  await visit("/integrations");
  const table = main.getByRole("table", { name: "Destinations" });
  await table.waitFor({ timeout: 30_000 });
  const headers = (await table.getByRole("columnheader").allInnerTexts()).map((t) => t.trim());
  const column = headers.indexOf("Health");
  require(column >= 0, "destinations have no Health column");
  const rows = await table.locator("tbody tr").all();
  for (const row of column >= 0 ? rows : []) {
    const health = (await row.getByRole("cell").nth(column).innerText()).trim();
    require(health !== "", "a destination has an empty Health cell");
    require(!RAW_CODE.test(health), `Health shows a raw code: ${health}`);
  }
  const failures = main.getByRole("table", { name: "Failed deliveries" });
  if ((await failures.count()) === 1) {
    for (const row of await failures.locator("tbody tr").all()) {
      const cell = (await row.getByRole("cell").nth(1).innerText()).trim();
      require(!RAW_CODE.test(cell), `failed delivery shows a raw code: ${cell}`);
    }
  }
  const before = rows.length;

  step("invalid destination");
  await main.getByRole("button", { name: "Add destination", exact: true }).first().click();
  const dialog = page.getByRole("dialog", { name: "Add destination" });
  await dialog.waitFor({ timeout: 30_000 });
  await dialog.getByLabel("Name", { exact: true }).fill("Owner check receiver");
  await dialog.getByLabel("Address", { exact: true }).fill("http://receiver.example/events");
  await dialog.getByLabel("Signing secret", { exact: true }).fill("abcde");
  await dialog.getByRole("button", { name: "Create destination", exact: true }).click();
  const text = await dialog.innerText();
  require(/Use an https:\/\/ address/.test(text), "no error for the http:// address");
  require(/Use 32 to 64 characters\. This secret has 5\./.test(
    text,
  ), "no error for the short secret");
  require(/Enter a reason that contains visible text/.test(
    text,
  ), "no error for the missing reason");
  require((await dialog.locator("[aria-invalid='true']").count()) >=
    3, "invalid fields are not marked invalid");
  await capture("integrations-add-invalid");
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden", timeout: 30_000 });
  require((await table.locator("tbody tr").count()) ===
    before, "an invalid destination was created");
}
