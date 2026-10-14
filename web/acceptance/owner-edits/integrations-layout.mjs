// SPDX-License-Identifier: Apache-2.0

// Owner task (pass 2, Integrations): the page was ~9,000 px tall. Destinations,
// schedules and reports are rows, create/edit open dialogs and delivery history
// is collapsed into per-destination counts. Read-only: opens and closes a dialog.
export const task = {
  name: "Integrations compact layout",
  screenId: "",
  route: "/integrations",
  priority: "normal",
  acceptance:
    "/integrations is at most 3,000 px tall on desktop (4,500 px below 1024 px wide); destinations and schedules are table rows; Add destination opens a dialog; no 'Delivered' row is listed by default.",
};

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  step("open integrations");
  await visit("/integrations");
  await main.getByRole("table", { name: "Destinations" }).waitFor({ timeout: 30_000 });
  await main.getByRole("table", { name: "Report schedules" }).waitFor({ timeout: 30_000 });
  await settle();
  const { height, width } = await page.evaluate(() => ({
    height: document.scrollingElement.scrollHeight,
    width: window.innerWidth,
  }));
  const bound = width >= 1024 ? 3000 : 4500;
  require(height <=
    bound, `/integrations is ${height} px tall at ${width} px wide (bound ${bound})`);
  require((await main.getByRole("textbox").count()) ===
    0, "an always-open form is on the page instead of in a dialog");
  require((await main.getByText("Delivered", { exact: true }).count()) ===
    0, "individual delivered rows are listed by default");
  await capture("integrations-page");

  step("add destination opens a dialog");
  await main.getByRole("button", { name: "Add destination", exact: true }).first().click();
  const dialog = page.getByRole("dialog", { name: "Add destination" });
  await dialog.waitFor({ timeout: 30_000 });
  await capture("integrations-add-destination");
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden", timeout: 30_000 });
}
