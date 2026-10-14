// SPDX-License-Identifier: Apache-2.0

// Owner task (ui-pass-2 item 51): Control/Command+K while typing in a form field
// does not open the command palette over the form. Read-only: types nothing.
export const task = {
  name: "Palette shortcut ignores typing",
  screenId: "",
  route: "/devices",
  priority: "normal",
  acceptance:
    "With focus in a text field, Control+K does not open the command palette; with focus outside a field it still opens.",
};

export async function check({ page, visit, require, step }) {
  const main = page.getByRole("main");
  const palette = page.getByRole("dialog", { name: "Search console" });

  step("press the shortcut in a text field");
  await visit("/devices");
  // The device list's hostname filter (a search field) or, failing that, any text field.
  const field = main.getByRole("searchbox").or(main.getByRole("textbox")).first();
  await field.waitFor({ timeout: 30_000 });
  await field.focus();
  await page.keyboard.press("Control+k");
  await page.waitForTimeout(500);
  require((await palette.count()) === 0, "Control+K in a text field opened the command palette");
  if (await palette.count()) {
    await page.keyboard.press("Escape");
    await palette.waitFor({ state: "hidden", timeout: 10_000 });
  }

  step("press the shortcut outside a field");
  await field.blur();
  await main.getByRole("heading", { level: 1 }).first().click();
  await page.keyboard.press("Control+k");
  await palette.waitFor({ timeout: 10_000 });
  await page.keyboard.press("Escape");
  await palette.waitFor({ state: "hidden", timeout: 10_000 });
}
