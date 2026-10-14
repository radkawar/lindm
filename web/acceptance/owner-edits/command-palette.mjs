// SPDX-License-Identifier: Apache-2.0

// Owner task: the command palette finds actions, not only pages and devices, and
// never describes its own implementation. Read-only: it opens the wipe review and
// the one-time code dialog without choosing a target or creating a code.
export const task = {
  name: "Command palette actions",
  screenId: "",
  route: "/dashboard",
  priority: "normal",
  acceptance:
    "Keyboard search and page-navigation shortcuts work beside retained closed enrollment dialogs but never stack over or change navigation behind an open task dialog. Typing 'wipe' lists 'Wipe device…'; choosing it and a device opens that device's wipe review; 'enrollment code' lists 'Create enrollment code', which opens the one-time code dialog; 'Create secret' opens the Create secret dialog; an unmatched search names what was searched; no 'first 200' text.",
};

const NOTHING = "zz-no-such-command";

// A chosen command navigates before its old popup finishes closing. Wait for
// that popup and asynchronous focus restoration before reopening; retained
// closing options are not the next search's live choices.
async function search(page, text) {
  await page
    .getByRole("dialog", { name: "Search console" })
    .waitFor({ state: "hidden", timeout: 10_000 });
  await page.waitForFunction(
    () => !document.activeElement?.matches("input, textarea, select, [contenteditable]"),
    null,
    { timeout: 10_000 },
  );
  await page.keyboard.press("Control+k");
  const dialog = page
    .getByRole("dialog", { name: "Search console" })
    .and(page.locator("[data-open]"));
  const box = dialog.getByRole("combobox");
  await box.waitFor({ timeout: 10_000 });
  await box.pressSequentially(text);
  return dialog;
}

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const deviceId = demo.Routes.DeviceID;
  const main = page.getByRole("main");

  step("read the route device's hostname");
  await visit(`/devices/${deviceId}`);
  const heading = main.getByRole("heading", { level: 1 }).first();
  await heading.waitFor({ timeout: 30_000 });
  const hostname = (await heading.innerText()).trim();
  require(hostname !== "", "Route device has no hostname heading");

  step("search beside retained closed enrollment dialogs");
  await visit("/enrollment");
  await page.getByRole("button", { name: "Create one-time code", exact: true }).click();
  const retained = page.getByRole("dialog", { name: "Enroll one device now", exact: true });
  await retained.waitFor({ state: "visible", timeout: 30_000 });
  await page.keyboard.press("Escape");
  await retained.waitFor({ state: "hidden", timeout: 10_000 });
  require((await page.locator('[role="dialog"][data-closed]').count()) >
    0, "The closed enrollment-dialog shortcut case was not exercised");
  const pageToggle = page.locator('header button[aria-label="Toggle page navigation"]');
  for (const shortcut of ["Control+b", "Meta+b"]) {
    const before = await pageToggle.getAttribute("aria-expanded");
    await pageToggle.focus();
    await page.keyboard.press(shortcut);
    require((await pageToggle.getAttribute("aria-expanded")) !==
      before, `${shortcut} does not toggle navigation beside retained closed dialogs`);
    await page.keyboard.press(shortcut);
    require((await pageToggle.getAttribute("aria-expanded")) ===
      before, `${shortcut} does not restore navigation beside retained closed dialogs`);
  }

  step("search for wipe");
  let dialog = await search(page, "wipe");
  const wipe = dialog.getByRole("option", { name: "Wipe device…" });
  await wipe.waitFor({ timeout: 10_000 });
  require(!(await dialog.innerText()).includes("first 200"), "Palette shows 'first 200' text");
  await capture("wipe-search");

  step("choose the device to wipe");
  await wipe.click();
  await dialog.getByText("Choose the device to wipe", { exact: true }).waitFor({ timeout: 10_000 });
  await dialog.getByRole("combobox").pressSequentially(hostname);
  const escaped = hostname.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const device = dialog.getByRole("option", { name: new RegExp(`^${escaped}( |$)`) });
  await device.first().waitFor({ timeout: 15_000 });
  await capture("wipe-choose-device");
  await device.first().click();
  await page.waitForURL(new RegExp(`/devices/${deviceId}/actions/new/cryptoErase`), {
    timeout: 15_000,
  });
  await settle();
  await main
    .getByRole("heading", { name: "Wipe encrypted storage", exact: true })
    .waitFor({ timeout: 30_000 });

  step("search for an enrollment code");
  dialog = await search(page, "enrollment code");
  const code = dialog.getByRole("option", { name: "Create enrollment code" });
  await code.waitFor({ timeout: 10_000 });
  await code.click();
  await page.waitForURL(/\/enrollment/, { timeout: 15_000 });
  const issue = page.getByRole("dialog", { name: "Enroll one device now" });
  await issue.waitFor({ timeout: 30_000 });
  await issue.locator('[data-slot="dialog-close"]').focus();
  await page.keyboard.press("Control+k");
  require((await page.getByRole("dialog", { name: "Search console" }).count()) ===
    0, "Keyboard search stacked a second modal over an open enrollment dialog");
  const expanded = await pageToggle.getAttribute("aria-expanded");
  for (const shortcut of ["Control+b", "Meta+b"]) {
    await page.keyboard.press(shortcut);
    require((await pageToggle.getAttribute("aria-expanded")) ===
      expanded, `${shortcut} changed navigation behind an open enrollment dialog`);
  }
  await capture("enrollment-code-dialog");
  await page.keyboard.press("Escape");
  await issue.waitFor({ state: "hidden", timeout: 10_000 });

  step("create a secret from the palette");
  dialog = await search(page, "create secret");
  const secret = dialog.getByRole("option", { name: "Create secret" });
  await secret.waitFor({ timeout: 10_000 });
  await secret.click();
  await page.waitForURL(/\/secrets/, { timeout: 15_000 });
  const create = page.getByRole("dialog", { name: "Create secret" });
  await create.waitFor({ timeout: 30_000 });
  await page.keyboard.press("Escape");
  await create.waitFor({ state: "hidden", timeout: 10_000 });

  step("search for nothing");
  dialog = await search(page, NOTHING);
  await dialog
    .getByText(`No pages, actions or devices match “${NOTHING}”.`, { exact: true })
    .waitFor({ timeout: 10_000 });
  require(!(await dialog.innerText()).includes("first 200"), "Palette shows 'first 200' text");
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden", timeout: 10_000 });
}
