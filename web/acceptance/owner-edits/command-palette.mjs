// Owner task: the command palette finds actions, not only pages and devices, and
// never describes its own implementation. Read-only: it opens the wipe review and
// the one-time code dialog without choosing a target or creating a code.
export const task = {
  name: "Command palette actions",
  screenId: "",
  route: "/dashboard",
  priority: "normal",
  acceptance:
    "Typing 'wipe' lists 'Wipe device…'; choosing it and a device opens that device's wipe review; 'enrollment code' lists 'Create enrollment code', which opens the one-time code dialog; 'Create secret' opens the Create secret dialog; an unmatched search names what was searched; no 'first 200' text.",
};

const NOTHING = "zz-no-such-command";

// Opens the palette and types into its search box; focus may still be returning
// from a closed dialog when the shortcut fires, so the box is targeted directly.
async function search(page, text) {
  await page.keyboard.press("Control+k");
  const dialog = page.getByRole("dialog", { name: "Search console" });
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
