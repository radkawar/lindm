// SPDX-License-Identifier: Apache-2.0

// Owner task (pass 2, Integrations): a destination's CA certificate was shown in
// full as an editable PEM. The Edit dialog shows subject, expiry and SHA-256
// fingerprint; PEM input appears only after Replace certificate. Read-only.
export const task = {
  name: "Integrations CA certificate summary",
  screenId: "",
  route: "/integrations",
  priority: "normal",
  acceptance:
    "Editing SOC webhook shows its pinned CA as subject, expiry and SHA-256 fingerprint with no PEM text box; a PEM box appears only after Replace certificate and goes away with Keep current certificate.",
};

export async function check({ page, visit, require, capture, step }) {
  const main = page.getByRole("main");
  step("open edit dialog");
  await visit("/integrations");
  const row = main.getByRole("row").filter({ hasText: "SOC webhook" }).first();
  await row.waitFor({ timeout: 30_000 });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Edit SOC webhook" });
  await dialog.waitFor({ timeout: 30_000 });
  const pinned = dialog.getByRole("list", { name: "Pinned CA certificate" });
  require((await pinned.count()) === 1, "pinned CA is not summarized");
  if ((await pinned.count()) === 1) {
    const text = await pinned.innerText();
    require(/SHA-256 ([0-9A-F]{2}:){31}[0-9A-F]{2}/.test(text), "no SHA-256 fingerprint shown");
    require(/Expires|Expired/.test(text), "no certificate expiry shown");
  }
  require(!(await dialog.innerText()).includes(
    "BEGIN CERTIFICATE-----\n",
  ), "the PEM is shown in the dialog");
  require((await dialog.locator("textarea").count()) ===
    0, "a PEM text box is shown before Replace certificate");
  await capture("integrations-ca-summary");

  step("replace certificate");
  await dialog.getByRole("button", { name: "Replace certificate", exact: true }).click();
  require((await dialog.locator("textarea").count()) ===
    1, "Replace certificate does not offer a PEM text box");
  await capture("integrations-ca-replace");
  await dialog.getByRole("button", { name: "Keep current certificate", exact: true }).click();
  require((await dialog.locator("textarea").count()) === 0, "PEM text box stays after Keep");
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden", timeout: 30_000 });
}
