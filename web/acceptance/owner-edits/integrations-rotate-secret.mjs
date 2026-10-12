// Owner task (pass 2, Integrations): "Rotate signing secret" was disabled with
// "Old secret stops working: Not recorded". Rotate is available for a webhook
// with a secret and states the overlap consequence before confirming.
// Read-only: generates a secret in the dialog but never submits.
export const task = {
  name: "Integrations rotate signing secret",
  screenId: "",
  route: "/integrations",
  priority: "high",
  acceptance:
    "SOC webhook has an enabled Rotate secret action; its dialog says 'The old secret keeps working for 1 hour; update the receiver before <time>' (and 'stops working immediately' for no overlap); after Generate, Rotate secret is enabled; 'Not recorded' never appears.",
};

export async function check({ page, visit, require, capture, step }) {
  const main = page.getByRole("main");
  step("open rotate");
  await visit("/integrations");
  const row = main.getByRole("row").filter({ hasText: "SOC webhook" }).first();
  await row.waitFor({ timeout: 30_000 });
  const open = row.getByRole("button", { name: "Rotate secret", exact: true });
  require((await open.count()) === 1, "no Rotate secret action on SOC webhook");
  require(await open.isEnabled(), "Rotate secret is disabled");
  await open.click();
  const dialog = page.getByRole("dialog", { name: "Rotate signing secret for SOC webhook" });
  await dialog.waitFor({ timeout: 30_000 });
  const text = await dialog.innerText();
  require(/The old secret keeps working for 1 hour; update the receiver before \S.+\./.test(
    text,
  ), "the overlap consequence is not stated");
  require(!text.includes("Not recorded"), "the dialog says 'Not recorded'");

  step("generate");
  await dialog.getByRole("button", { name: "Generate", exact: true }).click();
  const submit = dialog.getByRole("button", { name: "Rotate secret", exact: true });
  require(await submit.isEnabled(), "Rotate secret is disabled after generating a secret");
  await capture("integrations-rotate");

  step("no overlap");
  await dialog.getByRole("combobox", { name: "Keep the old secret working for" }).click();
  await page.getByRole("option", { name: "Stop immediately", exact: true }).click();
  require((await dialog.innerText()).includes(
    "The old secret stops working immediately",
  ), "no consequence for stopping the old secret immediately");
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden", timeout: 30_000 });
}
