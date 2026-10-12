// Owner task (pass 2, Integrations): the Signing secret field sat below the
// reason and Create button. Every destination form ends with reason, then submit.
// Read-only: opens the Add and Edit dialogs without submitting.
export const task = {
  name: "Integrations reason and submit last",
  screenId: "",
  route: "/integrations",
  priority: "normal",
  acceptance:
    "In Add destination the Signing secret field comes before Reason, and Reason comes before Create destination; Edit, Rotate and Delete dialogs also end with Reason then their submit button.",
};

// Document order of the reason field relative to every other control in the dialog.
function order(dialog) {
  return dialog.evaluate((root) => {
    const controls = [
      ...root.querySelectorAll("input, textarea, button, [role='combobox']"),
    ].filter((element) => element.getBoundingClientRect().height > 0);
    const labels = controls.map(
      (element) =>
        element.labels?.[0]?.innerText.trim() ||
        element.getAttribute("aria-label") ||
        element.innerText.trim(),
    );
    return labels;
  });
}

async function requireReasonLast(dialog, submit, require, name) {
  const labels = await order(dialog);
  const reason = labels.findIndex((label) => label.startsWith("Reason"));
  const button = labels.lastIndexOf(submit);
  require(reason >= 0, `${name}: no Reason field`);
  require(button === reason + 1, `${name}: ${submit} does not directly follow Reason`);
  // The dialog's own Close control follows in the portal; nothing else may.
  const trailing = labels.slice(button + 1).filter((label) => label !== "Close");
  require(trailing.length === 0, `${name}: controls after ${submit}: ${trailing.join(", ")}`);
  return labels;
}

export async function check({ page, visit, require, capture, step }) {
  const main = page.getByRole("main");
  step("add destination");
  await visit("/integrations");
  await main.getByRole("button", { name: "Add destination", exact: true }).first().click();
  const add = page.getByRole("dialog", { name: "Add destination" });
  await add.waitFor({ timeout: 30_000 });
  const labels = await requireReasonLast(add, "Create destination", require, "Add destination");
  const secret = labels.findIndex((label) => label.startsWith("Signing secret"));
  const reason = labels.findIndex((label) => label.startsWith("Reason"));
  require(secret >= 0 && secret < reason, "Signing secret is not before Reason");
  await capture("integrations-add-order");
  await page.keyboard.press("Escape");

  const row = main.getByRole("row").filter({ hasText: "SOC webhook" }).first();
  for (const [button, title, submit] of [
    ["Edit", "Edit SOC webhook", "Save changes"],
    ["Rotate secret", "Rotate signing secret for SOC webhook", "Rotate secret"],
    ["Delete SOC webhook", "Delete SOC webhook", "Delete destination"],
  ]) {
    step(`${title} order`);
    await row.getByRole("button", { name: button, exact: true }).click();
    const dialog = page.getByRole("dialog", { name: title });
    await dialog.waitFor({ timeout: 30_000 });
    await requireReasonLast(dialog, submit, require, title);
    await page.keyboard.press("Escape");
    await dialog.waitFor({ state: "hidden", timeout: 30_000 });
  }
}
