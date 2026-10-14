// SPDX-License-Identifier: Apache-2.0

// Owner task: values that already exist are chosen, not typed. The device's
// Packages filter offers the package managers its latest list reports; the
// Local admin account is chosen from the device's reported accounts with root
// shown as ineligible (or, when none were reported, says so) and the
// eligibility rule appears before the field. Read-only: pickers are opened and
// closed without saving.
export const task = {
  name: "Recorded values are choices",
  screenId: "typeahead-recorded-choices",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "On ubuntu-ws-01, Package manager is a choice listing dpkg (no free-text box) and Local account is a choice of reported accounts with root disabled, the root/agent-settings rule shown before the field.",
};

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const { DeviceID } = demo.Routes;
  const main = page.getByRole("main");

  step("open the Inventory tab");
  await visit(`/devices/${DeviceID}`);
  await main.getByRole("tab", { name: "Inventory", exact: true }).click();
  const manager = main.getByRole("button", { name: /^Package manager/ });
  await manager.first().waitFor({ timeout: 30_000 });
  await settle();

  step("package manager is a choice of reported managers");
  require((await main.getByRole("textbox", { name: "Package manager" }).count()) ===
    0, "Package manager is still a free-text box");
  require((await manager.count()) === 1, "Expected one Package manager picker");
  await manager.click();
  const managers = page.getByRole("option");
  await managers.filter({ hasText: "dpkg" }).first().waitFor({ timeout: 15_000 });
  await capture("recorded-choices-package-manager");
  await page.keyboard.press("Escape");

  step("open the Local admin tab");
  await main.getByRole("tab", { name: "Local admin", exact: true }).click();
  const panel = main.locator('[role="tabpanel"]:not([hidden])');
  const account = panel.getByRole("button", { name: /^Local account/ });
  await account.waitFor({ timeout: 30_000 });
  await settle();

  step("eligibility rule precedes the account field");
  const rule = panel.getByText(/other than root/);
  require((await rule.count()) === 1, "The root rule is not stated on the policy form");
  const [ruleBox, accountBox] = [await rule.boundingBox(), await account.boundingBox()];
  require(ruleBox !== null &&
    accountBox !== null &&
    ruleBox.y < accountBox.y, "The root/agent-settings rule appears after the account field");
  require((await panel.getByRole("textbox", { name: "Local account" }).count()) ===
    0, "Local account is still a free-text box");

  step("accounts come from the device's inventory");
  await account.click();
  await page
    .locator('[cmdk-input][aria-label="Search local account"]')
    .waitFor({ timeout: 15_000 });
  const root = page.getByRole("option", { name: /^root\b/ });
  if (await root.count()) {
    require((await root.first().getAttribute("aria-disabled")) ===
      "true", "root is offered as a selectable account");
  } else {
    require((await page
      .getByText("The device hasn't reported its local accounts.", { exact: false })
      .count()) === 1, "Neither reported accounts nor an explanation of their absence is shown");
  }
  await capture("recorded-choices-local-account");
  await page.keyboard.press("Escape");
}
