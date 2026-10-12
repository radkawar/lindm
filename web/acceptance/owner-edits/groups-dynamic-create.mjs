// Owner tasks (pass 2, Groups items 33-34): creating a dynamic group needs no
// blank technical field, refuses mistakes in words, and leaves a read view with
// the member count and names plus Edit. State-moving: creates one group.
export const task = {
  name: "Dynamic group create and read view",
  screenId: "",
  route: "/groups",
  priority: "normal",
  acceptance:
    "Creating 'OS is Ubuntu' needs only a name, a condition and a reason (no depth, maximum age, JSON or ISO timestamp fields); mistakes read as words, never a field path; the saved group is a read view (condition sentence, 'N devices match: hostnames', Edit) with no open form.",
};

const RAW_VALIDATION = /group\.|expression\.|nodes\[|\[uint32|\[string\.|depth/i;

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  const name = `Ubuntu workstations ${Date.now().toString(36)}`;
  step("open the builder");
  await visit("/groups");
  await main.getByRole("button", { name: "New dynamic group", exact: true }).first().click();
  const dialog = page.getByRole("dialog", { name: "New dynamic group" });
  await dialog.waitFor();
  await settle();
  require((await dialog.locator("textarea").count()) ===
    1, "Builder shows a JSON textarea besides the reason");
  require((await dialog
    .getByLabel(/Depth|Maximum inventory age|Last seen from|Labels|Attributes/)
    .count()) === 0, "Builder exposes depth, maximum age, date or JSON fields");
  require((await dialog.getByPlaceholder(/\d{4}-\d{2}-\d{2}T/).count()) ===
    0, "Builder asks for an ISO timestamp");

  step("mistakes in words");
  await dialog.getByRole("button", { name: "Create group", exact: true }).click();
  const alert = dialog.getByRole("alert");
  await alert.waitFor();
  const message = (await alert.innerText()).trim();
  require(message === "Enter a group name.", `Missing name reads '${message}'`);
  require(!RAW_VALIDATION.test(message), `Validation shows a field path: '${message}'`);

  step("create OS is Ubuntu");
  await dialog.getByLabel("Group name").fill(name);
  await dialog.getByRole("button", { name: /^Condition 1 operating system/ }).click();
  await page.getByRole("combobox", { name: /Search condition 1 operating system/i }).fill("ubuntu");
  await page
    .getByRole("option", { name: /^Ubuntu/ })
    .first()
    .click();
  // An out-of-range number of days reads as words, never a proto field path.
  await dialog.getByRole("button", { name: "Add condition", exact: true }).click();
  await dialog.getByRole("combobox", { name: "Condition 2", exact: true }).click();
  await page.getByRole("option", { name: "Last seen", exact: true }).click();
  const daysField = dialog.getByRole("spinbutton", { name: "Condition 2 days" });
  await daysField.fill("400");
  require((await daysField.getAttribute("aria-invalid")) === "true" &&
    (await dialog
      .getByText("Enter a whole number of days from 1 to 366.", { exact: true })
      .count()) === 1, "Days out of range is not named under its field");
  await dialog.getByRole("button", { name: "Create group", exact: true }).click();
  await alert.filter({ hasNotText: message }).waitFor({ timeout: 10_000 });
  const days = (await alert.innerText()).trim();
  require(days ===
    "Condition 2: enter a whole number of days from 1 to 366.", `Days out of range reads '${days}'`);
  require(!RAW_VALIDATION.test(days), `Validation shows a field path: '${days}'`);
  await dialog.getByRole("button", { name: "Remove condition 2", exact: true }).click();
  await dialog.getByRole("button", { name: "Create group", exact: true }).click();
  await alert.filter({ hasNotText: days }).waitFor({ timeout: 10_000 });
  const reason = (await alert.innerText()).trim();
  require(reason === "Enter a reason for this change.", `Missing reason reads '${reason}'`);
  await dialog
    .getByLabel("Reason for this change")
    .fill("Owner pass: Ubuntu workstation targeting");
  await dialog.getByRole("button", { name: "Create group", exact: true }).click();
  await dialog.waitFor({ state: "hidden", timeout: 30_000 });
  await settle();

  step("read view with members");
  const row = main
    .getByRole("list", { name: "Dynamic groups" })
    .getByRole("listitem")
    .filter({ has: page.getByRole("heading", { name, exact: true }) });
  await row.waitFor();
  const members = row.getByRole("status", { name: "Matching devices" });
  await members.filter({ hasText: /\d+ devices? match/ }).waitFor({ timeout: 30_000 });
  const text = await row.innerText();
  require(text.includes(
    "Operating system is Ubuntu",
  ), "Saved group does not read 'Operating system is Ubuntu'");
  require(/ubuntu-ws-01/.test(text), "Saved group does not name its member ubuntu-ws-01");
  require((await row.getByRole("button", { name: `Edit ${name}` }).count()) ===
    1, "Saved group has no Edit");
  require((await row.locator("form, textarea, input").count()) ===
    0, "Saved group is an open form");
  require(!/Once sent, edits are locked|Group ID/.test(
    text,
  ), "Saved group shows locked-edit copy or its ID");
  await capture("groups-dynamic-read-view");
}
