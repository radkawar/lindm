// SPDX-License-Identifier: Apache-2.0

// Owner tasks (pass 2, Groups): one device multi-select with removable chips,
// a plain rule builder with a live match count, no group IDs and no
// "Once sent, edits are locked". Read-only: dialogs are closed without saving.
export const task = {
  name: "Groups plain editors",
  screenId: "",
  route: "/groups",
  priority: "normal",
  acceptance:
    "Static group devices are one multi-select with chips (hostname and OS) removable by keyboard, with no 'Member devices N' or 'Remove selection'; the dynamic group builder reads as sentences (All/Any of these conditions, OS is ..., Last seen within N days, condition groups) without developer terms; a live server count of matching devices appears and changes with a rule; no 'Group ID' and no 'Once sent, edits are locked'.",
};

const DEVELOPER_TERMS = [
  "node index",
  "Negated node index",
  "Depth",
  "Expression",
  "All children",
  "Any children",
  "Inventory filter",
];
const MATCHED = /(\d+) devices? match|No devices match/;

async function matching(dialog) {
  const status = dialog.getByRole("status", { name: "Matching devices" });
  await status.filter({ hasText: MATCHED }).waitFor({ timeout: 30_000 });
  return (await status.innerText()).trim();
}

async function choose(page, combobox, option) {
  await combobox.click();
  await page.getByRole("option", { name: option, exact: true }).click();
}

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  step("open groups");
  await visit("/groups");
  await main.getByRole("heading", { name: "Device groups", exact: true }).waitFor();
  const text = await main.innerText();
  // Collapsed Details content is not in innerText; count matching elements instead.
  require((await main.getByText("Group ID", { exact: true }).count()) ===
    0, "Groups page shows 'Group ID' (also inside Details)");
  require(!/Once sent, edits are locked/.test(
    text,
  ), "Groups page says 'Once sent, edits are locked'");

  step("edit a static group");
  const edit = main
    .getByRole("list", { name: "Device groups" })
    .getByRole("button", { name: /^Edit / })
    .first();
  await edit.click();
  const staticDialog = page.getByRole("dialog");
  await staticDialog.waitFor();
  await settle();
  const dialogText = await staticDialog.innerText();
  require(!/Member devices \d/.test(dialogText), "Static group still lists 'Member devices N'");
  require(!/Remove selection/.test(
    dialogText,
  ), "Static group still has 'Remove selection' buttons");
  require(!dialogText.includes("Group ID"), "Static group dialog shows 'Group ID'");
  require(!/Once sent, edits are locked/.test(
    dialogText,
  ), "Static group dialog says 'Once sent, edits are locked'");
  const chips = staticDialog.getByRole("list", { name: "Selected devices" }).getByRole("listitem");
  const before = await chips.count();
  require(before > 0, "Static group shows no selected device chips");
  if (before > 0) {
    const first = (await chips.first().innerText()).trim();
    require(/\S+ · \S+/.test(first), `Chip does not show hostname and OS: '${first}'`);
    const remove = chips.first().getByRole("button", { name: /^Remove / });
    require((await remove.count()) === 1, "Chip has no 'Remove <hostname>' button");
    await capture("groups-static-chips");
    await remove.focus();
    await page.keyboard.press("Backspace");
    require((await chips.count()) === before - 1, "Backspace on a chip did not remove it");
  }
  require((await staticDialog.getByRole("button", { name: /^Add a device/ }).count()) ===
    1, "Static group does not have exactly one 'Add a device' picker");
  await page.keyboard.press("Escape");
  await staticDialog.waitFor({ state: "hidden" });

  step("open the dynamic group builder");
  await main.getByRole("button", { name: "New dynamic group", exact: true }).first().click();
  const dialog = page.getByRole("dialog", { name: "New dynamic group" });
  await dialog.waitFor();
  await settle();
  const builder = await dialog.innerText();
  for (const term of DEVELOPER_TERMS)
    require(!builder.includes(term), `Dynamic group builder shows developer term '${term}'`);
  require(!/Once sent, edits are locked/.test(
    builder,
  ), "Create form says 'Once sent, edits are locked'");
  const match = dialog.getByRole("combobox", { name: "Include devices that match" });
  require((await match.count()) === 1, "No 'Include devices that match' all/any choice");
  require((await match.innerText()).includes(
    "All of these conditions",
  ), "Top-level match does not read 'All of these conditions'");
  require((await dialog
    .getByRole("button", { name: "Add condition group", exact: true })
    .count()) === 1, "No way to add a nested condition group");
  require((await dialog.getByRole("status", { name: "Matching devices" }).innerText()).includes(
    "Complete the conditions",
  ), "Incomplete conditions do not say the count is waiting for them");

  step("OS is Ubuntu: live count");
  await dialog.getByRole("button", { name: /^Condition 1 operating system/ }).click();
  await page.getByRole("combobox", { name: /Search condition 1 operating system/i }).fill("ubuntu");
  await page
    .getByRole("option", { name: /^Ubuntu/ })
    .first()
    .click();
  const comparison = dialog.getByRole("combobox", { name: "Condition 1 comparison" });
  require((await comparison.innerText()).trim() ===
    "is", "Condition 1 does not read 'Operating system is …'");
  const included = await matching(dialog);
  require(/ubuntu-ws-01/.test(included), `OS is ubuntu does not name ubuntu-ws-01: '${included}'`);
  await capture("groups-dynamic-os-is-ubuntu");

  step("OS is not ubuntu: count changes");
  await choose(page, comparison, "is not");
  await dialog
    .getByRole("status", { name: "Matching devices" })
    .filter({ hasNotText: included.split("\n")[0] })
    .filter({ hasText: MATCHED })
    .waitFor({ timeout: 30_000 });
  const excluded = await matching(dialog);
  require(excluded !== included, "Match count did not change with the rule");
  require(!/ubuntu-ws-01/.test(excluded), "OS is not ubuntu still names ubuntu-ws-01");

  step("last seen within N days and a condition group");
  await dialog.getByRole("button", { name: "Add condition", exact: true }).click();
  await choose(
    page,
    dialog.getByRole("combobox", { name: "Condition 2", exact: true }),
    "Last seen",
  );
  require((
    await dialog.getByRole("combobox", { name: "Condition 2 comparison" }).innerText()
  ).trim() === "within", "Last seen condition does not read 'within'");
  require((await dialog.getByRole("spinbutton", { name: "Condition 2 days" }).inputValue()) ===
    "7", "Last seen condition has no default number of days");
  await dialog.getByRole("button", { name: "Add condition group", exact: true }).click();
  require((await dialog.getByRole("combobox", { name: "Group 3 matches" }).count()) ===
    1, "Condition group has no All/Any choice");
  // The new group's first condition is still blank, so no count is claimed.
  await dialog
    .getByRole("status", { name: "Matching devices" })
    .filter({ hasText: "Complete the conditions" })
    .waitFor({ timeout: 30_000 });
  await capture("groups-dynamic-builder");
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden" });
}
