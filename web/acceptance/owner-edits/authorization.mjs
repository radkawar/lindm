// Owner task: /authorization never shows a built-in approval rule as optional.
// Revoke and wipe (destructive actions) always need a second administrator, so
// the editor shows them checked and locked as "Always required"; permission
// names say what they allow; an empty custom-role list says so; a disabled Save
// names its prerequisite.
// Read-only: opens the editor and cancels it unsaved.
export const task = {
  name: "Authorization built-in approvals locked",
  screenId: "",
  route: "/authorization",
  priority: "high",
  acceptance:
    "Read view and editor list Revoke devices and Run destructive actions as 'Always required' (checked, disabled in the editor); no 'Manage execution trust' wording; the editor's empty Custom roles says 'No custom roles'; Save is disabled with a visible 'Confirm the review above to save.'; a role name 'Patch operator' is explained as invalid before saving; editing after the review says the review was cleared.",
};

const timeout = 30_000;
const BUILT_IN = ["Revoke devices", "Run destructive actions"];

export async function check({ page, visit, require, capture, step }) {
  const main = page.getByRole("main");
  step("read view");
  await visit("/authorization");
  await main.getByRole("heading", { name: "Authorization", exact: true }).waitFor({ timeout });
  const approval = main.getByRole("region", { name: "Independent approval", exact: true });
  await approval.waitFor({ timeout });
  const approvalText = await approval.innerText();
  const always = approvalText.match(/Always required\s+([^\n]*)/)?.[1] ?? "";
  for (const label of BUILT_IN)
    require(always.includes(
      label,
    ), `Read view does not list '${label}' as always required (got '${always}')`);
  require(!(await main.innerText()).includes(
    "Manage execution trust",
  ), "Read view uses 'Manage execution trust'");
  require((await main.getByRole("button", { name: /^Refresh/ }).count()) ===
    1, "Authorization has more than one Refresh");
  await capture("authorization-read-view");

  step("editor");
  await main.getByRole("button", { name: "Edit access policy", exact: true }).click();
  const roles = main.getByRole("region", { name: "Edit custom roles", exact: true });
  await roles.waitFor({ timeout });
  if ((await roles.getByRole("textbox", { name: "Role name" }).count()) === 0)
    require((await roles.getByText(/^No custom roles\./).count()) ===
      1, "Empty Custom roles in the editor has no text");
  for (const label of BUILT_IN) {
    const box = main.getByRole("checkbox", { name: `${label} · Always required`, exact: true });
    if ((await box.count()) !== 1) {
      require(false, `Editor does not show '${label}' as always required`);
      continue;
    }
    require(await box.isChecked(), `Built-in approval '${label}' is unticked`);
    require(await box.isDisabled(), `Built-in approval '${label}' can be unticked`);
  }
  // Custom roles grant the same operation by the same name, so read the
  // approval requirement in its own group.
  require((await main
    .getByRole("group", { name: "Require independent approval", exact: true })
    .getByRole("checkbox", {
      name: "Change which signing keys devices trust for commands",
      exact: true,
    })
    .count()) === 1, "Execution trust approval is not described in plain words");
  require(!(await main.innerText()).includes(
    "Manage execution trust",
  ), "Editor uses 'Manage execution trust'");
  const save = main.getByRole("button", { name: "Save access policy", exact: true });
  require(await save.isDisabled(), "Save is enabled before the review is confirmed");
  const hintId = await save.getAttribute("aria-describedby");
  const hint = hintId ? page.locator(`[id="${hintId}"]`) : null;
  require(Boolean(hint) &&
    (await hint.isVisible()) &&
    (await hint.innerText()).includes(
      "Confirm the review",
    ), "Disabled Save does not state its prerequisite");
  await capture("authorization-editor");

  step("role name rule in words before saving");
  await roles.getByRole("button", { name: "Add custom role", exact: true }).click();
  const name = roles.getByRole("textbox", { name: "Role name", exact: true }).last();
  await name.fill("Patch operator");
  const nameHelp = await name.evaluate((input) =>
    (input.getAttribute("aria-describedby") ?? "")
      .split(/\s+/)
      .map((id) => document.getElementById(id)?.textContent ?? "")
      .join(" "),
  );
  require(/can't be used/.test(nameHelp) &&
    /lowercase/i.test(
      nameHelp,
    ), `Invalid role name 'Patch operator' is not explained before saving (got '${nameHelp}')`);
  require((await name.getAttribute("aria-invalid")) ===
    "true", "Invalid role name is not marked invalid");

  step("an edit after review says the review was cleared");
  const reviewed = main.getByRole("checkbox", {
    name: "I reviewed the complete access policy and sign-out consequences.",
    exact: true,
  });
  await reviewed.check();
  await name.fill("patch-operator");
  require(!(await reviewed.isChecked()) &&
    (await main.getByText(/review was cleared/).count()) ===
      1, "Editing after the review unticked it silently");
  await capture("authorization-review-cleared");
  await main.getByRole("button", { name: "Cancel editing", exact: true }).click();
  await main.getByRole("button", { name: "Edit access policy", exact: true }).waitFor({ timeout });
}
