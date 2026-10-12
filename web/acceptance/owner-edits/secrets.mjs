// Owner task: /secrets lists first, creates in a dialog with no preselected
// purpose, offers Rotate/Delete/Where it's used on each row, and names the
// blast radius before deletion. Read-only: dialogs open and close, nothing is
// created, rotated, revealed or deleted.
export const task = {
  name: "Secrets list, row actions and delete blast radius",
  screenId: "",
  route: "/secrets",
  priority: "normal",
  acceptance:
    "The secret list precedes any create form and has no page-size control for one page; Create secret opens a dialog whose Purpose reads 'Choose a purpose' with submit disabled and explained; each row offers Where it's used, Rotate and Delete; Where it's used lists the Office network profile for the seeded Office Wi-Fi key; Delete names that profile and refuses while it is in use; the secret page lists the same use.",
};

const SECRET = "Office Wi-Fi";
const PROFILE = "Office network";

export async function check({ page, demo, visit, require, capture, step }) {
  const timeout = 30_000;
  const main = page.getByRole("main");

  step("open the secret list");
  await visit("/secrets");
  await main.getByRole("heading", { name: "Secrets", exact: true }).waitFor({ timeout });
  const row = main.getByRole("row").filter({ hasText: SECRET });
  await row.first().waitFor({ timeout });
  require((await main.getByLabel("Display name").count()) ===
    0, "A create form is shown on the page before Create secret is chosen");
  require((await main.getByText("Rows per page").count()) ===
    0, "A page-size control is shown for a single page of secrets");
  await capture("secrets-list");

  step("open Create secret");
  await main.getByRole("button", { name: "Create secret", exact: true }).click();
  const create = page.getByRole("dialog", { name: "Create secret" });
  await create.waitFor({ timeout });
  const purpose = create.getByRole("combobox", { name: "Purpose" });
  require((await purpose.innerText()).trim() ===
    "Choose a purpose", `Purpose defaults to '${(await purpose.innerText()).trim()}', not 'Choose a purpose'`);
  const submit = create.getByRole("button", { name: "Create secret", exact: true });
  require(await submit.isDisabled(), "Create secret is enabled before a purpose is chosen");
  const describedBy = (await submit.getAttribute("aria-describedby")) ?? "";
  const explained = describedBy
    ? ((await create.locator(`[id="${describedBy}"]`).textContent()) ?? "")
    : "";
  require(/purpose/i.test(explained), "Disabled Create secret does not state its prerequisite");
  await capture("secrets-create-dialog");
  await page.keyboard.press("Escape");
  await create.waitFor({ state: "hidden", timeout });

  step("row actions");
  const actions = row.first().getByRole("button", { name: `Actions for ${SECRET}` });
  require((await actions.count()) === 1, "The secret row has no actions menu");
  await actions.click();
  await page.getByRole("menu").waitFor({ timeout });
  for (const name of ["Where it's used", "Rotate…", "Delete…"])
    require((await page.getByRole("menuitem", { name }).count()) ===
      1, `Row actions lack '${name}'`);
  await capture("secrets-row-actions");

  step("where it's used");
  await page.getByRole("menuitem", { name: "Where it's used" }).click();
  const uses = page.getByRole("dialog", { name: `Where ${SECRET} is used` });
  await uses.waitFor({ timeout });
  await uses.getByRole("link", { name: PROFILE }).waitFor({ timeout });
  await capture("secrets-where-used");
  await page.keyboard.press("Escape");
  await uses.waitFor({ state: "hidden", timeout });

  step("delete names the uses and refuses while in use");
  await actions.click();
  await page.getByRole("menuitem", { name: "Delete…" }).click();
  const remove = page.getByRole("dialog", { name: `Delete ${SECRET}` });
  await remove.waitFor({ timeout });
  await remove.getByRole("link", { name: PROFILE }).waitFor({ timeout });
  require((await remove.getByText("In use, so it can't be deleted").count()) ===
    1, "Delete does not explain that the secret is in use");
  require(await remove
    .getByRole("button", { name: "Delete secret", exact: true })
    .isDisabled(), "Delete is enabled while the secret is in use");
  await capture("secrets-delete-in-use");
  await page.keyboard.press("Escape");
  await remove.waitFor({ state: "hidden", timeout });

  step("uses on the secret page");
  await visit(`/secrets/${demo.Routes.SecretID}`);
  await main.getByText("Where it's used", { exact: true }).waitFor({ timeout });
  await main.getByRole("link", { name: PROFILE }).first().waitFor({ timeout });
  await capture("secret-detail");
}
