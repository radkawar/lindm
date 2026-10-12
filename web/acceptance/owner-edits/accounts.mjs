// Owner task: /accounts is a read view. Each account is a row (role, device
// access, plain sign-in state) and changes start only from its Edit dialog; the
// seeded approver reads as Admin, not a second owner; local sign-in hides the
// directory recheck settings; times use the console's one date format.
// Read-only: opens one Edit dialog and dismisses it unsaved.
export const task = {
  name: "Accounts read view with Edit",
  screenId: "",
  route: "/accounts",
  priority: "high",
  acceptance:
    "No role dropdown, Enabled/break-glass checkbox or Save is live on the page until Edit opens a dialog; the seeded 'approver' row reads Admin and 'owner' Owner; sign-in state reads 'Password and passkey set' / 'Waiting for enrollment' / 'Disabled' with a sentence, never 'Set up'; local sign-in shows no access-recheck rows; no numeric dates or GMT offsets; Reset credentials asks in the dialog (no native confirm) and Keep credentials backs out.",
};

const timeout = 30_000;
const STATES = ["Password and passkey set", "Waiting for enrollment", "Disabled"];

async function accountRows(main) {
  return main.locator("table tbody tr").evaluateAll((rows) =>
    rows.map((row) => {
      const cells = [...row.querySelectorAll("td")].map((cell) => cell.innerText.trim());
      return {
        username: (cells[0] ?? "").replace(/ \(you\)$/, ""),
        role: cells[1] ?? "",
        state: cells[3] ?? "",
      };
    }),
  );
}

export async function check({ page, visit, require, capture, step }) {
  const main = page.getByRole("main");
  step("open accounts");
  await visit("/accounts");
  await main.getByRole("heading", { name: "Accounts", exact: true }).waitFor({ timeout });
  // Wait for whichever list renders, so a per-account editor fails the check below by name.
  await main
    .locator("table tbody tr")
    .or(main.getByRole("combobox", { name: "Role" }))
    .first()
    .waitFor({ timeout });

  step("read view has no live editors");
  require((await main.getByRole("combobox", { name: "Role" }).count()) ===
    0, "A role dropdown is live on the account list");
  require((await main.getByRole("checkbox").count()) ===
    0, "Enabled/break-glass checkboxes are live on the account list");
  require((await main.getByRole("button", { name: /^Save/ }).count()) ===
    0, "A Save button is live on the account list");

  const rows = await accountRows(main);
  const byName = new Map(rows.map((row) => [row.username, row]));
  for (const row of rows)
    require((await main
      .getByRole("button", { name: `Edit ${row.username}`, exact: true })
      .count()) === 1, `Account ${row.username} has no Edit button`);

  step("seeded roles");
  require(byName.has("approver") &&
    byName.has("owner"), `Seeded accounts missing: ${rows.map((row) => row.username).join(", ")}`);
  if (!byName.has("approver") || !byName.has("owner")) return;
  require(byName.get("approver").role ===
    "Admin", `Seeded approver reads '${byName.get("approver").role}', want Admin (least role that decides every approval)`);
  require(byName.get("owner").role === "Owner", `Seeded owner reads '${byName.get("owner").role}'`);

  step("plain sign-in state");
  require(!rows.some((row) =>
    /^Set up$/m.test(row.state),
  ), "An account still shows the bare 'Set up' chip");
  for (const row of rows) {
    const [label, description] = row.state.split("\n").map((line) => line.trim());
    require(STATES.includes(
      label,
    ), `Account ${row.username} sign-in state '${label}' is not a plain state`);
    require(Boolean(
      description,
    ), `Account ${row.username} sign-in state has no explaining sentence`);
  }
  require(rows.some((row) =>
    row.state.startsWith("Password and passkey set"),
  ), "No enrolled account reads 'Password and passkey set'");

  step("local sign-in source");
  const source = main.getByRole("region", { name: "Sign-in source", exact: true });
  await source.waitFor({ timeout });
  const sourceText = await source.innerText();
  if (sourceText.includes("Local accounts on this server"))
    require(!/recheck/i.test(sourceText) &&
      !/Not applicable/.test(sourceText), "Local sign-in shows access-recheck rows");

  step("one date format");
  const text = await main.innerText();
  require(!/\b\d{1,2}\/\d{1,2}\/\d{4}\b/.test(text), "A numeric date (e.g. 10/12/2026) is shown");
  require(!/GMT[+-]\d/.test(text), "A GMT offset is shown instead of a zone name");
  await capture("accounts-read-view");

  step("edit happens in a dialog");
  await main.getByRole("button", { name: "Edit approver", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Edit approver", exact: true });
  await dialog.waitFor({ timeout });
  require((await dialog.getByRole("combobox", { name: "Role", exact: true }).count()) ===
    1, "Edit dialog has no role choice");
  require((await dialog.getByRole("checkbox", { name: "Enabled", exact: true }).count()) ===
    1, "Edit dialog has no Enabled choice");
  require((await dialog.getByRole("button", { name: "Save account", exact: true }).count()) ===
    1, "Edit dialog has no Save");
  await capture("accounts-edit-dialog");

  step("reset credentials confirms in the dialog, not the browser");
  // A native confirm() is dismissed (cancelled) here, so nothing is ever reset.
  let nativeDialog = "";
  const onDialog = (native) => {
    nativeDialog = native.type();
    void native.dismiss();
  };
  page.on("dialog", onDialog);
  await dialog.getByRole("button", { name: /^Reset credentials/ }).click();
  const confirm = dialog.getByRole("region", {
    name: "Reset approver's credentials?",
    exact: true,
  });
  await confirm
    .or(dialog.getByRole("button", { name: "Save account", exact: true }))
    .first()
    .waitFor({ timeout });
  page.off("dialog", onDialog);
  require(nativeDialog === "", `Reset credentials opened a native browser ${nativeDialog}`);
  if ((await confirm.count()) === 1) {
    require((await confirm.innerText()).includes(
      "signed out",
    ), "Reset confirmation does not say the account is signed out");
    await capture("accounts-reset-confirmation");
    await confirm.getByRole("button", { name: "Keep credentials", exact: true }).click();
    await confirm.waitFor({ state: "hidden", timeout });
  } else {
    require(false, "Reset credentials shows no in-app confirmation");
  }
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden", timeout });
}
