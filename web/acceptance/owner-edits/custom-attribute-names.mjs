// Owner task (pass 2 items 35 and 10): a custom attribute has a display name
// and a key derived from it, one human type name in the form and the table,
// and field errors in words before anything is sent. State-moving: creates
// (or re-saves) the "Cost center" attribute on the demo.
export const task = {
  name: "Custom attribute display name and key",
  screenId: "",
  route: "/settings",
  priority: "normal",
  acceptance:
    "Typing 'Cost center' as Name fills Key 'cost-center'; an invalid key and repeated list values are refused before submit with sentences, never validator text like '[string.pattern]' or 'definition.key'; after saving, the table shows 'Cost center', its key and 'List of values' (never 'enum').",
};

const RAW = /\[(string|repeated)\.|definition\.(key|enum_values)|does not match regex/;

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  step("open add attribute");
  await visit("/settings");
  await main.getByText("Custom attributes", { exact: true }).waitFor({ timeout: 30_000 });
  await settle();
  await main.getByRole("button", { name: "Add attribute", exact: true }).click();
  const name = main.getByRole("textbox", { name: "Name", exact: true });
  const key = main.getByRole("textbox", { name: "Key", exact: true });
  await name.waitFor({ timeout: 10_000 });
  require((await key.count()) === 1, "The form has no separate Key field");

  step("key derives from the name");
  await name.fill("Cost center");
  require((await key.inputValue()) ===
    "cost-center", `Key derived from 'Cost center' is '${await key.inputValue()}'`);

  step("worded errors before submit");
  const type = main.getByRole("combobox", { name: "Type", exact: true });
  await type.click();
  await page.getByRole("option", { name: "List of values", exact: true }).click();
  const values = main.getByRole("textbox", { name: "Allowed values (one per line)", exact: true });
  await values.fill("R&D\nSales\nR&D");
  await main.getByRole("textbox", { name: "Reason", exact: true }).fill("Owner check: cost center");
  await key.fill("Cost Center");
  let sent = 0;
  const count = (request) => {
    if (request.url().endsWith("/SetAttributeDefinition")) sent += 1;
  };
  page.on("request", count);
  const save = main.getByRole("button", { name: "Save attribute", exact: true });
  await save.click();
  await main.getByText(/Start with a lowercase letter/).waitFor({ timeout: 10_000 });
  await main.getByText(/Each value can appear once/).waitFor({ timeout: 10_000 });
  const text = await main.innerText();
  require(!RAW.test(text), "Validator text reached the admin");
  require(sent === 0, "The invalid attribute was sent to the server");
  await capture("custom-attribute-worded-errors");

  step("save and show human names");
  await key.fill("cost-center");
  await values.fill("R&D\nSales");
  await save.click();
  await main.getByText("Attribute saved.", { exact: true }).waitFor({ timeout: 30_000 });
  page.off("request", count);
  require(sent === 1, `Expected one save request, saw ${sent}`);
  await main.getByRole("button", { name: "Close", exact: true }).click();
  const row = main.getByRole("row").filter({ hasText: "Cost center" });
  await row.first().waitFor({ timeout: 30_000 });
  const rowText = await row.first().innerText();
  require(rowText.includes("cost-center"), "The table row does not show the key under the name");
  require(rowText.includes("List of values"), `Type is not 'List of values': ${rowText}`);
  const table = await main.getByRole("table").last().innerText();
  require(!/\benum\b/.test(table), "The table still names a type 'enum'");
  await capture("custom-attribute-saved");
}
