// Owner pass 2, Profile editor: the draft leads and the version picker is a
// compact secondary control; "Start over" sits in the editor header; no
// "N of 64 settings" counter; a new setting starts as "Choose a setting type";
// one Advanced options switch and one View JSON for the whole editor; a trash
// icon removes a setting; encryption checks are two named choices each; types
// the server doesn't dispatch are disabled as not available yet. Never publishes.
export const task = {
  name: "Profile editor layout and setting types",
  screenId: "owner-pass2-profile-editor",
  route: "/profiles/$profileId",
  priority: "normal",
  acceptance:
    "The editor comes before any version picker and Start over is in its header; no settings counter; new settings start untyped; one Advanced options and one View JSON control however many settings; Remove is an icon button labelled with the setting; encryption checks offer Don't check / Required; Login and session policy and Package repository are disabled as not available yet; setting forms don't mention catalogs, digests or byte sizes.",
};

const timeout = 30_000;

export async function check({ page, demo, visit, require, capture, step }) {
  const main = page.getByRole("main");

  step("profile page order");
  await visit(`/profiles/${encodeURIComponent(demo.Routes.ProfileID)}`);
  const editor = main.locator("[data-profile-editor]");
  await editor.waitFor({ timeout });
  require((await main.getByText("Find a version", { exact: true }).count()) ===
    0, "a 'Find a version' card is still shown");
  const order = await main.evaluate((root) => {
    const editorNode = root.querySelector("[data-profile-editor]");
    const picker = root.querySelector("[data-profile-version-picker]");
    const pickerBox = picker?.getBoundingClientRect();
    return {
      pickerBeforeEditor:
        !!picker &&
        !!editorNode &&
        !!(picker.compareDocumentPosition(editorNode) & Node.DOCUMENT_POSITION_FOLLOWING) &&
        (pickerBox?.height ?? 0) > 80,
      pickerCollapsed: picker?.tagName === "DETAILS" && !picker.open,
    };
  });
  require(!order.pickerBeforeEditor, "an expanded version picker leads the draft");
  require(order.pickerCollapsed, "the version picker isn't a collapsed secondary control");
  const startOver = main.getByRole("button", { name: "Start over from this version" });
  require((await startOver.count()) === 1, "no 'Start over from this version' control");
  const headerAligned = await startOver.evaluate((button) => {
    const header = button.closest("[data-slot=card-header]");
    return !!header?.closest("[data-profile-editor]");
  });
  require(headerAligned, "'Start over from this version' isn't in the editor header");
  require((await main.getByText(/\b\d+ of \d+ settings\b/).count()) ===
    0, "the 'N of 64 settings' counter is still shown");
  await capture("profile editor leads");

  step("new setting");
  const settings = editor.locator("fieldset[data-setting-index]");
  const before = await settings.count();
  await editor.getByRole("button", { name: "Add setting", exact: true }).click();
  await settings.nth(before).waitFor({ timeout });
  await editor.getByRole("button", { name: "Add setting", exact: true }).click();
  await settings.nth(before + 1).waitFor({ timeout });
  const added = settings.nth(before);
  const type = added.getByRole("combobox", { name: "Setting type", exact: true });
  require((await type.innerText()).trim() ===
    "Choose a setting type", `a new setting starts as "${(await type.innerText()).trim()}"`);

  step("one advanced and JSON control");
  const advanced = editor.getByRole("checkbox", { name: "Advanced options" });
  require((await advanced.count()) === 1, "no single Advanced options switch");
  require((await editor.locator("summary", { hasText: /^Advanced options$/ }).count()) ===
    0, "settings still have their own Advanced options toggles");
  require((await editor.locator("summary", { hasText: /^View JSON$/ }).count()) ===
    1, "View JSON isn't one editor-level control");

  step("remove is an icon button");
  require((await editor.getByText(/^Remove setting \d+$/).count()) ===
    0, "a 'Remove setting N' text button is shown");
  const remove = added.getByRole("button", { name: new RegExp(`^Remove setting ${before + 1}`) });
  require((await remove.count()) === 1, "the new setting has no labelled remove button");
  require((await remove.innerText()).trim() === "", "the remove button shows text, not an icon");

  step("setting type availability");
  await type.click();
  for (const name of ["Login and session policy", "Package repository"]) {
    const option = page.getByRole("option", { name: new RegExp(`^${name}`) });
    await option.first().waitFor({ timeout });
    require((await option.first().getAttribute("aria-disabled")) === "true" &&
      /not available yet/i.test(
        await option.first().innerText(),
      ), `${name} is offered although the server doesn't apply it`);
  }
  const encryption = page.getByRole("option", { name: "Encryption compliance", exact: true });
  require((await encryption.getAttribute("aria-disabled")) !==
    "true", "Encryption compliance, a qualified type, is disabled");
  await capture("setting types");
  await encryption.click();

  step("encryption checks");
  const escrow = added.getByRole("group", { name: "Recovery key escrow" });
  await escrow.waitFor({ timeout });
  const choices = await escrow.getByRole("radio").count();
  require(choices ===
    2, `recovery key escrow offers ${choices} choices, not Don't check / Required`);
  require((await escrow.getByRole("radio", { name: /^Don't check/ }).isChecked()) &&
    (await escrow.getByRole("radio", { name: /^Required/ }).count()) ===
      1, "recovery key escrow isn't a Don't check / Required choice");
  require((await added.getByText(/Not managed/).count()) ===
    0, "the encryption setting still shows 'Not managed'");
  await capture("encryption checks");

  step("advanced shows every setting's options");
  await advanced.check();
  require((await editor.locator("[data-setting-advanced]").count()) ===
    (await settings.count()), "Advanced options doesn't apply to every setting");

  step("kernel setting ownership");
  // SYSCTL dispatches only as an approved takeover: no other choice is offered.
  const second = settings.nth(before + 1);
  await second.getByRole("combobox", { name: "Setting type", exact: true }).click();
  await page.getByRole("option", { name: "Kernel setting", exact: true }).click();
  const mode = second.getByRole("combobox", {
    name: "If the item already exists on the device",
    exact: true,
  });
  await mode.waitFor({ timeout });
  require(/^Take over the existing one/.test(
    (await mode.innerText()).trim(),
  ), `a kernel setting defaults to "${(await mode.innerText()).trim()}", which devices refuse`);
  require(await mode.isDisabled(), "a kernel setting offers ownership modes devices refuse");
  require((await second.locator("[data-setting-ownership-refused]").count()) ===
    0, "a freshly chosen kernel setting is marked as refused");
  await capture("kernel setting ownership");

  step("local user without numeric ID");
  await advanced.uncheck();
  await second.getByRole("combobox", { name: "Setting type", exact: true }).click();
  await page.getByRole("option", { name: "Local user", exact: true }).click();
  await second.getByText("Name", { exact: true }).first().waitFor({ timeout });
  require((await second.getByText(/^UID$/).count()) ===
    0, "a new local user asks for a numeric UID outside Advanced options");

  step("setting forms in admin terms");
  await advanced.check();
  await second.getByRole("combobox", { name: "Setting type", exact: true }).click();
  await page.getByRole("option", { name: "Package", exact: true }).click();
  await second.getByText("Package name", { exact: true }).first().waitFor({ timeout });
  const wording = await second.innerText();
  for (const phrase of [/selection catalog/i, /\bSha256\b/, /Size bytes/, /full apt\//])
    require(!phrase.test(wording), `a package setting still says ${phrase}`);
  await capture("setting form wording");
}
