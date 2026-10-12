// Owner pass 2 findings 40 and 42: the create page states its purpose once,
// and after Publish the outcome replaces the form where the editor starts
// instead of a greyed form with "Profile published" below the fold. Publishes
// one new, never-assigned single-service profile.
export const task = {
  name: "Profile publish outcome",
  screenId: "owner-pass2-profile-publish",
  route: "/profiles/new",
  priority: "normal",
  acceptance:
    "/profiles/new has one 'Create profile' heading and no repeated sentence; after Publish the form is gone, 'Profile published' is on screen and focused, and Create another profile is offered.",
};

const timeout = 30_000;

export async function check({ page, visit, require, capture, step }) {
  const main = page.getByRole("main");

  step("create page");
  await visit("/profiles/new");
  const editor = main.locator("[data-profile-editor]");
  await editor.waitFor({ timeout });
  require((await main.getByText("Create profile", { exact: true }).count()) ===
    1, "'Create profile' is repeated on the create page");
  const sentences = (await main.innerText())
    .split(/(?<=\.)\s+/)
    .map((sentence) => sentence.trim())
    .filter((sentence) => sentence.length > 20);
  const repeated = sentences.find((sentence, index) => sentences.indexOf(sentence) !== index);
  require(!repeated, `the create page repeats "${repeated}"`);

  step("publish");
  await main.getByRole("textbox", { name: "Name", exact: true }).fill("ui-review publish outcome");
  const setting = editor.locator("fieldset[data-setting-index]").first();
  await setting.getByRole("combobox", { name: "Setting type", exact: true }).click();
  await page.getByRole("option", { name: "Systemd service", exact: true }).click();
  await setting.getByRole("textbox", { name: "Unit name", exact: true }).fill("ui-review.service");
  await main
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("ui-review: check the publish outcome; never assigned");
  await main.getByRole("button", { name: "Publish profile", exact: true }).click();

  step("outcome");
  const outcome = main.locator("[data-profile-publish-outcome]");
  await outcome.waitFor({ timeout });
  require((await editor.locator("form, fieldset").count()) ===
    0, "the published draft still shows its form");
  const placement = await outcome.evaluate((node) => ({
    top: node.getBoundingClientRect().top,
    bottom: node.getBoundingClientRect().bottom,
    focused: document.activeElement === node,
  }));
  require(placement.top >= 0 &&
    placement.bottom <=
      (page.viewportSize()?.height ?? 900), "the publish outcome isn't on screen after publishing");
  require(placement.focused, "focus didn't move to the publish outcome");
  require((await main.getByRole("button", { name: "Create another profile" }).count()) ===
    1, "no way to start another profile after publishing");
  await capture("publish outcome");
}
