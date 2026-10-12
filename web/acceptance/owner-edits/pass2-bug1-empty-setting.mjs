// Owner pass 2, bug 1: a draft with an empty firewall zone (no interface, source
// network or rule) published as a new version. Adding one to the seeded profile
// and pressing Publish must mark that setting, not just the page, and must leave
// the published version unchanged. The refusal happens before any request, so
// nothing is created; the check never publishes.
export const task = {
  name: "Empty setting refused at publish",
  screenId: "owner-pass2-bug1-empty-setting",
  route: "/profiles/$profileId",
  priority: "high",
  acceptance:
    "Adding a Firewall zone with no interface, source network or rule and pressing Publish shows the refusal on that setting, names what to add, and publishes no new version.",
};

const timeout = 30_000;
const EMPTY_ZONE = /Add an interface, source network or rule\./;

async function publishedVersion(main) {
  const version = main.locator("[data-profile-version]");
  await version.waitFor({ timeout });
  return (await version.innerText()).match(/Version (\d+)/)?.[1] ?? "";
}

export async function check({ page, demo, visit, require, capture, step }) {
  const profileId = demo.Routes.ProfileID;
  if (!profileId) throw new Error("demo route profile is missing");
  const main = page.getByRole("main");

  step("open profile");
  await visit(`/profiles/${encodeURIComponent(profileId)}`);
  const before = await publishedVersion(main);
  const settings = main.locator("[data-profile-editor] fieldset[data-setting-index]");
  await settings.first().waitFor({ timeout });
  const count = await settings.count();

  step("add empty firewall zone");
  await main.getByRole("button", { name: "Add setting", exact: true }).click();
  const setting = main.locator(`fieldset[data-setting-index="${count}"]`);
  await setting.waitFor({ timeout });
  await setting.getByRole("combobox", { name: "Setting type", exact: true }).click();
  await page.getByRole("option", { name: "Firewall zone", exact: true }).click();
  await main
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("ui-review: an empty firewall zone must not publish");

  step("publish");
  await main.getByRole("button", { name: "Publish changes", exact: true }).click();
  const errors = setting.locator("[data-setting-errors]");
  await errors.waitFor({ timeout });
  require(EMPTY_ZONE.test(
    await errors.innerText(),
  ), "the setting's error doesn't name what to add");
  const describedBy = (await setting.getAttribute("aria-describedby")) ?? "";
  require(describedBy !== "" &&
    describedBy ===
      (await errors.getAttribute("id")), "the refused setting isn't described by its error");
  const summary = main.locator("#profile-draft-errors");
  require((await summary.innerText()).includes(
    `Setting ${count + 1} needs changes before publishing.`,
  ), "the page summary doesn't name the refused setting");
  require((await main.getByText("Profile published", { exact: true }).count()) ===
    0, "an empty firewall zone was published");
  require((await setting
    .getByRole("combobox", { name: "Setting type", exact: true })
    .isEnabled()) &&
    (await main
      .getByRole("button", { name: "Publish changes", exact: true })
      .isVisible()), "the draft isn't editable after the refusal");
  await capture("empty firewall zone refused");

  step("version unchanged");
  await visit(`/profiles/${encodeURIComponent(profileId)}`);
  const after = await publishedVersion(main);
  require(after === before, `published version changed from ${before} to ${after}`);
}
