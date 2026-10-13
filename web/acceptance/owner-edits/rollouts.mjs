// Owner task (pass 2, items 25-32, 50, bug 8): /rollouts has one "Roll out"
// flow. Rollouts carry real names and live device results, controls are
// secondary buttons with their own confirmation, and New rollout is a dialog
// whose stages, target picker and one-line impact summary meet the owner's
// edits. Read-only: it opens dialogs and reviews impact but never rolls out,
// pauses or advances anything.
export const task = {
  name: "Rollouts one roll-out flow",
  screenId: "2031ff7e60ccbf0eb971b2a4",
  route: "/rollouts",
  priority: "high",
  acceptance:
    "No 'not proof of device execution' disclaimer or 'Saving records this assignment only'; no rollout is titled by its stage list; pausing is a secondary button with its own dialog; New rollout opens a dialog whose Target picker lists no type names, whose Profile picker leaves the sidebar groups alone, whose final stage stays at 100%, and whose impact summary is one line that never calls an excluded device 'Settings would change'.",
};

const timeout = 30_000;
const TYPE_NAMES = ["Device group", "Dynamic group", "One device"];
// A title made only of stage names, e.g. "pilot, fleet" or "Stage-1".
const STAGE_LIST = /^[A-Za-z0-9_.-]+(, [A-Za-z0-9_.-]+)*$/;
const SUMMARY =
  /^(At least )?\d+ devices? will change( · \d+ unchanged)?( · \d+ not targeted)?( · \d+ unknown)?$/;

// Expanded state of every sidebar group toggle, in order.
function navGroups(page) {
  return page
    .locator('[data-sidebar="group-label"][aria-expanded], [data-slot="sidebar-group-label"]')
    .evaluateAll((nodes) => nodes.map((node) => node.getAttribute("aria-expanded")));
}

// Choose the first named option of a SearchPicker whose label is `label`.
async function chooseFirst(page, container, label) {
  await container.getByRole("button", { name: new RegExp(`^${label} `) }).click();
  const options = page.getByRole("option").filter({ hasNotText: "No selection" });
  await options.first().waitFor({ timeout });
  const names = (await options.allInnerTexts()).map((text) => text.split("\n")[0].trim());
  await options.first().click();
  return names;
}

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  step("open rollouts");
  await visit("/rollouts");
  await main.getByRole("heading", { name: "Rollouts", exact: true }).waitFor({ timeout });
  await main
    .locator("article")
    .first()
    .or(main.getByText("No rollouts yet", { exact: true }))
    .waitFor({ timeout });
  await settle();

  step("no disclaimers");
  const text = (await main.textContent()) ?? "";
  require(!/not proof of device execution/i.test(
    text,
  ), "The saved-counts disclaimer is still shown");
  require(!/Saving records this assignment only/i.test(
    text,
  ), "'Saving records this assignment only' is still shown");

  step("rollout names are not stage lists");
  const titles = await main.locator("article h3").allInnerTexts();
  require(titles.length > 0, "No rollout is listed on /rollouts");
  for (const title of titles)
    require(!STAGE_LIST.test(
      title.trim(),
    ), `Rollout "${title.trim()}" is titled by its stage names`);

  step("controls are secondary buttons");
  require((await main.getByRole("combobox", { name: "Rollout decision" }).count()) ===
    0, "The always-expanded rollout decision form is still shown");
  require((await main.getByRole("textbox", { name: /^Reason/ }).count()) ===
    0, "A reason field is shown before choosing a rollout action");
  // An active rollout offers Pause, or Resume when its guardrails paused it.
  const control = main.getByRole("button", { name: /^(Pause|Resume)$/ }).first();
  require((await control.count()) === 1, "No active rollout offers Pause or Resume");
  if (await control.count()) {
    const action = (await control.innerText()).trim();
    await control.click();
    const confirm = page.getByRole("dialog", { name: new RegExp(`^${action}: `) });
    await confirm.waitFor({ timeout });
    require(await confirm
      .getByRole("textbox", { name: "Reason", exact: true })
      .isVisible(), `${action} doesn't ask for a reason`);
    await confirm.getByRole("button", { name: "Cancel", exact: true }).click();
    await confirm.waitFor({ state: "detached", timeout });
  }
  await capture("rollouts list");

  step("new rollout is a dialog");
  await main.getByRole("button", { name: "New rollout", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "New rollout", exact: true });
  await dialog.waitFor({ timeout });
  require(await dialog.isVisible(), "New rollout does not open a dialog");

  step("profile picker leaves the sidebar alone");
  const before = await navGroups(page);
  await dialog.getByRole("button", { name: /^Profile / }).click();
  await page.getByRole("combobox", { name: "Search profile", exact: true }).waitFor({ timeout });
  const during = await navGroups(page);
  await page.keyboard.press("Escape");
  require(before.length > 0 &&
    JSON.stringify(before) ===
      JSON.stringify(
        during,
      ), `Opening the Profile picker changed the sidebar groups (${before} → ${during})`);
  const profiles = await chooseFirst(page, dialog, "Profile");
  require(profiles.length > 0, "The Profile picker offers no profile");

  step("target picker lists names only");
  require((await dialog.getByRole("combobox", { name: "Target type" }).count()) ===
    0, "Target type is still a dropdown");
  const targets = await chooseFirst(page, dialog, "Target");
  const listed = targets.filter((name) => TYPE_NAMES.includes(name));
  require(listed.length === 0, `The Target picker lists type names: ${listed.join(", ")}`);

  step("final stage stays at 100%");
  await dialog.getByRole("radio", { name: "In stages", exact: true }).check();
  const shares = dialog.getByRole("spinbutton", { name: /^Stage \d+ share of devices/ });
  const final = shares.last();
  require((await shares.count()) >= 2, "In stages does not offer a stage before the final one");
  require(!(await final.isEditable()), "The final stage's share can be edited below 100%");
  require((await final.inputValue()) === "100", "The final stage does not cover 100%");
  require((await dialog.getByRole("textbox", { name: "Stage 1 name" }).inputValue()) !==
    "Stage-1", "The first stage is still named 'Stage-1'");
  await capture("new rollout stages");

  step("one-line impact summary");
  await dialog.getByRole("button", { name: "Review impact", exact: true }).click();
  const summary = dialog.locator("[data-impact-summary]");
  await summary.or(dialog.getByRole("alert")).first().waitFor({ timeout });
  require((await summary.count()) === 1, "Review impact shows no impact summary");
  if (await summary.count()) {
    const line = (await summary.innerText()).trim();
    require(SUMMARY.test(
      line,
    ), `Impact summary "${line}" is not "N devices will change · N unchanged · N not targeted · N unknown"`);
    const lines = await summary.evaluate((node) =>
      Math.round(
        node.getBoundingClientRect().height / parseFloat(getComputedStyle(node).lineHeight),
      ),
    );
    require(lines === 1, `Impact summary wraps to ${lines} lines`);
  }
  const dialogText = (await dialog.textContent()) ?? "";
  require(!/Settings would change/.test(
    dialogText,
  ), "The impact still says 'Settings would change'");
  require(!/Saving records this assignment only/i.test(
    dialogText,
  ), "The dialog still says 'Saving records this assignment only'");
  require((await dialog
    .getByRole("button", { name: /^(Roll out|Request approval to roll out)$/ })
    .count()) === 1, "The reviewed impact has no Roll out action");
  await capture("new rollout impact");
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden", timeout });
}
