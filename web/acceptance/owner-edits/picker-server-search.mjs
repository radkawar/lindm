// Owner report: pickers over paged lists searched only the loaded page, so on the
// scale seed (120 device groups) typing a group that was not among the first 50
// read "No matching options". Device group, dynamic group and rollout pickers now
// ask the server for any part of the name, page inside the open picker with
// More choices, and name an empty search result.
// Read-only: searches in the New rollout form and closes it without saving.
export const task = {
  name: "Pickers search every group and rollout, not one page",
  screenId: "owner-picker-server-search",
  route: "/rollouts",
  priority: "normal",
  acceptance:
    "In the New rollout form, a device group that is only on the Target picker's second page (More choices) is found by typing part of its name in another case and can be chosen; a search with no match says no group names contain it; the dynamic group Target picker finds 'Finance devices' by 'NANCE' and lists nothing else; the Optional staged rollout picker finds the seeded 'Pilot, Fleet' rollout by part of a stage name in another case and names an empty search.",
};

const timeout = 30_000;

// Option labels in an open picker, without descriptions or the clear choice.
async function labels(list) {
  const texts = await list.getByRole("option").allInnerTexts();
  return texts
    .map((text) => text.split("\n")[0].trim())
    .filter((text) => text && text !== "No selection");
}

// Waits until the open picker lists options that all satisfy accept (the previous
// page or search stays on screen while the next one loads).
async function waitForLabels(page, list, accept) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const current = await labels(list);
    if (current.length && current.every(accept)) return current;
    if (Date.now() > deadline) return current;
    await page.waitForTimeout(100);
  }
}

// The choices of the one open picker (its popover's command list).
function openChoices(page) {
  return page.locator('[data-slot="command-list"]');
}

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  step("open New rollout");
  await visit("/rollouts");
  await main.getByRole("heading", { name: "Rollouts", exact: true }).waitFor({ timeout });
  await settle();
  await main.getByRole("button", { name: "New rollout", exact: true }).click();
  const form = main.getByRole("region", { name: "New rollout", exact: true });
  await form.waitFor({ timeout });
  await settle();

  step("find a device group past the first page");
  await form.getByRole("button", { name: /^Target Choose/ }).click();
  const groups = openChoices(page);
  const first = await waitForLabels(page, groups, () => true);
  require(first.length > 0, "the Target picker listed no device groups");
  const more = page.getByRole("button", { name: "More choices", exact: true });
  await more.waitFor({ timeout }).catch(() => {});
  require(await more.isVisible(), `the Target picker offers no More choices with ${first.length} groups listed`);
  if (!(await more.isVisible())) return;
  await more.click();
  const second = await waitForLabels(page, groups, (name) => !first.includes(name));
  const wanted = second.find((name) => !first.includes(name));
  require(wanted, "More choices showed no group that was not on the first page");
  if (!wanted) return;
  await capture("group-picker-more-choices");
  const part = wanted.length > 6 ? wanted.slice(1, -1) : wanted;
  const typed = part.toUpperCase();
  await page.getByRole("combobox", { name: "Search target", exact: true }).fill(typed);
  const matches = await waitForLabels(page, groups, (name) =>
    name.toLowerCase().includes(part.toLowerCase()),
  );
  for (const name of matches)
    require(name
      .toLowerCase()
      .includes(part.toLowerCase()), `searching "${typed}" listed "${name}"`);
  require(matches.includes(
    wanted,
  ), `searching "${typed}" did not find "${wanted}", which is past the first page`);
  await capture("group-picker-server-search");
  if (matches.includes(wanted)) {
    await groups.getByRole("option").filter({ hasText: wanted }).first().click();
    require((await form.getByRole("button", { name: `Target ${wanted}`, exact: true }).count()) ===
      1, `choosing "${wanted}" did not show it as the target`);
  }

  step("name an empty group search");
  await form.getByRole("button", { name: /^Target (?!type)/ }).click();
  await page.getByRole("combobox", { name: "Search target", exact: true }).fill("zq no such group");
  const noGroup = page.getByText("No device group names contain “zq no such group”.", {
    exact: true,
  });
  await noGroup.waitFor({ timeout }).catch(() => {});
  require(await noGroup.isVisible(), "an unmatched group search does not say that no group names contain it");
  await capture("group-picker-no-match");
  await page.keyboard.press("Escape");

  step("find a dynamic group by part of its name");
  await form.getByRole("combobox", { name: "Target type", exact: true }).click();
  await page.getByRole("option", { name: "Dynamic group", exact: true }).click();
  await form.getByRole("button", { name: /^Target Choose/ }).click();
  const dynamic = openChoices(page);
  await page.getByRole("combobox", { name: "Search target", exact: true }).fill("NANCE");
  const dynamicFound = await waitForLabels(page, dynamic, (name) =>
    name.toLowerCase().includes("nance"),
  );
  require(dynamicFound.length === 1 &&
    dynamicFound[0] ===
      "Finance devices", `searching "NANCE" listed ${JSON.stringify(dynamicFound)}, not only "Finance devices"`);
  await capture("dynamic-group-picker-server-search");
  await page.keyboard.press("Escape");

  step("find the seeded rollout by part of a stage name");
  await form.locator("summary", { hasText: "Timing, exclusions and priority" }).click();
  await form.getByRole("button", { name: /^Optional staged rollout/ }).click();
  const rolloutSearch = page.getByRole("combobox", {
    name: "Search optional staged rollout",
    exact: true,
  });
  const rollouts = openChoices(page);
  await rolloutSearch.fill("FLEE");
  const found = await waitForLabels(page, rollouts, (name) => name.toLowerCase().includes("flee"));
  require(found.some(
    (name) => name.toLowerCase() === "pilot, fleet",
  ), `searching "FLEE" listed ${JSON.stringify(found)}, not the "Pilot, Fleet" rollout`);
  await capture("rollout-picker-server-search");
  await rolloutSearch.fill("zq-no-such-stage");
  const noRollout = page.getByText(
    "No staged rollouts have a stage name containing “zq-no-such-stage”.",
    { exact: true },
  );
  await noRollout.waitFor({ timeout }).catch(() => {});
  require(await noRollout.isVisible(), "an unmatched rollout search does not say that no stage names contain it");
  await page.keyboard.press("Escape");

  await form.getByRole("button", { name: "Close", exact: true }).click();
  await form.waitFor({ state: "detached", timeout });
}
