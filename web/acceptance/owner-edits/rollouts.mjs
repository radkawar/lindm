// Owner task: /rollouts shows staged rollouts and saved assignments as visible
// lists, keeps the form behind "New rollout" with distinct field labels, and
// uses Profile/Version wording. Read-only: opens and closes the form without
// reviewing or saving anything.
export const task = {
  name: "Rollouts visible state",
  screenId: "2031ff7e60ccbf0eb971b2a4",
  route: "/rollouts",
  priority: "normal",
  acceptance:
    "No two fields share a label; the words 'baseline revision' no longer appear; with any active rollout seeded, it is visible without expanding anything.",
};

const timeout = 30_000;
const ACTIVE = /^(Waiting to advance|Manual promotion required|Final stage)$/;
const SUMMARY = /^(\d+) in progress, (\d+) paused/;

// Visible on screen and not inside a closed disclosure or hidden subtree.
async function shownWithoutExpanding(locator) {
  if (!(await locator.isVisible())) return false;
  return locator.evaluate(
    (node) =>
      !node.closest("details:not([open])") && !node.closest('[hidden],[aria-hidden="true"]'),
  );
}

// Primary text only: rendered text nodes outside Technical details.
function primaryText(root) {
  return root.evaluate((node) => {
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
    const parts = [];
    for (let text = walker.nextNode(); text; text = walker.nextNode()) {
      const parent = text.parentElement;
      if (!parent || parent.closest('[data-slot="technical-details"]')) continue;
      if (!parent.checkVisibility()) continue;
      parts.push(text.textContent ?? "");
    }
    return parts.join(" ").replace(/\s+/g, " ");
  });
}

// Every labelled control: aria-label, the first aria-labelledby element (the
// picker label, not its current value), label[for], or the wrapping label text.
function controlLabels(root) {
  return root.evaluate((node) => {
    const text = (element) => (element?.textContent ?? "").replace(/\s+/g, " ").trim();
    const controls = node.querySelectorAll(
      'input:not([type="hidden"]):not([aria-hidden="true"]), select, textarea, [role="combobox"], button[aria-labelledby]',
    );
    const labels = [];
    for (const control of controls) {
      let label = control.getAttribute("aria-label") ?? "";
      const labelledBy = control.getAttribute("aria-labelledby");
      if (!label && labelledBy)
        label = text(document.getElementById(labelledBy.trim().split(/\s+/)[0]));
      if (!label && control.id)
        label = text(node.querySelector(`label[for="${CSS.escape(control.id)}"]`));
      if (!label) {
        const wrapper = control.closest("label");
        if (wrapper) {
          const clone = wrapper.cloneNode(true);
          clone
            .querySelectorAll('input, select, textarea, button, [role="combobox"]')
            .forEach((child) => child.remove());
          label = text(clone);
        }
      }
      if (label) labels.push(label);
    }
    return labels;
  });
}

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  step("open rollouts");
  await visit("/rollouts");
  await main.getByRole("heading", { name: "Rollouts", exact: true }).waitFor({ timeout });
  const staged = main.getByRole("region", { name: "Staged rollouts", exact: true });
  const saved = main.getByRole("region", { name: "Saved assignments", exact: true });
  // A loaded list shows its in-progress summary; an empty one its empty state.
  await staged
    .getByText(SUMMARY)
    .or(staged.getByText("No staged rollouts on this page", { exact: true }))
    .first()
    .waitFor({ timeout });
  await saved
    .getByRole("listitem")
    .or(saved.getByText("No saved assignments on this page", { exact: true }))
    .first()
    .waitFor({ timeout });
  await settle();

  step("active rollout visible without expanding");
  const cards = await staged.getByRole("article").all();
  let active = 0;
  let activeShown = 0;
  for (const card of cards) {
    const status = card.getByText(ACTIVE);
    if ((await status.count()) === 0) continue;
    active++;
    // The rollout's name is the card's first heading; its decision form follows.
    const heading = card.getByRole("heading", { level: 3 }).first();
    const stage = card.getByText(/^Stage \d+ of \d+: /);
    if (
      (await shownWithoutExpanding(heading)) &&
      (await shownWithoutExpanding(status.first())) &&
      (await stage.count()) === 1 &&
      (await shownWithoutExpanding(stage))
    )
      activeShown++;
  }
  require(active > 0, "No active (not paused) staged rollout is listed on /rollouts");
  require(activeShown ===
    active, `${active - activeShown} of ${active} active rollout(s) are hidden or need expanding`);
  const summary = staged.getByText(SUMMARY);
  const summaryText = (await summary.count()) === 1 ? (await summary.innerText()).trim() : "";
  require(summaryText !== "", "Staged rollouts has no 'N in progress, N paused' summary");
  require(!summaryText ||
    Number(SUMMARY.exec(summaryText)?.[1]) ===
      active, `Summary "${summaryText}" does not match ${active} active rollout card(s)`);
  require(await shownWithoutExpanding(
    saved.getByRole("heading", { name: "Saved assignments" }),
  ), "Saved assignments list is not visible without expanding");
  const form = main.getByRole("region", { name: "New rollout", exact: true });
  require((await form.count()) === 0, "The rollout form is shown before choosing New rollout");
  await capture("lists visible");

  step("open new rollout");
  const open = main.getByRole("button", { name: "New rollout", exact: true });
  await open.click();
  await form.waitFor({ timeout });
  const listBottom = await saved.boundingBox();
  const formTop = await form.boundingBox();
  require(!!listBottom &&
    !!formTop &&
    formTop.y >=
      listBottom.y +
        listBottom.height -
        1, "The new rollout form is not below the rollout and assignment lists");

  step("distinct field labels");
  const labels = await controlLabels(form);
  const seen = new Map();
  for (const label of labels) seen.set(label, (seen.get(label) ?? 0) + 1);
  const shared = [...seen].filter(([, count]) => count > 1).map(([label]) => label);
  require(shared.length === 0, `Fields share a label: ${shared.join(", ")}`);
  for (const expected of ["Target type", "Target", "Profile", "Version"])
    require(seen.has(expected), `New rollout has no field labelled "${expected}"`);
  require(!seen.has("Cohort"), "A field is still labelled 'Cohort'");

  step("profile and version wording on /rollouts");
  const rolloutsText = (await main.textContent()) ?? "";
  require(!/baseline revision/i.test(rolloutsText), "/rollouts still says 'baseline revision'");
  const rolloutsPrimary = await primaryText(main);
  require(!/\brevisions?\b/i.test(
    rolloutsPrimary,
  ), "/rollouts primary text says 'revision' instead of 'version'");
  await capture("new rollout form");
  await form.getByRole("button", { name: "Close", exact: true }).click();
  await form.waitFor({ state: "detached", timeout });

  step("profile and version wording on /profiles");
  await visit("/profiles");
  await main.getByRole("heading", { name: "Profiles", exact: true }).waitFor({ timeout });
  await settle();
  const profilesText = (await main.textContent()) ?? "";
  require(!/baseline revision/i.test(profilesText), "/profiles still says 'baseline revision'");
  require(!/\brevisions?\b/i.test(
    await primaryText(main),
  ), "/profiles primary text says 'revision' instead of 'version'");
}
