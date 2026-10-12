// Owner pass 2, bug 8: choosing a profile in the New rollout form collapsed the
// sidebar's Fleet navigation group. The check drives the Profile picker with
// real pointer and keyboard input on the scrolled rollouts page (the form opens
// below the lists) and asserts that every navigation group keeps its state,
// the Fleet links stay visible, and no pointer or key event from the picker
// reaches the main navigation. The only path found that toggles a group without
// its visible header: collapsed to icons, each group's invisible label covered
// the previous group's last icon, so the check also hit-tests every icon.
// Read-only: the form is closed without review and the sidebar is re-expanded.
export const task = {
  name: "Rollout profile picker leaves navigation alone",
  screenId: "owner-pass2-bug8-picker-sidebar",
  route: "/rollouts",
  priority: "normal",
  acceptance:
    "Opening the New rollout Profile picker and choosing a profile by pointer and by keyboard leaves the sidebar's Fleet group (and every other group) expanded; nothing in the navigation receives the picker's events; collapsed to icons, every navigation icon receives its own clicks.",
};

const timeout = 30_000;
const FLEET_LINKS = ["Dashboard", "Devices", "Profiles", "Rollouts", "Enrollment"];
const NAV = 'nav[aria-label="Main navigation"]';

function groups(page) {
  return page.evaluate(
    (nav) =>
      [...document.querySelectorAll(`${nav} button[aria-expanded]`)].map(
        (button) => `${button.textContent.trim()}=${button.getAttribute("aria-expanded")}`,
      ),
    NAV,
  );
}

// Records pointer, click and key events whose target is inside the navigation.
function listen(nav) {
  window.__ownerNavEvents = [];
  for (const type of ["pointerdown", "click", "keydown"])
    document.addEventListener(
      type,
      (event) => {
        if (event.target instanceof Element && event.target.closest(nav))
          window.__ownerNavEvents.push(
            `${type} on ${event.target.textContent.trim().slice(0, 40)}`,
          );
      },
      true,
    );
}

// A pointer click where the user sees the element, without Playwright's scroll-into-view.
async function pointerClick(page, locator) {
  await locator.evaluate((node) => {
    const rect = node.getBoundingClientRect();
    if (rect.top < 0 || rect.bottom > window.innerHeight) node.scrollIntoView({ block: "center" });
  });
  const box = await locator.boundingBox();
  if (!box) throw new Error("element has no box");
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
}

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  const nav = page.locator(NAV);
  step("open new rollout");
  await visit("/rollouts");
  await main.getByRole("heading", { name: "Rollouts", exact: true }).waitFor({ timeout });
  await settle();
  const initial = await groups(page);
  require(initial.some((group) =>
    /^fleet=true$/i.test(group),
  ), `The Fleet group is not expanded on load (${initial.join(", ")})`);
  await main.getByRole("button", { name: "New rollout", exact: true }).click();
  const form = main.getByRole("region", { name: "New rollout", exact: true });
  await form.waitFor({ timeout });
  await page.evaluate(listen, NAV);
  const scrollY = await page.evaluate(() => window.scrollY);
  require(scrollY >
    0, "The rollouts page did not scroll to the form, so the scrolled case is not exercised");

  const profile = form.getByRole("button", { name: /^Profile\b/ });
  // The open picker's choice list: it always offers "No selection" first.
  const choices = page
    .getByRole("listbox")
    .filter({ has: page.getByRole("option", { name: "No selection", exact: true }) });
  const verify = async (how) => {
    const now = await groups(page);
    require(now.join() ===
      initial.join(), `After ${how} the navigation groups changed from ${initial.join(", ")} to ${now.join(", ")}`);
    for (const name of FLEET_LINKS)
      require(await nav
        .getByRole("link", { name, exact: true })
        .isVisible(), `After ${how} the Fleet link "${name}" is hidden`);
    const events = await page.evaluate(() => window.__ownerNavEvents.splice(0));
    require(events.length === 0, `After ${how} the navigation received ${events.join("; ")}`);
  };

  step("pick a profile with the pointer");
  await pointerClick(page, profile);
  await choices.waitFor({ timeout });
  await verify("opening the Profile picker");
  const options = choices.getByRole("option");
  // "No selection" renders at once; the seeded profiles follow their query.
  await options.nth(1).waitFor({ timeout });
  const names = (await options.allInnerTexts()).map((text) => text.split("\n")[0].trim());
  const first = names.findIndex((name) => name && name !== "No selection");
  require(first >= 0, "The Profile picker lists no profiles");
  if (first < 0) return;
  await pointerClick(page, options.nth(first));
  await choices.waitFor({ state: "hidden", timeout });
  require((await profile.innerText()).includes(
    names[first],
  ), `The Profile picker does not show "${names[first]}" after choosing it`);
  await verify("choosing a profile with the pointer");
  await capture("profile chosen");

  step("pick a profile with the keyboard");
  await profile.focus();
  await page.keyboard.press("Enter");
  await choices.waitFor({ timeout });
  const second = names.findIndex(
    (name, index) => index !== first && name && name !== "No selection",
  );
  if (second >= 0) {
    await page.keyboard.type(names[second]);
    await page.keyboard.press("Enter");
    await choices.waitFor({ state: "hidden", timeout });
    require((await profile.innerText()).includes(
      names[second],
    ), `The Profile picker does not show "${names[second]}" after choosing it with Enter`);
  } else {
    await page.keyboard.press("Escape");
    await choices.waitFor({ state: "hidden", timeout });
  }
  await verify("choosing a profile with the keyboard");

  step("close the form");
  await form.getByRole("button", { name: "Close", exact: true }).click();
  await form.waitFor({ state: "detached", timeout });
  await verify("closing the form");

  // Collapsed to icons, each group's label is invisible over the previous
  // group's last icon; a click there must reach the icon, never toggle a group.
  step("icon sidebar hit targets");
  const toggle = page.locator("header").getByRole("button", { name: "Toggle navigation" });
  await pointerClick(page, toggle);
  await page.locator('[data-slot="sidebar"][data-state="collapsed"]').waitFor({ timeout });
  try {
    await page.evaluate(() =>
      Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => {}))),
    );
    const blocked = await page.evaluate(
      (selector) =>
        [...document.querySelectorAll(`${selector} a[href]`)]
          .filter((link) => {
            const rect = link.getBoundingClientRect();
            const hit = document.elementFromPoint(
              rect.x + rect.width / 2,
              rect.y + rect.height / 2,
            );
            return !hit || !link.contains(hit);
          })
          .map((link) => link.getAttribute("href")),
      NAV,
    );
    require(blocked.length ===
      0, `With the sidebar collapsed to icons, clicks on ${blocked.join(", ")} land on something else`);
  } finally {
    await pointerClick(page, toggle);
    await page.locator('[data-slot="sidebar"][data-state="expanded"]').waitFor({ timeout });
  }
  await verify("collapsing and expanding the sidebar");
}
