// SPDX-License-Identifier: Apache-2.0

// The rollout profile picker must not change the selected work area or page
// column state. Exercise pointer and keyboard input on a scrolled page, then
// hit-test every persistent rail link with the page column collapsed.
// Read-only: the form closes without review and navigation returns to its initial state.
export const task = {
  name: "Rollout profile picker leaves navigation alone",
  screenId: "owner-pass2-bug8-picker-sidebar",
  route: "/rollouts",
  priority: "normal",
  acceptance:
    "Choosing a profile by pointer and keyboard preserves the Changes page column and selected area; the picker sends no events to navigation; every collapsed rail link receives its own clicks.",
};

const timeout = 30_000;
const CURRENT_LINKS = ["Profiles", "Rollouts", "Approvals"];
const NAV = "[data-shell-rail], [data-shell-pages]";

function groups(page) {
  return page.evaluate(() => [
    document.querySelector("[data-shell]")?.getAttribute("data-pages-state"),
    document.querySelector("[data-shell-rail] [aria-current]")?.getAttribute("data-work-area"),
  ]);
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
  const toggle = page.getByRole("button", { name: "Toggle page navigation", exact: true });
  if ((await toggle.getAttribute("aria-expanded")) === "false") await toggle.click();
  const initial = await groups(page);
  require(initial.join() ===
    "expanded,Changes", `Changes navigation is not expanded (${initial.join(", ")})`);
  // Open the dialog from a scrolled page: the original fault toggled the
  // sidebar group under a picker opened below the fold.
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await main.getByRole("button", { name: "New rollout", exact: true }).click();
  const form = page.getByRole("dialog", { name: "New rollout", exact: true });
  await form.waitFor({ timeout });
  await settle();
  // The console scrolls the form into view when it opens; lists above it may still
  // be loading or refreshing then, so the check scrolls to it as a user would.
  const heading = form.getByRole("heading", { name: "New rollout", exact: true });
  for (let attempt = 0; attempt < 20; attempt++) {
    const box = await heading.boundingBox();
    const height = page.viewportSize()?.height ?? 0;
    if (box && box.y >= 0 && box.y + box.height <= height) break;
    await page.mouse.move(800, Math.max(1, height / 2));
    await page.mouse.wheel(0, box && box.y < 0 ? box.y - 100 : (box?.y ?? height) - height / 3);
    await page.waitForTimeout(150);
  }
  await page.evaluate(listen, NAV);

  const profile = form.getByRole("button", { name: /^Profile\b/ });
  // The open picker's choice list: it always offers "No selection" first.
  const choices = page
    .getByRole("listbox")
    .filter({ has: page.getByRole("option", { name: "No selection", exact: true }) });
  const verify = async (how) => {
    const now = await groups(page);
    require(now.join() ===
      initial.join(), `After ${how} the navigation groups changed from ${initial.join(", ")} to ${now.join(", ")}`);
    // The modal dialog hides the page from assistive technology while open,
    // so look the links up including hidden roles and check their layout.
    for (const name of CURRENT_LINKS)
      require(await nav
        .getByRole("link", { name, exact: true, includeHidden: true })
        .isVisible(), `After ${how} the Changes link "${name}" is hidden`);
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
  await form.waitFor({ state: "hidden", timeout });
  await verify("closing the form");

  step("collapsed rail hit targets");
  await pointerClick(page, toggle);
  await page.locator('[data-shell][data-pages-state="collapsed"]').waitFor({ timeout });
  try {
    // Wait for the collapse transition only: an infinite animation (a loading
    // skeleton's pulse under load) never finishes and would stall the review.
    await page.evaluate(() =>
      Promise.all(
        document
          .getAnimations()
          .filter((animation) => animation.effect?.getComputedTiming().iterations !== Infinity)
          .map((animation) => animation.finished.catch(() => {})),
      ),
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
      "[data-shell-rail] nav",
    );
    require(blocked.length ===
      0, `With the page column collapsed, clicks on ${blocked.join(", ")} land on something else`);
  } finally {
    await pointerClick(page, toggle);
    await page.locator('[data-shell][data-pages-state="expanded"]').waitFor({ timeout });
  }
  await verify("collapsing and expanding page navigation");
}
