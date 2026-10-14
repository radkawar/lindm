// SPDX-License-Identifier: Apache-2.0

// ui-review found the device page's action dialogs (Refresh inventory, Patch now,
// Shut down device) intermittently ignoring Escape for over 2 s under load; the
// next dialog check then met the old dialog with focus outside it. The open
// action dialog lives in the URL (?action=…), and every navigation, in-page ones
// too, waited for the signed-in layout's session read once the cached session
// was stale (30 s); under load that read took seconds. A known session is now
// rechecked in the background instead.
// This check holds every session read open, as a slow server would, after the
// cached session has gone stale (the page clock jumps ahead), then closes an open
// action dialog with Escape and opens and closes another: each must happen
// without the read answering, with focus inside and then back on Actions.
// A separate browser context keeps the clock and the held reads off the review's
// pages. Read-only: nothing is sent.
export const task = {
  name: "Action dialogs answer while the session is rechecked",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "With the cached session stale and its recheck unanswered, Escape closes an open device action dialog and returns focus to Actions, and another action dialog opens from the Actions menu with focus inside; none of this waits for the recheck.",
};

const timeout = 30_000;
// Without the recheck answering, an in-page navigation that awaited it never
// completes; one that doesn't completes far sooner than this.
const prompt = 5_000;

async function shown(locator, state) {
  return locator.waitFor({ state, timeout: prompt }).then(
    () => true,
    () => false,
  );
}

// Focus moves on a later frame (Base UI's focus manager), so poll.
async function focused(locator, within = false) {
  const deadline = Date.now() + prompt;
  while (Date.now() < deadline) {
    const active = await locator.evaluate(
      (node, within) =>
        within ? node.contains(document.activeElement) : node === document.activeElement,
      within,
    );
    if (active) return true;
    await new Promise((done) => setTimeout(done, 100));
  }
  return false;
}

export async function check({ page, config, demo, require, step }) {
  const deviceId = demo?.Routes?.DeviceID;
  if (!deviceId) throw new Error("demo route device is missing");
  const context = await page
    .context()
    .browser()
    .newContext({
      ignoreHTTPSErrors: true,
      viewport: page.viewportSize() ?? undefined,
      storageState: await page.context().storageState(),
    });
  const held = [];
  let hold = false;
  try {
    await context.route(
      (url) => url.pathname === "/auth/session",
      (route) => (hold ? held.push(route) : route.continue()),
    );
    // Installed before the page loads; time flows normally until it jumps.
    await context.clock.install();
    const device = await context.newPage();
    device.setDefaultTimeout(timeout);
    const main = device.getByRole("main");
    const actions = main.getByRole("button", { name: "Actions", exact: true });
    const open = async (name) => {
      await actions.click();
      await device.getByRole("menuitem", { name, exact: true }).click();
      return device.getByRole("dialog", { name, exact: true });
    };

    step("open Refresh inventory with a fresh session");
    await device.goto(`${config.origin}/devices/${encodeURIComponent(deviceId)}`);
    const first = await open("Refresh inventory");
    await first.waitFor({ timeout });

    step("the cached session goes stale and its recheck does not answer");
    hold = true;
    await context.clock.setSystemTime((await device.evaluate(() => Date.now())) + 5 * 60_000);

    step("Escape closes Refresh inventory");
    await device.keyboard.press("Escape");
    const closed = await shown(first, "hidden");
    require(closed, "Escape did not close Refresh inventory while the session recheck was unanswered");
    if (closed)
      require(await focused(actions), "Closing Refresh inventory did not return focus to Actions");

    step("open Shut down device");
    if (!closed) return;
    const second = await open("Shut down device");
    const opened = await shown(second, "visible");
    require(opened, "Shut down device did not open while the session recheck was unanswered");
    if (!opened) return;
    require(await focused(second, true), "Focus did not move into Shut down device");
    step("Escape closes Shut down device");
    await device.keyboard.press("Escape");
    require(await shown(
      second,
      "hidden",
    ), "Escape did not close Shut down device while the session recheck was unanswered");
    require(held.length >
      0, "No session recheck was made after the clock jumped, so the case was not exercised");
  } finally {
    hold = false;
    for (const route of held) await route.continue().catch(() => {});
    await context.close();
  }
}
