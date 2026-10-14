// SPDX-License-Identifier: Apache-2.0

// Owner pass 2, bug 7: on a scrolled page a modal rendered half: the top of the
// page stayed unblurred, the sidebar moved down and the dialog was drawn over
// the content. The owner reviews through full-page captures of headless
// Chromium; Base UI's scroll lock left the document scrolled, so a capture drew
// every fixed layer (backdrop, sidebar, sticky header, dialog) at the scroll
// offset. Each case scrolls a long page, opens a modal with real input and
// asserts what the user sees and what a full-page capture shows: the backdrop
// covers every edge of the viewport, the document is exactly one viewport tall
// (a full-page capture equals the viewport), the dialog is fully in view, the
// sidebar, header and main content don't move or change width (a lock that drops
// a classic scrollbar's gutter widens and re-wraps the page under the backdrop),
// and closing restores the scroll position.
// Runs in the review browser and again in a second Chromium with the other
// scrollbar mode, so both overlay (the owner's headless browser) and classic
// scrollbars are exercised. Read-only: every modal is closed with Escape.
import { chromium } from "playwright";

export const task = {
  name: "Dialogs on a scrolled page",
  screenId: "owner-pass2-bug7-dialog-scrolled",
  route: "/enrollment",
  priority: "high",
  acceptance:
    "Scrolled Enrollment, wipe form and mobile Accounts, with overlay and classic scrollbars: an open dialog's backdrop covers the whole viewport and a full-page capture equals the viewport; the dialog is fully in view; sidebar, header and main content keep their position and width; closing restores the scroll position. The mobile navigation sheet behaves the same.",
};

const timeout = 30_000;
const tolerancePx = 1;

function cases(demo) {
  const deviceId = demo?.Routes?.DeviceID;
  if (!deviceId) throw new Error("demo route device is missing");
  return [
    {
      name: "enrollment offline dialog",
      url: "/enrollment",
      viewport: { width: 1440, height: 900 },
      ready: (main) => main.getByRole("heading", { name: "Enroll a device", exact: true }),
      trigger: (page) =>
        page
          .getByRole("main")
          .getByRole("button", { name: "Enroll devices at offline sites", exact: true }),
      popup: (page) =>
        page.getByRole("dialog", { name: "Enroll devices at offline sites", exact: true }),
      overlay: "dialog-overlay",
    },
    {
      // The stale-storage wipe form fits a 900 px desktop viewport; a laptop height scrolls it.
      name: "wipe form refresh dialog",
      url: `/devices/${encodeURIComponent(deviceId)}/actions/new/cryptoErase`,
      viewport: { width: 1440, height: 600 },
      ready: (main) =>
        main.getByRole("heading", { level: 1, name: "Wipe encrypted storage", exact: true }),
      trigger: (page) =>
        page
          .getByRole("main")
          .getByRole("region", { name: "Observed storage target" })
          .getByRole("button", { name: "Refresh inventory", exact: true }),
      popup: (page) => page.getByRole("dialog", { name: "Refresh inventory", exact: true }),
      overlay: "dialog-overlay",
    },
    {
      name: "mobile navigation sheet",
      url: "/enrollment",
      viewport: { width: 390, height: 844 },
      ready: (main) => main.getByRole("heading", { name: "Enroll a device", exact: true }),
      trigger: (page) =>
        page.locator("header").getByRole("button", { name: "Toggle navigation", exact: true }),
      popup: (page) => page.getByRole("dialog", { name: "Navigation", exact: true }),
      overlay: "sheet-overlay",
    },
    {
      // At 390 px a classic scrollbar is 4% of the width; its gutter must stay reserved.
      name: "mobile accounts edit dialog",
      url: "/accounts",
      viewport: { width: 390, height: 844 },
      ready: (main) => main.getByRole("heading", { level: 1, name: "Accounts", exact: true }),
      trigger: (page) =>
        page
          .getByRole("main")
          .getByRole("button", { name: /^Edit / })
          .last(),
      popup: (page) => page.getByRole("dialog", { name: /^Edit / }),
      overlay: "dialog-overlay",
    },
  ];
}

// Layout facts read in the page: scroll, document and viewport sizes, the
// shell's fixed/sticky boxes and what the top and bottom edge points hit.
function layout(overlaySlot) {
  const box = (node) => {
    if (!node || node.getClientRects().length === 0) return null;
    const rect = node.getBoundingClientRect();
    return { x: rect.x, y: rect.y, width: rect.width, height: rect.height };
  };
  const html = document.documentElement;
  // The page's own width: a classic scrollbar's gutter is never covered by page layers.
  const width = Math.min(html.clientWidth, document.body.getBoundingClientRect().width);
  const height = html.clientHeight;
  const points = [
    [2, 1],
    [width / 2, 1],
    [width - 2, 1],
    [2, height - 2],
    [width - 2, height - 2],
  ];
  const overlay = document.querySelector(`[data-slot="${overlaySlot}"][data-open]`);
  const popup = document.querySelector('[role="dialog"][data-open]');
  return {
    scrollY: window.scrollY,
    innerHeight: window.innerHeight,
    gutter: window.innerWidth - html.clientWidth,
    // The height Playwright's full-page capture uses.
    documentHeight: Math.max(
      document.body.scrollHeight,
      html.scrollHeight,
      document.body.offsetHeight,
      html.offsetHeight,
      html.clientHeight,
    ),
    sidebar: box(document.querySelector("[data-shell-rail]")),
    header: box(document.querySelector("header")),
    // Main content: a widened layout re-wraps text, which moves and resizes these.
    main: box(document.querySelector("main")),
    heading: box(document.querySelector("main h1")),
    popup: box(popup),
    uncovered: points
      .filter(([x, y]) => {
        const hit = document.elementFromPoint(x, y);
        return !hit || !(hit === overlay || popup?.contains(hit));
      })
      .map(([x, y]) => `(${Math.round(x)}, ${Math.round(y)})`),
  };
}

function moved(before, after) {
  if (!before || !after) return before !== after;
  return ["x", "y", "width", "height"].some(
    (key) => Math.abs(before[key] - after[key]) > tolerancePx,
  );
}

function pngHeight(buffer) {
  return buffer.readUInt32BE(20);
}

// Returns the scrollbar mode the page showed ("classic" or "overlay").
async function scrolledModal({ page, origin, item, require, capture }) {
  let where = item.name;
  await page.setViewportSize(item.viewport);
  await page.goto(`${origin}${item.url}`, { waitUntil: "domcontentloaded" });
  const main = page.getByRole("main");
  await item.ready(main).waitFor({ timeout });
  const trigger = item.trigger(page);
  await trigger.waitFor({ timeout });
  await page.waitForLoadState("networkidle", { timeout: 5_000 }).catch(() => {});
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  // Real pointer input at the trigger: Playwright's own scroll-into-view treats
  // anything in the sticky header as hidden behind the page's scroll padding.
  await trigger.evaluate((node) => {
    const rect = node.getBoundingClientRect();
    if (
      rect.top < 0 ||
      rect.bottom > window.innerHeight ||
      rect.left < 0 ||
      rect.right > window.innerWidth
    )
      node.scrollIntoView({ block: "center", inline: "nearest" });
  });
  const before = await page.evaluate(layout, item.overlay);
  const mode = before.gutter > 0 ? "classic" : "overlay";
  where = `${item.name} (${mode} scrollbars)`;
  require(before.scrollY > 0, `${where}: the page does not scroll, so the case is not exercised`);
  const target = await trigger.boundingBox();
  if (!target) throw new Error(`${where}: the trigger has no box`);
  await page.mouse.click(target.x + target.width / 2, target.y + target.height / 2);
  const popup = item.popup(page);
  await popup.waitFor({ timeout });
  // Base UI mounts a popup with data-starting-style (the sheet at its 2.5rem
  // starting offset, transparent but already visible to Playwright) and removes
  // it on a later frame; only then does the entry transition start. On a loaded
  // browser that frame came after the wait below, which then measured the sheet
  // at its starting offset, outside the viewport.
  await page.waitForFunction(() => !document.querySelector("[data-starting-style]"), null, {
    timeout,
  });
  await page.evaluate(() =>
    Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => {}))),
  );
  const open = await page.evaluate(layout, item.overlay);
  require(open.uncovered.length ===
    0, `${where}: the backdrop does not cover the viewport at ${open.uncovered.join(", ")}`);
  require(open.documentHeight <=
    open.innerHeight +
      tolerancePx, `${where}: with the dialog open the document is ${open.documentHeight}px tall in a ${open.innerHeight}px viewport, so a full-page capture draws the backdrop over part of it`);
  const shot = await page.screenshot({ fullPage: true, animations: "disabled" });
  require(Math.abs(pngHeight(shot) - open.innerHeight) <=
    tolerancePx, `${where}: a full-page capture is ${pngHeight(shot)}px tall, not the ${open.innerHeight}px viewport the user sees`);
  const box = open.popup;
  require(!!box &&
    box.x >= -tolerancePx &&
    box.y >= -tolerancePx &&
    box.x + box.width <= item.viewport.width + tolerancePx &&
    box.y + box.height <=
      item.viewport.height + tolerancePx, `${where}: the dialog is not fully within the viewport`);
  require(!moved(
    before.sidebar,
    open.sidebar,
  ), `${where}: the sidebar moved when the dialog opened`);
  require(!moved(before.header, open.header), `${where}: the header moved when the dialog opened`);
  for (const part of ["main", "heading"])
    require(!moved(
      before[part],
      open[part],
    ), `${where}: the page's ${part} moved or changed width under the dialog (${before[part]?.width}px to ${open[part]?.width}px wide)`);
  if (capture) await capture(`${item.name} open`);
  await page.keyboard.press("Escape");
  await popup.waitFor({ state: "hidden", timeout });
  const closed = await page.evaluate(layout, item.overlay);
  require(Math.abs(closed.scrollY - before.scrollY) <=
    tolerancePx, `${where}: closing the dialog moved the page from ${before.scrollY}px to ${closed.scrollY}px`);
  require(!moved(
    before.header,
    closed.header,
  ), `${where}: the header moved after the dialog closed`);
  return mode;
}

async function runCases({ page, origin, items, require, capture, step, label }) {
  const modes = new Set();
  for (const item of items) {
    step(`${item.name}, ${label}`);
    modes.add(await scrolledModal({ page, origin, item, require, capture }));
  }
  return modes;
}

export async function check({ page, config, demo, require, capture, step }) {
  const items = cases(demo);
  const viewport = page.viewportSize();
  let reviewModes;
  try {
    reviewModes = await runCases({
      page,
      origin: config.origin,
      items,
      require,
      capture,
      step,
      label: "review browser",
    });
  } finally {
    if (viewport) await page.setViewportSize(viewport);
  }
  require(reviewModes.size === 1, "The review browser switched scrollbar modes between cases");

  // A second headless Chromium with the other scrollbar mode: overlay is the
  // owner's (Playwright's default hides scrollbars), classic what most desktops show.
  const classicReview = reviewModes.has("classic");
  const browser = await chromium.launch({
    headless: true,
    timeout,
    ...(classicReview ? {} : { ignoreDefaultArgs: ["--hide-scrollbars"] }),
  });
  try {
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      viewport: items[0].viewport,
      storageState: await page.context().storageState(),
    });
    const other = await context.newPage();
    other.setDefaultTimeout(timeout);
    const otherModes = await runCases({
      page: other,
      origin: config.origin,
      items,
      require,
      step,
      label: "second browser",
    });
    const all = new Set([...reviewModes, ...otherModes]);
    require(all.has("overlay") &&
      all.has("classic"), `Only ${[...all].join(" and ")} scrollbars were exercised`);
  } finally {
    await browser.close();
  }
}
