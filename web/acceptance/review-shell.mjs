// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 lindm contributors

// Consumer-visible shell contract: stable location, centered logo, persisted
// collapse, keyboard/focus recovery and the single accessible mobile menu.
export async function reviewShell({ page, prefix, desktop, probe, screenshot, axe }) {
  const findings = [];
  const screenshots = {};
  const require = (condition, message) => {
    if (!condition) findings.push({ message, elements: [] });
  };
  if (desktop) {
    const toggle = page.getByRole("button", { name: "Toggle page navigation", exact: true });
    if ((await toggle.getAttribute("aria-expanded")) === "false") await toggle.click();
    const pages = page.getByRole("navigation", { name: "Fleet pages", exact: true });
    require(await pages.isVisible(), "The current work area has no visible page column");
    require((await pages
      .getByRole("link", { name: "Dashboard", exact: true })
      .getAttribute("aria-current")) === "page", "The current page is not marked");
    const shortcuts = await toggle.getAttribute("aria-keyshortcuts");
    require(shortcuts?.includes("Control+b") &&
      shortcuts.includes(
        "Meta+b",
      ), "The collapse control has no announced Control/Command shortcut");
    await toggle.hover();
    const hint = page.locator('[data-slot="tooltip-content"][data-open]');
    await hint.waitFor();
    require((await hint.getAttribute("role")) ===
      "tooltip", "The page navigation hint has no tooltip semantics");
    require(await hint.evaluate(
      (node) => node.closest("main") !== null,
    ), "The page navigation hint is outside its page landmark");
    await toggle.click();
    require((await toggle.getAttribute("aria-expanded")) ===
      "false", "The page column does not collapse");
    require(!(await pages.isVisible()), "Collapsed page navigation remains visible");
    screenshots.collapsed = await screenshot(page, `${prefix}-collapsed.png`, false);
    findings.push(...(await probe(page, "layout", true)));
    await page.reload({ waitUntil: "domcontentloaded" });
    await toggle.waitFor();
    require((await toggle.getAttribute("aria-expanded")) ===
      "false", "Reload lost the user collapse preference");
    await toggle.focus();
    await page.keyboard.press("Control+b");
    require((await toggle.getAttribute("aria-expanded")) ===
      "true", "Control B does not show the page column");
    const link = pages.getByRole("link", { name: "Devices", exact: true });
    await link.focus();
    await page.keyboard.press("Control+b");
    require(await toggle.evaluate(
      (node) => document.activeElement === node,
    ), "Collapsing a focused page link loses focus");
    require((await toggle.getAttribute("aria-expanded")) ===
      "false", "Control B does not hide the page column");
    require(await page
      .getByRole("status")
      .filter({ hasText: "Page navigation hidden." })
      .isVisible(), "Collapse is not announced");
    await toggle.click();
    require((await toggle.getAttribute("aria-expanded")) ===
      "true", "The page column does not restore");
    await page.keyboard.press("Meta+b");
    require((await toggle.getAttribute("aria-expanded")) ===
      "false", "Command B does not hide the page column");
    await page.keyboard.press("Meta+b");
    require((await toggle.getAttribute("aria-expanded")) ===
      "true", "Command B does not restore the page column");
  } else {
    const trigger = page.getByRole("button", { name: "Toggle navigation", exact: true });
    await trigger.click();
    const dialog = page.getByRole("dialog", { name: "Navigation", exact: true });
    await dialog.waitFor();
    await dialog.evaluate(async (node) => {
      await Promise.all(
        node
          .getAnimations({ subtree: true })
          .map((animation) => animation.finished.catch(() => {})),
      );
    });
    await page.waitForFunction(() => {
      const dialog = document.querySelector('[role="dialog"]');
      if (!dialog) return false;
      const box = dialog.getBoundingClientRect();
      return box.x >= -1 && box.width > 250 && box.right <= window.innerWidth + 1;
    });
    const nav = dialog.getByRole("navigation", { name: "Main navigation", exact: true });
    require(await nav
      .getByRole("link", { name: "Dashboard", exact: true })
      .isVisible(), "Mobile navigation does not start with current-area pages");
    const order = await nav.evaluate((node) => {
      const current = node.querySelector("h2");
      const others = [...node.querySelectorAll("h3")].find(
        (heading) => heading.textContent === "Other areas",
      );
      const account = node.querySelector('button[aria-label^="Account menu"]');
      return (
        current &&
        others &&
        account &&
        Boolean(current.compareDocumentPosition(others) & Node.DOCUMENT_POSITION_FOLLOWING) &&
        Boolean(others.compareDocumentPosition(account) & Node.DOCUMENT_POSITION_FOLLOWING)
      );
    });
    require(order, "Mobile navigation order is not current pages, other areas, account");
    screenshots.navigation = await screenshot(page, `${prefix}-navigation.png`, false);
    findings.push(...(await probe(page, "layout", false)));
    for (const violation of await axe(page, '[role="dialog"]')) {
      if (violation.blocking)
        findings.push({
          message: `Mobile navigation: ${violation.id}: ${violation.help}`,
          elements: violation.nodes.map((node) => node.target),
        });
    }
    await page.keyboard.press("Escape");
    await dialog.waitFor({ state: "hidden" });
    require(await trigger.evaluate(
      (node) => document.activeElement === node,
    ), "Closing mobile navigation does not restore focus");
  }
  return { findings, screenshots };
}

// Run after the parallel route captures: these choices share one user's browser storage.
export async function reviewTheme({ page, origin }) {
  const findings = [];
  const original = await page.evaluate(() => localStorage.getItem("lindm-theme"));
  const require = (condition, message) => {
    if (!condition) findings.push({ message, elements: [] });
  };
  const waitTheme = async (dark) => {
    await page.waitForFunction(
      (expected) =>
        document.documentElement.classList.contains("dark") === expected &&
        getComputedStyle(document.documentElement).colorScheme === (expected ? "dark" : "light"),
      dark,
    );
  };
  try {
    await page.evaluate(() => localStorage.removeItem("lindm-theme"));
    await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
    await page.goto(`${origin}/dashboard`, { waitUntil: "domcontentloaded" });
    await waitTheme(false);
    require((await page.evaluate(() => localStorage.getItem("lindm-theme"))) ===
      null, "Mounting the shell overwrites the implicit system theme");
    await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
    await waitTheme(true);
    require((await page.evaluate(() => localStorage.getItem("lindm-theme"))) ===
      null, "A system theme change becomes an explicit stored choice");
    await page.getByRole("button", { name: "Switch to light theme", exact: true }).click();
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitTheme(false);
    require((await page.evaluate(() => localStorage.getItem("lindm-theme"))) ===
      "light", "Stored light preference does not override dark system preference across reload");
    await page.getByRole("button", { name: "Switch to dark theme", exact: true }).click();
    await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitTheme(true);
    require((await page.evaluate(() => localStorage.getItem("lindm-theme"))) ===
      "dark", "Stored dark preference does not override light system preference across reload");
  } finally {
    await page.evaluate((value) => {
      if (value === null) localStorage.removeItem("lindm-theme");
      else localStorage.setItem("lindm-theme", value);
    }, original);
    await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
    await page.goto(`${origin}/dashboard`, { waitUntil: "domcontentloaded" });
  }
  return { findings };
}
