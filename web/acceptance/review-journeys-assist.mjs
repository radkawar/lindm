// SPDX-License-Identifier: Apache-2.0

// Uses the real console and its synthetic device. Local consent and native screen,
// clipboard, keyboard, notification and file effects belong to lab vm assistance;
// this walk never answers consent or manufactures a connected desktop.
function requireState(condition, token) {
  if (!condition) throw new Error(token);
}

async function capture(ctx, name, screen, outcome) {
  await ctx.capture(name, {
    screen,
    taskShaped: "yes",
    generic: "None in the observed task boundary.",
    remedy:
      "Keep named device context, consent and access state visible; do not imply native completion.",
    outcome,
  });
}

async function settledTransitions(page) {
  await page.evaluate(async () => {
    await Promise.all(
      document.getAnimations().map((animation) => animation.finished.catch(() => {})),
    );
  });
}

async function remoteHelp(ctx) {
  const { page, config } = ctx;
  const device = config.demo.Devices.find((item) => item.ID === config.demo.Routes.DeviceID);
  requireState(device?.Hostname, "assistance_route_device_missing");
  const main = page.getByRole("main");
  const searchTrigger = page.getByRole("button", {
    name: "Search pages, actions and devices (Control or Command K)",
    exact: true,
  });
  const theme = async (value) => {
    const dark = value === "dark";
    const opposite = page.getByRole("button", {
      name: dark ? "Switch to dark theme" : "Switch to light theme",
      exact: true,
    });
    if (await opposite.isVisible()) await opposite.click();
    await page.waitForFunction(
      (expected) => document.documentElement.classList.contains("dark") === expected,
      dark,
    );
    await settledTransitions(page);
  };
  let openRequest = false;
  let sessionPath = "";
  const reason = "Help diagnose a frozen application. The user decides whether to share.";
  try {
    await ctx.visit("/devices");
    await searchTrigger.focus();
    const shortcuts = await searchTrigger.getAttribute("aria-keyshortcuts");
    requireState(
      shortcuts?.includes("Control+k") && shortcuts.includes("Meta+k"),
      "search_shortcut_unannounced",
    );
    await page.keyboard.press("Control+k");
    const search = page.getByRole("dialog", { name: "Search console", exact: true });
    await search.getByRole("combobox").fill(device.Hostname);
    const result = search.getByRole("option").filter({ hasText: device.Hostname });
    await result.waitFor();
    await capture(
      ctx,
      "find-device",
      "Search console",
      "Control K found the authorized device by hostname with operating-system context.",
    );
    await result.click();
    await main.getByRole("heading", { name: device.Hostname, exact: true }).waitFor();
    await main.getByRole("tab", { name: "Remote assistance", exact: true }).click();
    const request = main
      .locator("form")
      .filter({ has: page.getByRole("heading", { name: "Ask to help", exact: true }) });
    await request
      .getByRole("textbox", {
        name: "Reason (the user sees this; the audit log records it)",
        exact: true,
      })
      .waitFor();
    requireState(
      (await request.getByRole("combobox", { name: "Mode", exact: true }).innerText()).includes(
        "View screen",
      ),
      "assistance_default_not_view_only",
    );
    const tools = request.locator("[data-assistance-request-tools]");
    requireState((await tools.getAttribute("open")) === null, "assistance_tools_not_collapsed");
    await tools.locator("summary").click();
    for (const name of ["Clipboard", "Keyboard", "Messages", "Files"])
      await tools.getByRole("combobox", { name, exact: true }).waitFor();
    await capture(
      ctx,
      "review-session-tools",
      "Tools requested with consent",
      "Reviewed clipboard, keyboard, message and file choices before the request; the fixture policy leaves them off.",
    );
    await tools.locator("summary").click();
    await request
      .getByRole("textbox", {
        name: "Reason (the user sees this; the audit log records it)",
        exact: true,
      })
      .fill(reason);
    await request
      .getByRole("spinbutton", { name: "Maximum duration (minutes, 1 to 30)", exact: true })
      .fill("5");
    await request.getByRole("combobox", { name: "Mode", exact: true }).click();
    await page.getByRole("option", { name: "View and request control", exact: true }).click();
    await theme("light");
    await capture(
      ctx,
      "request-light-desktop",
      "Ask to help",
      "The reason, access, time limit and consent impact precede the request; optional tools are collapsed with their requested count.",
    );
    await page.setViewportSize({ width: 390, height: 844 });
    await theme("dark");
    await capture(
      ctx,
      "request-dark-mobile",
      "Ask to help on mobile",
      "The same request keeps its reason and consent impact readable at 390 pixels in dark mode.",
    );
    await request.getByRole("button", { name: "Request remote assistance", exact: true }).click();
    openRequest = true;
    await page.waitForURL(/\/assistance\/[0-9a-f-]{36}$/);
    sessionPath = new URL(page.url()).pathname;
    await main
      .locator('[data-assistance-state="requested"], [data-assistance-state="prompted"]')
      .waitFor();
    await main
      .getByText(
        "The device shares no screen or input yet. Wait for user consent, or stop the request.",
        { exact: true },
      )
      .waitFor();
    const takeControl = main.getByRole("button", { name: "Take control", exact: true });
    requireState(await takeControl.isDisabled(), "assistance_control_before_consent");
    const described = await takeControl.getAttribute("aria-describedby");
    requireState(described, "assistance_control_explanation_missing");
    for (const id of described.split(/\s+/))
      await page.locator(`[id=${JSON.stringify(id)}]`).waitFor();
    requireState(
      !(await main.getByRole("region", { name: "Remote screen", exact: true }).isVisible()),
      "assistance_screen_before_consent",
    );
    for (const name of [
      "Send clipboard",
      "Send special keys",
      "Send message",
      "Send file",
      "Request file",
    ])
      requireState(
        !(await main.getByRole("button", { name, exact: true }).isVisible()),
        "assistance_tools_before_consent",
      );
    await capture(
      ctx,
      "waiting-dark-mobile",
      "Waiting for consent",
      "No screen or input is shared. Take control is disabled with its reason; inactive tools do not fill the page.",
    );
    // A task modal must own keyboard shortcuts, including mobile navigation.
    const navigationTrigger = page.getByRole("button", { name: "Toggle navigation", exact: true });
    await navigationTrigger.click();
    const navigation = page.getByRole("dialog", { name: "Navigation", exact: true });
    await navigation.waitFor();
    await settledTransitions(page);
    await page.keyboard.press("Control+k");
    requireState(!(await search.isVisible()), "search_stacked_over_navigation");
    await capture(
      ctx,
      "navigation-dark-mobile",
      "Mobile navigation",
      "Navigation retains the current Devices page and does not open a second modal on Control K.",
    );
    await page.keyboard.press("Escape");
    await navigation.waitFor({ state: "hidden" });
    await page.waitForFunction(() => !document.querySelector('[role="dialog"]'));
    requireState(
      await navigationTrigger.evaluate((node) => document.activeElement === node),
      "assistance_mobile_navigation_focus_lost",
    );
    await page.setViewportSize({ width: 1440, height: 900 });
    await theme("light");
    const visibleBreadcrumbs = await page
      .getByRole("navigation")
      .evaluateAll(
        (nodes) =>
          nodes.filter(
            (node) =>
              /breadcrumbs?/i.test(node.getAttribute("aria-label") ?? "") &&
              node.getClientRects().length,
          ).length,
      );
    requireState(visibleBreadcrumbs === 1, "assistance_duplicate_desktop_breadcrumbs");
    await capture(
      ctx,
      "waiting-light-desktop",
      "Waiting for consent",
      "One breadcrumb trail identifies the device; the stop action and actual consent wait remain prominent.",
    );
    await main.getByRole("button", { name: "Stop session", exact: true }).click();
    await main.locator('[data-assistance-state="ended"]').waitFor();
    openRequest = false;
    await main.getByText("Request record. The device shared nothing.", { exact: true }).waitFor();
    requireState(!(await takeControl.isVisible()), "assistance_ended_control_visible");
    requireState(
      !(await main.getByRole("region", { name: "Remote screen", exact: true }).isVisible()),
      "assistance_ended_screen_visible",
    );
    await main.getByText(reason, { exact: true }).waitFor();
    await capture(
      ctx,
      "ended-light-desktop",
      "Ended request record",
      "Stopping immediately shows the cause and reason as history, without live controls or a stale screen.",
    );
    await page.setViewportSize({ width: 390, height: 844 });
    await theme("dark");
    await capture(
      ctx,
      "ended-dark-mobile",
      "Ended request record on mobile",
      "The record fits mobile dark mode and explicitly requires fresh consent for another request.",
    );
    await main.getByRole("link", { name: "Return to device", exact: true }).click();
    await main.getByRole("heading", { name: "Session history", exact: true }).waitFor();
    requireState(
      new URL(page.url()).searchParams.get("tab") === "assistance",
      "assistance_return_lost_context",
    );
    const recordLink = main.locator(`a[href=${JSON.stringify(sessionPath)}]`);
    await recordLink.waitFor();
    await main.getByText(reason, { exact: true }).waitFor();
    await capture(
      ctx,
      "return-to-history",
      "Device assistance history",
      "Return to device opens the assistance tab in one action, with this request's support reason and record link.",
    );
    await recordLink.click();
    await main.locator('[data-assistance-state="ended"]').waitFor();
    await main.getByText(reason, { exact: true }).waitFor();
    await capture(
      ctx,
      "history-record",
      "Session history record",
      "The device history opens this exact stopped request and preserves its support reason, not current access.",
    );
    return {
      outcome: "blocked",
      reason:
        "Completed hostname search, mobile navigation, theme and breadcrumb checks, requested support, observed consent waiting, stopped and reopened the exact record. Native viewing, control, clipboard, special keys, messages and files require the maintained assistance VM lane; the synthetic fixture cannot answer user consent or prove those effects.",
    };
  } finally {
    if (openRequest) {
      const stop = main.getByRole("button", { name: "Stop session", exact: true });
      if (await stop.isVisible()) {
        await stop.click();
        await main.locator('[data-assistance-state="ended"]').waitFor();
      } else await ctx.visit("/devices");
    }
    await page.setViewportSize({ width: 1440, height: 900 });
    await theme("light");
  }
}

export const journeys = [
  { id: "remote-help", title: "Help a user and review the session record", run: remoteHelp },
];
