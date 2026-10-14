// SPDX-License-Identifier: Apache-2.0

// Real profile authoring, never an intercepted or synthetic mutation response.
// The draft is deliberately not published or assigned by a visual review.
export async function reviewOSUpdate({ pages, combos, config, screenshot, axe, probe, settle }) {
  const results = [];
  for (const [index, { theme, viewport }] of combos.entries()) {
    const page = pages[index];
    const prefix = `profiles-os-update-${theme}-${viewport.name}`;
    const entry = {
      route: "/profiles/new",
      url: "/profiles/new",
      variant: "Independent restart window",
      theme,
      viewport: viewport.name,
      size: `${viewport.width}x${viewport.height}`,
      passed: false,
      screenshots: {},
      checks: { contract: { findings: [] } },
    };
    try {
      await page.goto(`${config.origin}/profiles/new`);
      await page.getByRole("button", { name: "Add setting", exact: true }).waitFor();
      if ((await page.getByLabel("Setting type", { exact: true }).count()) === 0) {
        await page.getByRole("button", { name: "Add setting", exact: true }).click();
      }
      await page.getByLabel("Setting type", { exact: true }).first().click();
      await page.getByRole("option", { name: "OS update policy", exact: true }).click();
      // Capture the selected setting even on an older binary, so before-review
      // evidence remains available when the new controls are correctly absent.
      await page.evaluate(() => window.scrollTo(0, 0));
      await settle(page);
      entry.screenshots.initial = await screenshot(page, `${prefix}-initial.png`, true);
      await page.getByLabel("Use a separate restart window", { exact: true }).check();
      await page.getByLabel("Allow employees to defer a restart", { exact: true }).check();
      await page
        .getByLabel("Restart deadline after updates (minutes)", { exact: true })
        .fill("360");
      await page.getByLabel("Start time", { exact: true }).nth(1).fill("06:00");
      await page.getByLabel("Maximum deferrals", { exact: true }).fill("2");
      await page.getByLabel("Defer each restart by (minutes)", { exact: true }).fill("30");
      const setting = page.getByRole("group", { name: "Setting 1", exact: true });
      const body = await setting.innerText();
      for (const text of [
        "Install updates",
        "Restart devices",
        "The device schedules no restart if no allowed time fits before the deadline.",
        "Deferrals move to the next allowed time, never beyond the deadline.",
      ]) {
        if (!body.includes(text))
          entry.checks.contract.findings.push({
            message: `OS update editor omits ${text}`,
            elements: [],
          });
      }
      await page.evaluate(() => window.scrollTo(0, 0));
      await settle(page);
      entry.screenshots.full = await screenshot(page, `${prefix}-full.png`, true);
      await page
        .getByRole("heading", { name: "Restart devices", exact: true })
        .scrollIntoViewIfNeeded();
      entry.screenshots.restart = await screenshot(page, `${prefix}-restart.png`, false);
      await page.evaluate(() => window.scrollTo(0, 0));
      const violations = await axe(page, null);
      entry.checks.axe = {
        violations,
        findings: violations
          .filter((item) => item.blocking)
          .map((item) => ({
            message: `${item.id} (${item.impact}): ${item.help}`,
            elements: item.nodes.map((node) => node.target),
          })),
      };
      entry.checks.layout = { findings: await probe(page, "layout", viewport.name === "desktop") };
      entry.checks.copy = { findings: await probe(page, "copy") };
    } catch (error) {
      entry.checks.contract.findings.push({
        message: `OS update authoring review failed: ${error.message}`,
        elements: [],
      });
      entry.screenshots.full = await screenshot(page, `${prefix}-failure.png`, true);
    }
    entry.passed = Object.values(entry.checks).every((check) => check.findings.length === 0);
    results.push(entry);
  }
  return results;
}
