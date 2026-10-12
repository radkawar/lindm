// Real console scenarios, backed by the review's missing-publication and signed
// publication fixtures. No RPC interception or fabricated readiness responses.
import { ChromiumDriver, UI } from "./drivers.mjs";
import { enroll, signIn } from "./journey.mjs";

export async function reviewEnrollmentFixtures({
  driver,
  pages,
  combos,
  config,
  protectSecret,
  ...helpers
}) {
  const results = [];
  await driver.context.grantPermissions(["clipboard-read", "clipboard-write"], {
    origin: config.origin,
  });
  for (const [index, { theme, viewport }] of combos.entries()) {
    results.push(
      ...(await reviewEnrollment({
        page: pages[index],
        origin: config.origin,
        theme,
        viewport,
        ready: false,
        protectSecret,
        ...helpers,
      })),
    );
  }

  // A distinct browser context is required: cookie scope does not include ports.
  const published = new ChromiumDriver();
  await published.open({ ignoreHTTPSErrors: true, actionTimeoutMs: 30_000 });
  try {
    const fixture = config.enrollmentFixture;
    await published.context.grantPermissions(["clipboard-read", "clipboard-write"], {
      origin: fixture.origin,
    });
    await published.context.addInitScript(() => {
      try {
        localStorage.removeItem("lindm-theme");
      } catch {
        /* Theme still follows the emulated system preference. */
      }
    });
    await published.authenticator([]);
    await published.goto(fixture.origin);
    const ui = new UI(published, 30_000);
    await enroll(ui, fixture);
    await signIn(ui, fixture);
    for (const { theme, viewport } of combos) {
      await published.page.setViewportSize({ width: viewport.width, height: viewport.height });
      await published.page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      results.push(
        ...(await reviewEnrollment({
          page: published.page,
          origin: fixture.origin,
          theme,
          viewport,
          ready: true,
          protectSecret,
          ...helpers,
        })),
      );
    }
  } finally {
    await published.close();
  }
  return results;
}
const choices = ["Ubuntu 24.04 LTS", "Fedora 44"];

const contracts = {
  "/settings": {
    headings: ["Settings", "Agent repository"],
    buttons: ["Refresh"],
    disclosure: "Repository and trust details",
  },
  "/enrollment": {
    heading: "One-time enrollment code",
    chooser: "Operating system",
    command: "Install and enroll command",
    copy: "Copy install command",
    disclosure: "What this does",
  },
};
async function reviewEnrollment({
  page,
  origin,
  theme,
  viewport,
  ready,
  protectSecret,
  screenshot,
  axe,
  probe,
  settle,
}) {
  const results = [];
  const publication = ready ? "published" : "missing-publication";
  async function record(route, variant, operation) {
    const prefix = `${route.slice(1)}-${publication}-${variant}-${theme}-${viewport.name}`;
    const entry = {
      route,
      url: route,
      variant: `${publication} ${variant}`,
      theme,
      viewport: viewport.name,
      size: `${viewport.width}x${viewport.height}`,
      passed: false,
      screenshots: {},
      checks: { contract: { findings: [] } },
    };
    const findings = entry.checks.contract.findings;
    function require(value, message) {
      if (!value) findings.push({ message, elements: [] });
    }
    try {
      await operation(require, prefix, entry);
      // Opening a disclosure can scroll the page below its sticky header.
      // Judge the same initial viewport as the task screenshot, not content
      // intentionally occluded by that header after an interaction.
      await page.evaluate(() => {
        window.scrollTo(0, 0);
        const dialog = document.querySelector('[role="dialog"]');
        if (dialog) dialog.scrollTop = 0;
      });
      await settle(page);
      entry.screenshots.full = await screenshot(page, `${prefix}-full.png`, true);
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
    } catch {
      // Browser diagnostics can include the shown-once credential or command.
      findings.push({
        message: "Enrollment review could not complete the named scenario",
        elements: [],
      });
      // The edit sheet requires a full-page capture of every scenario, failed ones included.
      entry.screenshots.failure = await screenshot(page, `${prefix}-failure.png`, true);
      entry.screenshots.full = entry.screenshots.failure;
    }
    entry.passed = Object.values(entry.checks).every((check) => check.findings.length === 0);
    results.push(entry);
  }

  await record("/settings", "repository-readiness", async (require, prefix, entry) => {
    const contract = contracts["/settings"];
    await page.goto(`${origin}/settings`);
    await settle(page);
    for (const name of contract.headings)
      await page.getByRole("heading", { name, exact: true }).waitFor();
    for (const name of contract.buttons)
      require(await page
        .getByRole("button", { name, exact: true })
        .isEnabled(), "Settings refresh is unavailable");
    const status = ready ? "Ready for listed platforms" : "Installation needs setup";
    await page.getByText(status, { exact: true }).waitFor();
    const section = page.getByRole("region", { name: "Agent repository" });
    for (const label of choices) await section.getByText(label, { exact: true }).waitFor();
    require(!(await section.innerText()).includes(
      "releaseRepository",
    ), "Primary repository text names server configuration keys");
    require((await section
      .getByRole("link", { name: "Server setup guide", exact: true })
      .count()) === 1, "Repository readiness does not link the server setup guide");
    entry.screenshots.viewport = await screenshot(page, `${prefix}.png`, false);
    const details = page.locator("summary").filter({ hasText: contract.disclosure });
    await details.click();
    // Technical details label each value as a term ("Label: value").
    await page
      .getByRole("term")
      .filter({ hasText: /^Execution root SHA-256:?\s*$/ })
      .waitFor();
    require((await section.innerText()).includes(
      ready ? `${origin}/repo/apt` : "Not published",
    ), "Repository details do not match this fixture's publication state");
    if (!ready)
      require((await section.innerText()).includes(
        "releaseRepository.directory/repo",
      ), "Missing repository details do not name the publication configuration remedy");
    entry.screenshots.details = await screenshot(page, `${prefix}-details.png`, false);
    await details.click();
  });

  await page.goto(`${origin}/enrollment`);
  await settle(page);
  const contract = contracts["/enrollment"];
  await page.getByRole("button", { name: "Create one-time code", exact: true }).click();
  const creation = page.getByRole("dialog");
  await creation
    .getByLabel("Reason", { exact: true })
    .fill("UI review of server-hosted agent installation");
  await creation.getByRole("button", { name: "Create one-time code", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("heading", { name: contract.heading, exact: true }).waitFor();
  await dialog.getByLabel(contract.chooser, { exact: true }).waitFor();
  const secret = await dialog.getByLabel(contract.heading, { exact: true }).inputValue();
  protectSecret(secret);
  protectSecret(btoa(secret));

  try {
    for (const [index, label] of choices.entries()) {
      await record(
        "/enrollment",
        index === 0 ? "ubuntu-install" : "fedora-install",
        async (require, prefix, entry) => {
          const chooser = dialog.getByLabel(contract.chooser, { exact: true });
          if (ready && index === 0) {
            // The published fixture has no devices, so no OS can be preselected.
            await settle(page);
            require((await chooser.innerText()).trim() ===
              "Choose an OS", "An empty fleet preselects an operating system");
            require((await dialog
              .getByRole("button", { name: contract.copy, exact: true })
              .count()) === 0, "An install command is offered before an OS is chosen");
          }
          await chooser.click();
          await page.getByRole("option", { name: label, exact: true }).waitFor();
          const options = await page.getByRole("option").allTextContents();
          for (const family of [
            /Ubuntu/,
            /Debian/,
            /Mint/,
            /Pop/,
            /Fedora/,
            /RHEL|Red Hat/,
            /Rocky/,
            /Alma/,
            /openSUSE/,
            /Arch/,
          ]) {
            require(options.some((option) =>
              family.test(option),
            ), `Operating system choices omit ${family.source}`);
          }
          await page.getByRole("option", { name: label, exact: true }).click();
          await page.getByRole("listbox").waitFor({ state: "hidden" });
          const copy = dialog.getByRole("button", { name: contract.copy, exact: true });
          const command = dialog.getByLabel(contract.command, { exact: true });
          if (ready) {
            await copy.waitFor();
            require(await copy.isEnabled(), "Published repository does not enable the install command");
            await page.evaluate(() => navigator.clipboard.writeText(""));
            await copy.click();
            await dialog
              .getByRole("status")
              .filter({ hasText: "Install command copied." })
              .waitFor();
            const matches = await page.evaluate(async () => {
              const shown = document.querySelector(
                'textarea[aria-label="Install and enroll command"]',
              )?.value;
              const copied = await navigator.clipboard.readText();
              await navigator.clipboard.writeText("");
              return !!shown && copied === shown;
            });
            require(matches, "Copy install command did not reproduce the displayed command");
          } else {
            const settings = dialog.getByRole("link", { name: /^Settings › Agent repository/ });
            await settings.waitFor();
            require((await settings.getAttribute("href")) ===
              "/settings#agent-repository", "Missing repository does not link to Settings › Agent repository");
            require((await copy.count()) ===
              0, "Missing repository still offers an install command copy");
            require((await command.count()) ===
              0, "Missing repository still shows an install command field");
            require(!(await dialog.innerText()).includes(
              "releaseRepository",
            ), "Missing repository shows server configuration keys");
          }
          await dialog.evaluate((node) => {
            node.scrollTop = 0;
          });
          entry.screenshots.viewport = await screenshot(page, `${prefix}.png`, false);
          if (ready) {
            const details = dialog.locator("summary").filter({ hasText: contract.disclosure });
            require(!(await details.evaluate(
              (node) => node.parentElement.open,
            )), "What this does is not collapsed initially");
            await details.click();
            require((await dialog.innerText()).includes(
              "Authenticates the package signing key",
            ), "What this does omits signer authentication");
            await details.scrollIntoViewIfNeeded();
            entry.screenshots.details = await screenshot(page, `${prefix}-details.png`, false);
            await details.click();
          }
        },
      );
    }
  } finally {
    await page.evaluate(() => navigator.clipboard.writeText(""));
    await dialog.getByRole("button", { name: "Done, forget secret", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
    // The fixture owns and deletes these unused one-time credentials at Close.
  }
  return results;
}
