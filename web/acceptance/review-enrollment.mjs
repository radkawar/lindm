// SPDX-License-Identifier: Apache-2.0

// Real stock console scenarios and a deliberately absent signed artifact.
// Missing repository configuration alone is not an installation failure.
import { ChromiumDriver } from "./drivers.mjs";
import { reviewSetup } from "./review-setup.mjs";
import { packageSourcePrerequisite } from "./review-journeys-policy.mjs";

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
        publication: "stock-fleet",
        ready: true,
        protectSecret,
        ...helpers,
      })),
    );
  }

  // A distinct browser context is required: cookie scope does not include ports.
  for (const [fixture, publication, ready] of [
    [config.enrollmentFixture, "stock-empty-fleet", true],
    [config.missingArtifactFixture, "missing-artifact", false],
  ]) {
    const published = new ChromiumDriver();
    await published.open({ ignoreHTTPSErrors: true, actionTimeoutMs: 30_000 });
    try {
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
      results.push(
        ...(await reviewSetup({ driver: published, fixture, publication, combos, ...helpers })),
      );
      for (const { theme, viewport } of combos) {
        await published.page.setViewportSize({ width: viewport.width, height: viewport.height });
        await published.page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
        results.push(
          ...(await reviewEnrollment({
            page: published.page,
            origin: fixture.origin,
            theme,
            viewport,
            publication,
            ready,
            emptyFleet: true,
            protectSecret,
            ...helpers,
          })),
        );
      }
      if (publication === "stock-empty-fleet") {
        await published.page.setViewportSize({ width: 1440, height: 900 });
        await published.page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
        const entry = {
          route: "/profiles/new",
          url: "/profiles/new",
          variant: `${publication} package-source-prerequisite`,
          theme: "light",
          viewport: "desktop",
          size: "1440x900",
          passed: false,
          screenshots: {},
          checks: { contract: { findings: [] } },
        };
        try {
          entry.screenshots.prerequisite = await packageSourcePrerequisite(
            published.page,
            helpers.screenshot,
          );
          entry.screenshots.full = entry.screenshots.prerequisite;
          entry.passed = true;
        } catch {
          entry.checks.contract.findings.push({
            message:
              "The empty stock fixture does not explain the approved package source prerequisite.",
            elements: [],
          });
          entry.screenshots.blocked = await helpers.screenshot(
            published.page,
            "package-source-prerequisite-blocked.png",
            true,
          );
          entry.screenshots.full = entry.screenshots.blocked;
        }
        results.push(entry);
      }
    } finally {
      await published.close();
    }
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
  },
};
async function reviewEnrollment({
  page,
  origin,
  theme,
  viewport,
  ready,
  publication,
  emptyFleet = false,
  protectSecret,
  screenshot,
  axe,
  probe,
  settle,
}) {
  const results = [];
  const main = page.getByRole("main");
  let step = "open scenario";
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
    } catch (error) {
      // Browser diagnostics can include the shown-once credential or command.
      findings.push({
        message: `Enrollment review could not complete: ${step} (${error?.name ?? "Error"})`,
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
    step = "read repository readiness";
    await page.goto(`${origin}/settings`);
    await settle(page);
    for (const name of contract.headings)
      await main.getByRole("heading", { name, exact: true }).waitFor();
    // The page Refresh is disabled while any read on the page is in flight
    // (readiness, attributes, capabilities); it must become available, not
    // be enabled at one arbitrary instant.
    for (const name of contract.buttons) {
      const button = main.getByRole("button", { name, exact: true });
      let enabled = false;
      for (const deadline = Date.now() + 15_000; !enabled && Date.now() < deadline;) {
        enabled = await button.isEnabled();
        if (!enabled) await page.waitForTimeout(250);
      }
      require(enabled, "Settings refresh is unavailable");
    }
    const status = ready ? "Ready" : "Repository needs attention";
    await page.getByText(status, { exact: true }).waitFor();
    const section = page.getByRole("region", { name: "Agent repository" });
    for (const label of choices) await section.getByText(label, { exact: true }).waitFor();
    require(!(await section.innerText()).includes(
      "releaseRepository",
    ), "Primary repository text names server configuration keys");
    require((await section
      .getByRole("link", { name: "Installation guide", exact: true })
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
    ), "Repository details do not match this fixture's artifact state");
    if (!ready)
      require((await section.innerText()).includes(
        "reinstall the signed lindmd release bundle",
      ), "Missing artifact details do not name the release installation remedy");
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
  const creationSuccessToastVisible =
    (await page
      .locator('[data-sonner-toast][data-type="success"]')
      .filter({ visible: true })
      .count()) !== 0;
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
          if (index === 0)
            require(!creationSuccessToastVisible, "Creation duplicates the shown-once result with a success toast");
          step = "choose operating system";
          const chooser = dialog.getByLabel(contract.chooser, { exact: true });
          if (emptyFleet && ready && index === 0) {
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
            step = "copy install command";
            await copy.waitFor();
            require(await copy.isEnabled(), "Published repository does not enable the install command");
            await page.evaluate(() => navigator.clipboard.writeText(""));
            await copy.click();
            await dialog
              .getByRole("status")
              .filter({ hasText: /^Install command copied\./ })
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
            step = "read missing artifact remedy";
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
          step = "review forget-secret action";
          await settle(page);
          const forget = dialog.getByRole("button", { name: "Done, forget secret", exact: true });
          const forgetUncovered = await forget.evaluate((node) => {
            const rect = node.getBoundingClientRect();
            const popup = node.closest('[role="dialog"]')?.getBoundingClientRect();
            if (
              !popup ||
              rect.width < 24 ||
              rect.height < 24 ||
              rect.left < Math.max(0, popup.left) ||
              rect.top < Math.max(0, popup.top) ||
              rect.right > Math.min(window.innerWidth, popup.right) ||
              rect.bottom > Math.min(window.innerHeight, popup.bottom)
            )
              return false;
            const hit = document.elementFromPoint(
              rect.left + rect.width / 2,
              rect.top + rect.height / 2,
            );
            return hit === node || node.contains(hit);
          });
          require(forgetUncovered, "The forget-secret action is clipped or covered");
          entry.screenshots.viewport = await screenshot(page, `${prefix}.png`, false);
          if (ready) {
            step = "review install trust disclosure";
            const details = dialog.locator("summary").filter({ hasText: /^Details$/ });
            require(!(await details.evaluate(
              (node) => node.parentElement.open,
            )), "Install details are not collapsed initially");
            await details.click();
            require((await dialog.innerText()).includes(
              "authenticates the package signing key",
            ), "Install details omit signer authentication");
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
