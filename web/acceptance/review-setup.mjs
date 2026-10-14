// SPDX-License-Identifier: Apache-2.0

import { consoleSetupDNSWarning } from "../src/features/auth/setup-origin.ts";

// Can also be run on an IP-origin setup page without attempting a passkey ceremony.
export async function reviewSetupDNSWarning(page, require) {
  const hostname = await page.evaluate(() => window.location.hostname);
  const warning = consoleSetupDNSWarning(hostname);
  const alert = page.locator("#setup-dns-warning");
  if (warning) {
    require(await alert.isVisible(), "IP-origin setup omitted the DNS requirement warning");
    require((await alert.innerText()).includes(warning), "IP-origin setup lost DNS remediation");
  } else {
    require((await alert.count()) === 0, "DNS-origin setup incorrectly displayed an IP warning");
  }
}
// Real first-run browser ceremonies with signed or deliberately absent publication.
// No HTTP/RPC interception or fabricated authentication/readiness response.
export async function reviewSetup({
  driver,
  fixture,
  publication,
  combos,
  screenshot,
  axe,
  probe,
  settle,
}) {
  const results = [];
  const page = driver.page;
  async function record(variant, theme, viewport, operation) {
    const prefix = `setup-${publication}-${variant}-${theme}-${viewport.name}`;
    const entry = {
      route: variant === "completed-dashboard" ? "/dashboard" : "/setup",
      url: variant === "completed-dashboard" ? "/dashboard" : "/setup",
      variant,
      publication,
      theme,
      viewport: viewport.name,
      size: `${viewport.width}x${viewport.height}`,
      passed: false,
      screenshots: {},
      checks: { contract: { findings: [] } },
    };
    const findings = entry.checks.contract.findings;
    const require = (value, message) => {
      if (!value) findings.push({ message, elements: [] });
    };
    try {
      await operation(require);
      await settle(page);
      entry.screenshots.viewport = await screenshot(page, `${prefix}.png`, false);
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
      require(!page.url().includes(fixture.setupCode), "Setup capability entered the URL");
      const stored = await page.evaluate(() =>
        JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }),
      );
      require(!stored.includes(fixture.setupCode) &&
        !stored.includes(
          fixture.password,
        ), "Setup authentication material entered browser storage");
    } catch {
      // Framework exceptions can include filled credentials. Never retain them.
      findings.push({ message: `Setup review could not complete ${variant}`, elements: [] });
      entry.screenshots.failure = await screenshot(page, `${prefix}-failure.png`, true);
      entry.screenshots.full = entry.screenshots.failure;
    }
    entry.passed = Object.values(entry.checks).every((check) => check.findings.length === 0);
    results.push(entry);
  }
  async function fill(code) {
    await page.getByLabel("Setup code", { exact: true }).fill(code);
    await page.getByLabel("Username", { exact: true }).fill(fixture.username);
    await page.getByLabel("Password", { exact: true }).fill(fixture.password);
  }
  await driver.cdp.send("WebAuthn.setAutomaticPresenceSimulation", {
    authenticatorId: driver.authenticatorId,
    enabled: false,
  });
  for (const { theme, viewport } of combos) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await page.goto(`${fixture.origin}/setup`);
    await record("first-run", theme, viewport, async (require) => {
      await page.getByRole("heading", { name: "Set up your owner account", exact: true }).waitFor();
      require(await page
        .getByRole("img", { name: "lindm", exact: true })
        .isVisible(), "First-run setup does not identify the console");
      await page.getByLabel("Setup code", { exact: true }).waitFor();
      require(await page
        .getByText(
          "Use at least 12 bytes. Have a security key or passkey ready for the next step.",
          { exact: true },
        )
        .isVisible(), "Setup password and authenticator prerequisites are absent");
      require(await page
        .getByText(
          "If this console uses a private CA, import the console CA printed by the installer, not the device CA. A publicly trusted console certificate needs no custom CA import.",
          { exact: true },
        )
        .isVisible(), "Setup does not distinguish private console trust from device trust and public CA trust");
      await reviewSetupDNSWarning(page, require);
      require(await page
        .getByRole("button", { name: "Create owner account", exact: true })
        .isEnabled(), "Owner setup action is unavailable");
      require(await page
        .getByText("This account controls administrator access and device management.", {
          exact: false,
        })
        .isVisible(), "Owner authority warning is absent");
    });
    await record("wrong-code", theme, viewport, async () => {
      await fill("A".repeat(43));
      await page.getByRole("button", { name: "Create owner account", exact: true }).click();
      await page.getByText("Check your setup details", { exact: true }).waitFor();
    });
    await record("cancelled-passkey", theme, viewport, async (require) => {
      await fill(fixture.setupCode);
      const [response] = await Promise.all([
        page.waitForResponse(
          (response) =>
            response.url().endsWith("/auth/setup/begin") && response.request().method() === "POST",
        ),
        page.getByRole("button", { name: "Create owner account", exact: true }).click(),
      ]);
      require(response.status() === 200, "Authorized setup did not reserve its account");
      await page.getByRole("button", { name: "Cancel", exact: true }).click();
      await page.getByRole("button", { name: "Create owner account", exact: true }).waitFor();
      require(await page
        .getByText("If you stop, continue with the same setup code, username and password.", {
          exact: true,
        })
        .isVisible(), "Interrupted setup lost its safe continuation advice");
      const status = await page.evaluate(
        async () =>
          (await fetch("/auth/session", { credentials: "same-origin", cache: "no-store" })).status,
      );
      require(status === 401, "Cancelled passkey setup created an authenticated session");
    });
  }
  await driver.cdp.send("WebAuthn.setAutomaticPresenceSimulation", {
    authenticatorId: driver.authenticatorId,
    enabled: true,
  });
  await fill(fixture.setupCode);
  await page.getByRole("button", { name: "Create owner account", exact: true }).click();
  await page.waitForURL(/\/dashboard(?:[?#]|$)/, { timeout: 30_000 });
  for (const { theme, viewport } of combos) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await record("completed-dashboard", theme, viewport, async (require) => {
      await page.getByRole("heading", { name: "Dashboard", exact: true }).waitFor();
      const session = await page.evaluate(async () => {
        const response = await fetch("/auth/session", {
          credentials: "same-origin",
          cache: "no-store",
        });
        return response.ok ? response.json() : null;
      });
      require(session?.displayName === fixture.username &&
        session?.role === "owner", "Dashboard does not identify the newly enrolled owner");
    });
  }
  return results;
}
