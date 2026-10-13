import { ChromiumDriver } from "./drivers.mjs";

// Only transport routing is replaced: every page, RPC and cookie comes from the
// disposable real server. The logical Origin/Host and Keycloak code/PKCE flow are
// preserved, without touching the shared development server at that public port.
async function openDirectoryBrowser(fixture) {
  const driver = new ChromiumDriver();
  await driver.open({
    ignoreHTTPSErrors: true,
    actionTimeoutMs: 30_000,
    // Browser DNS routing also covers redirects; Playwright route interception
    // only handles the first request in a redirect chain.
    browserArgs: [`--host-resolver-rules=MAP ${new URL(fixture.origin).host} ${fixture.address}`],
  });
  let failSourceRead = false;
  await driver.context.route(`${fixture.origin}/auth/settings`, async (route) => {
    if (failSourceRead) await route.abort("connectionfailed");
    else await route.continue();
  });
  await driver.context.addInitScript(() => localStorage.removeItem("lindm-theme"));
  return {
    driver,
    failSourceRead: (value) => {
      failSourceRead = value;
    },
  };
}

export async function reviewDirectoryAuthorization({
  config,
  combos,
  screenshot,
  axe,
  probe,
  settle,
  keyboard,
  protectSecret,
}) {
  const fixture = config.directoryFixture;
  if (!fixture?.ownerCookies?.length || !fixture.readerPassword)
    throw new Error("Real directory authorization review credentials are unavailable");
  protectSecret(fixture.readerPassword);
  for (const cookie of fixture.ownerCookies) protectSecret(cookie.value);
  const results = [];
  const owner = await openDirectoryBrowser(fixture);
  async function prepare(page, theme, viewport) {
    page.setDefaultTimeout(30_000);
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
  }
  function entryFor(theme, viewport, variant) {
    const entry = {
      route: "/authorization",
      url: "/authorization",
      variant,
      theme,
      viewport: viewport.name,
      size: `${viewport.width}x${viewport.height}`,
      passed: false,
      screenshots: {},
      checks: { contract: { findings: [] } },
    };
    results.push(entry);
    return entry;
  }
  function require(entry, value, message) {
    if (!value) entry.checks.contract.findings.push({ message, elements: [] });
  }
  async function capture(page, entry, name) {
    await page.evaluate(() => window.scrollTo(0, 0));
    await settle(page);
    const prefix = `directory-authorization-${entry.theme}-${entry.viewport}-${entry.variant}`;
    entry.screenshots[name] = await screenshot(page, `${prefix}-${name}.png`, true);
    // The scenario's first state is its edit-sheet capture.
    entry.screenshots.full ??= entry.screenshots[name];
    const violations = await axe(page, null);
    entry.checks[`axe-${name}`] = {
      findings: violations
        .filter((item) => item.blocking)
        .map((item) => ({
          message: `${item.id}: ${item.help}`,
          elements: item.nodes.map((node) => node.target),
        })),
    };
    entry.checks[`layout-${name}`] = {
      findings: await probe(page, "layout", entry.viewport === "desktop"),
    };
    entry.checks[`copy-${name}`] = { findings: await probe(page, "copy") };
    entry.checks[`keyboard-${name}`] = await keyboard(page);
  }
  async function select(page, scope, label, name) {
    await scope.getByRole("button", { name: new RegExp(`^${label}\\b`) }).click();
    await page.getByRole("option").filter({ hasText: name }).first().click();
  }
  async function save(page) {
    await page
      .getByLabel("Reason", { exact: true })
      .fill("Review real directory group access and named device scope");
    await page
      .getByLabel("I reviewed the complete access policy and sign-out consequences.", {
        exact: true,
      })
      .check();
    await page.getByRole("button", { name: "Save access policy", exact: true }).click();
    await page.getByRole("button", { name: "Edit access policy", exact: true }).waitFor();
  }
  try {
    await owner.driver.context.addCookies(
      fixture.ownerCookies.map((cookie) => ({
        ...cookie,
        url: fixture.origin,
        secure: true,
        httpOnly: true,
        sameSite: "Lax",
      })),
    );
    for (const [index, { theme, viewport }] of combos.entries()) {
      const page = owner.driver.page;
      const entry = entryFor(theme, viewport, "owner");
      let step = "open directory policy";
      await prepare(page, theme, viewport);
      try {
        await page.goto(`${fixture.origin}/authorization`);
        await page.getByRole("button", { name: "Edit access policy", exact: true }).click();
        const section = page.getByRole("region", { name: "Edit directory access", exact: true });
        const first = section.locator("div.grid.min-w-0.gap-4.border.p-4").first();
        step = "select known binding and named device";
        await select(page, first, "Directory group 1", fixture.knownGroup);
        const role = index % 2 === 0 ? "directory-review-auditor" : "directory-review-reader";
        await select(page, first, "Role", role);
        const devices = first.getByRole("group", { name: "Devices", exact: true });
        if ((await devices.getByRole("button", { name: /^Devices 1\b/ }).count()) === 0)
          await devices.getByRole("button", { name: "Add selection", exact: true }).click();
        await select(page, devices, "Devices 1", fixture.allowedHostname);
        await capture(page, entry, "known-binding-and-device-scope");
        step = "edit source-issued Advanced reference";
        if (index === 0)
          await section
            .getByRole("button", { name: "Add directory group access", exact: true })
            .click();
        const second = section.locator("div.grid.min-w-0.gap-4.border.p-4").nth(1);
        await second.getByText("Advanced directory setup", { exact: true }).click();
        await second.getByLabel("Keycloak group path", { exact: true }).fill(fixture.advancedGroup);
        await capture(page, entry, "source-issued-advanced-reference");
        await second.getByRole("button", { name: "Use directory reference", exact: true }).click();
        await select(page, second, "Role", "directory-review-reader");
        if (index === 0) {
          await second.getByRole("button", { name: "Add rule", exact: true }).click();
          const groups = second.getByRole("group", { name: "Device groups", exact: true });
          await groups.getByRole("button", { name: "Add selection", exact: true }).click();
          await select(page, groups, "Device groups 1", fixture.deviceGroup);
        }
        step = "commit directory policy";
        await save(page);
        await capture(page, entry, "directory-policy-saved");
        const snapshot = await page.evaluate(async () => {
          const session = await fetch("/auth/session").then((response) => response.json());
          const response = await fetch("/lindm.admin.v1.AdminService/GetAuthorization", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Connect-Protocol-Version": "1",
              "X-CSRF-Token": session.csrfToken,
            },
            body: "{}",
          });
          if (!response.ok) throw new Error("Read committed directory policy failed");
          return response.json();
        });
        require(entry, snapshot.authorization?.policy?.groupBindings?.some(
          (binding) =>
            binding.group === fixture.knownGroup &&
            binding.role === role &&
            binding.scopes?.some((scope) => scope.deviceIds?.includes(fixture.allowedDeviceId)),
        ), "Saved group role/device selection did not reach real runtime policy");
        require(entry, snapshot.authorization?.policy?.groupBindings?.some(
          (binding) => binding.group === fixture.advancedGroup,
        ), "Source-issued Advanced reference was not committed");
        step = "deny editing after source-settings transport failure";
        owner.failSourceRead(true);
        await page.reload();
        await page.getByRole("alert").first().waitFor();
        require(entry, (await page
          .getByRole("button", { name: "Edit access policy", exact: true })
          .count()) === 0, "Failed source-settings read still offered a replacement policy");
        await capture(page, entry, "failed-source-settings-read");
      } catch {
        entry.checks.contract.findings.push({
          message: `Real directory binding review did not complete: ${step}`,
          elements: [],
        });
        entry.screenshots.failure = await screenshot(
          page,
          `directory-authorization-${theme}-${viewport.name}-owner-failure.png`,
          true,
        );
        entry.screenshots.full ??= entry.screenshots.failure;
      } finally {
        owner.failSourceRead(false);
      }
      entry.passed = Object.values(entry.checks).every((check) => check.findings.length === 0);
    }
  } finally {
    await owner.driver.close();
  }

  const reader = await openDirectoryBrowser(fixture);
  const loginResponses = [];
  reader.driver.page.on("response", (response) => {
    const path = new URL(response.url()).pathname;
    if (path.startsWith("/auth/") || path.startsWith("/realms/"))
      loginResponses.push(`${response.status()} ${path}`);
  });
  reader.driver.page.on("requestfailed", (request) => {
    const url = new URL(request.url());
    loginResponses.push(
      `${request.failure()?.errorText ?? "request failed"} ${url.origin}${url.pathname}`,
    );
  });
  let loginStep = "open real Keycloak login";
  try {
    const page = reader.driver.page;
    await page.goto(`${fixture.origin}/auth/login`);
    loginStep = "enter real directory credentials";
    await page.locator("#username").fill(fixture.readerUsername);
    await page.locator("#password").fill(fixture.readerPassword);
    loginStep = "complete real Keycloak code and PKCE callback";
    await page.locator("#kc-login").click();
    await page.waitForURL(
      (url) => url.origin === fixture.origin && !url.pathname.startsWith("/auth/"),
    );
    for (const { theme, viewport } of combos) {
      const entry = entryFor(theme, viewport, "scoped-reader");
      let step = "read in-scope device";
      await prepare(page, theme, viewport);
      try {
        const allowed = page.waitForResponse(
          (response) =>
            response.url().endsWith("/GetDevice") &&
            response.request().postData()?.includes(fixture.allowedDeviceId),
        );
        await page.goto(`${fixture.origin}/devices/${fixture.allowedDeviceId}`);
        require(entry, (
          await allowed
        ).ok(), "Real scoped directory session could not read the allowed device");
        await page.getByText(fixture.allowedHostname, { exact: true }).first().waitFor();
        await capture(page, entry, "in-scope-device");
        step = "deny authorization editor";
        await page.goto(`${fixture.origin}/authorization`);
        await page.getByText("Access policy requires permission", { exact: true }).waitFor();
        require(entry, (await page
          .getByRole("button", { name: "Edit access policy", exact: true })
          .count()) === 0, "Scoped directory user reached policy editing");
        await capture(page, entry, "authorization-denied");
        step = "deny excluded device";
        const denied = page.waitForResponse(
          (response) =>
            response.url().endsWith("/GetDevice") &&
            response.request().postData()?.includes(fixture.excludedDeviceId),
        );
        await page.goto(`${fixture.origin}/devices/${fixture.excludedDeviceId}`);
        const response = await denied;
        require(entry, response.status() === 404 &&
          (await response.json()).code ===
            "not_found", "Excluded existing device was not fenced by real server authorization");
        await page.getByRole("alert").first().waitFor();
        await capture(page, entry, "out-of-scope-device");
      } catch {
        entry.checks.contract.findings.push({
          message: `Real scoped directory denial review did not complete: ${step}`,
          elements: [],
        });
        entry.screenshots.failure = await screenshot(
          page,
          `directory-authorization-${theme}-${viewport.name}-reader-failure.png`,
          true,
        );
        entry.screenshots.full ??= entry.screenshots.failure;
      }
      entry.passed = Object.values(entry.checks).every((check) => check.findings.length === 0);
    }
  } catch {
    const { theme, viewport } = combos[0];
    const entry = entryFor(theme, viewport, "directory-login");
    entry.checks.contract.findings.push({
      message: `Real directory browser login did not complete: ${loginStep}`,
      elements: [
        `${new URL(reader.driver.page.url()).origin}${new URL(reader.driver.page.url()).pathname}`,
        ...loginResponses.slice(-12),
      ],
    });
    entry.screenshots.failure = await screenshot(
      reader.driver.page,
      "directory-authorization-reader-login-failure.png",
      true,
    );
    entry.screenshots.full = entry.screenshots.failure;
  } finally {
    await reader.driver.close();
  }
  return results;
}
