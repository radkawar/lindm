// Real disposable UI-review server only. The policy recovery case drops a real
// committed response, never fabricates policy or account issuance responses.
export async function reviewAuthorization({
  pages,
  combos,
  config,
  screenshot,
  axe,
  probe,
  settle,
  protectSecret,
}) {
  const results = [];
  for (const [index, { theme, viewport }] of combos.entries()) {
    const page = pages[index];
    const prefix = `authorization-organization-${theme}-${viewport.name}`;
    const updateRoute = "**/lindm.admin.v1.AdminService/UpdateAuthorization";
    const entry = {
      route: "/authorization",
      url: "/authorization",
      variant: "runtime policy and organization accounts",
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
    async function capture(name) {
      await page.evaluate(() => window.scrollTo(0, 0));
      await settle(page);
      entry.screenshots[name] = await screenshot(page, `${prefix}-${name}.png`, true);
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
        findings: await probe(page, "layout", viewport.name === "desktop"),
      };
      entry.checks[`copy-${name}`] = { findings: await probe(page, "copy") };
    }
    try {
      await page.goto(`${config.origin}/authorization`);
      await settle(page);
      await page.getByRole("button", { name: "Edit access policy", exact: true }).click();
      await page.getByRole("button", { name: "Add custom role", exact: true }).click();
      const name = `review-reader-${index}-${crypto.randomUUID().slice(0, 8)}`;
      const roleName = page.getByLabel("Role name", { exact: true }).last();
      await roleName.fill(name);
      const role = roleName.locator("../..");
      await role.getByLabel("View devices", { exact: true }).check();
      await page
        .getByLabel("Reason", { exact: true })
        .fill("Review runtime console access editing");
      require(!(await page
        .getByRole("button", { name: "Save access policy", exact: true })
        .isEnabled()), "Policy save allowed without reviewing consequences");
      await capture("policy-review");
      await page
        .getByLabel("I reviewed the complete access policy and sign-out consequences.", {
          exact: true,
        })
        .check();
      const attempts = [];
      await page.route(updateRoute, async (route) => {
        attempts.push(route.request().postData());
        if (attempts.length === 1) {
          const committed = await route.fetch();
          await committed.dispose();
          await route.abort("failed");
        } else {
          await route.continue();
        }
      });
      await page.getByRole("button", { name: "Save access policy", exact: true }).click();
      const retry = page.getByRole("button", { name: "Retry exact access change", exact: true });
      await retry.waitFor();
      require(await page
        .getByRole("button", { name: "Cancel editing", exact: true })
        .isDisabled(), "An uncertain policy update could be discarded as a new request");
      // Acknowledge the transient notification as a user would, while retaining
      // its screenshot/accessibility evidence and the persistent inline result.
      const notice = page.locator("[data-sonner-toast]").filter({
        hasText: "Couldn't confirm the access policy: outcome unknown",
      });
      await notice.waitFor();
      await notice.hover();
      entry.screenshots["policy-uncertain-notice"] = await screenshot(
        page,
        `${prefix}-policy-uncertain-notice.png`,
        false,
      );
      const toastState = await probe(page, "toast");
      require(Boolean(toastState), "Ambiguous mutation did not show its outcome notification");
      entry.checks["toast-policy-uncertain"] = {
        findings: (toastState?.problems ?? []).map((message) => ({ message, elements: [] })),
      };
      entry.checks["axe-policy-uncertain-notice"] = {
        findings: (await axe(page, "[data-sonner-toaster]"))
          .filter((item) => item.blocking)
          .map((item) => ({
            message: `${item.id}: ${item.help}`,
            elements: item.nodes.map((node) => node.target),
          })),
      };
      await notice.getByRole("button", { name: "Close toast", exact: true }).click();
      await notice.waitFor({ state: "detached" });
      await page
        .getByText(
          "The outcome is unknown. Retry only this exact change; do not start another policy update.",
          { exact: true },
        )
        .waitFor();
      await capture("policy-uncertain");
      await retry.click();
      await page.getByRole("button", { name: "Edit access policy", exact: true }).waitFor();
      await page.getByRole("heading", { name, exact: true }).waitFor();
      require(attempts.length === 2 &&
        attempts[0] ===
          attempts[1], "Policy ambiguity recovery did not preserve the complete request and identity");
      await page.unroute(updateRoute);
      await capture("policy-saved");

      await page.goto(`${config.origin}/accounts`);
      await settle(page);
      const importer = page.getByRole("region", { name: "Import organization", exact: true });
      const upload = importer.getByLabel("Organization JSON", { exact: true });
      await upload.setInputFiles({
        name: "invalid.json",
        mimeType: "application/json",
        buffer: Buffer.from('{"unknownField":true}'),
      });
      await importer
        .getByText(
          "Choose a valid organization JSON file, at most 16 MiB. Unknown fields are not accepted.",
          { exact: true },
        )
        .waitFor();
      require(!(await importer
        .getByRole("button", { name: "Review current plan", exact: true })
        .isEnabled()), "Invalid organization upload remained reviewable");
      await capture("invalid-upload");
      const username = `review-import-${index}-${crypto.randomUUID().slice(0, 8)}`;
      const organization = {
        name: "UI review account import",
        accounts: [{ username, role: name }],
      };
      await upload.setInputFiles({
        name: "organization.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify(organization)),
      });
      await importer.getByRole("button", { name: "Review current plan", exact: true }).click();
      const apply = importer.getByRole("button", { name: "Apply reviewed plan", exact: true });
      await apply.waitFor();
      require(!(await apply.isEnabled()), "Organization apply allowed without reviewed consequences");
      await importer.getByText("Will create", { exact: true }).waitFor();
      await capture("organization-plan");
      await importer
        .getByLabel("I reviewed the affected accounts, resources and access changes.", {
          exact: true,
        })
        .check();
      await apply.click();
      const shown = importer.getByRole("region", {
        name: "Shown-once organization secrets",
        exact: true,
      });
      await shown.waitFor();
      const secret = await shown.locator("code").innerText();
      protectSecret(secret);
      require(Boolean(secret), "Organization account import did not display its enrollment secret");
      const stored = await page.evaluate(() =>
        JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }),
      );
      require(!stored.includes(secret), "Organization secret was retained in browser storage");
      require(!(await importer
        .getByRole("button", { name: "Review current plan", exact: true })
        .isEnabled()), "A new review could discard an undismissed secret");
      require(await shown
        .getByRole("button", { name: "Download secrets", exact: true })
        .isEnabled(), "Explicit secrets download is unavailable");
      await capture("shown-once");
      await shown.getByRole("button", { name: "Dismiss secrets", exact: true }).click();
      await shown.waitFor({ state: "detached" });
      await importer.getByRole("button", { name: "Review current plan", exact: true }).click();
      await importer.getByText("No change", { exact: true }).waitFor();
      require((await importer.locator("[data-sensitive='true']").count()) ===
        0, "Review replay revealed an existing account secret");
      await capture("organization-unchanged");
      // Account roles are checked by the real account mutation. The first account
      // commits before the second's absent role refuses issuance, exercising the
      // actual partial-result path rather than a mocked successful secret.
      const partial = {
        name: "UI review partial account import",
        accounts: [
          { username: `${username}-partial`, role: name },
          { username: `${username}-refused`, role: `absent-${crypto.randomUUID().slice(0, 8)}` },
        ],
      };
      await upload.setInputFiles({
        name: "partial.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify(partial)),
      });
      await importer.getByRole("button", { name: "Review current plan", exact: true }).click();
      await apply.waitFor();
      await importer
        .getByLabel("I reviewed the affected accounts, resources and access changes.", {
          exact: true,
        })
        .check();
      await apply.click();
      await importer
        .getByText(
          "The import stopped before all work completed. Retain the outcomes and save any secrets below before reviewing again.",
          { exact: true },
        )
        .waitFor();
      await shown.waitFor();
      const partialSecret = await shown.locator("code").innerText();
      protectSecret(partialSecret);
      require(Boolean(
        partialSecret,
      ), "Partial apply discarded the already-issued enrollment secret");
      await importer.getByText("Created", { exact: true }).waitFor();
      require((await apply.count()) ===
        0, "Partial apply offered to replay a consumed account plan");
      await capture("partial-outcomes");
      await shown.getByRole("button", { name: "Dismiss secrets", exact: true }).click();
      await page.goto(`${config.origin}/audit`);
      await page.getByText("Organization access policy changed", { exact: true }).first().waitFor();
      await capture("authorization-audit");
    } catch {
      // Playwright call logs may include the uploaded document or displayed secret.
      findings.push({
        message: "Runtime authorization or organization account scenario did not complete",
        elements: [],
      });
      entry.screenshots.failure = await screenshot(page, `${prefix}-failure.png`, false);
    } finally {
      await page.unroute(updateRoute);
    }
    entry.passed = Object.values(entry.checks).every((check) => check.findings.length === 0);
    results.push(entry);
  }
  return results;
}
