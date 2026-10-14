// SPDX-License-Identifier: Apache-2.0

// Real Settings/token requests against the private ui-review server. Screenshots
// mask the shown-once token. A lost response is injected only after the server's
// real issuance request returns, so recovery tests a committed, unused token.
export async function reviewMCPAccess({
  pages,
  combos,
  visit,
  settle,
  screenshot,
  axe,
  probe,
  protectSecret,
}) {
  const results = [];
  const route = "/settings/assistant-access";
  const owner = pages[0];
  let initiallyEnabled;
  const issuedLabels = [];
  const run = crypto.randomUUID().slice(0, 8);
  const capture = async (page, combo, variant, prefix) => {
    const entry = {
      route,
      url: route,
      variant,
      theme: combo.theme,
      viewport: combo.viewport.name,
      size: `${combo.viewport.width}x${combo.viewport.height}`,
      screenshots: {},
      checks: { contract: { findings: [] } },
    };
    await settle(page);
    await page.evaluate(() => window.scrollTo(0, 0));
    entry.screenshots.full = await screenshot(page, `${prefix}.png`, true);
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
    entry.checks.layout = {
      findings: await probe(page, "layout", combo.viewport.name === "desktop"),
    };
    entry.checks.copy = { findings: await probe(page, "copy") };
    results.push(entry);
    return entry;
  };
  let step = "open Settings";
  try {
    await visit(owner, "/settings");
    await owner.getByRole("link", { name: "Configure assistant access", exact: true }).click();
    await owner.waitForURL(`**${route}`);
    await settle(owner);
    const deployment = owner.getByRole("region", { name: "Access on this server", exact: true });
    initiallyEnabled = (await deployment.getByText("Enabled", { exact: true }).count()) === 1;
    if (!initiallyEnabled) {
      step = "enable assistant access";
      await deployment.getByRole("button", { name: "Enable access", exact: true }).click();
      await owner
        .getByRole("dialog")
        .getByRole("button", { name: "Enable access", exact: true })
        .click();
      await owner.getByRole("dialog").waitFor({ state: "hidden" });
    }
    for (const [index, combo] of combos.entries()) {
      const page = pages[index];
      const suffix = `${combo.theme}-${combo.viewport.name}`;
      await visit(page, route);
      await settle(page);
      for (const access of ["Read only", "Read and request human review"]) {
        const proposal = access !== "Read only";
        const label = `UI review ${proposal ? "review requests" : "read only"} ${run} ${suffix}`;
        issuedLabels.push(label);
        step = `create ${proposal ? "review" : "read"} token ${suffix}`;
        await page.getByRole("button", { name: "Create token", exact: true }).click();
        const form = page.getByRole("dialog");
        await form.getByLabel("New token name", { exact: true }).fill(label);
        await form.getByRole("combobox", { name: "Access", exact: true }).click();
        await page.getByRole("option", { name: access, exact: true }).click();
        await form.getByRole("combobox", { name: "Expires after", exact: true }).click();
        await page.getByRole("option", { name: "1 day", exact: true }).click();
        if (!proposal)
          await capture(page, combo, "Create read-only token", `assistant-token-form-${suffix}`);
        await form.getByRole("button", { name: "Create token", exact: true }).click();
        const secretDialog = page.getByRole("dialog", { name: "Copy your token now", exact: true });
        await secretDialog.waitFor();
        const token = await secretDialog
          .getByRole("textbox", { name: "Assistant token", exact: true })
          .inputValue();
        protectSecret(token);
        if (!token) throw new Error("shown_once_token_missing");
        if (
          await page.evaluate(
            (value) =>
              location.href.includes(value) ||
              Object.values(localStorage).some((item) => item.includes(value)) ||
              Object.values(sessionStorage).some((item) => item.includes(value)),
            token,
          )
        )
          throw new Error("shown_once_token_persisted");
        if (!proposal)
          await capture(page, combo, "Shown-once token (masked)", `assistant-token-once-${suffix}`);
        await secretDialog.getByRole("button", { name: "Hide token", exact: true }).click();
        await secretDialog.waitFor({ state: "hidden" });
        const row = page
          .locator("[data-mcp-token-row]")
          .filter({ has: page.getByRole("heading", { name: label, exact: true }) });
        await row.waitFor();
        if (!(await row.innerText()).includes(access))
          throw new Error("token_capability_not_named");
      }
      await capture(page, combo, "Own active tokens", `assistant-tokens-${suffix}`);
      for (const label of issuedLabels.filter((name) => name.endsWith(suffix))) {
        step = `revoke token ${suffix}`;
        const row = page
          .locator("[data-mcp-token-row]")
          .filter({ has: page.getByRole("heading", { name: label, exact: true }) });
        await row.getByRole("button", { name: "Revoke token", exact: true }).click();
        if (label.includes("read only"))
          await capture(page, combo, "Revoke named token", `assistant-token-revoke-${suffix}`);
        await page
          .getByRole("dialog")
          .getByRole("button", { name: "Revoke token", exact: true })
          .click();
        await row.waitFor({ state: "hidden" });
      }
    }
    step = "recover a lost issuance response";
    await visit(owner, route);
    await settle(owner);
    const ambiguousLabel = `UI review lost response ${run}`;
    issuedLabels.push(ambiguousLabel);
    let issuanceCount = 0;
    let commitStatus = 0;
    await owner.route("**/auth/mcp/tokens", async (request) => {
      issuanceCount++;
      const response = await request.fetch();
      commitStatus = response.status();
      await response.dispose();
      await request.abort("failed");
    });
    try {
      const createToken = owner
        .getByRole("region", { name: "Your tokens", exact: true })
        .getByRole("button", { name: "Create token", exact: true });
      await createToken.click();
      await owner
        .getByRole("dialog")
        .getByLabel("New token name", { exact: true })
        .fill(ambiguousLabel);
      await owner
        .getByRole("dialog")
        .getByRole("button", { name: "Create token", exact: true })
        .click();
      step = "confirm committed lost issuance";
      await owner.getByText("Check the token before creating another", { exact: true }).waitFor();
      if (commitStatus !== 200) throw new Error("lost_issuance_not_committed");
      step = "close uncertain issuance dialog";
      await owner.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
      step = "wait for the uncertain issuance dialog to close";
      await owner.getByRole("dialog").waitFor({ state: "hidden" });
      step = "check token creation stays blocked";
      if (!(await createToken.isDisabled())) throw new Error("ambiguous_issuance_allows_new_token");
      step = "check issuance was not retried";
      if (issuanceCount !== 1) throw new Error("issuance_retried_automatically");
      step = "refresh tokens after lost issuance";
      const [refreshed] = await Promise.all([
        owner.waitForResponse(
          (response) =>
            response.url().endsWith("/auth/mcp/settings") && response.request().method() === "GET",
        ),
        owner.getByRole("button", { name: "Refresh tokens", exact: true }).click(),
      ]);
      if (refreshed.status() !== 200) throw new Error("unused_token_refresh_failed");
      step = "find the committed unused token";
      const row = owner
        .locator("[data-mcp-token-row]")
        .filter({ has: owner.getByRole("heading", { name: ambiguousLabel, exact: true }) });
      await row.waitFor();
      if (
        !(await owner
          .getByRole("button", { name: "I checked unused tokens", exact: true })
          .isDisabled())
      )
        throw new Error("unused_token_recovery_allows_unsafe_acknowledgment");
      step = "capture lost issuance recovery";
      await capture(owner, combos[0], "Lost issuance response", "assistant-token-unknown");
      await row.getByRole("button", { name: "Revoke token", exact: true }).click();
      await owner
        .getByRole("dialog")
        .getByRole("button", { name: "Revoke token", exact: true })
        .click();
      await row.waitFor({ state: "hidden" });
      step = "acknowledge the revoked unused token";
      await owner.getByRole("button", { name: "I checked unused tokens", exact: true }).click();
      if (await createToken.isDisabled())
        throw new Error("unused_token_recovery_does_not_reopen_creation");
    } finally {
      await owner.unroute("**/auth/mcp/tokens");
    }
  } catch {
    results.push({
      route,
      url: route,
      variant: `Assistant workflow: ${step}`,
      theme: combos[0].theme,
      viewport: combos[0].viewport.name,
      screenshots: { full: await screenshot(owner, "assistant-access-workflow-failure.png", true) },
      checks: {
        contract: {
          findings: [{ message: `Assistant workflow did not complete: ${step}`, elements: [] }],
        },
      },
    });
  } finally {
    // Remove only tokens this walkthrough named. Never change another token.
    await visit(owner, route);
    await settle(owner);
    for (const label of issuedLabels) {
      const rows = owner
        .locator("[data-mcp-token-row]")
        .filter({ has: owner.getByRole("heading", { name: label, exact: true }) });
      for (let remaining = await rows.count(); remaining > 0; remaining--) {
        const row = rows.first();
        await row.getByRole("button", { name: "Revoke token", exact: true }).click();
        await owner
          .getByRole("dialog")
          .getByRole("button", { name: "Revoke token", exact: true })
          .click();
        await row.waitFor({ state: "hidden" });
      }
    }
    if (initiallyEnabled === false) {
      await owner
        .getByRole("region", { name: "Access on this server", exact: true })
        .getByRole("button", { name: "Disable access", exact: true })
        .click();
      await owner
        .getByRole("dialog")
        .getByRole("button", { name: "Disable access", exact: true })
        .click();
      await owner.getByRole("dialog").waitFor({ state: "hidden" });
    }
  }
  return results;
}
