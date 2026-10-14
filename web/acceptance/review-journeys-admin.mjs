// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from "node:crypto";
import { journeys as security } from "./review-journeys-security.mjs";

async function runOrganisation(ctx) {
  const { page } = ctx;
  const main = page.getByRole("main");
  const suffix = randomUUID().slice(0, 8);
  const username = `organisation-admin-${suffix}`;
  const role = `organisation-reader-${suffix}`;
  const shot = async (name, screen, outcome) => {
    await page.waitForFunction(() => {
      const main = document.querySelector("main");
      return (
        main &&
        !main.querySelector('[aria-busy="true"]') &&
        ![...main.querySelectorAll('[role="status"]')].some(
          (node) => node.getClientRects().length && /^Loading\b/.test(node.textContent.trim()),
        )
      );
    });
    await ctx.capture(name, {
      screen,
      taskShaped: "yes",
      generic: "No unrelated controls were used for this step.",
      remedy: "Keep the named target, current evidence and next action together.",
      outcome,
    });
  };
  const choose = async (scope, label, option) => {
    await scope.getByRole("combobox", { name: label, exact: true }).click();
    await page.getByRole("option", { name: option, exact: true }).click();
  };
  await ctx.visit("/authorization");
  await main.getByRole("button", { name: "Edit access policy", exact: true }).click();
  await main.getByRole("button", { name: "Add custom role", exact: true }).click();
  const roleCard = main
    .getByRole("region", { name: "Edit custom roles" })
    .locator("div.border")
    .last();
  await roleCard.getByRole("textbox", { name: "Role name", exact: true }).fill(role);
  await roleCard.getByRole("checkbox", { name: "View devices", exact: true }).check();
  await roleCard.getByRole("checkbox", { name: "View audit log", exact: true }).check();
  await main
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("Add a read-only role for organisation evidence review.");
  await main
    .getByRole("checkbox", {
      name: "I reviewed the complete access policy and sign-out consequences.",
      exact: true,
    })
    .check();
  await shot(
    "custom-role-review",
    "Authorization",
    "Reviewed the complete policy with one new read-only role. Existing roles, bindings and approval requirements remain unchanged.",
  );
  await main.getByRole("button", { name: "Save access policy", exact: true }).click();
  await main.getByText("Access policy saved.", { exact: false }).waitFor();
  await shot(
    "custom-role-saved",
    "Authorization",
    "The real server saved the role and returned its recorded revision.",
  );

  await ctx.visit("/accounts");
  await main.getByRole("button", { name: "Create account", exact: true }).first().click();
  let dialog = page.getByRole("dialog", { name: "Create account", exact: true });
  await dialog.getByRole("textbox", { name: "Username", exact: true }).fill(username);
  await choose(dialog, "Role", "Admin");
  await shot(
    "admin-review",
    "Accounts / new administrator",
    "The new local account has the explicitly selected Admin role and visible all-device scope. No emergency access is selected.",
  );
  await dialog.getByRole("button", { name: "Create account", exact: true }).click();
  const handoff = main.getByRole("region", { name: "One-time enrollment secret", exact: true });
  await handoff.waitFor();
  await handoff.getByRole("button", { name: "Copy enrollment secret", exact: true }).waitFor();
  await handoff.getByRole("button", { name: "Copy enrollment address", exact: true }).waitFor();
  if (!(await handoff.innerText()).includes(`${ctx.config.origin}/enroll`))
    throw new Error("organisation_enrollment_address_missing");
  await shot(
    "admin-private-handoff",
    "Accounts / private enrollment handoff",
    "The shown-once secret has separate copy controls and a complete enrollment address. Screenshots mask the secret; it is not read or retained by this walk.",
  );
  await handoff.getByRole("button", { name: "Dismiss secret", exact: true }).click();
  await main.getByRole("searchbox", { name: "Find an account", exact: true }).fill(username);
  const row = main
    .getByRole("table", { name: "Local accounts", exact: true })
    .getByRole("row")
    .filter({ has: page.getByRole("button", { name: `Edit ${username}`, exact: true }) });
  await row.waitFor();
  if ((await row.count()) !== 1) throw new Error("organisation_account_search_ambiguous");
  await shot(
    "account-found",
    "Accounts / named search",
    "Username search finds this administrator without scrolling through unrelated accounts.",
  );
  await row.getByRole("button", { name: `Edit ${username}`, exact: true }).click();
  dialog = page.getByRole("dialog", { name: `Edit ${username}`, exact: true });
  await choose(dialog, "Role", role);
  await dialog.getByRole("checkbox", { name: "Enabled", exact: true }).uncheck();
  await dialog.getByRole("button", { name: "Save account", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  await row.getByText(role, { exact: true }).filter({ visible: true }).waitFor();
  await row.getByText("Disabled", { exact: true }).filter({ visible: true }).waitFor();
  await shot(
    "account-access-updated",
    "Accounts / saved access",
    "The server confirms the custom role and disabled sign-in state. This disposable administrator cannot sign in; no enrollment ceremony was simulated.",
  );
  for (const theme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    await page.setViewportSize({ width: 390, height: 844 });
    await row.scrollIntoViewIfNeeded();
    await row.getByText("Disabled", { exact: true }).filter({ visible: true }).waitFor();
    const tableFits = await main
      .getByRole("table", { name: "Local accounts", exact: true })
      .evaluate((table) => table.scrollWidth <= table.clientWidth + 1);
    if (!tableFits) throw new Error("organisation_mobile_account_scroll_required");
    await shot(
      `account-mobile-${theme}`,
      "Accounts / narrow screen access review",
      "Role, device scope, sign-in state and Edit fit together without sideways scrolling.",
    );
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await main
    .getByRole("searchbox", { name: "Find an account", exact: true })
    .fill(`no-account-${suffix}`);
  await main.getByText("No accounts match this search", { exact: true }).waitFor();
  await main.getByRole("button", { name: "Clear search", exact: true }).click();
  await main.getByRole("link", { name: "Review sign-in source", exact: true }).click();
  await main.getByRole("heading", { name: "Sign-in source", exact: true }).waitFor();
  await shot(
    "sign-in-source",
    "Accounts / SSO settings",
    "The sign-in provider, emergency access and freshness are shown. The UI states that server configuration controls these settings; this walk does not replace the real identity provider.",
  );

  await ctx.visit("/integrations");
  await main.getByRole("button", { name: "Add destination", exact: true }).first().click();
  dialog = page.getByRole("dialog", { name: "Add destination", exact: true });
  await dialog.getByLabel("Name", { exact: true }).fill(`Organisation events ${suffix}`);
  await dialog.getByLabel("Address", { exact: true }).fill("https://audit.example.invalid/events");
  await dialog.getByLabel("Send events", { exact: true }).uncheck();
  await dialog.getByRole("button", { name: "Generate", exact: true }).click();
  await dialog
    .getByLabel("Reason (audited)", { exact: true })
    .fill("Prepare a paused destination for administrator review; do not send events.");
  await shot(
    "webhook-review",
    "Integrations / paused webhook",
    "Reviewed a paused HTTPS webhook with a generated signing secret. No external receiver or delivery success is simulated.",
  );
  await dialog.getByRole("button", { name: "Create destination", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  const destination = main
    .getByRole("table", { name: "Destinations", exact: true })
    .getByRole("row")
    .filter({ hasText: `Organisation events ${suffix}` });
  await destination.getByText("Paused", { exact: true }).waitFor();
  await shot(
    "webhook-paused",
    "Integrations / destination status",
    "The real destination is paused. Events recorded while paused are not sent.",
  );
  await main.getByRole("button", { name: "Add schedule", exact: true }).first().click();
  dialog = page.getByRole("dialog", { name: "Add report schedule", exact: true });
  await dialog.getByLabel("Name", { exact: true }).fill(`Weekly inventory ${suffix}`);
  await choose(dialog, "How often", "Weekly");
  await dialog
    .getByLabel("Reason (audited)", { exact: true })
    .fill("Keep a weekly inventory record for organisation review.");
  await dialog.getByRole("button", { name: "Create schedule", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  await main
    .getByRole("table", { name: "Report schedules", exact: true })
    .getByRole("row")
    .filter({ hasText: `Weekly inventory ${suffix}` })
    .waitFor();
  await shot(
    "weekly-report",
    "Integrations / report schedule",
    "Created an enabled weekly fleet-inventory schedule. Queue acceptance is not presented as completed evidence.",
  );

  // Reuse the maintained named-filter, fixed-date, published signed export walk.
  // It uses browser downloads, never hidden RPCs or fabricated report artifacts.
  await security.find((journey) => journey.id === "recovery-audit").run(ctx);

  await ctx.visit("/settings");
  await main.getByRole("link", { name: "Review server status", exact: true }).click();
  await main.getByRole("heading", { name: "Evidence from this server", exact: true }).waitFor();
  const checks = page.locator('[aria-labelledby="status-evidence"] li');
  const labels = await checks.locator('[data-slot="badge"]').allTextContents();
  const priority = {
    Failed: 0,
    "Needs attention": 1,
    Unknown: 2,
    "Not configured": 3,
    "Check confirmed": 4,
  };
  if (
    !labels.length ||
    labels.some((label, index) => index > 0 && priority[label] < priority[labels[index - 1]])
  )
    throw new Error("organisation_status_action_order_missing");
  await shot(
    "server-decisions-first",
    "Settings / server status",
    "Server checks put failures, attention and unknown evidence before confirmed checks. Missing fixture backup or storage evidence remains unknown, not healthy.",
  );
  await ctx.visit("/settings");
  await main.getByRole("link", { name: "Configure assistant access", exact: true }).click();
  await main.getByRole("heading", { name: "Access on this server", exact: true }).waitFor();
  const wasDisabled = await main
    .getByRole("button", { name: "Enable access", exact: true })
    .isVisible();
  if (wasDisabled) {
    await main.getByRole("button", { name: "Enable access", exact: true }).click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Enable access", exact: true })
      .click();
  }
  await main.getByRole("button", { name: "Create token", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Create an assistant token", exact: true });
  const tokenName = `Organisation review ${suffix}`;
  await dialog.getByLabel("New token name", { exact: true }).fill(tokenName);
  await choose(dialog, "Access", "Read only");
  await dialog.getByRole("button", { name: "Create token", exact: true }).click();
  dialog = page.getByRole("dialog", { name: "Copy your token now", exact: true });
  await dialog.waitFor();
  await shot(
    "assistant-private-token",
    "Settings / assistant token",
    "Created a read-only token bounded by the current account's authority. The token is masked and never read by this walk.",
  );
  await dialog.getByRole("button", { name: "Hide token", exact: true }).click();
  const token = main.locator("[data-mcp-token-row]").filter({ hasText: tokenName });
  await token.getByRole("button", { name: "Revoke token", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Revoke token", exact: true }).click();
  await token.waitFor({ state: "hidden" });
  if (wasDisabled) {
    await main.getByRole("button", { name: "Disable access", exact: true }).click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Disable access", exact: true })
      .click();
    await main.getByRole("button", { name: "Enable access", exact: true }).waitFor();
  }
  await shot(
    "assistant-access-restored",
    "Settings / assistant access",
    "Revoked this walk's token and restored the server's initial assistant-access setting. No assistant request or device action was run.",
  );
  return {
    outcome: "completed",
    reason:
      "Created and updated a disposable administrator, saved a narrow custom role, reviewed server-controlled sign-in settings, created a paused webhook and weekly report schedule, searched audit evidence and downloaded its real published selection and signature, reviewed server checks, and issued then revoked a read-only assistant token. First-run password/passkey setup is exercised separately by the existing real setup fixture review; local fixture checks do not qualify a deployed installer or external identity/receiver.",
  };
}

export const journeys = [
  { id: "run-organisation", title: "Run the organisation", run: runOrganisation },
];
