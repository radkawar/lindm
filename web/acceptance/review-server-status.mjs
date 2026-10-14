// SPDX-License-Identifier: Apache-2.0

// UI-only synthetic transport cases. They use the generated protobuf schema,
// not a second status model, and never qualify live health, backups or delivery.
import { readFileSync } from "node:fs";
import { registerHooks, stripTypeScriptTypes } from "node:module";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { create, toJsonString } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";

export async function statusSchema(checkout) {
  const url = pathToFileURL(join(checkout, "web/gen/lindm/admin/v1/server_status_pb.ts"));
  // Node's default type stripping cannot execute generated TypeScript enums.
  // Transform this one generated file, then immediately remove the loader hook.
  const hooks = registerHooks({
    load(target, context, nextLoad) {
      if (target !== url.href) return nextLoad(target, context);
      return {
        format: "module",
        shortCircuit: true,
        source: stripTypeScriptTypes(readFileSync(url, "utf8"), { mode: "transform" }),
      };
    },
  });
  try {
    return await import(url.href);
  } finally {
    hooks.deregister();
  }
}

export function fixtureResponse(schema, variant, now) {
  const { ServerStatusState: state, GetServerStatusResponseSchema: responseSchema } = schema;
  const observed = variant === "stale" ? now - 3 * 60_000 : now;
  const evidence = now - 30 * 60_000;
  const components = [
    ["database", "The verified database connection answered."],
    ["admin_database", "The console database connection answered."],
    ["https_certificate", "The loaded certificate expires within 30 days."],
    ["device_ca", "The loaded certificate is within its validity period."],
    ["backups", "The latest backup attempt failed."],
    ["server_release_feed", "An authenticated import offers a server security update."],
    ["agent_repository", "Startup checks verified signed agent packages for the listed platforms."],
    ["advisory_feeds", "Enabled advisory feeds have current acquisition evidence."],
    ["disk", "Server state storage has available space and file slots."],
    ["job_queue", "Delivery and report work has no observed overdue backlog."],
  ];
  return create(responseSchema, {
    version: "synthetic-ui-review",
    observedAt: variant === "unknown" ? undefined : timestampFromMs(observed),
    checks: components.map(([component, summary]) => ({
      component,
      state:
        variant === "unknown" || variant === "stale"
          ? state.UNKNOWN
          : component === "backups"
            ? state.FAILED
            : component === "https_certificate" || component === "server_release_feed"
              ? state.ATTENTION
              : state.OK,
      summary:
        variant === "unknown"
          ? "No check has completed yet."
          : variant === "stale"
            ? "The server check has not refreshed."
            : summary,
      nextAction:
        variant === "stale"
          ? "Inspect the server service journal."
          : variant === "unknown"
            ? "Wait for the next server check."
            : component === "backups"
              ? "Inspect the backup service journal and repeat the backup."
              : component === "https_certificate"
                ? "Renew the certificate before its expiry."
                : component === "server_release_feed"
                  ? "Back up the server, review the notice and apply the signed offline bundle."
                  : "Review the scope of this check before planning maintenance.",
      observedAt: variant === "unknown" ? undefined : timestampFromMs(observed),
      evidenceAt: variant === "unknown" ? undefined : timestampFromMs(evidence),
      expiresAt:
        component === "https_certificate" && variant !== "unknown"
          ? timestampFromMs(now + 15 * 24 * 60 * 60_000)
          : undefined,
      detail: "Synthetic transport evidence, not a live server observation.",
    })),
  });
}

export async function reviewServerStatus({
  schema,
  pages,
  combos,
  config,
  screenshot,
  axe,
  probe,
  settle,
}) {
  const results = [];
  const rpc = `${config.origin}/lindm.admin.v1.AdminService/GetServerStatus`;
  const variants = ["known", "unknown", "stale", "error", "retained-error"];
  for (const [index, { theme, viewport }] of combos.entries()) {
    const page = pages[index];
    for (const variant of variants) {
      const prefix = `settings-status-synthetic-${variant}-${theme}-${viewport.name}`;
      const entry = {
        route: "/settings/status",
        url: "/settings/status",
        variant: `Synthetic status transport: ${variant}`,
        evidenceKind: "synthetic_transport_fixture",
        scope: "Presentation only; no live server, certificate, backup or alert delivery claim.",
        theme,
        viewport: viewport.name,
        size: `${viewport.width}x${viewport.height}`,
        passed: false,
        screenshots: {},
        checks: { contract: { findings: [] } },
      };
      const findings = entry.checks.contract.findings;
      const require = (condition, message) => {
        if (!condition) findings.push({ message, elements: [] });
      };
      const now = Math.floor(Date.now() / 1000) * 1000;
      const response = fixtureResponse(
        schema,
        variant === "retained-error" ? "known" : variant,
        now,
      );
      let failedRead = variant === "error";
      const intercept = async (route) => {
        await route.fulfill({
          status: failedRead ? 503 : 200,
          headers: {
            "content-type": "application/json",
            "cache-control": "no-store",
            ...(failedRead ? { "lindm-reason": "server_status_unavailable" } : {}),
          },
          body: failedRead
            ? JSON.stringify({ code: "unavailable", message: "Synthetic status read failure" })
            : toJsonString(schema.GetServerStatusResponseSchema, response),
        });
      };
      await page.route(rpc, intercept);
      try {
        await page.goto(`${config.origin}/settings/status`);
        await settle(page);
        await page.getByRole("heading", { name: "Server status", exact: true }).waitFor();
        if (variant === "retained-error") {
          failedRead = true;
          await page.getByRole("button", { name: "Refresh", exact: true }).click();
          await settle(page);
        }
        if (variant === "error" || variant === "retained-error") {
          await page.getByRole("alert").waitFor();
          require((await page.locator("#status-evidence").count()) ===
            (variant === "error"
              ? 0
              : 1), "A failed read fabricated evidence or lost its retained observation");
          if (variant === "error") {
            require((await page.locator("#status-decision").count()) ===
              0, "A failed initial read displayed reassuring check counts");
          } else {
            await page
              .getByText("The latest read failed; retained checks may be stale", {
                exact: true,
              })
              .waitFor();
          }
        } else {
          require((await page.locator('section[aria-labelledby="status-evidence"] li').count()) ===
            response.checks.length, "The page omitted a server check");
          if (variant === "known") {
            require((await page
              .locator('section[aria-labelledby="status-evidence"]')
              .getByText("Failed", { exact: true })
              .count()) === 1, "Observed failure did not remain separate from uncertainty");
            require((await page
              .locator('section[aria-labelledby="status-evidence"]')
              .getByText("Needs attention", { exact: true })
              .count()) ===
              2, "Certificate expiry or the authenticated security notice omitted its attention state");
          } else {
            require((await page
              .locator('section[aria-labelledby="status-evidence"]')
              .getByText("Unknown", { exact: true })
              .count()) ===
              response.checks.length, "Missing or stale observations fabricated confirmed checks");
            require((await page
              .locator('section[aria-labelledby="status-evidence"]')
              .getByText("Check confirmed", { exact: true })
              .count()) === 0, "Missing or stale evidence displayed a confirmed check");
          }
          if (variant === "unknown") {
            require((await page
              .locator('section[aria-labelledby="status-evidence"] time')
              .count()) ===
              0, "An unchecked component fabricated an observation or evidence timestamp");
          }
          if (variant === "stale") {
            const times = await page
              .locator('section[aria-labelledby="status-evidence"] time')
              .evaluateAll((nodes) => nodes.map((node) => node.getAttribute("datetime")));
            require(times.includes(
              new Date(now - 30 * 60_000).toISOString(),
            ), "Stale presentation advanced the original evidence time");
          }
        }
        if (variant !== "error") {
          const fields = await page
            .locator('section[aria-labelledby="status-evidence"] li')
            .evaluateAll((rows) =>
              rows.map((row) => {
                const metadata = row.querySelector(":scope > div > dl");
                return [...(metadata?.children ?? [])].map((field) => ({
                  label: field.querySelector("dt")?.textContent?.trim(),
                  value: field.querySelector("dd")?.textContent?.trim(),
                }));
              }),
            );
          require(fields.length === response.checks.length &&
            fields.every(
              (row, position) =>
                row.map((field) => field.label).join(",") ===
                  (response.checks[position].expiresAt
                    ? "Checked,Evidence,Expires"
                    : "Checked,Evidence") && row.every((field) => field.value),
            ), "Check, evidence and expiry times must remain separate labeled fields with visible values");
        }
        await page.evaluate(() => window.scrollTo(0, 0));
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
        entry.checks.layout = {
          findings: await probe(page, "layout", viewport.name === "desktop"),
        };
        entry.checks.copy = { findings: await probe(page, "copy") };
        entry.checks.conventions = { findings: await probe(page, "conventions", false) };
      } catch {
        findings.push({
          message: "Synthetic status review could not complete this scenario",
          elements: [],
        });
        entry.screenshots.full = await screenshot(page, `${prefix}-failure.png`, true);
      } finally {
        await page.unroute(rpc, intercept);
      }
      entry.passed = Object.values(entry.checks).every((check) => check.findings.length === 0);
      results.push(entry);
    }
  }
  return results;
}
