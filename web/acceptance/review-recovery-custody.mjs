// SPDX-License-Identifier: Apache-2.0

// Explicitly synthetic transport presentation tests, not owner authorization,
// real passkey, encrypted-key transfer or off-server storage qualification.
import { create, fromJsonString, toJsonString } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { fixtureResponse } from "./review-server-status.mjs";

export async function reviewRecoveryCustody({
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
  const readRPC = `${config.origin}/lindm.admin.v1.AdminService/GetServerStatus`;
  const confirmRPC = `${config.origin}/lindm.admin.v1.AdminService/ConfirmRecoveryKeyCustody`;
  const variants = [
    "owner-unconfirmed",
    "admin-unconfirmed",
    "requires-step-up",
    "confirmed",
    "restored-export-set",
    "fresh-database-only",
    "unknown",
    "external-recipients",
  ];
  for (const [index, { theme, viewport }] of combos.entries()) {
    const page = pages[index];
    for (const variant of variants) {
      const prefix = `settings-custody-synthetic-${variant}-${theme}-${viewport.name}`;
      const entry = {
        route: "/settings/status",
        url: "/settings/status",
        variant: `Synthetic custody transport: ${variant}`,
        evidenceKind: "synthetic_transport_fixture",
        scope:
          "Presentation only; no actual owner, passkey, management, encrypted transfer or off-server custody proof.",
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
      const state = schema.RecoveryKeyCustodyState;
      const original = "a".repeat(64),
        replacement = "b".repeat(64);
      let replaced = false;
      let submittedDigest;
      const response = () => {
        const value = fixtureResponse(schema, "known", now);
        const recorded =
          variant === "confirmed" || (variant === "restored-export-set" && !replaced);
        const unknown = variant === "unknown",
          external = variant === "external-recipients";
        value.recoveryKeyCustody = create(schema.RecoveryKeyCustodySchema, {
          state: unknown
            ? state.UNKNOWN
            : external
              ? state.EXTERNAL_RECIPIENTS
              : recorded
                ? state.CONFIRMED
                : state.PENDING,
          canConfirm: !unknown && !external && !recorded && variant !== "admin-unconfirmed",
          confirmationDigest: unknown || external ? "" : replaced ? replacement : original,
          recordedAt: unknown ? undefined : timestampFromMs(now - 60 * 60_000),
          confirmedAt: recorded ? timestampFromMs(now - 30 * 60_000) : undefined,
          exports:
            unknown || external
              ? []
              : [
                  ...(variant === "fresh-database-only"
                    ? []
                    : [
                        {
                          kind: schema.RecoveryKeyCustodyExportKind.CANONICAL_AUTHORITY,
                          path: "/var/lib/lindmd-operations/recovery-custody.age",
                          sha256: "c".repeat(64),
                          localPresent: false,
                        },
                      ]),
                  ...((variant === "restored-export-set" && replaced) ||
                  variant === "fresh-database-only"
                    ? [
                        {
                          kind: schema.RecoveryKeyCustodyExportKind.FRESH_DATABASE,
                          path: `/var/lib/lindmd-operations/database-custody/${"d".repeat(64)}/identities.age`,
                          sha256: "e".repeat(64),
                          localPresent: true,
                        },
                      ]
                    : []),
                ],
        });
        return value;
      };
      const read = async (route) =>
        route.fulfill({
          status: 200,
          headers: { "content-type": "application/json", "cache-control": "no-store" },
          body: toJsonString(schema.GetServerStatusResponseSchema, response()),
        });
      const confirm = async (route) => {
        const request = fromJsonString(
          schema.ConfirmRecoveryKeyCustodyRequestSchema,
          route.request().postData() ?? "{}",
        );
        submittedDigest = request.expectedConfirmationDigest;
        require(request.confirmOffServerCustody, "The modal omitted the owner's explicit attestation");
        await route.fulfill({
          status: 403,
          headers: {
            "content-type": "application/json",
            "cache-control": "no-store",
            "lindm-reason": "recent_step_up_required",
          },
          body: JSON.stringify({
            code: "permission_denied",
            message: "Synthetic scoped verification refusal",
          }),
        });
      };
      await page.route(readRPC, read);
      await page.route(confirmRPC, confirm);
      try {
        await page.goto(`${config.origin}/settings/status`);
        await settle(page);
        const task = page.locator("section[data-slot='recovery-custody-task']");
        await task.waitFor();
        if (variant === "restored-export-set") {
          await task
            .getByRole("heading", { name: "Owner confirmation recorded", exact: true })
            .waitFor();
          replaced = true;
          await page.getByRole("button", { name: "Refresh", exact: true }).click();
          await task
            .getByRole("heading", { name: "Move your recovery keys off this server", exact: true })
            .waitFor();
          require((await task.getByText("Recorded", { exact: true }).count()) ===
            0, "A source-only confirmation cleared a fresh target database identity task");
        }
        if (
          variant === "owner-unconfirmed" ||
          variant === "admin-unconfirmed" ||
          variant === "requires-step-up" ||
          variant === "restored-export-set" ||
          variant === "fresh-database-only"
        ) {
          await task
            .getByRole("heading", { name: "Move your recovery keys off this server", exact: true })
            .waitFor();
          require((await task
            .getByRole("button", { name: "Confirm off-server custody", exact: true })
            .count()) ===
            (variant === "admin-unconfirmed"
              ? 0
              : 1), "Custody confirmation controls ignored the provider's owner eligibility");
          if (variant === "admin-unconfirmed")
            await task
              .getByText("Only the deployment owner can record this confirmation.", { exact: true })
              .waitFor();
        } else if (variant === "confirmed") {
          await task
            .getByRole("heading", { name: "Owner confirmation recorded", exact: true })
            .waitFor();
          await task
            .getByText(
              "An owner recorded custody for this export set. lindm does not verify storage or removal.",
              { exact: true },
            )
            .waitFor();
          require((await task
            .getByRole("button", { name: "Confirm off-server custody", exact: true })
            .count()) === 0, "A recorded attestation offered another confirmation");
          const times = await task
            .locator("time")
            .evaluateAll((nodes) => nodes.map((node) => node.getAttribute("datetime")));
          require(times.includes(
            new Date(now - 30 * 60_000).toISOString(),
          ), "The custody confirmation omitted its original evidence time");
        } else if (variant === "unknown") {
          await task.getByText("Unknown", { exact: true }).waitFor();
          require((await task.locator("time").count()) === 0 &&
            (await task.getByRole("button").count()) ===
              0, "Missing custody metadata fabricated evidence or offered confirmation");
        } else {
          await task
            .getByRole("heading", { name: "Recovery keys use external recipients", exact: true })
            .waitFor();
          require((await task.getByRole("button").count()) ===
            0, "Explicit external recipients fabricated a generated-bundle task");
        }
        if (variant !== "unknown" && variant !== "external-recipients") {
          await task.locator("summary").click();
          const exports = task.locator("[data-slot='recovery-custody-export']");
          const expectedCount = variant === "restored-export-set" ? 2 : 1;
          require((await exports.count()) ===
            expectedCount, "The custody task omitted a required encrypted export");
          const digest = task
            .locator("dt")
            .filter({ hasText: /^Confirmation digest:/ })
            .locator("..")
            .locator("dd");
          require((await digest.textContent()) ===
            (replaced
              ? replacement
              : original), "The composite confirmation digest was missing or mislabeled");
          for (let file = 0; file < expectedCount; file++) {
            const entry = exports.nth(file);
            const fresh = variant === "fresh-database-only" || file === 1;
            const path = fresh
              ? `/var/lib/lindmd-operations/database-custody/${"d".repeat(64)}/identities.age`
              : "/var/lib/lindmd-operations/recovery-custody.age";
            require((await entry.locator("dd").nth(0).textContent()) ===
              path, "A required export omitted its actual protected path");
            require((await entry.locator("dd").nth(1).textContent()) ===
              (fresh ? "e" : "c").repeat(
                64,
              ), "An individual file checksum became the composite digest");
            await entry
              .getByText("Keep this file's passphrase separately.", { exact: true })
              .waitFor();
          }
        }
        if (variant === "requires-step-up") {
          await task
            .getByRole("button", { name: "Confirm off-server custody", exact: true })
            .click();
          const dialog = page.getByRole("dialog", {
            name: "Confirm off-server custody",
            exact: true,
          });
          await dialog.waitFor();
          require(await dialog
            .getByRole("button", { name: "Record my confirmation", exact: true })
            .isDisabled(), "Confirmation omitted explicit owner attestation");
          await dialog
            .getByRole("checkbox", {
              name: "I stored every listed recovery export off this server.",
              exact: true,
            })
            .check();
          await dialog.getByRole("button", { name: "Record my confirmation", exact: true }).click();
          await dialog.getByText("Verify it's you", { exact: true }).waitFor();
          await dialog.getByLabel("Your password", { exact: true }).waitFor();
          await dialog.getByRole("button", { name: "Verify with passkey", exact: true }).waitFor();
          require(submittedDigest ===
            original, "The owner confirmation lost its reviewed export-set scope");
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
          message: "Synthetic custody review could not complete this scenario",
          elements: [],
        });
        entry.screenshots.full = await screenshot(page, `${prefix}-failure.png`, true);
      } finally {
        await page.unroute(readRPC, read);
        await page.unroute(confirmRPC, confirm);
        const dialog = page.getByRole("dialog", {
          name: "Confirm off-server custody",
          exact: true,
        });
        if (await dialog.count()) await page.keyboard.press("Escape");
      }
      entry.passed = Object.values(entry.checks).every((check) => check.findings.length === 0);
      results.push(entry);
    }
  }
  return results;
}
