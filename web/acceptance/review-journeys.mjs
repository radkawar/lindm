// SPDX-License-Identifier: Apache-2.0

import { journeys as provisioning } from "./review-journeys-provision.mjs";
import { journeys as security } from "./review-journeys-security.mjs";

const order = [
  "onboard",
  "baseline",
  "lost-laptop",
  "critical-cve",
  "remote-help",
  "helpdesk",
  "recovery-audit",
];
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character],
  );

// These are administrator task walks through the real seeded console, not native
// device qualification. A prerequisite or product blocker remains a recorded
// blocker; a screenshot never turns a request into an observed device effect.
export async function taskWalkthroughs({ page, config, visit, settle, screenshot }) {
  const definitions = [...provisioning, ...security];
  if (
    definitions.length !== order.length ||
    new Set(definitions.map((item) => item.id)).size !== order.length ||
    order.some((id) => !definitions.some((item) => item.id === id))
  ) {
    throw new Error("seven_task_walkthroughs_required");
  }
  const results = [];
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  for (const id of order) {
    const definition = definitions.find((item) => item.id === id);
    const entry = {
      id,
      title: definition.title,
      outcome: "blocked",
      reason: "",
      steps: [],
      failure: "",
      rpcFailures: [],
    };
    const pendingDiagnostics = new Set();
    const recordResponse = (response) => {
      const operation = new URL(response.url()).pathname.match(
        /^\/lindm\.admin\.v1\.AdminService\/([A-Za-z]{1,80})$/,
      )?.[1];
      if (!operation || response.status() < 400) return;
      const diagnostic = response
        .headerValue("lindm-reason")
        .catch(() => null)
        .then((reason) => {
          if (entry.rpcFailures.length === 20) entry.rpcFailures.shift();
          entry.rpcFailures.push({
            operation,
            status: response.status(),
            reason: /^[a-z][a-z0-9_]{0,119}$/.test(reason ?? "") ? reason : "unavailable",
          });
        })
        .finally(() => pendingDiagnostics.delete(diagnostic));
      pendingDiagnostics.add(diagnostic);
    };
    page.on("response", recordResponse);
    const capture = async (name, assessment) => {
      if (
        !/^[a-z0-9-]+$/.test(name) ||
        !["yes", "partly", "no"].includes(assessment.taskShaped) ||
        ["screen", "generic", "remedy", "outcome"].some(
          (key) => typeof assessment[key] !== "string" || !assessment[key].trim(),
        )
      ) {
        throw new Error("task_assessment_incomplete");
      }
      await settle(page);
      const prefix = `task-${id}-${String(entry.steps.length + 1).padStart(2, "0")}-${name}`;
      entry.steps.push({
        name,
        ...assessment,
        url: new URL(page.url()).pathname,
        screenshots: {
          full: await screenshot(page, `${prefix}-full.png`, true),
          viewport: await screenshot(page, `${prefix}.png`, false),
        },
      });
    };
    try {
      const outcome = await definition.run({
        page,
        config,
        visit: (path) => visit(page, path),
        capture,
      });
      if (
        !entry.steps.length ||
        !outcome ||
        !["completed", "blocked"].includes(outcome.outcome) ||
        typeof outcome.reason !== "string" ||
        !outcome.reason.trim()
      )
        throw new Error("task_outcome_missing");
      entry.outcome = outcome.outcome;
      entry.reason = outcome.reason;
    } catch (error) {
      // Playwright errors may echo filled credentials; keep only our token or type.
      entry.failure = /^[a-z][a-z0-9_]+$/.test(error?.message ?? "")
        ? error.message
        : `${error?.name ?? "Error"} during task walk`;
      entry.reason =
        "The walkthrough could not reach its next expected screen. Inspect the last capture; this is not a completed task.";
      // Support details contain the product's bounded error reason, not request
      // bodies. Open them so a rendered RPC failure is distinguishable from a
      // broken task selector without copying Playwright's credential-bearing log.
      for (const summary of await page
        .locator('main [role="alert"] details:not([open]) > summary')
        .all()) {
        if (await summary.isVisible()) await summary.click();
      }
      const prefix = `task-${id}-blocked`;
      entry.failureScreenshots = {
        full: await screenshot(page, `${prefix}-full.png`, true),
        viewport: await screenshot(page, `${prefix}.png`, false),
      };
    } finally {
      page.off("response", recordResponse);
      await Promise.all(pendingDiagnostics);
    }
    if (entry.rpcFailures.length && !entry.failure) {
      entry.failure = "unexpected_task_rpc_failure";
      entry.outcome = "blocked";
      entry.reason =
        "An administrator RPC failed during this nominal task. Later success does not erase that failure; inspect the redacted RPC diagnostics.";
      const prefix = `task-${id}-rpc-failure`;
      entry.failureScreenshots = {
        full: await screenshot(page, `${prefix}-full.png`, true),
        viewport: await screenshot(page, `${prefix}.png`, false),
      };
    }
    results.push(entry);
  }
  return {
    scope:
      "Real administrator UI in a synthetic seeded organization; light desktop task walks supplement the four-appearance route review. No installer, employee consent or native patch/lock execution is simulated by these browser steps.",
    passed:
      results.length === order.length &&
      results.every((entry) => !entry.failure && entry.steps.length > 0),
    results,
  };
}

export function taskAuditSheet(walkthroughs) {
  const sections = walkthroughs.results
    .map(
      (job) =>
        `<section><h2>${escape(job.title)}</h2><p><strong>${escape(job.outcome)}</strong>: ${escape(job.reason)}</p>${job.failure ? `<p>Automation failure: ${escape(job.failure)}. <a href="${escape(job.failureScreenshots?.full)}">Blocked step</a></p>` : ""}<table><thead><tr><th>Screen / step</th><th>Task-shaped?</th><th>Generic or zombie</th><th>Remedy</th><th>Observed outcome</th></tr></thead><tbody>${job.steps.map((step) => `<tr><td><a href="${escape(step.screenshots.full)}">${escape(step.screen)}: ${escape(step.name)}</a></td><td>${escape(step.taskShaped)}</td><td>${escape(step.generic)}</td><td>${escape(step.remedy)}</td><td>${escape(step.outcome)}</td></tr>`).join("")}</tbody></table></section>`,
    )
    .join("\n");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>lindm administrator task audit</title><style>body{font:14px system-ui,sans-serif;margin:24px;line-height:1.5}h1{font-size:24px}h2{font-size:20px}table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;border:1px solid #999;padding:10px}a{color:inherit}section{margin:32px 0}@media(max-width:700px){table{display:block;overflow:auto}}</style></head><body><h1>Administrator task audit: DRAFT for owner editing</h1><p>${escape(walkthroughs.scope)}</p><p>Grades are authored design assessments tied to captured steps, not an automated usability score or owner approval. A blocked prerequisite remains visible even when the walkthrough automation ran successfully.</p><p><a href="index.html">Route contact sheet</a> · <a href="edit-sheet.html">Owner editing pass</a> · <a href="task-audit.json">Task evidence</a></p>${sections}</body></html>\n`;
}
