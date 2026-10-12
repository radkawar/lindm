#!/usr/bin/env node
// Console UI review runner for `lab console review` (docs/engineering.md).
// Private JSON-file API like run.mjs: credentials arrive in a 0600 config file and
// are never printed, persisted or placed in evidence. Sign-in uses the real
// enrollment and WebAuthn flow through a Chromium CDP virtual authenticator.
import { readFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { createRequire } from "node:module";
import { ChromiumDriver, UI } from "./drivers.mjs";
import { enroll, signIn } from "./journey.mjs";
import {
  privateDirectory,
  readPrivateJSON,
  writePrivate,
  writePrivateJSON,
} from "./private-files.mjs";
import { installProbes } from "./review-probes.mjs";
import { contactSheet } from "./review-report.mjs";
import { reviewEnrollmentFixtures } from "./review-enrollment.mjs";
import { routeContracts, destructiveCoverage, listRoutes } from "./review-contracts.mjs";
import { editManifest, editSheet, annotationTemplate } from "./review-edit-sheet.mjs";
import { taskWalkthroughs, taskAuditSheet } from "./review-journeys.mjs";
import { reviewAuthorization } from "./review-authorization.mjs";
import { reviewDirectoryAuthorization } from "./review-directory-authorization.mjs";
import { reviewSSHBanner } from "./review-ssh-banner.mjs";
import { reviewOSUpdate } from "./review-os-update.mjs";
import { reviewAdvisoryControls } from "./review-advisory-approvals.mjs";
import { reviewOwnerEdits } from "./review-owner-edits.mjs";
import { reviewRoleWalkthroughs } from "./review-roles.mjs";
import { popupStability } from "./review-popups.mjs";

process.umask(0o077);

const themes = ["light", "dark"];
const viewports = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "mobile", width: 390, height: 844 },
];
const blockingImpacts = new Set(["serious", "critical"]);
const maxDialogsPerPage = 16;
// Controls a capture must render. The assistance viewer's control button stays
// discoverable, with a stated reason whenever it is disabled.
const viewerControls = ["Take control"];

let config;
let secrets = [];
const report = {
  startedAt: new Date().toISOString(),
  passed: false,
  routes: [],
  results: [],
  sessions: [],
  failures: [],
};

function redact(value) {
  if (typeof value === "string") {
    let text = value;
    for (const secret of secrets) text = text.split(secret).join("[redacted]");
    return text;
  }
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redact(item)]));
  return value;
}

function slug(value) {
  return value
    .replace(/^\//, "")
    .replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase();
}

// Every file route in the generated TanStack tree. Authenticated routes live
// under the `_authenticated` layout id; the others are public pages.
async function routeTree(path) {
  const source = await readFile(path, "utf8");
  const block = (name) => {
    const match = source.match(new RegExp(`export interface ${name} \\{([\\s\\S]*?)\\n\\}`));
    if (!match) throw new Error(`route_tree_${name}_missing`);
    return [...match[1].matchAll(/^\s*'([^']+)': typeof (\w+)/gm)].map((item) => ({
      key: item[1],
      type: item[2],
    }));
  };
  const ids = new Map(block("FileRoutesById").map((item) => [item.type, item.key]));
  return block("FileRoutesByFullPath").map(({ key, type }) => ({
    path: key,
    authenticated: (ids.get(type) ?? "").startsWith("/_authenticated/"),
  }));
}

async function complexActionKinds(path) {
  const source = await readFile(path, "utf8");
  const match = source.match(/complexActionKinds = \[([^\]]+)\] as const/);
  if (!match) throw new Error("complex_action_kinds_missing");
  return [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]);
}

// Concrete URLs for a route path. A parameter without a seeded value leaves the
// route unvisitable, which fails the review instead of silently skipping it.
function concrete(path, params) {
  const names = [...path.matchAll(/\$(\w+)/g)].map((item) => item[1]);
  let urls = [{ url: path, label: "" }];
  for (const name of names) {
    const values = params[`${path}:${name}`] ?? params[name];
    if (!values?.length) return { missing: name, urls: [] };
    urls = urls.flatMap((item) =>
      values.map((value) => ({
        url: item.url.replace(`$${name}`, encodeURIComponent(value)),
        label: name === "kind" ? [item.label, value].filter(Boolean).join(" ") : item.label,
      })),
    );
  }
  return { urls };
}

async function probe(page, name, ...args) {
  await page.evaluate(installProbes, config.copyRules);
  return page.evaluate(({ name, args }) => window.__review[name](...args), { name, args });
}

async function settle(page) {
  await page.waitForLoadState("load");
  await page.waitForLoadState("networkidle", { timeout: 5_000 }).catch(() => {});
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (await probe(page, "settled")) break;
    await delay(150);
  }
  await page.evaluate(() => document.fonts.ready);
  await delay(250);
  return probe(page, "settled");
}

async function axe(page, selector) {
  await page.evaluate(config.axeSource);
  const result = await page.evaluate(
    async ({ selector }) => {
      const context = selector ? document.querySelector(selector) : document;
      const run = await window.axe.run(context, {
        resultTypes: ["violations"],
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"],
        },
      });
      return run.violations.map((violation) => ({
        id: violation.id,
        impact: violation.impact,
        help: violation.help,
        nodes: violation.nodes.slice(0, 8).map((node) => ({
          target: node.target.join(" "),
          summary: (node.failureSummary ?? "").replace(/\s+/g, " ").slice(0, 300),
        })),
        count: violation.nodes.length,
      }));
    },
    { selector },
  );
  return result.map((violation) => ({
    ...violation,
    blocking: blockingImpacts.has(violation.impact),
  }));
}

async function screenshot(page, file, fullPage) {
  const path = join(config.evidenceDirectory, "screenshots", file);
  const mask = [
    page.locator('[data-sensitive="true"]'),
    page.locator('input[type="password"]'),
    page.locator('section[aria-label="One-time enrollment secret"] code'),
  ];
  await writePrivate(
    path,
    await page.screenshot({ fullPage, animations: "disabled", mask, timeout: 30_000 }),
  );
  return `screenshots/${file}`;
}

// Wait two frames (focus managers redirect focus on the next frame, e.g. Base UI
// focus guards), then for finite animations (dialog and tooltip entry).
async function settleAnimations(page) {
  await page.evaluate(
    () => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(() => done()))),
  );
  await page.evaluate(() =>
    Promise.race([
      Promise.all(
        document
          .getAnimations()
          .filter((animation) => animation.effect?.getTiming().iterations !== Infinity)
          .map((animation) => animation.finished.catch(() => {})),
      ),
      new Promise((done) => setTimeout(done, 1_000)),
    ]),
  );
}

async function pressAndInspect(page, key, dialogSelector) {
  await page.keyboard.press(key);
  await settleAnimations(page);
  return probe(page, "focused", dialogSelector);
}

async function keyboard(page) {
  const findings = [];
  const state = await probe(page, "page");
  // Interactive variants may leave a field focused. Measure its unfocused
  // appearance only after clearing focus and finishing the blur transition.
  await probe(page, "focusStart");
  await settleAnimations(page);
  const candidates = await probe(page, "tabbables", null);
  const first = await pressAndInspect(page, "Tab");
  const skip = candidates.find((item) => /Skip to content/.test(item.description));
  if (skip) {
    if (first.key !== skip.key)
      findings.push({
        check: "skip-link",
        message: "First Tab does not reach the skip link",
        elements: [first.description ?? "document"],
      });
    else if (!first.visible || !first.indicator)
      findings.push({
        check: "skip-link",
        message: "Skip link is not visible when focused",
        elements: [first.description],
      });
    else if (state.main) {
      await page.keyboard.press("Enter");
      const next = await pressAndInspect(page, "Tab", "#main");
      if (!next.inDialog)
        findings.push({
          check: "skip-link",
          message: "After the skip link, Tab does not continue inside main content",
          elements: [next.description ?? "document"],
        });
    }
  }
  // Full traversal from the document start. A control can be briefly disabled by a
  // background refetch while Tab passes it, so a second pass covers what the first
  // missed; an element is reported only when both passes miss it.
  const reached = new Map();
  const limit = Math.min(candidates.length * 2 + 20, 1200);
  const unreached = () => {
    const radioGroups = new Set(
      [...reached.values()]
        .map((focus) => candidates.find((item) => item.key === focus.key)?.radioGroup)
        .filter(Boolean),
    );
    return candidates.filter(
      (candidate) =>
        !reached.has(candidate.key) &&
        !(candidate.radioGroup && radioGroups.has(candidate.radioGroup)),
    );
  };
  for (let pass = 0; pass < 2 && (pass === 0 || unreached().length); pass += 1) {
    await probe(page, "focusStart");
    let start = "";
    let bodies = 0;
    for (let index = 0; index < limit; index += 1) {
      const focus = await pressAndInspect(page, "Tab");
      if (focus.body) {
        bodies += 1;
        if (bodies > 1) break;
        continue;
      }
      if (focus.key && focus.key === start) break;
      if (!start) start = focus.key || focus.description;
      if (reached.has(focus.key || focus.description)) continue;
      reached.set(focus.key || focus.description, focus);
      if (!focus.indicator)
        findings.push({
          check: "focus-indicator",
          message: "Focused element has no visible focus indicator",
          elements: [focus.description],
        });
      if (focus.obscured)
        findings.push({
          check: "focus-obscured",
          message: "Focused element is covered by another element",
          elements: [focus.description, focus.obscured],
        });
    }
  }
  for (const candidate of unreached()) {
    findings.push({
      check: "tab-order",
      message: "Tab never reaches this element",
      elements: [candidate.description],
    });
  }
  return { tabbable: candidates.length, reached: reached.size, findings };
}

async function waitFor(page, name, expected, timeout = 3_000) {
  const deadline = Date.now() + timeout;
  let value;
  while (Date.now() < deadline) {
    value = await probe(page, name);
    if (expected(value)) return value;
    await delay(100);
  }
  return value;
}

async function checkDialog(page, opener, restoreKey, label, evidence) {
  const findings = [];
  await probe(page, "clearDialogMark");
  const opened = await opener();
  const dialog = opened
    ? await waitFor(page, "openDialog", (value) => value !== null, 5_000)
    : null;
  if (!dialog) {
    findings.push({
      check: "dialog-open",
      message: opened
        ? "Control declares a dialog but none opened"
        : "Control declaring a dialog could not be reached by keyboard",
      elements: [label],
    });
    await page.keyboard.press("Escape");
    return findings;
  }
  await delay(100);
  await settleAnimations(page);
  const impact = await probe(page, "destructive");
  findings.push(...impact.findings);
  evidence.destructive.push(...impact.observed);
  const current = await probe(page, "openDialog");
  if (!current?.focusInside)
    findings.push({
      check: "dialog-focus",
      message: "Focus does not move into the open dialog",
      elements: [label, dialog.description],
    });
  if (!dialog.named)
    findings.push({
      check: "dialog-name",
      message: "Dialog has no accessible name",
      elements: [dialog.description],
    });
  evidence.push(
    await screenshot(page, `${evidence.prefix}-dialog-${evidence.length + 1}.png`, false),
  );
  for (const violation of await axe(page, '[data-review-dialog="open"]')) {
    if (violation.blocking)
      findings.push({
        check: "dialog-axe",
        message: `${violation.id} (${violation.impact}): ${violation.help}`,
        elements: violation.nodes.map((node) => `${node.target}: ${node.summary}`),
      });
  }
  if (dialog.modal) {
    const steps = Math.min(dialog.tabbables + 2, 40);
    for (const key of ["Tab", "Shift+Tab"]) {
      for (let index = 0; index < steps; index += 1) {
        const focus = await pressAndInspect(page, key, '[data-review-dialog="open"]');
        if (!focus.inDialog) {
          findings.push({
            check: "dialog-focus-trap",
            message: `${key} moves focus out of the modal dialog`,
            elements: [label, focus.description ?? "document"],
          });
          break;
        }
      }
    }
  }
  await page.keyboard.press("Escape");
  const closed = await waitFor(page, "dialogOpen", (value) => value === false, 2_000);
  if (closed) {
    findings.push({
      check: "dialog-escape",
      message: "Escape does not close the dialog",
      elements: [label],
    });
    return findings;
  }
  // Focus returns after the close animation; allow it to finish under load.
  const active = await waitFor(page, "activeKey", (key) => key === restoreKey, 2_000);
  if (active !== restoreKey)
    findings.push({
      check: "dialog-restore-focus",
      message: "Closing the dialog does not return focus to its trigger",
      elements: [label],
    });
  return findings;
}

async function dialogs(page, prefix) {
  const findings = [];
  const evidence = [];
  evidence.prefix = prefix;
  evidence.destructive = [];
  let count = 0;
  for (const trigger of await probe(page, "dialogTriggers")) {
    if ((count += 1) > maxDialogsPerPage) break;
    findings.push(
      ...(await checkDialog(
        page,
        async () => {
          if (!(await probe(page, "focusKey", trigger.key))) return false;
          await page.keyboard.press("Enter");
          return true;
        },
        trigger.key,
        trigger.description,
        evidence,
      )),
    );
  }
  for (const menu of await probe(page, "menuTriggers")) {
    if (!(await probe(page, "focusKey", menu.key))) continue;
    await page.keyboard.press("Enter");
    const items = await waitFor(page, "openMenuDialogItems", (value) => value !== null, 2_000);
    await page.keyboard.press("Escape");
    await delay(200);
    for (const item of items ?? []) {
      if ((count += 1) > maxDialogsPerPage) break;
      findings.push(
        ...(await checkDialog(
          page,
          async () => {
            if (!(await probe(page, "focusKey", menu.key))) return false;
            await page.keyboard.press("Enter");
            await waitFor(page, "openMenuDialogItems", (value) => value !== null, 2_000);
            for (let step = 0; step < 30; step += 1) {
              if ((await probe(page, "highlightedMenuItem")) === item) {
                await page.keyboard.press("Enter");
                return true;
              }
              await page.keyboard.press("ArrowDown");
            }
            return false;
          },
          menu.key,
          `${menu.description} > ${item}`,
          evidence,
        )),
      );
    }
  }
  return {
    findings,
    screenshots: evidence.slice(),
    destructive: [...new Set(evidence.destructive)],
  };
}

async function palette(page) {
  const findings = [];
  for (const chord of ["Control+k", "Meta+k"]) {
    await probe(page, "focusStart");
    const before = await pressAndInspect(page, "Tab");
    before.key = await probe(page, "activeKey");
    await probe(page, "clearDialogMark");
    await page.keyboard.press(chord);
    const dialog = await waitFor(page, "openDialog", (value) => value?.focusInside === true);
    if (!dialog?.focusInside) {
      findings.push({
        check: "command-palette",
        message: `${chord} does not open the command palette with focus inside`,
        elements: [],
      });
      await page.keyboard.press("Escape");
      continue;
    }
    await page.keyboard.type("dash");
    await delay(200);
    const options = await page.locator('[data-review-dialog="open"] [role="option"]').count();
    if (options === 0)
      findings.push({
        check: "command-palette",
        message: "Typing in the command palette shows no results",
        elements: [],
      });
    await page.keyboard.press("Escape");
    const open = await waitFor(page, "dialogOpen", (value) => value === false, 2_000);
    if (open)
      findings.push({
        check: "command-palette",
        message: "Escape does not close the command palette",
        elements: [],
      });
    else if ((await probe(page, "activeKey")) !== before.key)
      findings.push({
        check: "command-palette",
        message: "Closing the command palette does not restore focus",
        elements: [before.description ?? "document"],
      });
  }
  return findings;
}

// One real toast through the console UI: saving device details on the seeded device.
async function toast(page, prefix) {
  const findings = [];
  await page.goto(`${config.origin}/devices/${config.deviceId}`);
  await settle(page);
  const card = page
    .locator('[data-slot="card"]')
    .filter({ has: page.getByText("Owner, labels and attributes", { exact: true }) });
  try {
    await card.getByRole("button", { name: "Edit", exact: true }).click({ timeout: 10_000 });
    await card.locator("#metadata-reason").fill("UI review toast check");
    await card.getByRole("button", { name: "Save", exact: true }).click();
  } catch {
    return {
      findings: [
        { check: "toast", message: "Could not trigger the device-details toast", elements: [] },
      ],
      screenshot: "",
    };
  }
  const shown = await waitFor(page, "toast", (value) => value !== null, 10_000);
  if (!shown)
    return {
      findings: [
        { check: "toast", message: "Saving device details showed no toast", elements: [] },
      ],
      screenshot: "",
    };
  await delay(500);
  const styled = await probe(page, "toast");
  for (const problem of styled?.problems ?? [])
    findings.push({
      check: "toast",
      message: `Unstyled toast: ${problem}`,
      elements: [styled.text],
    });
  const file = await screenshot(page, `${prefix}-toast.png`, false);
  return { findings, screenshot: file };
}

function summarize(entry) {
  for (const [name, check] of Object.entries(entry.checks)) {
    for (const finding of check.findings ?? []) {
      const where = `${entry.route}${entry.variant ? ` [${entry.variant}]` : ""} ${entry.theme} ${entry.viewport}`;
      const detail = finding.message ?? finding.rule ?? "";
      const elements = (finding.elements ?? []).slice(0, 3).join(" | ");
      report.failures.push(
        `${where} ${name}: ${detail}${finding.excerpt ? ` "${finding.excerpt}"` : ""}${elements ? ` @ ${elements}` : ""}`,
      );
    }
  }
}

async function review(page, route, target, theme, viewport, variant, expectedButtons = []) {
  const entry = {
    route: route.path,
    url: target.url,
    variant,
    theme,
    viewport: viewport.name,
    size: `${viewport.width}x${viewport.height}`,
    passed: false,
    screenshots: {},
    checks: {},
  };
  entry.checks.advisory = { findings: await reviewAdvisoryControls(page, route.path) };
  const prefix =
    slug(
      `${route.path}${target.label ? `-${target.label}` : ""}${variant ? `-${variant}` : ""}-${theme}-${viewport.name}`,
    ) || "root";
  // Capture from scroll 0, including inner scroll containers.
  await page.evaluate(() => {
    window.scrollTo(0, 0);
    for (const node of document.querySelectorAll("*")) if (node.scrollTop > 0) node.scrollTop = 0;
  });
  await delay(100);
  entry.screenshots.viewport = await screenshot(page, `${prefix}.png`, false);
  entry.screenshots.full = await screenshot(page, `${prefix}-full.png`, true);
  entry.checks.layout = { findings: await probe(page, "layout", viewport.name === "desktop") };
  const violations = await axe(page, null);
  entry.checks.axe = {
    violations,
    findings: violations
      .filter((violation) => violation.blocking)
      .map((violation) => ({
        message: `${violation.id} (${violation.impact}, ${violation.count} nodes): ${violation.help}`,
        elements: violation.nodes.map((node) => `${node.target}: ${node.summary}`),
      })),
  };
  entry.checks.copy = { findings: await probe(page, "copy") };
  entry.checks.forms = { findings: await probe(page, "forms") };
  entry.checks.idInputs = { findings: await probe(page, "idInputs") };
  entry.checks.conventions = {
    findings: await probe(page, "conventions", listRoutes.includes(route.path)),
  };
  entry.checks.pov = await probe(page, "pov", routeContracts[route.path] ?? null);
  entry.checks.expected = { findings: [] };
  for (const name of expectedButtons) {
    const problem = await probe(page, "expectButton", name);
    if (problem) entry.checks.expected.findings.push({ message: problem, elements: [] });
  }
  const leaks = await probe(page, "leaks", secrets);
  entry.checks.secrets = {
    findings: leaks ? [{ message: "A sign-in secret is visible on the page", elements: [] }] : [],
  };
  entry.checks.keyboard = await keyboard(page);
  const dialog = await dialogs(page, prefix);
  entry.checks.dialogs = { findings: dialog.findings, destructive: dialog.destructive };
  entry.screenshots.dialogs = dialog.screenshots;
  entry.checks.popups = await popupStability(page, settleAnimations);
  entry.passed = Object.values(entry.checks).every((check) => check.findings.length === 0);
  summarize(entry);
  report.results.push(entry);
}

async function visit(page, url) {
  await page.goto(`${config.origin}${url}`, { waitUntil: "domcontentloaded" });
  const settled = await settle(page);
  return { state: await probe(page, "page"), settled };
}

async function reviewRoute(page, route, theme, viewport) {
  const record = report.routes.find((item) => item.path === route.path);
  for (const target of record.targets) {
    const { state, settled } = await visit(page, target.url);
    const expected = new URL(`${config.origin}${target.url}`).pathname;
    if (state.path !== expected || state.routeError) {
      record.errors.push(
        `${theme} ${viewport.name}: ${target.url} rendered ${state.routeError ? "the route error page" : state.path}`,
      );
      continue;
    }
    if (!settled)
      record.errors.push(`${theme} ${viewport.name}: ${target.url} never finished loading`);
    const variants = state.tabs.length ? state.tabs : [""];
    for (const [index, variant] of variants.entries()) {
      if (index > 0) {
        await visit(page, target.url);
        await page.getByRole("tab", { name: variant, exact: true }).click();
        await settle(page);
      }
      await review(
        page,
        route,
        target,
        theme,
        viewport,
        [target.label, variant].filter(Boolean).join(" ") || "",
      );
    }
    if (route.path === "/profiles/new") {
      await visit(page, target.url);
      await page.getByRole("combobox", { name: "Setting type", exact: true }).first().click();
      await page.getByRole("option", { name: "Block kernel modules", exact: true }).click();
      await page.getByLabel("Modules to block", { exact: true }).fill("usb_storage\nuas");
      await settle(page);
      await review(page, route, target, theme, viewport, "Block kernel modules");
    }
    record.visits += 1;
  }
}

async function session(page, theme, viewport, routes) {
  const entry = { theme, viewport: viewport.name, checks: {} };
  await page.setViewportSize({ width: viewport.width, height: viewport.height });
  await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
  for (const route of routes) await reviewRoute(page, route, theme, viewport);
  return entry;
}

async function main() {
  config = await readPrivateJSON(resolve(process.argv[2]));
  for (const key of [
    "origin",
    "username",
    "password",
    "enrollmentSecret",
    "evidenceDirectory",
    "checkout",
  ])
    if (typeof config[key] !== "string" || !config[key])
      throw new Error("required_configuration_missing");
  for (const key of ["origin", "username", "password", "enrollmentSecret"])
    if (typeof config.enrollmentFixture?.[key] !== "string" || !config.enrollmentFixture[key])
      throw new Error("published_enrollment_fixture_required");
  secrets = [
    config.password,
    config.enrollmentSecret,
    config.enrollmentFixture.password,
    config.enrollmentFixture.enrollmentSecret,
  ];
  config.evidenceDirectory = resolve(config.evidenceDirectory);
  await privateDirectory(config.evidenceDirectory);
  config.copyRules = JSON.parse(
    await readFile(join(config.checkout, "web/acceptance/copy-rules.json"), "utf8"),
  );
  const require = createRequire(import.meta.url);
  config.axeSource = await readFile(require.resolve("axe-core/axe.min.js"), "utf8");
  report.axeVersion = JSON.parse(
    await readFile(require.resolve("axe-core/package.json"), "utf8"),
  ).version;
  report.demo = config.demo ?? null;
  report.build = config.build ?? null;
  const routes = await routeTree(join(config.checkout, "web/src/routeTree.gen.ts"));
  const kinds = await complexActionKinds(
    join(config.checkout, "web/src/features/devices/action-menu.tsx"),
  );
  // Seeded identifiers from loadlab.DemoRoutes (Go field names).
  const ids = config.demo?.Routes ?? {};
  config.deviceId = ids.DeviceID;
  const params = {
    deviceId: [ids.DeviceID],
    profileId: [ids.ProfileID],
    secretId: [ids.SecretID],
    sessionId: [ids.AssistanceSessionID],
    "/devices/$deviceId/actions/$actionId:actionId": [ids.ActionID],
    "/devices/$deviceId/recovery/$actionId:actionId": [ids.RecoveryActionID],
    kind: kinds,
  };
  for (const [name, values] of Object.entries(params)) params[name] = values.filter(Boolean);
  for (const route of routes) {
    const { urls, missing } = concrete(route.path, params);
    report.routes.push({
      path: route.path,
      authenticated: route.authenticated,
      targets: urls,
      missing: missing ?? "",
      visits: 0,
      errors: [],
    });
  }

  const combos = themes.flatMap((theme) => viewports.map((viewport) => ({ theme, viewport })));
  if (config.directoryFixture) {
    const directoryResults = await reviewDirectoryAuthorization({
      config,
      combos,
      screenshot,
      axe,
      probe,
      settle,
      keyboard,
      protectSecret: (value) => {
        if (value) secrets.push(value);
      },
    });
    for (const entry of directoryResults) {
      summarize(entry);
      report.results.push(entry);
    }
  }
  if (report.results.some((entry) => !entry.passed))
    throw new Error("directory_authorization_review_failed");
  const driver = new ChromiumDriver();
  await driver.open({ ignoreHTTPSErrors: true, actionTimeoutMs: 30_000, classicScrollbars: true });
  try {
    report.browser = driver.metadata;
    const pages = [driver.page];
    for (let index = 1; index < themes.length * viewports.length; index += 1)
      pages.push(await driver.context.newPage());
    for (const page of pages) page.setDefaultTimeout(30_000);
    // Theme follows the emulated color scheme; the toggle's stored choice is cleared.
    await driver.context.addInitScript(() => {
      try {
        localStorage.removeItem("lindm-theme");
      } catch {
        /* Storage disabled: system preference applies. */
      }
    });
    const publicRoutes = report.routes.filter((route) => !route.authenticated);
    const privateRoutes = report.routes.filter((route) => route.authenticated);
    await Promise.all(
      combos.map(({ theme, viewport }, index) =>
        session(pages[index], theme, viewport, publicRoutes),
      ),
    );

    // Real enrollment and sign-in on one page; the others share the cookie session.
    await driver.authenticator([]);
    const ui = new UI(driver, 30_000);
    await driver.page.setViewportSize({ width: 1440, height: 900 });
    await driver.goto(config.origin);
    await enroll(ui, config);
    await signIn(ui, config);

    const sessions = await Promise.all(
      combos.map(async ({ theme, viewport }, index) => {
        const page = pages[index];
        const entry = await session(page, theme, viewport, privateRoutes);
        const prefix = `session-${theme}-${viewport.name}`;
        await visit(page, "/dashboard");
        entry.checks.palette = { findings: await palette(page) };
        const shown = await toast(page, prefix);
        entry.checks.toast = { findings: shown.findings };
        entry.screenshots = { toast: shown.screenshot };
        for (const [name, check] of Object.entries(entry.checks))
          for (const finding of check.findings)
            report.failures.push(
              `${theme} ${viewport.name} ${name}: ${finding.message}${finding.elements?.length ? ` @ ${finding.elements.join(" | ")}` : ""}`,
            );
        return entry;
      }),
    );
    report.sessions = sessions;
    // Owner edit acceptance reads the seeded fleet before enrollment fixtures and
    // task walkthroughs add requests, sessions and approvals of their own.
    report.ownerEdits = await reviewOwnerEdits({
      page: pages[0],
      config,
      visit,
      settle,
      screenshot,
    });
    for (const edit of report.ownerEdits)
      for (const finding of edit.findings)
        report.failures.push(`owner edit ${edit.route} ${edit.name}: ${finding}`);
    // Per-role walkthrough before task walkthroughs add requests of their own.
    report.roleWalkthroughs = await reviewRoleWalkthroughs({
      ownerPage: pages[0],
      config,
      visit,
      settle,
      screenshot,
      protectSecret: (value) => {
        if (value) secrets.push(value);
      },
    });
    for (const walkthrough of report.roleWalkthroughs)
      for (const finding of walkthrough.findings)
        report.failures.push(`role walkthrough ${walkthrough.role}: ${finding}`);
    const enrollmentResults = await reviewEnrollmentFixtures({
      driver,
      pages,
      combos,
      config,
      screenshot,
      axe,
      probe,
      settle,
      protectSecret: (value) => {
        if (value) secrets.push(value);
      },
    });
    for (const entry of enrollmentResults) {
      summarize(entry);
      report.results.push(entry);
    }
    report.failures.push(
      ...(await reviewSSHBanner({
        pages,
        combos,
        routes: report.routes,
        visit,
        settle,
        review,
        screenshot,
      })),
    );
    for (const entry of await reviewOSUpdate({
      pages,
      combos,
      config,
      screenshot,
      axe,
      probe,
      settle,
    })) {
      summarize(entry);
      report.results.push(entry);
    }
    // Seeded sessions belong to the seeding owner and have ended. Request a
    // control-mode session through the device page as the signed-in owner, so the
    // live viewer (Take control and its disabled reason) is reviewed in every theme
    // and viewport. The device never answers; one open session per device is allowed,
    // so a single request is reviewed from every page.
    const viewerRoute = report.routes.find(
      (route) => route.path === "/devices/$deviceId/assistance/$sessionId",
    );
    const requester = pages[0];
    let step = "open device";
    let viewerUrl = "";
    try {
      await visit(requester, `/devices/${config.deviceId}`);
      step = "open Remote assistance tab";
      await requester.getByRole("tab", { name: "Remote assistance", exact: true }).click();
      const form = requester.locator("form").filter({
        has: requester.getByRole("button", { name: "Request remote assistance" }),
      });
      step = "choose control mode";
      await form.getByRole("combobox").first().click();
      await requester.getByRole("option", { name: "View and request control" }).click();
      step = "enter reason";
      await form.getByLabel("Reason (shown to the local user and audited)").fill("UI review");
      step = "submit request";
      await form.getByRole("button", { name: "Request remote assistance" }).click();
      step = "open viewer";
      await requester.waitForURL(/\/assistance\/[0-9a-f-]{36}(?:[?#]|$)/, { timeout: 30_000 });
      viewerUrl = new URL(requester.url()).pathname;
    } catch {
      report.failures.push(
        `assistance: could not request a session from the device page (step: ${step}; see screenshots/assistance-request.png)`,
      );
      await screenshot(requester, "assistance-request.png", true);
    }
    for (const [index, { theme, viewport }] of viewerUrl ? combos.entries() : []) {
      const page = pages[index];
      if (page !== requester) await visit(page, viewerUrl);
      await settle(page);
      await review(
        page,
        viewerRoute,
        { url: viewerUrl, label: "" },
        theme,
        viewport,
        "requested by you",
        viewerControls,
      );
      viewerRoute.visits += 1;
    }
    // The route matrix owns this request. End it visibly before another job
    // asks to help the same device; navigation cleanup is not an observed end.
    if (viewerUrl) {
      try {
        await requester.getByRole("button", { name: "Stop session", exact: true }).click();
        await requester
          .getByRole("heading", { name: "Why this session ended", exact: true })
          .waitFor({ state: "visible", timeout: 30_000 });
      } catch {
        report.failures.push(
          "assistance: route-review request did not visibly end before task walkthroughs",
        );
        await screenshot(requester, "assistance-stop.png", true);
      }
    }
    report.walkthroughs = await taskWalkthroughs({
      page: requester,
      config,
      visit,
      settle,
      screenshot,
    });
    for (const job of report.walkthroughs.results) {
      if (job.failure) report.failures.push(`task ${job.id}: ${job.failure}`);
    }
    const authorizationResults = await reviewAuthorization({
      pages,
      combos,
      config,
      screenshot,
      axe,
      probe,
      settle,
      protectSecret: (value) => {
        if (value) secrets.push(value);
      },
    });
    for (const entry of authorizationResults) {
      summarize(entry);
      report.results.push(entry);
    }
  } finally {
    await driver.close();
  }
  for (const route of report.routes) {
    if (route.missing)
      report.failures.push(
        `${route.path}: no seeded value for $${route.missing}; route not visited`,
      );
    else if (route.visits === 0) report.failures.push(`${route.path}: route not visited`);
    for (const error of route.errors) report.failures.push(`${route.path}: ${error}`);
  }
  report.pov = {
    contracts: routeContracts,
    destructive: destructiveCoverage(report.results, themes, viewports),
    limitation:
      "DOM presence is not design approval. Unmarked metrics, unopened dialogs and unvisited states require human review.",
  };
  for (const coverage of report.pov.destructive)
    if (!coverage.observed)
      report.failures.push(
        `POV coverage: destructive dialog ${coverage.id} not observed in ${coverage.theme} ${coverage.viewport}`,
      );
  report.passed = report.failures.length === 0;
}

let exitCode = 1;
try {
  if (process.argv.length !== 3) throw new Error("private_config_path_required");
  await main();
  exitCode = report.passed ? 0 : 1;
} catch (error) {
  // Never print browser exceptions: their call logs can contain filled secrets.
  report.failures.push(
    `runner: ${/^[a-z][a-z0-9_]+$/.test(error?.message ?? "") ? error.message : `${error?.name ?? "Error"} during review`}`,
  );
  report.passed = false;
} finally {
  report.finishedAt = new Date().toISOString();
  if (config?.evidenceDirectory) {
    // An edit sheet that the importer would refuse is a review failure, recorded
    // in the report rather than discovered by the owner after annotating.
    let manifest = null;
    try {
      manifest = editManifest(redact(report));
    } catch (error) {
      report.failures.push(`edit sheet: ${error.message}`);
      report.passed = false;
      exitCode = 1;
    }
    const clean = redact(report);
    await writePrivateJSON(join(config.evidenceDirectory, "report.json"), clean);
    await writePrivate(join(config.evidenceDirectory, "index.html"), contactSheet(clean));
    if (clean.walkthroughs) {
      await writePrivateJSON(join(config.evidenceDirectory, "task-audit.json"), clean.walkthroughs);
      await writePrivate(
        join(config.evidenceDirectory, "task-audit.html"),
        taskAuditSheet(clean.walkthroughs),
      );
    }
    if (manifest) {
      await writePrivateJSON(join(config.evidenceDirectory, "edit-sheet.json"), manifest);
      await writePrivateJSON(
        join(config.evidenceDirectory, "annotations-template.json"),
        annotationTemplate(manifest),
      );
      await writePrivate(join(config.evidenceDirectory, "edit-sheet.html"), editSheet(manifest));
    }
  }
  process.exitCode = exitCode;
}
