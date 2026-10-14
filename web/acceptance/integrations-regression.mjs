#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

// Run once per state against an owned real-process fixture. The sole argument
// is a protected JSON file: origin, username, password, state (configured or
// unconfigured), credentialPath, evidenceDirectory, ignoreHTTPSErrors; the
// configured run also supplies enrollmentSecret; populated:true verifies a
// seeded demo's destination and schedule tables instead of fresh empty panels.
// Only the credential file is carried between runs, never cookies or browser
// storage. No RPC interception.
import assert from "node:assert/strict";
import { join, resolve } from "node:path";
import { ChromiumDriver, UI } from "./drivers.mjs";
import { enroll, openSignIn, signIn, signOut } from "./journey.mjs";
import {
  privateDirectory,
  readPrivateJSON,
  writePrivate,
  writePrivateJSON,
} from "./private-files.mjs";

process.umask(0o077);
const service = "/lindm.integrations.v1.";
const initialReads = [
  `${service}IntegrationService/ListDestinations`,
  `${service}IntegrationService/ListDeliveries`,
  `${service}IntegrationService/SummarizeDeliveries`,
  `${service}ReportService/ListReportSchedules`,
  `${service}ReportService/ListReportArtifacts`,
];
const setupInstruction =
  "Ask the server administrator to create and back up a protected 32-byte encryption key, set integrations.encryptionKeyFile to its path in the lindmd configuration, then restart lindmd. This enables destinations, deliveries and reports.";
const panelHeadings = ["Destinations", "Delivery log", "Scheduled reports", "Reports"];
const result = { passed: false, rpcResponses: [], screenshots: [] };
let config;
let driver;
let step = "configuration";

async function capture(name) {
  // Match the normal acceptance custody rule, including on failed journeys:
  // no filled password, command region, raw DOM, console dump, trace or HAR.
  await driver.observe(() => {
    for (const node of document.querySelectorAll(
      'input,textarea,pre,code,[data-sensitive="true"]',
    )) {
      node.dataset.integrationsOldVisibility = node.style.visibility;
      node.style.setProperty("visibility", "hidden", "important");
    }
  });
  try {
    const path = join(config.evidenceDirectory, `${config.state}-${name}.png`);
    await writePrivate(path, await driver.screenshot());
    result.screenshots.push(path);
  } finally {
    await driver.observe(() => {
      for (const node of document.querySelectorAll("[data-integrations-old-visibility]")) {
        node.style.visibility = node.dataset.integrationsOldVisibility;
        delete node.dataset.integrationsOldVisibility;
      }
    });
  }
}

try {
  assert.equal(process.argv.length, 3, "private_configuration_path_required");
  config = await readPrivateJSON(process.argv[2]);
  for (const key of ["origin", "username", "password", "credentialPath", "evidenceDirectory"]) {
    assert.equal(typeof config[key], "string", "required_configuration_missing");
    assert.ok(config[key], "required_configuration_missing");
  }
  assert.ok(["configured", "unconfigured"].includes(config.state), "invalid_integrations_state");
  const origin = new URL(config.origin);
  assert.ok(
    origin.protocol === "https:" && origin.origin === config.origin,
    "https_origin_required",
  );
  config.evidenceDirectory = resolve(config.evidenceDirectory);
  await privateDirectory(config.evidenceDirectory);
  result.state = config.state;
  driver = new ChromiumDriver();
  step = "browser_start";
  await driver.open({ ...config, actionTimeoutMs: 30_000 });
  result.browser = driver.metadata;
  const ui = new UI(driver, 30_000);
  let credentials = [];
  if (config.state === "unconfigured") {
    const saved = await readPrivateJSON(config.credentialPath);
    assert.equal(saved.origin, config.origin, "credential_binding_mismatch");
    assert.equal(saved.username, config.username, "credential_binding_mismatch");
    assert.equal(saved.credentials?.length, 1, "expected_one_owner_credential");
    credentials = saved.credentials;
  }
  await driver.authenticator(credentials);
  step = "sign_in_page";
  await openSignIn(ui, config.origin);
  if (config.state === "configured") {
    step = "browser_enrollment";
    assert.ok(config.enrollmentSecret, "enrollment_secret_required");
    await enroll(ui, config);
    config.enrollmentSecret = "";
  }
  step = "browser_sign_in";
  await signIn(ui, config);
  step = "browser_credential_capture";
  credentials = await driver.credentials();
  assert.equal(credentials.length, 1, "expected_one_owner_credential");
  // Persist the updated authenticator sign counter before checking the page.
  // Private keys stay in the separate protected credential file, not evidence.
  step = "browser_credential_store";
  await writePrivateJSON(config.credentialPath, {
    origin: config.origin,
    username: config.username,
    credentials,
  });

  step = "integrations_page";
  const page = driver.page;
  const main = page.getByRole("main");
  const requested = [];
  const unexpectedHTTP = [];
  const failedRequests = [];
  const pageErrors = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin === config.origin && url.pathname.startsWith(service)) {
      requested.push(url.pathname);
    }
  });
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.origin !== config.origin || response.status() < 400) return;
    // Connect maps the typed FailedPrecondition setup refusal to HTTP 400.
    // Chromium's corresponding failed-resource console line is expected.
    if (
      config.state === "unconfigured" &&
      url.pathname === initialReads[0] &&
      response.status() === 400
    )
      return;
    unexpectedHTTP.push({ path: url.pathname, status: response.status() });
  });
  page.on("requestfailed", (request) => {
    const url = new URL(request.url());
    if (url.origin === config.origin) failedRequests.push(url.pathname);
  });
  page.on("pageerror", () => pageErrors.push("page_error"));
  const expectedReads = config.state === "configured" ? initialReads : initialReads.slice(0, 1);
  const responses = await Promise.all([
    ...expectedReads.map((path) =>
      page.waitForResponse((response) => {
        const url = new URL(response.url());
        return url.origin === config.origin && url.pathname === path;
      }),
    ),
    driver.goto(`${config.origin}/integrations`),
  ]);
  responses.pop();
  await main.getByRole("heading", { name: "Integrations and reports", exact: true }).waitFor();
  for (const response of responses) {
    const path = new URL(response.url()).pathname;
    const status = response.status();
    if (config.state === "configured") {
      assert.equal(status, 200, "configured_rpc_failed");
      result.rpcResponses.push({ path, status });
    } else {
      assert.equal(status, 400, "setup_rpc_not_failed_precondition");
      const body = await response.json();
      assert.equal(body.code, "failed_precondition", "setup_rpc_wrong_code");
      assert.equal(
        response.headers()["lindm-reason"],
        "integrations_unconfigured",
        "setup_rpc_wrong_reason",
      );
      result.rpcResponses.push({
        path,
        status,
        code: body.code,
        reason: "integrations_unconfigured",
      });
    }
  }
  if (config.state === "configured") {
    for (const name of panelHeadings) {
      await main.getByRole("heading", { name, exact: true }).waitFor();
    }
    if (config.populated === true) {
      await main.getByRole("table", { name: "Destinations", exact: true }).waitFor();
      await main.getByRole("table", { name: "Report schedules", exact: true }).waitFor();
    } else {
      for (const text of [
        "No destinations yet",
        "No failed deliveries",
        "No scheduled reports yet",
        "No reports yet",
      ]) {
        await main.getByText(text, { exact: true }).waitFor();
      }
    }
    assert.equal(await main.getByText("Integrations are not set up", { exact: true }).count(), 0);
  } else {
    await main.getByText("Integrations are not set up", { exact: true }).waitFor();
    await main.getByText(setupInstruction, { exact: true }).waitFor();
    for (const name of panelHeadings) {
      assert.equal(
        await main.getByRole("heading", { name, exact: true }).count(),
        0,
        "setup_gate_mounted_panel",
      );
    }
  }
  await page.waitForFunction(() => !document.querySelector('main [aria-busy="true"]'));
  await driver.observe(async () => {
    await document.fonts.ready;
    await new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)));
  });
  assert.deepEqual(
    [...new Set(requested)].sort(),
    [...expectedReads].sort(),
    "incorrect_initial_rpc_set",
  );
  if (config.state === "unconfigured") {
    assert.deepEqual(requested, [initialReads[0]], "setup_gate_must_only_query_destinations_once");
  }
  assert.equal(
    await main.locator('[role="alert"],[data-slot="alert"],[data-slot="support-details"]').count(),
    0,
    "integrations_alert_or_rpc_error",
  );
  assert.equal(
    await main.getByText("Result unknown", { exact: false }).count(),
    0,
    "integrations_result_unknown",
  );
  assert.deepEqual(unexpectedHTTP, [], "unexpected_http_error");
  assert.deepEqual(failedRequests, [], "unexpected_request_failure");
  assert.deepEqual(pageErrors, [], "unexpected_page_error");
  step = "integrations_screenshot";
  await capture("integrations");
  step = "browser_sign_out";
  await signOut(ui, config.origin);
  result.passed = true;
} catch (error) {
  // Never print browser exception text: filled secrets can appear in call logs.
  const safeFailures = new Set(["ui_condition_timeout", "ambiguous_ui_locator"]);
  result.failure = {
    step,
    code: safeFailures.has(error?.message)
      ? error.message
      : "integrations_browser_regression_failed",
  };
  if (driver?.page && config?.evidenceDirectory) {
    try {
      await capture("failure");
    } catch {
      result.failure.screenshotUnavailable = true;
    }
  }
  process.exitCode = 1;
} finally {
  if (driver) {
    try {
      await driver.close();
    } catch {
      result.passed = false;
      result.failure = { step: "browser_close", code: "browser_close_failed" };
      process.exitCode = 1;
    }
  }
  if (config?.evidenceDirectory && ["configured", "unconfigured"].includes(config.state)) {
    await writePrivateJSON(join(config.evidenceDirectory, `${config.state}-result.json`), result);
  }
}
