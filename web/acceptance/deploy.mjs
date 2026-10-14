#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

// Real visible setup, clipboard and management controls. TLS uses a private NSS
// CA store, never ignoreHTTPSErrors or a certificate-verification bypass.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { chromium } from "playwright";
import { ChromiumDriver, UI } from "./drivers.mjs";
import { enroll, signIn, signOut, createGrant, confirmEnrolledDevice } from "./journey.mjs";
import {
  privateDirectory,
  readPrivateJSON,
  writePrivate,
  writePrivateJSON,
} from "./private-files.mjs";

process.umask(0o077);
const exec = promisify(execFile);
let config;
let driver;
const result = { passed: false, screenshots: [], password_and_passkey: false, operations: [] };

class AuditedUI extends UI {
  async record(name, operation) {
    const entry = { name, kind: "decision", started_at: new Date().toISOString(), passed: false };
    result.operations.push(entry);
    try {
      const value = await operation();
      entry.passed = true;
      return value;
    } finally {
      entry.finished_at = new Date().toISOString();
    }
  }
  async click(query) {
    return this.record(`Click ${query.text ?? query.label ?? query.role ?? "named control"}`, () =>
      super.click(query),
    );
  }
  async fill(query, value) {
    return this.record(`Enter ${query.label ?? "named field"}`, () => super.fill(query, value));
  }
}

async function capture(name) {
  await driver.observe(() => {
    for (const node of document.querySelectorAll(
      'input,textarea,pre,code,[data-sensitive="true"]',
    )) {
      node.dataset.deployVisibility = node.style.visibility;
      node.style.setProperty("visibility", "hidden", "important");
    }
  });
  try {
    const path = join(config.evidenceDirectory, `${config.phase}-${name}.png`);
    await writePrivate(path, await driver.screenshot());
    result.screenshots.push(path);
  } finally {
    await driver.observe(() => {
      for (const node of document.querySelectorAll("[data-deploy-visibility]")) {
        node.style.visibility = node.dataset.deployVisibility;
        delete node.dataset.deployVisibility;
      }
    });
  }
}

async function openTrustedBrowser() {
  const home = join(config.privateDirectory, "browser-home");
  const store = join(home, ".pki", "nssdb");
  await privateDirectory(store);
  // The caller supplies the exact CA generated for this owned deployment. This
  // changes only the child's HOME, never the workstation's certificate store.
  try {
    await exec("certutil", ["-L", "-d", `sql:${store}`], { timeout: 10_000 });
  } catch {
    await exec("certutil", ["-N", "--empty-password", "-d", `sql:${store}`], { timeout: 10_000 });
  }
  await exec(
    "certutil",
    ["-A", "-d", `sql:${store}`, "-n", "lindm-owned-deployment", "-t", "C,,", "-i", config.caFile],
    { timeout: 10_000 },
  );
  driver = new ChromiumDriver();
  driver.browser = await chromium.launch({
    headless: true,
    timeout: 30_000,
    env: { ...process.env, HOME: home },
  });
  driver.context = await driver.browser.newContext({
    viewport: { width: 1440, height: 1000 },
    ignoreHTTPSErrors: false,
  });
  driver.page = await driver.context.newPage();
  driver.page.setDefaultTimeout(30_000);
  result.browser_version = driver.browser.version();
  await driver.context.grantPermissions(["clipboard-read", "clipboard-write"], {
    origin: config.origin,
  });
  const credentials = config.phase === "setup" ? [] : await readPrivateJSON(config.credentialPath);
  await driver.authenticator(credentials);
  result.authenticator = "chromium-ctap2-user-verified-virtual";
}

async function managedRefresh(ui) {
  await confirmEnrolledDevice(ui, config);
  // Capture the IDs present before issuance. An older completed refresh can
  // never satisfy this run, including when a backup restored its history.
  await driver.goto(`${config.origin}/devices/${encodeURIComponent(config.deviceId)}?tab=actions`);
  const previous = await driver.observe(() =>
    [...document.querySelectorAll("[data-device-action-row]")].map((row) => row.dataset.actionId),
  );
  const requestedAt = Date.now();
  await driver.goto(
    `${config.origin}/devices/${encodeURIComponent(config.deviceId)}?action=refreshInventory`,
  );
  await ui.fill(
    { label: "Reason", dialog: true },
    "Maintained deployment lifecycle same-device live inventory proof",
  );
  await ui.click({ role: "button", text: "Review action", dialog: true });
  await ui.click({ role: "button", text: "Send action", dialog: true });
  const deadline = Date.now() + 420_000;
  while (Date.now() < deadline) {
    await driver.goto(
      `${config.origin}/devices/${encodeURIComponent(config.deviceId)}?tab=actions`,
    );
    const observed = await driver.observe((old) => {
      const rows = [...document.querySelectorAll("[data-device-action-row]")];
      const candidates = rows.filter(
        (row) =>
          !old.includes(row.dataset.actionId) &&
          row.querySelector("summary")?.textContent.includes("Refresh inventory"),
      );
      if (candidates.length !== 1) return null;
      const row = candidates[0];
      const summary = row.querySelector("summary");
      const fact = (label) =>
        [...row.querySelectorAll("dt")].find((node) => node.textContent.trim() === label)
          ?.nextElementSibling;
      return {
        id: row.dataset.actionId,
        state: summary?.querySelector('[data-slot="badge"]')?.textContent.trim(),
        finished: fact("Finished")?.querySelector("time")?.getAttribute("datetime"),
        inventory: fact("Fresh inventory")?.textContent.trim(),
      };
    }, previous);
    if (
      observed?.state === "Completed" &&
      observed.inventory === "Received" &&
      Date.parse(observed.finished) >= requestedAt - 5_000
    ) {
      result.device_id = config.deviceId;
      result.action_id = observed.id;
      result.action_completed = true;
      result.fresh_inventory_received = true;
      result.action_finished_at = observed.finished;
      await capture("completed-live-refresh");
      return;
    }
    if (["Failed", "Expired", "Outcome unknown, don't retry"].includes(observed?.state))
      throw new Error("live_management_action_failed");
    await delay(1_000);
  }
  throw new Error("live_management_action_timeout");
}

async function confirmOffServerCustody(ui) {
  await driver.goto(`${config.origin}/settings/status`);
  await ui.wait({ role: "heading", text: "Move your recovery keys off this server" });
  await ui.click({ css: '[data-slot="recovery-custody-task"] summary' });
  const displayed = await driver.observe(() => {
    const task = document.querySelector('[data-slot="recovery-custody-task"]');
    const value = (scope, text) =>
      [...(scope?.querySelectorAll("dt") ?? [])]
        .find((node) => node.textContent.trim().replace(/:\s*$/, "") === text)
        ?.nextElementSibling?.textContent.trim();
    return {
      digest: value(task, "Confirmation digest"),
      exports: [...(task?.querySelectorAll('[data-slot="recovery-custody-export"]') ?? [])].map(
        (node) => ({
          kind:
            node.querySelector("h3")?.textContent.trim() === "Server recovery identities"
              ? "canonical_authority"
              : node.querySelector("h3")?.textContent.trim() === "Fresh database recovery identity"
                ? "fresh_database"
                : "",
          path: value(node, "Protected encrypted export"),
          sha256: value(node, "File checksum"),
        }),
      ),
    };
  });
  if (!/^[a-f0-9]{64}$/.test(config.custodySha256) || displayed.digest !== config.custodySha256)
    throw new Error("custody_confirmation_digest_not_displayed");
  if (
    !Array.isArray(config.custodyExports) ||
    config.custodyExports.length === 0 ||
    JSON.stringify(displayed.exports) !== JSON.stringify(config.custodyExports)
  )
    throw new Error("custody_required_export_set_not_displayed");
  await capture("off-server-custody-required");
  await ui.click({ role: "button", text: "Confirm off-server custody" });
  await ui.click({ label: "I stored every listed recovery export off this server.", dialog: true });
  await ui.click({ role: "button", text: "Record my confirmation", dialog: true });
  await ui.wait({ text: "Verify it's you", dialog: true });
  await ui.fill({ label: "Your password", dialog: true }, config.password);
  const before = await driver.credentials();
  await ui.click({ role: "button", text: "Verify with passkey", dialog: true });
  await ui.wait({ role: "heading", text: "Owner confirmation recorded" });
  const after = await driver.credentials();
  if (
    after.length !== 1 ||
    before.length !== 1 ||
    !Number.isSafeInteger(after[0].signCount) ||
    !Number.isSafeInteger(before[0].signCount) ||
    after[0].signCount <= before[0].signCount
  )
    throw new Error("custody_new_passkey_step_up_not_observed");
  result.owner_step_up = true;
  result.owner_custody_attested = true;
  result.custody_sha256 = displayed.digest;
  result.custody_exports = displayed.exports;
  await capture("owner-custody-confirmation-recorded");
}

async function createIntegrationProof(ui) {
  await driver.goto(`${config.origin}/integrations`);
  await ui.wait({ role: "button", text: "Add destination", first: true });
  await ui.click({ role: "button", text: "Add destination", first: true });
  await ui.fill({ label: "Name" }, "Restore key proof");
  await ui.fill({ label: "Address" }, "https://restore-check.invalid/events");
  await ui.click({ role: "button", text: "Generate" });
  result.integration_secret_sha256 = await driver.observe(async () => {
    const field = document.getElementById("new-secret");
    if (!field || field.value.length !== 48)
      throw new Error("integration_secret_generation_failed");
    const bytes = new TextEncoder().encode(field.value);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    bytes.fill(0);
    return [...digest].map((value) => value.toString(16).padStart(2, "0")).join("");
  });
  // Keep this cryptographic restore fixture local: no outbound attempt targets
  // the reserved invalid domain, and no receiver/signing secret is exported.
  await ui.click({ role: "checkbox", text: "Send events" });
  await ui.fill(
    { label: "Reason (audited)", dialog: true },
    "Prove encrypted destination recovery",
  );
  await ui.click({ role: "button", text: "Create destination" });
  await ui.wait({ role: "button", text: "Add destination", first: true });
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    result.integration_destination_id = await driver.observe(() => {
      const row = [...document.querySelectorAll("tr")].find((node) =>
        node.textContent.includes("Restore key proof"),
      );
      const label =
        row &&
        [...row.querySelectorAll("dt")].find(
          (node) => node.textContent.trim() === "Destination ID:",
        );
      return label?.nextElementSibling?.textContent?.trim() ?? "";
    });
    if (/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(result.integration_destination_id))
      break;
    await delay(250);
  }
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(result.integration_destination_id))
    throw new Error("integration_creation_not_observed");
  result.integration_created = true;
  await capture("encrypted-integration-created");
}

try {
  config = await readPrivateJSON(process.argv[2]);
  if (
    !["setup", "custody", "copy", "manage", "integration"].includes(config.phase) ||
    new URL(config.origin).protocol !== "https:"
  )
    throw new Error("invalid_deployment_browser_configuration");
  result.phase = config.phase;
  await privateDirectory(config.evidenceDirectory);
  await openTrustedBrowser();
  const ui = new AuditedUI(driver, 180_000);
  if (config.phase === "setup") {
    if (config.setupMethod === "native-bootstrap") {
      await driver.goto(config.origin);
      await capture("manual-owner-bootstrap");
      await enroll(ui, { ...config, enrollmentSecret: config.setupCode });
      await signIn(ui, config);
    } else {
      await driver.goto(`${config.origin}/setup`);
      await capture("protected-first-run");
      await ui.fill({ label: "Setup code" }, config.setupCode);
      await ui.fill({ label: "Username" }, config.username);
      await ui.fill({ label: "Password" }, config.password);
      await ui.click({ role: "button", text: "Create owner account" });
      await ui.wait({ role: "heading", text: "Dashboard" });
    }
    const credentials = await driver.credentials();
    if (credentials.length !== 1 || !Number.isSafeInteger(credentials[0].signCount))
      throw new Error("setup_user_verifying_passkey_missing");
    await writePrivateJSON(config.credentialPath, credentials);
    await signOut(ui, config.origin);
    await signIn(ui, config);
    const authenticated = await driver.credentials();
    if (authenticated.length !== 1 || authenticated[0].signCount <= credentials[0].signCount)
      throw new Error("setup_user_verified_signin_not_observed");
    await writePrivateJSON(config.credentialPath, authenticated);
    result.password_and_passkey = true;
    await capture("password-passkey-signin");
  } else {
    await driver.goto(config.origin);
    await signIn(ui, config);
    if (config.phase === "copy") {
      const family = config.platform.startsWith("Ubuntu") ? "apt" : "dnf";
      const grant = await createGrant(ui, {
        ...config,
        requireRepositories: true,
        enrollmentPlatforms: { [family]: config.platform },
        enrollmentCommandPaths: { [family]: config.commandPath },
      });
      result.command_sha256 = grant.commandSHA256[family];
      result.command_source = grant.commandSources[family];
      grant.secret = "";
      for (const key of Object.keys(grant.commands)) grant.commands[key] = "";
      await capture("console-command-copied");
    } else if (config.phase === "custody") await confirmOffServerCustody(ui);
    else if (config.phase === "integration") await createIntegrationProof(ui);
    else await managedRefresh(ui);
    await writePrivateJSON(config.credentialPath, await driver.credentials());
  }
  result.passed = true;
} catch (error) {
  result.failure = /^[a-z][a-z0-9_]+$/.test(String(error?.message))
    ? error.message
    : "deployment_browser_failed";
  if (driver?.page) {
    try {
      await capture("failure");
    } catch {
      result.screenshot_failure = true;
    }
  }
  process.exitCode = 1;
} finally {
  config && (config.password = config.setupCode = "");
  if (driver) {
    try {
      await driver.close();
    } catch {
      result.passed = false;
      result.failure = "browser_cleanup_failed";
      process.exitCode = 1;
    }
  }
  if (config?.resultPath) await writePrivateJSON(config.resultPath, result);
}
