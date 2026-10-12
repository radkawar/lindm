#!/usr/bin/env node
import { resolve, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { ChromiumDriver, WebDriver, UI } from "./drivers.mjs";
import { originPost } from "./origin-post.mjs";
import {
  readPrivateJSON,
  privateDirectory,
  writePrivate,
  writePrivateJSON,
} from "./private-files.mjs";
import {
  enroll,
  signIn,
  signOut,
  createGrant,
  createToken,
  confirmEnrolledDevice,
  assignProfile,
  storageSelection,
  provisioningFormatLabels,
  createProvisioningSnippet,
  findPendingEnrollment,
  approvePendingEnrollment,
  executeApprovedEnrollment,
} from "./journey.mjs";

// Private JSON-file API. The maintained caller contract is in docs/verification.md.
// Never print browser exceptions: their call logs can contain filled secrets.
process.umask(0o077);
let config;
let driver;
let deadline;
let forceExit;
let interrupted = false;
let activeStep = "configuration";
const result = { engine: "unknown", passed: false, steps: [], screenshots: [] };

function failure(error) {
  return {
    step: activeStep,
    code: /^[a-z][a-z0-9_]+$/.test(error?.message ?? "") ? error.message : "browser_journey_failed",
    transportCode: error?.code ?? error?.cause?.code ?? "",
    errorType: error?.name ?? "Error",
  };
}

async function screenshot(name, fullPage = true) {
  if (!driver) return;
  // Mask all editable/secret/command regions, including failure screenshots.
  // No trace, HAR, console capture or raw DOM dump is ever persisted.
  await driver.observe(() => {
    for (const node of document.querySelectorAll(
      'input,textarea,pre,code,[data-sensitive="true"]',
    )) {
      node.dataset.acceptanceOldVisibility = node.style.visibility;
      node.style.setProperty("visibility", "hidden", "important");
    }
  });
  try {
    const path = join(config.evidenceDirectory, `${config.engine}-${config.mode}-${name}.png`);
    await writePrivate(
      path,
      fullPage
        ? await driver.screenshot()
        : await driver.page.screenshot({ fullPage: false, timeout: 10_000 }),
    );
    result.screenshots.push(path);
  } finally {
    await driver.observe(() => {
      for (const node of document.querySelectorAll("[data-acceptance-old-visibility]")) {
        node.style.visibility = node.dataset.acceptanceOldVisibility;
        delete node.dataset.acceptanceOldVisibility;
      }
    });
  }
}

async function enrollmentScreenshots(name) {
  // Visual review only: vary theme/viewport without issuing another credential.
  // Reuse the runner's secret masking; these are not native-install evidence.
  const viewport = driver.page.viewportSize();
  const original = await driver.observe(() => ({
    dark: document.documentElement.classList.contains("dark"),
    colorScheme: document.documentElement.style.colorScheme,
  }));
  await driver.page.getByRole("listbox").waitFor({ state: "hidden" });
  try {
    for (const [size, width, height] of [
      ["desktop", 1440, 1000],
      ["mobile", 390, 844],
    ]) {
      await driver.page.setViewportSize({ width, height });
      for (const theme of ["light", "dark"]) {
        await driver.observe((value) => {
          document.documentElement.classList.toggle("dark", value === "dark");
          document.documentElement.style.colorScheme = value;
          window.scrollTo(0, 0);
          const dialog = document.querySelector('[role="dialog"]');
          if (dialog) dialog.scrollTop = 0;
        }, theme);
        await driver.page.evaluate(async () => {
          await document.fonts.ready;
          await Promise.all(
            document.getAnimations().map((animation) => animation.finished.catch(() => {})),
          );
          await new Promise((resolve) =>
            requestAnimationFrame(() => requestAnimationFrame(resolve)),
          );
        });
        await screenshot(`${name}-${theme}-${size}`, false);
      }
    }
  } finally {
    await driver.page.setViewportSize(viewport);
    await driver.observe((value) => {
      document.documentElement.classList.toggle("dark", value.dark);
      document.documentElement.style.colorScheme = value.colorScheme;
    }, original);
  }
}

async function step(name, operation) {
  if (interrupted) throw new Error("runner_interrupted");
  activeStep = name;
  const entry = { name, passed: false, startedAt: new Date().toISOString() };
  result.steps.push(entry);
  const value = await operation();
  if (interrupted) throw new Error("runner_interrupted");
  entry.passed = true;
  entry.finishedAt = new Date().toISOString();
  await screenshot(name);
  return value;
}

function validate(value) {
  if (!value || typeof value !== "object") throw new Error("invalid_configuration");
  for (const key of ["origin", "username", "password", "evidenceDirectory", "credentialPath"]) {
    if (typeof value[key] !== "string" || !value[key])
      throw new Error("required_configuration_missing");
  }
  if (!["chromium", "firefox", "webkit"].includes(value.engine)) throw new Error("invalid_engine");
  if (
    ![
      "enroll",
      "credentials",
      "grant",
      "native",
      "login",
      "enrollment-status",
      "provision",
      "approve-enrollment",
    ].includes(value.mode)
  )
    throw new Error("invalid_mode");
  if (value.enrollmentScreenshots && value.engine !== "chromium")
    throw new Error("enrollment_screenshots_require_chromium");
  if (value.enrollmentCommandPaths) {
    if (value.engine !== "chromium" || value.mode !== "grant" || !value.enrollmentScreenshots)
      throw new Error("clipboard_capture_requires_chromium_grant_screenshots");
    const paths = Object.entries(value.enrollmentCommandPaths);
    const platforms = Object.entries(value.enrollmentPlatforms ?? {});
    if (
      paths.length !== 1 ||
      platforms.length !== 1 ||
      paths[0][0] !== platforms[0][0] ||
      !["apt", "dnf", "zypper", "pacman"].includes(paths[0][0]) ||
      typeof paths[0][1] !== "string" ||
      !paths[0][1] ||
      typeof platforms[0][1] !== "string" ||
      !platforms[0][1]
    )
      throw new Error("clipboard_capture_requires_one_named_platform");
  }
  if (value.mode === "enroll" && !value.enrollmentSecret)
    throw new Error("enrollment_secret_required");
  const origin = new URL(value.origin);
  if (
    origin.protocol !== "https:" ||
    origin.origin !== value.origin ||
    origin.username ||
    origin.password
  )
    throw new Error("https_origin_required");
  if (value.mode === "native" && (!value.deviceId || !value.profileRevisionId))
    throw new Error("native_target_required");
  if (value.mode === "enrollment-status" && (typeof value.deviceId !== "string" || !value.deviceId))
    throw new Error("enrollment_status_device_required");
  if (
    value.expectToolCustodyPath !== undefined &&
    (value.mode !== "enrollment-status" ||
      typeof value.expectToolCustodyPath !== "string" ||
      !value.expectToolCustodyPath.startsWith("/"))
  )
    throw new Error("tool_custody_expectation_requires_enrollment_status_path");
  for (const kind of value.storageActions ?? ["escrowRotate", "cryptoErase"]) {
    if (!["escrowRotate", "cryptoErase", "tpm2Bind", "sanitize"].includes(kind))
      throw new Error("invalid_storage_action");
  }
  if (value.hostResolverRules !== undefined) {
    // One rule mapping exactly the origin's host; Chromium only.
    const rule = /^MAP ([a-z0-9.-]{1,253}) ([0-9.]{7,15})$/.exec(value.hostResolverRules);
    if (value.engine !== "chromium" || !rule || rule[1] !== origin.hostname)
      throw new Error("invalid_host_resolver_rules");
  }
  if (value.mode === "provision") {
    if (value.engine !== "chromium" || !value.enrollmentScreenshots || value.enrollmentCommandPaths)
      throw new Error("provision_requires_chromium_screenshots");
    if (
      !Object.hasOwn(provisioningFormatLabels, value.provisionFormat) ||
      typeof value.provisionPlatform !== "string" ||
      !value.provisionPlatform ||
      typeof value.provisionSnippetPath !== "string" ||
      !value.provisionSnippetPath
    )
      throw new Error("provision_target_required");
  }
  if (value.mode === "approve-enrollment") {
    const approver = value.approver;
    if (
      value.engine !== "chromium" ||
      typeof value.installationId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.installationId)
    )
      throw new Error("approval_installation_required");
    if (!approver || typeof approver !== "object")
      throw new Error("approver_configuration_missing");
    for (const key of ["username", "password", "credentialPath"]) {
      if (typeof approver[key] !== "string" || !approver[key])
        throw new Error("approver_configuration_missing");
    }
    if (
      approver.username === value.username ||
      resolve(approver.credentialPath) === resolve(value.credentialPath)
    )
      throw new Error("approver_must_be_distinct");
  }
  for (const [key, fallback, max] of [
    ["timeoutMs", 300_000, 900_000],
    ["actionTimeoutMs", 30_000, 120_000],
  ]) {
    value[key] ??= fallback;
    if (!Number.isInteger(value[key]) || value[key] < 1000 || value[key] > max)
      throw new Error("invalid_deadline");
  }
  return value;
}

async function journey() {
  driver = config.engine === "chromium" ? new ChromiumDriver() : new WebDriver();
  activeStep = "browser_start";
  await driver.open(config);
  if (config.enrollmentCommandPaths || config.mode === "provision") {
    await driver.context.grantPermissions(["clipboard-read", "clipboard-write"], {
      origin: config.origin,
    });
  }
  result.versions = driver.metadata;
  const ui = new UI(driver, config.actionTimeoutMs);
  await step("sign_in_page", () => driver.goto(config.origin));
  result.versions.webAuthnCapabilities = await driver.observe(() => ({
    secureContext: window.isSecureContext,
    publicKeyCredential: typeof PublicKeyCredential !== "undefined",
    parseCreationOptionsFromJSON:
      typeof PublicKeyCredential !== "undefined" &&
      typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function",
    parseRequestOptionsFromJSON:
      typeof PublicKeyCredential !== "undefined" &&
      typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function",
  }));
  if (config.engine === "webkit") {
    await step("same_origin_invalid_auth_post", async () => {
      result.originPost = await originPost(ui, config);
      if (!result.originPost.passed) throw new Error("same_origin_auth_post_not_accepted");
    });
  }
  let credentials = [];
  if (config.mode !== "enroll") credentials = await savedCredentials(config);
  activeStep = "native_authenticator";
  try {
    await driver.authenticator(credentials);
  } catch (error) {
    // A native GTK build without WebAuthn leaves the passkey phase unqualified.
    // A separately enrolled owner can still prove the browser's real password
    // POST reached the server, without injecting credentials or a session.
    const probe = config.passwordProbe ?? (config.mode !== "enroll" ? config : null);
    if (probe) {
      result.passwordPhase = {
        attempted: false,
        beginAccepted: false,
        authenticated: false,
        passkeyQualified: false,
      };
      const passwordStarted = await driver.observe(() => performance.now());
      await ui.fill({ label: "Username" }, probe.username);
      await ui.fill({ label: "Password" }, probe.password);
      await ui.click({ role: "button", text: "Sign in locally" });
      result.passwordPhase.attempted = true;
      const until = Date.now() + config.actionTimeoutMs;
      while (Date.now() < until) {
        const observation = await driver.observe((started) => {
          const request = performance
            .getEntriesByType("resource")
            .find(
              (entry) =>
                entry.startTime >= started &&
                new URL(entry.name).pathname === "/auth/local/login/begin",
            );
          const passwordCleared = document.getElementById("local-password")?.value === "";
          const waiting = [...document.querySelectorAll("button")].some((node) =>
            node.textContent.includes("Waiting for authenticator"),
          );
          const declined = document.body.innerText.includes(
            "Authenticator verification was not completed.",
          );
          return {
            requestObserved: !!request,
            responseStatus: request?.responseStatus ?? 0,
            passwordCleared,
            waitingForAuthenticator: waiting || declined,
          };
        }, passwordStarted);
        result.passwordPhase.observation = observation;
        const capability = result.versions.webAuthnCapabilities;
        if (
          !capability.secureContext ||
          !capability.publicKeyCredential ||
          !capability.parseCreationOptionsFromJSON ||
          !capability.parseRequestOptionsFromJSON
        ) {
          result.passwordPhase.reason = "ui_webauthn_capability_preflight_blocks_password_post";
          break;
        }
        if (
          observation.requestObserved &&
          (observation.responseStatus === 200 ||
            (observation.passwordCleared && observation.waitingForAuthenticator))
        ) {
          result.passwordPhase.beginAccepted = true;
          break;
        }
        await delay(100);
      }
      await screenshot("unqualified-passkey-prerequisite");
    }
    // Release policy: only WebKit's missing WebDriver virtual-authenticator
    // command is an upstream prerequisite, recorded as unqualified rather than
    // failing the gate. Its Origin/Referrer regression step above stays
    // mandatory and has already passed; any other authenticator failure fails.
    const cause = failure(error);
    if (
      config.engine === "webkit" &&
      cause.code === "native_virtual_authenticator_unavailable" &&
      cause.transportCode === "unknown command" &&
      result.originPost?.passed
    ) {
      result.passkeyPhase = {
        qualified: false,
        reason: "unqualified_upstream_prerequisite",
        detail: "webkit_webdriver_virtual_authenticator_unsupported",
      };
      result.passed = true;
      return;
    }
    throw error;
  }
  if (config.mode === "enroll") await step("owner_enrollment", () => enroll(ui, config));
  await step("owner_sign_in", () => signIn(ui, config));
  await saveCredential();
  // Sign out through the UI, then authenticate again. Never reuse/import a
  // session cookie as evidence of a working sign-in ceremony.
  await step("owner_sign_out", () => signOut(ui));
  await step("owner_fresh_sign_in", () => signIn(ui, config));
  await saveCredential();
  if (["enroll", "credentials", "grant"].includes(config.mode)) {
    const capture = config.enrollmentScreenshots ? enrollmentScreenshots : undefined;
    result.grant = await step("create_one_time_grant", () => createGrant(ui, config, capture));
    // Persist shown-once output before beginning the next irreversible issuance.
    await writePrivateJSON(config.resultPath, result);
    if (config.mode !== "grant")
      result.token = await step("create_provisioning_token", () =>
        createToken(ui, config, capture),
      );
    if (capture) {
      await driver.goto(`${config.origin}/settings`);
      await ui.wait({ role: "heading", text: "Agent repository" });
      await ui.wait({ css: "summary", text: "Repository and trust details" });
      await capture("settings-agent-repository");
    }
  }
  if (config.mode === "enrollment-status") {
    result.enrolledDevice = await step("confirm_enrolled_device", () =>
      confirmEnrolledDevice(ui, config),
    );
    // The unprotected-tool-path alert is console UI the lane must show; keep
    // light/dark desktop/mobile captures of the exact device page for review.
    if (config.expectToolCustodyPath && config.enrollmentScreenshots)
      await enrollmentScreenshots("device-tool-custody");
    await writePrivateJSON(config.resultPath, result);
  }
  if (config.mode === "native") {
    result.assignment = await step("assign_native_profile", () => assignProfile(ui, config));
    await writePrivateJSON(config.resultPath, result);
    result.storage = [];
    const actions = config.storageActions ?? ["escrowRotate", "cryptoErase", "tpm2Bind"];
    if (!actions.length) {
      result.storageNotApplicable = {
        reason: config.storageNotApplicableReason ?? "no_luks_in_native_inventory",
        source: "native_oracle_caller",
        selectable: false,
      };
    }
    let storageFailure;
    for (const kind of actions) {
      try {
        result.storage.push(await step(`select_${kind}`, () => storageSelection(ui, config, kind)));
      } catch (error) {
        result.storage.push({ kind, selectable: false, failure: failure(error), submitted: false });
        await screenshot(`select_${kind}-failure`);
        storageFailure ??= error;
      }
    }
    if (storageFailure) throw storageFailure;
  }
  if (config.mode === "provision") {
    result.provision = await step("create_provisioning_snippet", () =>
      createProvisioningSnippet(ui, config, enrollmentScreenshots),
    );
    await writePrivateJSON(config.resultPath, result);
  }
  if (config.mode === "approve-enrollment") {
    // Two humans in one browser: each signs in through the UI with only its
    // own passkey state loaded; no session or credential is shared.
    await step("owner_sign_out_for_approver", () => signOut(ui));
    await driver.authenticator(await savedCredentials(config.approver));
    await step("approver_sign_in", () => signIn(ui, config.approver));
    await saveCredential(config.approver);
    const pending = await step("find_pending_enrollment", () => findPendingEnrollment(ui, config));
    result.approval = {
      ...pending,
      approver: config.approver.username,
      approved: false,
      requesterExecuted: false,
    };
    await writePrivateJSON(config.resultPath, result);
    await step("approve_device_enrollment", () => approvePendingEnrollment(ui, config, pending));
    result.approval.approved = true;
    await writePrivateJSON(config.resultPath, result);
    await step("approver_sign_out", () => signOut(ui));
    await driver.authenticator(await savedCredentials(config));
    await step("owner_execute_sign_in", () => signIn(ui, config));
    await saveCredential();
    await step("execute_device_enrollment", () => executeApprovedEnrollment(ui, config, pending));
    result.approval.requesterExecuted = true;
    await writePrivateJSON(config.resultPath, result);
    result.enrolledDevice = await step("confirm_enrolled_device", () =>
      confirmEnrolledDevice(ui, { ...config, deviceId: pending.deviceId }),
    );
    await writePrivateJSON(config.resultPath, result);
  }
  await step("final_sign_out", () => signOut(ui));
  result.passed = true;
}

async function savedCredentials(account) {
  const saved = await readPrivateJSON(account.credentialPath);
  if (
    saved.origin !== config.origin ||
    saved.username !== account.username ||
    !saved.credentials?.length
  )
    throw new Error("credential_binding_mismatch");
  return saved.credentials;
}

async function saveCredential(account = config) {
  const credentials = await driver.credentials();
  if (credentials.length !== 1) throw new Error("expected_one_owner_credential");
  await writePrivateJSON(account.credentialPath, {
    origin: config.origin,
    username: account.username,
    credentials,
  });
}

try {
  if (process.argv.length !== 3) throw new Error("private_config_path_required");
  config = await readPrivateJSON(resolve(process.argv[2]));
  // Establish a safe result destination before validating remaining config.
  if (typeof config.evidenceDirectory !== "string" || !config.evidenceDirectory)
    throw new Error("evidence_directory_required");
  config.evidenceDirectory = resolve(config.evidenceDirectory);
  await privateDirectory(config.evidenceDirectory);
  config.resultPath = resolve(config.resultPath ?? join(config.evidenceDirectory, "result.json"));
  config = validate(config);
  result.engine = config.engine;
  result.mode = config.mode;
  result.startedAt = new Date().toISOString();
  let abort;
  const timedOut = new Promise((_, reject) => {
    abort = reject;
  });
  const interrupt = () => {
    interrupted = true;
    abort(new Error("runner_interrupted"));
  };
  process.once("SIGTERM", interrupt);
  process.once("SIGINT", interrupt);
  deadline = setTimeout(() => {
    interrupted = true;
    abort(new Error("runner_deadline_exceeded"));
  }, config.timeoutMs);
  // A native driver can itself hang while closing. Preserve a private failure
  // result and kill only this runner's owned driver process group in that case.
  forceExit = setTimeout(async () => {
    result.passed = false;
    result.failure = { step: activeStep, code: "runner_hard_deadline_exceeded" };
    try {
      await writePrivateJSON(config.resultPath, result);
    } finally {
      if (driver?.process?.pid) {
        try {
          process.kill(-driver.process.pid, "SIGKILL");
        } catch {
          /* Already exited. */
        }
      }
      process.exit(1);
    }
  }, config.timeoutMs + 45_000);
  await Promise.race([journey(), timedOut]);
} catch (error) {
  result.passed = false;
  result.failure = failure(error);
  if (config?.evidenceDirectory && driver) {
    try {
      // The console's own support details (code and reason identifiers only,
      // never server messages) make an ambiguous "Result unknown" diagnosable.
      result.failure.consoleErrors = await driver.observe(() =>
        [...document.querySelectorAll('[data-slot="support-details"]')].map((node) => {
          const field = (label) =>
            [...node.querySelectorAll("dt")]
              .find((term) => term.textContent.trim() === `${label}:`)
              ?.nextElementSibling?.textContent.trim() ?? "";
          return { code: field("Code"), reason: field("Reason") };
        }),
      );
    } catch {
      result.failure.consoleErrorsUnavailable = true;
    }
    try {
      await screenshot("failure");
    } catch {
      result.failure.screenshotUnavailable = true;
    }
  }
} finally {
  clearTimeout(deadline);
  try {
    if (driver) await driver.close();
  } catch {
    result.passed = false;
    result.cleanupFailure = "browser_cleanup_failed";
  }
  result.finishedAt = new Date().toISOString();
  if (config?.resultPath) {
    try {
      await writePrivateJSON(config.resultPath, result);
    } catch {
      result.passed = false;
      process.stderr.write("acceptance: private result could not be written\n");
    }
  } else {
    process.stderr.write("acceptance: private configuration/result path unavailable\n");
  }
  clearTimeout(forceExit);
  process.exitCode = result.passed ? 0 : 1;
}
