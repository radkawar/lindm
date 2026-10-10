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
  assignProfile,
  storageSelection,
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

async function screenshot(name) {
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
    await writePrivate(path, await driver.screenshot());
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
  if (!["enroll", "credentials", "grant", "native", "login"].includes(value.mode))
    throw new Error("invalid_mode");
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
  for (const kind of value.storageActions ?? ["escrowRotate", "cryptoErase"]) {
    if (!["escrowRotate", "cryptoErase", "tpm2Bind", "sanitize"].includes(kind))
      throw new Error("invalid_storage_action");
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
  if (config.mode !== "enroll") {
    const saved = await readPrivateJSON(config.credentialPath);
    if (
      saved.origin !== config.origin ||
      saved.username !== config.username ||
      !saved.credentials?.length
    )
      throw new Error("credential_binding_mismatch");
    credentials = saved.credentials;
  }
  activeStep = "native_authenticator";
  try {
    await driver.authenticator(credentials);
  } catch (error) {
    // A native GTK build without WebAuthn remains an unqualified failed gate.
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
    result.grant = await step("create_one_time_grant", () => createGrant(ui, config));
    // Persist shown-once output before beginning the next irreversible issuance.
    await writePrivateJSON(config.resultPath, result);
    if (config.mode !== "grant")
      result.token = await step("create_provisioning_token", () => createToken(ui, config));
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
  await step("final_sign_out", () => signOut(ui));
  result.passed = true;
}

async function saveCredential() {
  const credentials = await driver.credentials();
  if (credentials.length !== 1) throw new Error("expected_one_owner_credential");
  await writePrivateJSON(config.credentialPath, {
    origin: config.origin,
    username: config.username,
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
