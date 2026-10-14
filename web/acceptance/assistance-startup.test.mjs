// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { startupFailure, startupObservation } from "./assistance-startup.mjs";

// Classification tests do not launch Chromium or qualify a native picker.
test("startup evidence retains loader failure categories, not source or private paths", () => {
  for (const [code, expected] of [
    ["ERR_MODULE_NOT_FOUND", "module_not_found"],
    ["ERR_UNKNOWN_FILE_EXTENSION", "module_extension_unsupported"],
    ["ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX", "typescript_syntax_unsupported"],
    ["ERR_DLOPEN_FAILED", "native_library_load_failed"],
  ]) {
    const error = Object.assign(new Error("/private/password-and-cookie"), { code });
    assert.deepEqual(startupFailure(error, "module_load"), {
      code: expected,
      errorType: "Error",
      stage: "module_load",
    });
  }
});

test("startup evidence never serializes arbitrary exception fields", () => {
  const secret = "password_cookie_clipboard_file_content";
  const error = Object.assign(new Error(secret), {
    name: secret,
    code: secret,
    stack: secret,
    observation: { body: secret },
  });
  assert.deepEqual(startupFailure(error, secret), {
    code: "browser_startup_failed",
    errorType: "Error",
    stage: "unknown",
  });
  assert.equal(startupFailure(null, "configuration").code, "browser_startup_failed");
  assert.equal(
    startupFailure(new SyntaxError(secret), "module_load").code,
    "javascript_syntax_error",
  );
  assert.equal(
    startupFailure(Object.assign(new Error(secret), { name: "TimeoutError" }), "sign_in").code,
    "startup_timeout",
  );
});

test("launch signatures are bounded, specific to launch and return only fixed codes", () => {
  const message =
    "Target page, context or browser has been closed\n" +
    "private launch args\nMissing X server or $DISPLAY\npassword=cookie";
  assert.deepEqual(startupFailure(new Error(message), "chromium_launch"), {
    code: "chromium_display_unavailable",
    errorType: "Error",
    stage: "chromium_launch",
  });
  assert.equal(startupFailure(new Error(message), "sign_in").code, "browser_startup_failed");
  assert.equal(
    startupFailure(new Error("x".repeat(16_384) + message), "chromium_launch").code,
    "browser_startup_failed",
  );
  assert.equal(
    startupFailure(new Error("Invalid MIT-MAGIC-COOKIE-1 key: secret"), "chromium_launch").code,
    "chromium_display_authority_rejected",
  );
});

test("configuration diagnostic codes are an exact allowlist, not snake-case exception text", () => {
  assert.equal(
    startupFailure(new Error("private_owned_bounded_json_required"), "configuration").code,
    "private_owned_bounded_json_required",
  );
  assert.equal(
    startupFailure(new Error("private_owned_bounded_json_required_secret"), "configuration").code,
    "browser_startup_failed",
  );
});

test("console-stage failures keep the UI driver's code, a navigation under the step and Chromium's net error name only", () => {
  assert.deepEqual(startupFailure(new Error("ui_condition_timeout"), "enrollment"), {
    code: "ui_condition_timeout",
    errorType: "Error",
    stage: "enrollment",
  });
  assert.equal(
    startupFailure(new Error("ui_condition_timeout"), "configuration").code,
    "browser_startup_failed",
  );
  assert.deepEqual(
    startupFailure(
      new Error("page.goto: net::ERR_NETWORK_CHANGED at https://localhost:1/?secret=x"),
      "navigation",
    ),
    {
      code: "browser_network_error",
      errorType: "Error",
      stage: "navigation",
      netError: "ERR_NETWORK_CHANGED",
    },
  );
  assert.equal(
    startupFailure(new Error("net::ERR_NETWORK_CHANGED"), "chromium_launch").netError,
    undefined,
  );
  const reloaded = new Error(
    "page.evaluateHandle: Execution context was destroyed, most likely because of a navigation\n" +
      "call log: https://localhost:1/enroll?secret=x",
  );
  assert.deepEqual(startupFailure(reloaded, "enrollment"), {
    code: "page_navigated_during_step",
    errorType: "Error",
    stage: "enrollment",
  });
  assert.equal(
    startupFailure(new Error("elementHandle.click: Element is not attached to the DOM"), "sign_in")
      .code,
    "element_detached_during_step",
  );
  assert.equal(startupFailure(reloaded, "chromium_launch").code, "browser_startup_failed");
});

test("startup observation is bounded, typed and never carries the runner's credentials", () => {
  const password = "PRIVATEPASSWORD7Q";
  const secret = "ENROLLMENTSECRET2Z";
  const observation = startupObservation(
    {
      network: {
        location: "/enroll",
        navigations: ["about:", "/", "/enroll", `/x?${secret}`],
        httpErrors: [
          { path: "/auth/local/enroll/begin", status: 401, body: secret },
          { path: "/auth/options", status: 9000 },
        ],
        failed: [
          { path: "/auth/options", error: "net::ERR_NETWORK_CHANGED" },
          { path: "/auth/session", error: `custom ${password}` },
        ],
        pending: Array.from({ length: 30 }, () => ({ path: "/auth/session", ageMs: 12.5 })),
        pendingCount: 30,
        pageErrors: ["TypeError", secret],
        headers: { cookie: secret },
      },
      page: {
        alerts: [`Sign-in failed (401).\n  Try again. ${password}`, "x".repeat(1_000)],
        statuses: Array.from({ length: 9 }, (_, index) => `status ${index}`),
        headings: ["Enroll local administrator"],
        support: [{ code: "Unauthenticated", reason: `bad ${secret}`, message: secret }],
        body: secret,
      },
    },
    [password, secret, "", undefined],
  );
  const encoded = JSON.stringify(observation);
  assert.equal(encoded.includes(password), false);
  assert.equal(encoded.includes(secret), false);
  assert.equal(observation.location, "/enroll");
  assert.deepEqual(observation.navigations, ["about:", "/", "/enroll", ""]);
  assert.deepEqual(observation.httpErrors, [
    { path: "/auth/local/enroll/begin", status: 401 },
    { path: "/auth/options", status: 0 },
  ]);
  assert.deepEqual(observation.failed, [
    { path: "/auth/options", error: "net::ERR_NETWORK_CHANGED" },
    { path: "/auth/session", error: "other" },
  ]);
  assert.equal(observation.pending.length, 20);
  assert.deepEqual(observation.pending[0], { path: "/auth/session", ageMs: 0 });
  assert.deepEqual(observation.pageErrors, ["TypeError", "Error"]);
  assert.equal(observation.alerts[0], "Sign-in failed (401). Try again. [redacted]");
  assert.equal(observation.alerts[1].length, 300);
  assert.equal(observation.statuses.length, 5);
  assert.deepEqual(observation.headings, ["Enroll local administrator"]);
  assert.deepEqual(observation.support, [{ code: "Unauthenticated", reason: "" }]);
  assert.equal("body" in observation || "headers" in observation, false);
  assert.deepEqual(startupObservation({ network: {} }).pageUnavailable, true);
});

test("actual bootstrap retains pre-command failure and exits nonzero without exposing its config path", async () => {
  // No start command or valid configuration: the actual import graph loads,
  // but Chromium cannot launch and no sign-in or native effects occur.
  const secretPath = fileURLToPath(
    new URL("./missing-private-config-cookie-password.json", import.meta.url),
  );
  const { error, stdout, stderr } = await new Promise((done) =>
    execFile(
      process.execPath,
      [fileURLToPath(new URL("./assistance-bootstrap.mjs", import.meta.url)), secretPath],
      { timeout: 10_000, maxBuffer: 4096 },
      (error, stdout, stderr) => done({ error, stdout, stderr }),
    ),
  );
  assert.equal(error?.code, 1);
  assert.equal(error?.signal, null);
  assert.equal(stderr, "");
  const replies = stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.deepEqual(replies, [
    { id: 0, startupStage: "module_load" },
    { id: 0, startupStage: "configuration" },
    {
      id: 0,
      ok: false,
      error: { code: "resource_not_found", errorType: "Error", stage: "configuration" },
    },
  ]);
  assert.equal(stdout.includes(secretPath), false);
});
