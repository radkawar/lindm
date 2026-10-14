// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { enroll } from "./journey.mjs";

// A scripted console: each submission's outcome decides whether "Account
// enrolled." appears or the page reloads under the step, and the first
// gotoFailures reloads are themselves interrupted. No browser or server; the
// steps are the UI driver calls.
function console_(outcomes, { backFails = false, gotoFailures = 0 } = {}) {
  const steps = [];
  let page = "sign-in";
  let enrolled = false;
  const ui = {
    timeoutMs: 50,
    driver: {
      async goto(url) {
        steps.push(`goto ${url}`);
        if (gotoFailures-- > 0) throw new Error(`page.goto: net::ERR_NETWORK_CHANGED at ${url}`);
        page = "sign-in";
        enrolled = false;
      },
      async find(query) {
        return page === "sign-in" && query.label === "Username" ? {} : null;
      },
    },
    async click(query) {
      steps.push(`click ${query.text}`);
      if (query.text === "Enroll a local administrator account") page = "enroll";
      if (query.text === "Enroll account") {
        const outcome = outcomes.shift();
        if (outcome === "error") throw new Error("ambiguous_ui_locator");
        if (outcome === "reloaded")
          throw new Error(
            "elementHandle.click: Execution context was destroyed, most likely because of a navigation",
          );
        enrolled = outcome === "enrolled";
      }
      if (query.text === "Back to sign in") {
        if (backFails) throw new Error("ui_condition_timeout");
        page = "sign-in";
      }
    },
    async fill(query, value) {
      steps.push(`fill ${query.label}=${value}`);
    },
    async wait(query) {
      steps.push(`wait ${query.contains}`);
      if (query.contains === "Account enrolled." && !enrolled)
        throw new Error("ui_condition_timeout");
    },
  };
  return { ui, steps };
}

const account = { origin: "https://localhost:1", enrollmentSecret: "S", password: "P" };
const attempt = [
  "click Enroll a local administrator account",
  "fill One-time enrollment secret=S",
  "fill New password (at least 12 bytes)=P",
  "click Enroll account",
  "wait Account enrolled.",
];

test("an interrupted enrollment restarts from a reloaded sign-in page with the same secret", async () => {
  const { ui, steps } = console_(["interrupted", "enrolled"]);
  await enroll(ui, account);
  assert.deepEqual(steps, [
    ...attempt,
    "goto https://localhost:1",
    ...attempt,
    "click Back to sign in",
  ]);
});

test("a console reload under the step and an interrupted reload each use one bounded attempt", async () => {
  const reloaded = console_(["reloaded", "enrolled"]);
  await enroll(reloaded.ui, account);
  assert.deepEqual(reloaded.steps, [
    ...attempt.slice(0, 4),
    "goto https://localhost:1",
    ...attempt,
    "click Back to sign in",
  ]);

  const reopened = console_(["interrupted", "enrolled"], { gotoFailures: 1 });
  await enroll(reopened.ui, account);
  assert.deepEqual(reopened.steps, [
    ...attempt,
    "goto https://localhost:1",
    "goto https://localhost:1",
    ...attempt,
    "click Back to sign in",
  ]);

  const exhausted = console_(["interrupted", "enrolled"], { gotoFailures: 2 });
  await assert.rejects(enroll(exhausted.ui, account), /ERR_NETWORK_CHANGED/);
  assert.equal(exhausted.steps.filter((step) => step === "click Enroll account").length, 1);
});

test("a refused enrollment fails every bounded attempt and never reports success", async () => {
  const { ui, steps } = console_(["refused", "refused", "refused", "enrolled"]);
  await assert.rejects(enroll(ui, account), /ui_condition_timeout/);
  assert.equal(steps.filter((step) => step === "click Enroll account").length, 3);
  assert.equal(steps.includes("click Back to sign in"), false);
});

test("only interruptions repeat; a committed enrollment or another failure is not resubmitted", async () => {
  const other = console_(["error", "enrolled"]);
  await assert.rejects(enroll(other.ui, account), /ambiguous_ui_locator/);
  assert.equal(other.steps.filter((step) => step === "click Enroll account").length, 1);

  const committed = console_(["enrolled", "enrolled"], { backFails: true });
  await assert.rejects(enroll(committed.ui, account), /ui_condition_timeout/);
  assert.equal(committed.steps.filter((step) => step === "click Enroll account").length, 1);

  const noOrigin = console_(["interrupted", "enrolled"]);
  await assert.rejects(enroll(noOrigin.ui, { ...account, origin: undefined }));
  assert.equal(noOrigin.steps.filter((step) => step === "click Enroll account").length, 1);
});
