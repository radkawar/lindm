// SPDX-License-Identifier: Apache-2.0

// This module drives visible controls only. No RPC client, request interception,
// cookie import, synthetic WebAuthn API or alternate application implementation.

import { setTimeout as delay } from "node:timers/promises";
import { createHash } from "node:crypto";
import { writePrivate } from "./private-files.mjs";

// enroll registers config's password and a fresh authenticator credential
// with its one-time secret; origin (default the account's) lets an attempt a
// network change interrupted start again from a reloaded sign-in page. The
// server lets registration restart until a credential commits, so the same
// secret is offered again; a refused secret is refused on every attempt. A
// committed enrollment whose response was lost cannot be repeated (its secret
// is spent) and still fails here rather than being assumed.
export async function enroll(ui, config, origin = config.origin) {
  for (let attempt = 1; ; attempt++) {
    try {
      if (attempt > 1) await reopen(ui, origin);
      await ui.click({ role: "link", text: "Enroll a local administrator account" });
      await ui.fill({ label: "One-time enrollment secret" }, config.enrollmentSecret);
      await ui.fill({ label: "New password (at least 12 bytes)" }, config.password);
      await ui.click({ role: "button", text: "Enroll account" });
      await ui.wait({ role: "status", contains: "Account enrolled." });
      break;
    } catch (error) {
      if (!origin || attempt >= interruptedAttempts || !interrupted(error)) throw error;
    }
  }
  await ui.click({ role: "link", text: "Back to sign in" });
}

// Shared lab hosts add and remove container and VM links, and NetworkManager
// may keep re-activating an unconnected port, while lanes run. Each such
// address change (even IPv6 link-local) makes Chromium close its HTTP/2
// sessions, aborting every in-flight console request with
// net::ERR_NETWORK_CHANGED: a sign-in or enrollment shows "Result unknown", a
// page never finishes loading, or the console reloads itself after an aborted
// route chunk and destroys the step's page context. Only idempotent or
// restartable steps (sign-in/out, enrollment before its credential commits,
// page reads) are repeated, on a fresh navigation and a bounded number of
// times, so a product failure still fails every attempt. Decisions use the
// console's own same-request retry.
const interruptedAttempts = 3;

function interrupted(error) {
  const message = String(error?.message ?? "");
  return (
    message === "ui_condition_timeout" ||
    /net::ERR_(NETWORK_CHANGED|ABORTED|CONNECTION_RESET|CONNECTION_CLOSED|EMPTY_RESPONSE)/.test(
      message,
    ) ||
    // An aborted navigation (the console reloading itself after an aborted
    // route chunk) leaves an observation without its page or element.
    /Execution context was destroyed|Navigation interrupted the evaluation|Element is not attached to the DOM/.test(
      message,
    )
  );
}

// waitAny returns the index of the first query that becomes visible.
async function waitAny(ui, queries) {
  const deadline = Date.now() + ui.timeoutMs;
  while (Date.now() < deadline) {
    for (const [index, query] of queries.entries()) {
      if (await ui.driver.find(query)) return index;
    }
    await delay(100);
  }
  throw new Error("ui_condition_timeout");
}

const dashboard = { role: "heading", text: "Dashboard" };
const signInForm = { label: "Username" };

// reopen reloads the console after an interrupted step and reports whether
// the session is signed in.
async function reopen(ui, origin) {
  await ui.driver.goto(origin);
  return (await waitAny(ui, [dashboard, signInForm])) === 0;
}

// signIn signs account in; origin (default the account's) lets an
// interrupted attempt reopen the console. A reload that is itself interrupted
// counts as that attempt's failure.
export async function signIn(ui, account, origin = account.origin) {
  for (let attempt = 1; ; attempt++) {
    try {
      // The sign-in may have completed before its response was lost.
      if (attempt > 1 && (await reopen(ui, origin))) return;
      await ui.fill(signInForm, account.username);
      await ui.fill({ label: "Password" }, account.password);
      await ui.click({ role: "button", text: "Sign in locally" });
      await ui.wait(dashboard);
      return;
    } catch (error) {
      if (!origin || attempt >= interruptedAttempts || !interrupted(error)) throw error;
    }
  }
}

export async function signOut(ui, origin) {
  for (let attempt = 1; ; attempt++) {
    try {
      await ui.click({ css: 'button[aria-label^="Account menu for "]' });
      await ui.click({ role: "menuitem", text: "Sign out" });
      await ui.wait(signInForm);
      return;
    } catch (error) {
      if (!origin || attempt >= interruptedAttempts || !interrupted(error)) throw error;
      if (!(await reopen(ui, origin))) return;
    }
  }
}

// openPage navigates to a console page until its ready condition shows.
async function openPage(ui, config, path, ready) {
  for (let attempt = 1; ; attempt++) {
    try {
      await ui.driver.goto(`${config.origin}${path}`);
      await ui.wait(ready);
      return;
    } catch (error) {
      if (attempt >= interruptedAttempts || !interrupted(error)) throw error;
    }
  }
}

// openSignIn loads the console until its sign-in form shows.
export async function openSignIn(ui, origin) {
  await openPage(ui, { origin }, "/", signInForm);
}

async function credentialDetails(ui) {
  await ui.click({ css: "summary", text: "Details", dialog: true });
  const details = await ui.driver.observe(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].find(
      (node) => node.getClientRects().length,
    );
    const id = [...dialog.querySelectorAll("dt")]
      .find((node) => /^(Token|Grant) ID:/.test(node.textContent.trim()))
      ?.nextElementSibling?.textContent.trim();
    return {
      id,
      executionRootUrl: dialog.querySelector('a[href][href*="execution-root"]')?.href ?? "",
      bootstrapBundleUrl:
        [...dialog.querySelectorAll("a[href]")].find((node) =>
          node.textContent.includes("Download signed bootstrap"),
        )?.href ?? "",
    };
  });
  if (!details.id) throw new Error("credential_id_missing");
  await ui.click({ css: "summary", text: "Details", dialog: true });
  return details;
}

async function captureCredential(ui, kind, config, captureScreens) {
  const provisioning = kind === "token";
  const title = provisioning ? "Provisioning token" : "One-time enrollment code";
  const secret = await ui.nonemptyValue({ label: title, dialog: true });
  const details = await credentialDetails(ui);
  const commands = {};
  const commandSHA256 = {};
  const commandSources = {};
  const repositoryConfigured = {};
  const choices = config.enrollmentPlatforms ?? { apt: "Ubuntu 24.04 LTS", dnf: "Fedora 44" };
  for (const [family, label] of Object.entries(choices)) {
    await ui.select("Operating system", label, true);
    const name = provisioning ? "cloud-init provisioning snippet" : "Install and enroll command";
    let command = await ui.nonemptyValue({ label: name, dialog: true });
    const commandPath = config.enrollmentCommandPaths?.[family];
    if (!provisioning && commandPath) {
      await ui.driver.browserTask(() => navigator.clipboard.writeText(""));
      await ui.click({ role: "button", text: "Copy install command", dialog: true });
      await ui.wait({ role: "status", contains: "Install command copied.", dialog: true });
      const copied = await ui.driver.browserTask(() => navigator.clipboard.readText());
      if (!copied || copied !== command) throw new Error("clipboard_command_mismatch");
      command = copied;
      commandSHA256[family] = createHash("sha256").update(copied, "utf8").digest("hex");
      commandSources[family] = "browser-clipboard";
      await ui.driver.browserTask(() => navigator.clipboard.writeText(""));
    }
    const key = provisioning ? `cloud-init-${family}` : family;
    if (captureScreens) await captureScreens(`${kind}-${family}`);
    commands[key] = command;
    repositoryConfigured[family] =
      command.includes("/repo/") &&
      command.includes("sha256sum --check --status") &&
      command.includes("gpg --batch --with-colons --show-keys");
    if (config.requireRepositories && !repositoryConfigured[family]) {
      throw new Error("signed_repository_instructions_missing");
    }
    if (commandPath) await writePrivate(commandPath, command);
  }
  if (provisioning) {
    for (const [format, label, family] of [
      ["kickstart", "Kickstart", "dnf"],
      ["autoinstall", "Ubuntu autoinstall", "apt"],
    ]) {
      if (!choices[family]) continue;
      // Format first: the operating systems offered are those supporting it.
      await ui.select("Installer format", label, true);
      await ui.select("Operating system", choices[family], true);
      commands[format] = await ui.nonemptyValue({
        label: `${label} provisioning snippet`,
        dialog: true,
      });
    }
  }
  return { ...details, secret, commands, commandSHA256, commandSources, repositoryConfigured };
}

export async function createGrant(ui, config, captureScreens) {
  await ui.driver.goto(`${config.origin}/enrollment`);
  await ui.click({ role: "button", text: "Create one-time code" });
  await ui.select("Code expires after", "15 minutes", true);
  await ui.fill(
    { label: "Reason", dialog: true },
    "Release acceptance native single-device enrollment",
  );
  await ui.click({ role: "button", text: "Create one-time code", dialog: true });
  const grant = await captureCredential(ui, "grant", config, captureScreens);
  await ui.click({ role: "button", text: "Done, forget secret", dialog: true });
  return grant;
}

export async function createToken(ui, config, captureScreens) {
  await ui.click({ role: "button", text: "Create provisioning token" });
  await ui.fill(
    { label: "Purpose / audit reason", dialog: true },
    "Release acceptance disposable native provisioning",
  );
  await ui.select("Expires after", "4 hours", true);
  await ui.fill({ label: "Maximum uses", dialog: true }, "2");
  // This fixture has no second human. Explicitly exercise the UI's supported
  // direct-enrollment option rather than approving the owner's own request.
  await ui.click({ css: 'input[name="approval"]', dialog: true });
  await ui.click({ role: "button", text: "Create provisioning token", dialog: true });
  const token = await captureCredential(ui, "token", config, captureScreens);
  await ui.click({ role: "button", text: "Done, forget secret", dialog: true });
  return token;
}

export const provisioningFormatLabels = {
  "cloud-init": "cloud-init",
  kickstart: "Kickstart",
  autoinstall: "Ubuntu autoinstall",
  autoyast: "AutoYaST",
};

// Creates an approval-required provisioning token and captures one installer
// snippet through the real Copy button. Only the clipboard bytes, after an
// exact match with the visible snippet, reach the private snippet file.
export async function createProvisioningSnippet(ui, config, captureScreens) {
  const format = config.provisionFormat;
  await ui.driver.goto(`${config.origin}/enrollment`);
  await ui.click({ role: "button", text: "Create provisioning token" });
  await ui.fill(
    { label: "Purpose / audit reason", dialog: true },
    `Lab provision-${format} disposable installation`,
  );
  await ui.select("Expires after", "4 hours", true);
  await ui.fill({ label: "Maximum uses", dialog: true }, "1");
  // Another human must approve each device: keep the default, never untick it.
  const approval = await ui.wait({ css: 'input[name="approval"]', dialog: true });
  if ((await ui.driver.property(approval, "checked")) !== true)
    throw new Error("provisioning_approval_not_required");
  await ui.click({ role: "button", text: "Create provisioning token", dialog: true });
  await ui.wait({ label: "Provisioning token", dialog: true });
  const details = await credentialDetails(ui);
  // Format first: the operating systems offered are those supporting it.
  await ui.select("Installer format", provisioningFormatLabels[format], true);
  await ui.select("Operating system", config.provisionPlatform, true);
  const label = provisioningFormatLabels[format];
  const snippet = await ui.nonemptyValue({ label: `${label} provisioning snippet`, dialog: true });
  await ui.driver.browserTask(() => navigator.clipboard.writeText(""));
  await ui.click({ role: "button", text: `Copy ${label} snippet`, dialog: true });
  await ui.wait({ role: "status", contains: `${label} snippet copied.`, dialog: true });
  const copied = await ui.driver.browserTask(() => navigator.clipboard.readText());
  await ui.driver.browserTask(() => navigator.clipboard.writeText(""));
  if (!copied || copied !== snippet) throw new Error("clipboard_snippet_mismatch");
  await writePrivate(config.provisionSnippetPath, copied);
  const snippetSHA256 = createHash("sha256").update(copied, "utf8").digest("hex");
  if (captureScreens) await captureScreens(`provision-${format}`);
  await ui.click({ role: "button", text: "Done, forget secret", dialog: true });
  return {
    tokenId: details.id,
    format,
    platform: config.provisionPlatform,
    approvalRequired: true,
    snippetSHA256,
    snippetSource: "browser-clipboard",
  };
}

function readCards(id) {
  // Observation only: fields of each visible card naming this exact ID.
  return [...document.querySelectorAll("article")]
    .filter((node) => node.getClientRects().length > 0 && node.textContent.includes(id))
    .map((node) => ({
      title: node.querySelector("h2,h3")?.textContent.trim() ?? "",
      state: node.querySelector('[data-slot="badge"]')?.textContent.trim() ?? "",
      done: [...node.querySelectorAll('[role="status"]')].some(
        (status) => status.textContent.trim() === "Done.",
      ),
      failed: !!node.querySelector('[role="alert"]'),
      ambiguous: [...node.querySelectorAll('[role="alert"]')].some((alert) =>
        alert.textContent.includes("Result unknown"),
      ),
      payload: node.querySelector("pre")?.textContent ?? "",
      fields: Object.fromEntries(
        [...node.querySelectorAll("dt")].map((term) => [
          term.textContent.trim().replace(/:\s*$/, ""),
          term.nextElementSibling?.textContent.trim() ?? "",
        ]),
      ),
    }));
}

// The exact device waiting under the guest's installation ID, from the
// enrollment page's visible pending list.
export async function findPendingEnrollment(ui, config) {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    try {
      await ui.driver.goto(`${config.origin}/enrollment`);
      // The pending section is open on the page: a heading naming the count
      // when devices wait, otherwise the labelled empty section.
      await waitAny(ui, [
        { role: "heading", contains: "waiting for approval" },
        { label: "Devices waiting for approval" },
      ]);
    } catch (error) {
      // An interrupted page load is retried until the deadline.
      if (!interrupted(error)) throw error;
      continue;
    }
    const settle = Math.min(deadline, Date.now() + 10_000);
    while (Date.now() < settle) {
      const cards = (await ui.driver.observe(readCards, config.installationId)).filter(
        (card) => card.fields["Installation ID"] === config.installationId,
      );
      if (cards.length > 1) throw new Error("pending_enrollment_ambiguous");
      if (cards.length === 1) {
        const fields = cards[0].fields;
        if (!fields["Device ID"] || !fields["Approval ID"] || !fields["Token ID"])
          throw new Error("pending_enrollment_not_awaiting_approval");
        // Show the exact identifiers in this step's screenshot.
        await ui.click({ css: "summary", text: "Details", within: config.installationId });
        return {
          installationId: config.installationId,
          deviceId: fields["Device ID"],
          approvalId: fields["Approval ID"],
          tokenId: fields["Token ID"],
        };
      }
      await delay(250);
    }
  }
  throw new Error("pending_enrollment_not_found");
}

// waitApproval waits for the card to satisfy accept. An ambiguous decision
// failure ("Result unknown") is retried through the console's own control,
// which resubmits the same request, at most twice; any other failure ends it.
async function waitApproval(ui, approvalId, accept, retry) {
  const deadline = Date.now() + 60_000;
  let nextRefresh = Date.now() + 3_000;
  let retries = 0;
  while (Date.now() < deadline) {
    const cards = (await ui.driver.observe(readCards, approvalId)).filter(
      (card) => card.fields["Approval ID"] === approvalId,
    );
    if (cards.length > 1) throw new Error("approval_card_ambiguous");
    if (cards.length === 1) {
      if (accept(cards[0])) return cards[0];
      if (cards[0].failed) {
        if (!cards[0].ambiguous || !retry || retries >= 2)
          throw new Error("approval_action_failed");
        retries++;
        await retry();
        await delay(1000);
        continue;
      }
    }
    if (Date.now() >= nextRefresh) {
      // Read-only list refetch; never a repeated decision or execution.
      await ui.click({ role: "button", text: "Refresh" });
      nextRefresh = Date.now() + 3_000;
    }
    await delay(250);
  }
  throw new Error("approval_state_timeout");
}

// The approver, a different human from the requester, approves exactly the
// pending device's enrollment approval in the inbox.
export async function approvePendingEnrollment(ui, config, pending) {
  await openPage(ui, config, "/approvals", { role: "heading", text: "Approval inbox" });
  const card = await waitApproval(ui, pending.approvalId, (item) => item.state === "Pending");
  if (!card.title.startsWith("Approve device enrollment"))
    throw new Error("approval_not_device_enrollment");
  // The inbox shows a Device ID only when the approval row carries one; the
  // immutable payload always names the pending device.
  const device = card.fields["Device ID"];
  if (
    card.fields["Requester"] !== config.username ||
    (device ? device !== pending.deviceId : !card.payload.includes(`"${pending.deviceId}"`))
  )
    throw new Error("approval_request_mismatch");
  await ui.fill(
    { label: "Approval decision reason", within: pending.approvalId },
    "Lab provisioning: approve this exact pending installation",
  );
  await ui.click({ role: "button", text: "Approve", within: pending.approvalId });
  const decided = await waitApproval(
    ui,
    pending.approvalId,
    (item) => item.state === "Approved",
    () => ui.click({ role: "button", text: "Approve", within: pending.approvalId }),
  );
  if (decided.fields["Decided by"] !== config.approver.username)
    throw new Error("approval_decider_mismatch");
  return { approved: true, decidedBy: decided.fields["Decided by"] };
}

// The requester (token creator) runs the approved enrollment.
export async function executeApprovedEnrollment(ui, config, pending) {
  await openPage(ui, config, "/approvals", { role: "heading", text: "Approval inbox" });
  const card = await waitApproval(ui, pending.approvalId, (item) => item.state === "Approved");
  if (
    card.fields["Requester"] !== config.username ||
    card.fields["Decided by"] !== config.approver.username
  )
    throw new Error("approval_request_mismatch");
  await ui.click({ role: "button", text: "Run now", within: pending.approvalId });
  await waitApproval(
    ui,
    pending.approvalId,
    (item) => item.done || item.state === "Completed",
    () => ui.click({ role: "button", text: "Try again", within: pending.approvalId }),
  );
  return { requesterExecuted: true };
}

export async function confirmEnrolledDevice(ui, config) {
  const path = `/devices/${encodeURIComponent(config.deviceId)}`;
  const query = config.expectPackageRegistration ? "?tab=resources" : "";
  const toolPath = config.expectToolCustodyPath;
  const deadline = Date.now() + (toolPath ? 420_000 : 180_000);
  // Read-only page loads; an interrupted load or observation reloads the page
  // until the deadline, never Request inventory or an enrollment retry.
  const load = async () => {
    try {
      await ui.driver.goto(`${config.origin}${path}${query}`);
    } catch (error) {
      if (!interrupted(error)) throw error;
    }
  };
  await load();
  // The custody alert needs the first host inventory after enrollment.
  let nextRefresh = 0;
  while (Date.now() < deadline) {
    let state;
    try {
      state = await ui.driver.observe(
        ([expectedPath, expectedToolPath]) => {
          const section = document.querySelector("#main section[aria-busy]");
          // The first badge in the device heading is its authoritative lifecycle,
          // not an enrollment-history row or a phrase elsewhere on the page.
          const badge = section?.querySelector('[data-slot="badge"]');
          const visible = badge && badge.getClientRects().length > 0;
          const alert = section?.querySelector('[data-review-state="tool-custody"]');
          const codes = [...(alert?.querySelectorAll("code") ?? [])].map((code) =>
            code.textContent.trim(),
          );
          const servicesTab = section?.querySelector('[role="tab"][aria-selected="true"]');
          const servicesPanel =
            servicesTab?.textContent.trim() === "Services"
              ? document.getElementById(servicesTab.getAttribute("aria-controls"))
              : null;
          return {
            exactDevicePage: location.pathname === expectedPath,
            lifecycle: visible ? badge.textContent.trim() : "",
            busy: section?.getAttribute("aria-busy") !== "false",
            packageRegistrationRequired: [...(servicesPanel?.querySelectorAll("*") ?? [])].some(
              (node) =>
                node.getClientRects().length > 0 &&
                node.textContent.trim() === "Register this device with Red Hat",
            ),
            toolCustody:
              alert && alert.getClientRects().length > 0 && codes[0] === expectedToolPath
                ? {
                    path: codes[0],
                    remedy:
                      codes.includes(`chmod go-w ${expectedToolPath}`) &&
                      codes.includes("rpm --restore filesystem"),
                  }
                : undefined,
          };
        },
        [path, toolPath ?? ""],
      );
    } catch (error) {
      if (!interrupted(error)) throw error;
      await delay(1000);
      await load();
      continue;
    }
    if (!state.exactDevicePage) throw new Error("enrollment_device_page_mismatch");
    if (
      !state.busy &&
      state.lifecycle === "Enrolled" &&
      (!toolPath || state.toolCustody?.remedy) &&
      (!config.expectPackageRegistration || state.packageRegistrationRequired)
    )
      return {
        deviceId: config.deviceId,
        lifecycle: "Enrolled",
        ...(toolPath ? { toolCustody: state.toolCustody } : {}),
        ...(config.expectPackageRegistration ? { packageRegistrationRequired: true } : {}),
      };
    if (state.lifecycle === "Revoked" || state.lifecycle === "Recovery hold")
      throw new Error("enrollment_device_not_active");
    if (!state.busy && Date.now() >= nextRefresh) {
      await load();
      nextRefresh = Date.now() + 2_000;
    }
    await delay(250);
  }
  throw new Error(
    toolPath ? "enrollment_tool_custody_alert_timeout" : "enrollment_device_checkin_timeout",
  );
}

export async function assignProfile(ui, config) {
  await ui.driver.goto(`${config.origin}/devices/${encodeURIComponent(config.deviceId)}`);
  await ui.click({ role: "button", text: "Assign profile" });
  // The profile picker floats its choices in a popover; the form reports the
  // chosen profile's latest version in a hidden input read before submitting.
  const trigger = { css: '[role="dialog"] [data-slot="popover-trigger"]', enabled: true };
  await ui.wait(trigger);
  const chosen = (id) =>
    ui.driver.observe(
      (expected) => document.querySelector('input[name="profile-revision-id"]')?.value === expected,
      id,
    );
  const openChoices = async () => {
    await ui.click(trigger);
    // The empty choice is always rendered; wait for the popover before reading.
    await ui.wait({ role: "option", text: "No selection" });
  };
  let label = "";
  await openChoices();
  for (let page = 0; page < 20 && !label; page++) {
    const labels = await ui.driver.observe(() =>
      [
        ...document.querySelectorAll(
          '[data-slot="popover-content"]:not([data-closed]) [role="option"]',
        ),
      ]
        .filter(
          (node) => node.getClientRects().length && node.getAttribute("aria-disabled") !== "true",
        )
        .map((node) => (node.innerText ?? node.textContent).replace(/\s+/g, " ").trim())
        .filter((text) => text !== "No selection"),
    );
    if (labels.length > 200) throw new Error("profile_catalog_page_limit");
    for (let index = 0; index < labels.length; index++) {
      if (index) await openChoices();
      await ui.click({ role: "option", text: labels[index] });
      let selected = false;
      for (let attempt = 0; attempt < 20 && !selected; attempt++) {
        if (attempt) await delay(100);
        selected = await chosen(config.profileRevisionId);
      }
      if (selected) {
        label = labels[index];
        break;
      }
    }
    if (!label) {
      if (labels.length) await openChoices();
      const next = await ui.driver.find({ role: "button", text: "More profiles", enabled: true });
      if (!next) throw new Error("supplied_profile_revision_not_in_catalog");
      await ui.driver.click(next);
      await ui.wait({ role: "option", text: "No selection" });
    }
  }
  if (!label) throw new Error("profile_catalog_page_limit");
  await ui.fill(
    { label: "Reason (required)" },
    "Release acceptance verify native profile application",
  );
  await ui.click({ role: "button", text: "Save assignment" });
  await ui.wait({ role: "status", contains: "Assignment saved", dialog: true });
  // The dialog retains the accepted assignment and its next-check-in explanation.
  // Finish reviewing that receipt before interacting with the page behind it.
  await ui.click({ role: "button", text: "Close", dialog: true });
  return {
    deviceId: config.deviceId,
    profileRevisionId: config.profileRevisionId,
    label,
    accepted: true,
    nativeEffectVerified: false,
  };
}

export async function storageSelection(ui, config, kind) {
  const names = {
    escrowRotate: "Rotate escrow recovery key",
    cryptoErase: "Wipe encrypted storage",
    tpm2Bind: "Bind TPM 2.0 unlock",
    sanitize: "Sanitize offline unencrypted disk",
  };
  await ui.driver.goto(
    `${config.origin}/devices/${encodeURIComponent(config.deviceId)}/actions/new/${kind}`,
  );
  await ui.wait({ role: "heading", text: names[kind] });
  await ui.click({ label: "Target" });
  const option = await ui.wait({ role: "option", enabled: true, first: true });
  const optionText = await ui.driver.property(option, "innerText");
  if (!optionText || optionText.includes("Select observed storage"))
    throw new Error("eligible_storage_target_missing");
  await ui.click({ role: "option", text: optionText.trim() });
  await ui.click({ css: "summary", text: "Exact observed identity (read-only)" });
  const identity = await ui.driver.observe(() => {
    const section = document.querySelector('[aria-label="Observed storage target"]');
    return Object.fromEntries(
      [...section.querySelectorAll("dt")].map((node) => [
        node.textContent.trim().replace(/:\s*$/, ""),
        node.nextElementSibling?.textContent.trim(),
      ]),
    );
  });
  if (!identity["Exact size (bytes)"] || !/^[1-9][0-9]*$/.test(identity["Exact size (bytes)"]))
    throw new Error("storage_size_missing");
  if (
    ["escrowRotate", "cryptoErase", "tpm2Bind"].includes(kind) &&
    !/^[0-9a-f-]{36}$/i.test(identity["LUKS UUID"] ?? "")
  )
    throw new Error("storage_luks_identity_missing");
  // TechnicalDetails omits empty identifiers; an absent WWN is not placeholder copy.
  if (config.requireNoWWN && Object.hasOwn(identity, "WWN"))
    throw new Error("unexpected_storage_wwn");
  // Selection only. Never submit an encryption, recovery or destructive action.
  return { kind, selectable: true, label: optionText.trim(), identity, submitted: false };
}
