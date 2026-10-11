// This module drives visible controls only. No RPC client, request interception,
// cookie import, synthetic WebAuthn API or alternate application implementation.

import { setTimeout as delay } from "node:timers/promises";
import { createHash } from "node:crypto";
import { writePrivate } from "./private-files.mjs";

export async function enroll(ui, config) {
  await ui.click({ role: "link", text: "Enroll a local administrator account" });
  await ui.fill({ label: "One-time enrollment secret" }, config.enrollmentSecret);
  await ui.fill({ label: "New password (at least 12 bytes)" }, config.password);
  await ui.click({ role: "button", text: "Enroll account" });
  await ui.wait({ role: "status", contains: "Account enrolled." });
  await ui.click({ role: "link", text: "Back to sign in" });
}

export async function signIn(ui, config) {
  await ui.fill({ label: "Username" }, config.username);
  await ui.fill({ label: "Password" }, config.password);
  await ui.click({ role: "button", text: "Sign in locally" });
  await ui.wait({ role: "heading", text: "Dashboard" });
}

export async function signOut(ui) {
  await ui.click({ css: 'button[aria-label^="Account menu for "]' });
  await ui.click({ role: "menuitem", text: "Sign out" });
  await ui.wait({ label: "Username" });
}

async function captureCredential(ui, kind, config, captureScreens) {
  const provisioning = kind === "token";
  const title = provisioning ? "Provisioning token" : "One-time enrollment code";
  const secret = await ui.nonemptyValue({ label: title, dialog: true });
  await ui.click({ css: "summary", text: "Credential details and safe delivery", dialog: true });
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
  await ui.click({ css: "summary", text: "Credential details and safe delivery", dialog: true });
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
      await ui.select("Operating system", choices[family], true);
      await ui.select("Installer format", label, true);
      commands[format] = await ui.nonemptyValue({
        label: `${format} provisioning snippet`,
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

export async function confirmEnrolledDevice(ui, config) {
  const path = `/devices/${encodeURIComponent(config.deviceId)}`;
  await ui.driver.goto(`${config.origin}${path}`);
  const deadline = Date.now() + 180_000;
  let nextRefresh = 0;
  while (Date.now() < deadline) {
    const state = await ui.driver.observe((expectedPath) => {
      const section = document.querySelector("#main section[aria-busy]");
      // The first badge in the device heading is its authoritative lifecycle,
      // not an enrollment-history row or a phrase elsewhere on the page.
      const badge = section?.querySelector('[data-slot="badge"]');
      const visible = badge && badge.getClientRects().length > 0;
      const refresh = [...(section?.querySelectorAll("button") ?? [])].find(
        (button) => button.textContent.trim() === "Refresh page",
      );
      return {
        exactDevicePage: location.pathname === expectedPath,
        lifecycle: visible ? badge.textContent.trim() : "",
        busy: section?.getAttribute("aria-busy") !== "false",
        canRefresh: !!refresh && !refresh.disabled,
      };
    }, path);
    if (!state.exactDevicePage) throw new Error("enrollment_device_page_mismatch");
    if (!state.busy && state.lifecycle === "Enrolled")
      return { deviceId: config.deviceId, lifecycle: "Enrolled" };
    if (state.lifecycle === "Revoked" || state.lifecycle === "Recovery hold")
      throw new Error("enrollment_device_not_active");
    if (state.canRefresh && Date.now() >= nextRefresh) {
      // Read-only query refresh, never Request inventory or an enrollment retry.
      await ui.click({ role: "button", text: "Refresh page" });
      nextRefresh = Date.now() + 2_000;
    }
    await delay(250);
  }
  throw new Error("enrollment_device_checkin_timeout");
}

export async function assignProfile(ui, config) {
  await ui.driver.goto(`${config.origin}/devices/${encodeURIComponent(config.deviceId)}`);
  await ui.click({ role: "button", text: "Assign profile" });
  await ui.wait({ label: "Profile revision", enabled: true });
  let label = "";
  // Choose visible options with real input. Base UI's hidden form input
  // reflects the exact selected server revision; read it before submitting.
  for (let page = 0; page < 20 && !label; page++) {
    await ui.click({ label: "Profile revision" });
    // The placeholder option is always rendered; wait for the popup to mount
    // before reading the page's options once.
    await ui.wait({ role: "option", text: "Select a profile" });
    const labels = await ui.driver.observe(() =>
      [...document.querySelectorAll('[role="option"]')]
        .filter(
          (node) => node.getClientRects().length && node.getAttribute("aria-disabled") !== "true",
        )
        .map((node) => node.textContent.trim())
        .filter((text) => text !== "Select a profile"),
    );
    if (labels.length > 200) throw new Error("profile_catalog_page_limit");
    for (let index = 0; index < labels.length; index++) {
      if (index) await ui.click({ label: "Profile revision" });
      await ui.click({ role: "option", text: labels[index] });
      // Base UI commits the hidden input value asynchronously after input.
      let selected = false;
      for (let attempt = 0; attempt < 20 && !selected; attempt++) {
        if (attempt) await delay(100);
        selected = await ui.driver.observe(
          (id) =>
            [...document.querySelectorAll('form input[aria-hidden="true"]')].some(
              (input) => input.value === id,
            ),
          config.profileRevisionId,
        );
      }
      if (selected) {
        label = labels[index];
        break;
      }
    }
    if (!labels.length) await ui.click({ label: "Profile revision" });
    if (!label) {
      const next = await ui.driver.find({
        role: "button",
        text: "Next profile page",
        enabled: true,
      });
      if (!next) throw new Error("supplied_profile_revision_not_in_catalog");
      await ui.driver.click(next);
      await ui.wait({ label: "Profile revision", enabled: true });
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
