// This module drives visible controls only. No RPC client, request interception,
// cookie import, synthetic WebAuthn API or alternate application implementation.

import { setTimeout as delay } from "node:timers/promises";

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

async function captureCredential(ui, kind, config) {
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
  const commands = {};
  const repositoryConfigured = {};
  for (const [family, label] of [
    ["apt", "Debian / Ubuntu (APT)"],
    ["dnf", "Fedora / RHEL (DNF)"],
  ]) {
    await ui.select("Package manager", label, true);
    const name = provisioning ? "cloud-init provisioning snippet" : `${family} enrollment snippet`;
    const command = await ui.nonemptyValue({ label: name, dialog: true });
    const key = provisioning ? `cloud-init-${family}` : family;
    commands[key] = command;
    repositoryConfigured[family] = command.includes(
      "# Install only from this deployment's configured signed repository.",
    );
    if (config.requireRepositories && !repositoryConfigured[family]) {
      throw new Error("signed_repository_instructions_missing");
    }
  }
  if (provisioning) {
    for (const [format, label] of [
      ["kickstart", "Kickstart"],
      ["autoinstall", "Ubuntu autoinstall"],
    ]) {
      await ui.select("Installer format", label, true);
      commands[format] = await ui.nonemptyValue({
        label: `${format} provisioning snippet`,
        dialog: true,
      });
    }
  }
  return { ...details, secret, commands, repositoryConfigured };
}

export async function createGrant(ui, config) {
  await ui.driver.goto(`${config.origin}/enrollment`);
  await ui.click({ role: "button", text: "Create one-time code" });
  await ui.select("Code expires after", "15 minutes", true);
  await ui.fill(
    { label: "Reason", dialog: true },
    "Release acceptance native single-device enrollment",
  );
  await ui.click({ role: "button", text: "Create one-time code", dialog: true });
  const grant = await captureCredential(ui, "grant", config);
  await ui.click({ role: "button", text: "Done, forget secret", dialog: true });
  return grant;
}

export async function createToken(ui, config) {
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
  const token = await captureCredential(ui, "token", config);
  await ui.click({ role: "button", text: "Done, forget secret", dialog: true });
  return token;
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
    await ui.wait({ role: "option", text: "Select a profile head" });
    const labels = await ui.driver.observe(() =>
      [...document.querySelectorAll('[role="option"]')]
        .filter(
          (node) => node.getClientRects().length && node.getAttribute("aria-disabled") !== "true",
        )
        .map((node) => node.textContent.trim())
        .filter((text) => text !== "Select a profile head"),
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
  await ui.click({ role: "button", text: "Assign selected revision" });
  await ui.wait({ role: "status", contains: "Assignment accepted." });
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
        node.textContent.trim(),
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
  if (config.requireNoWWN && identity.WWN !== "Not reported")
    throw new Error("unexpected_storage_wwn");
  // Selection only. Never submit an encryption, recovery or destructive action.
  return { kind, selectable: true, label: optionText.trim(), identity, submitted: false };
}
