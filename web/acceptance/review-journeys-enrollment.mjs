// SPDX-License-Identifier: Apache-2.0

// Customer UI only. The seeded device is evidence of the review fixture, not
// consumption of the new credential. The native enroll-from-console lane owns
// bare-device installation and enrollment qualification.
const timeout = 30_000;

function assertFlow(value, reason) {
  if (!value) throw new Error(reason);
}

async function capture(ctx, name, screen, outcome) {
  await ctx.capture(name, {
    screen,
    taskShaped: "yes",
    generic:
      "The operator selects an operating system and installer by name; secrets remain masked in captures.",
    remedy:
      "Keep installation, enrollment, inventory receipt and advisory assessment as separate observed states.",
    outcome,
  });
}

async function choose(page, dialog, label, option) {
  await dialog.getByLabel(label, { exact: true }).click();
  await page.getByRole("option", { name: option, exact: true }).click();
  await page.getByRole("listbox").waitFor({ state: "hidden", timeout });
}

async function copyExactly(page, dialog, label, button) {
  await dialog.getByLabel(label, { exact: true }).waitFor({ timeout });
  await page.evaluate(() => navigator.clipboard.writeText(""));
  await dialog.getByRole("button", { name: button, exact: true }).click();
  await dialog
    .getByRole("status")
    .filter({ hasText: /copied\./ })
    .waitFor({ timeout });
  // Return equality only, never credential-bearing command bytes.
  const matched = await dialog.getByLabel(label, { exact: true }).evaluate(async (node) => {
    const copied = await navigator.clipboard.readText();
    await navigator.clipboard.writeText("");
    return !!node.value && copied === node.value;
  });
  assertFlow(matched, "enrollment_clipboard_does_not_match_shown_input");
}

async function secretContract(dialog) {
  await dialog
    .locator("p")
    .filter({ hasText: /^Expires:/ })
    .waitFor({ timeout });
  assertFlow(
    (await dialog.locator("details").count()) === 1,
    "enrollment_has_multiple_disclosures",
  );
  const done = dialog.getByRole("button", { name: "Done, forget secret", exact: true });
  assertFlow(await done.isVisible(), "enrollment_dismiss_action_unavailable");
  const details = dialog.locator("summary").filter({ hasText: /^Details$/ });
  await details.click();
  await dialog.getByText(/Don't reinstall to retry\./).waitFor({ timeout });
  await details.click();
}

export async function firstDevice(ctx) {
  const { page, config } = ctx;
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"], {
    origin: config.origin,
  });
  await ctx.visit("/enrollment");
  await page.getByRole("heading", { name: "Enroll a device", exact: true }).waitFor({ timeout });
  await capture(
    ctx,
    "choose-enrollment",
    "Enrollment / first device or batch",
    "The two enrollment methods name their intended jobs and credential limits.",
  );
  await page.getByRole("button", { name: "Create one-time code", exact: true }).click();
  let dialog = page.getByRole("dialog");
  await dialog
    .getByLabel("Reason", { exact: true })
    .fill("First Linux laptop installation walkthrough");
  await capture(
    ctx,
    "one-time-code-review",
    "Enrollment / one-time code review",
    "The code's lifetime is visible before creation. No installation has started.",
  );
  await dialog.getByRole("button", { name: "Create one-time code", exact: true }).click();
  await dialog
    .getByRole("heading", { name: "One-time enrollment code", exact: true })
    .waitFor({ timeout });
  try {
    await choose(page, dialog, "Operating system", "Fedora 44");
    await copyExactly(page, dialog, "Install and enroll command", "Copy install command");
    await capture(
      ctx,
      "fedora-command",
      "Enrollment / selected Fedora command",
      "The clipboard exactly matches the selected operating system's shown install command. The command was not executed by this synthetic walkthrough.",
    );
    await choose(page, dialog, "Operating system", "Ubuntu 24.04 LTS");
    await copyExactly(page, dialog, "Install and enroll command", "Copy install command");
    await secretContract(dialog);
    await capture(
      ctx,
      "ubuntu-command",
      "Enrollment / first laptop command",
      "Expiry, sudo and secret handling, and the next enrollment check are visible. A copied command is not an enrollment confirmation.",
    );
  } finally {
    await page.evaluate(() => navigator.clipboard.writeText(""));
    await dialog.getByRole("button", { name: "Done, forget secret", exact: true }).click();
    await dialog.waitFor({ state: "hidden", timeout });
  }
  assertFlow(
    (await page.locator("[data-sensitive]").count()) === 0,
    "enrollment_secret_retained_after_dismissal",
  );
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await page
    .getByText(/Enrollment does not confirm that inventory or findings have arrived\./)
    .waitFor({ timeout });
  await capture(
    ctx,
    "enrollment-check",
    "Enrollment / enrollment confirmation guidance",
    "The operator refreshes enrollment and is directed to the enrolled device in code history or to required approval. The new code remains unused because no laptop is attached to this review.",
  );

  await page.getByRole("button", { name: "Create provisioning token", exact: true }).click();
  dialog = page.getByRole("dialog");
  await dialog
    .getByLabel("Purpose / audit reason", { exact: true })
    .fill("Three Linux laptops through cloud-init or autoinstall");
  await dialog.getByLabel("Maximum uses", { exact: true }).fill("3");
  await capture(
    ctx,
    "batch-token-review",
    "Enrollment / bounded batch token",
    "The operator limits the batch to three uses. Expiry and the existing approval requirement stay visible and unchanged.",
  );
  await dialog.getByRole("button", { name: "Create provisioning token", exact: true }).click();
  await dialog
    .getByRole("heading", { name: "Provisioning token", exact: true })
    .waitFor({ timeout });
  try {
    for (const [format, label] of [
      ["cloud-init", "cloud-init"],
      ["autoinstall", "Ubuntu autoinstall"],
    ]) {
      await choose(page, dialog, "Installer format", label);
      await choose(page, dialog, "Operating system", "Ubuntu 24.04 LTS");
      await dialog
        .getByText(/Merge this snippet into your complete installer configuration\./)
        .waitFor({ timeout });
      await copyExactly(page, dialog, `${label} provisioning snippet`, `Copy ${label} snippet`);
      await secretContract(dialog);
      await capture(
        ctx,
        `batch-${format}`,
        `Enrollment / ${format} batch input`,
        "The copied snippet exactly matches the displayed input. Merge instructions and secret handling are visible; installation and enrollment still require real devices.",
      );
    }
  } finally {
    await page.evaluate(() => navigator.clipboard.writeText(""));
    await dialog.getByRole("button", { name: "Done, forget secret", exact: true }).click();
    await dialog.waitFor({ state: "hidden", timeout });
  }
  const representative = config.demo?.Devices?.find(
    (device) => device.State === "enrolled" && device.Hostname === "ubuntu-ws-01",
  );
  assertFlow(representative, "first_device_seeded_representative_missing");
  await ctx.visit("/devices");
  const device = page.getByRole("link", { name: representative.Hostname, exact: true });
  await device.waitFor({ timeout });
  await capture(
    ctx,
    "device-list",
    "Devices / enrolled seeded representative",
    "The seeded hostname appears in the device list. It is not the laptop for the newly created unused one-time code.",
  );
  await device.click();
  await page
    .getByRole("heading", { name: representative.Hostname, exact: true })
    .waitFor({ timeout });
  await capture(
    ctx,
    "enrolled-device",
    "Device / enrolled state",
    "Enrollment is shown separately from inventory and security posture on the seeded device.",
  );
  await page.getByRole("tab", { name: "Inventory", exact: true }).click();
  await page.getByText("System", { exact: true }).waitFor({ timeout });
  await page
    .getByText("Lindm capacity simulator", { exact: true })
    .filter({ visible: true })
    .waitFor({ timeout });
  await capture(
    ctx,
    "first-inventory",
    "Device / inventory receipt",
    "Reported time and synthetic hardware provenance identify the inventory observation. No native laptop inventory is claimed.",
  );
  await page.getByRole("tab", { name: "Findings", exact: true }).click();
  await page.getByText("Security findings", { exact: true }).waitFor({ timeout });
  await page.getByText(/Inventory collected:/).waitFor({ timeout });
  await page.getByText(/Advisories checked:/).waitFor({ timeout });
  await capture(
    ctx,
    "first-findings",
    "Device / first advisory assessment",
    "The findings view retains inventory and advisory assessment freshness rather than equating enrollment with no exposure.",
  );
  return {
    outcome: "blocked",
    reason:
      "The real console created and copied a one-time command and both bounded batch inputs, then showed the seeded device list, inventory and findings. This synthetic walkthrough has no bare laptop or installer to consume those credentials. Native enrollment proof belongs to the enroll-from-console and provisioning matrix lanes; no enrollment or native inventory result is simulated here.",
  };
}

export const journeys = [
  { id: "first-device", title: "First device and batch enrollment", run: firstDevice },
];
