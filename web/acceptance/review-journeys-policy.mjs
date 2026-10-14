// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from "node:crypto";
import { ChromiumDriver, UI } from "./drivers.mjs";
import { enroll, signIn } from "./journey.mjs";
import { openNavigationPage } from "./review-navigation.mjs";
import { chooseNamed, createGroup } from "./review-journeys-provision.mjs";

const timeout = 30_000;

// The empty stock console is a real prerequisite case, not an intercepted RPC.
export async function packageSourcePrerequisite(page, screenshot) {
  await openNavigationPage(page, "Profiles");
  await page.getByRole("link", { name: "Create profile", exact: true }).click();
  await page.getByRole("combobox", { name: "Setting type", exact: true }).click();
  await page.getByRole("option", { name: "Package", exact: true }).click();
  await page.getByRole("button", { name: /^Approved package source / }).click();
  await page
    .getByText(
      "No device reports approved package sources yet. Each device's local agent configuration defines these approvals.",
      { exact: true },
    )
    .waitFor({ timeout });
  const path = await screenshot(page, "package-source-prerequisite.png", true);
  await page.keyboard.press("Escape");
  return path;
}

export async function configureFleet(ctx) {
  const { page, config } = ctx;
  const device =
    (config.demo?.Devices ?? []).find((entry) => entry.ID === config.demo?.Routes?.DeviceID) ??
    (config.demo?.Devices ?? []).find((entry) => entry.Hostname === "ubuntu-ws-01");
  if (!device?.Hostname) throw new Error("fleet_route_device_missing");
  const record = async (name, screen, outcome, observedPage = page) => {
    await ctx.capture(
      name,
      {
        screen,
        taskShaped: "yes",
        generic: "Named settings, devices and stages carry the administrator's context.",
        remedy: "Keep actual device outcomes separate from requests and approvals.",
        outcome,
      },
      observedPage,
    );
  };
  const group = await createGroup(ctx, "configure-fleet", "Fleet pilot", device);
  await openNavigationPage(page, "Profiles");
  await page.getByRole("link", { name: "Create profile", exact: true }).click();
  const another = page.getByRole("button", { name: "Create another profile", exact: true });
  if (await another.isVisible()) await another.click();
  const profileName = `Fleet baseline review ${randomUUID().slice(0, 8)}`;
  await page.getByRole("textbox", { name: "Name", exact: true }).fill(profileName);
  await page
    .getByRole("textbox", { name: "Description", exact: true })
    .fill(
      "Pilot packages, public SSH notice, isolated network rules and scheduled security updates.",
    );
  for (const [index, name] of [
    "Package",
    "SSH sign-in banner",
    "Firewall zone",
    "OS update policy",
  ].entries()) {
    if (index) await page.getByRole("button", { name: "Add setting", exact: true }).click();
    const setting = page.locator(`[data-setting-index="${index}"]`);
    await setting.getByRole("combobox", { name: "Setting type", exact: true }).click();
    await page
      .locator("[data-slot=select-content][data-open]")
      .getByRole("option", { name, exact: true })
      .click();
    if (index === 0) {
      await chooseNamed(ctx, setting, "Package name", "curl", "fleet-package");
      await setting.getByRole("button", { name: /^Approved package source / }).click();
      const popup = page.locator('[data-slot="popover-content"]');
      const source = popup.getByRole("option", { name: /^APT ·/ }).first();
      await source.waitFor({ timeout });
      if (await popup.getByRole("option", { name: /^RPM ·/ }).count())
        throw new Error("fleet_package_source_format_mismatch_offered");
      await record(
        "package-source",
        "Profile editor / matching approved source",
        "DEB packages offer APT sources reported by devices, not unrelated RPM sources.",
      );
      await source.click();
    } else if (index === 1) {
      await setting
        .getByRole("textbox", { name: "Notice before SSH sign-in", exact: true })
        .fill("Authorized use only. Contact IT for help.");
    } else if (index === 2) {
      await setting.getByRole("button", { name: "Add source networks", exact: true }).click();
      await setting
        .getByRole("textbox", { name: "Network address", exact: true })
        .fill("192.0.2.0");
      await setting.getByRole("spinbutton", { name: "Prefix length", exact: true }).fill("24");
      await setting.getByText(/Firewall rules can block SSH and device contact/).waitFor();
    } else {
      await setting
        .getByRole("combobox", { name: "After updates need a restart", exact: true })
        .click();
      await page
        .locator("[data-slot=select-content][data-open]")
        .getByRole("option", { name: "Let the employee restart", exact: true })
        .click();
    }
  }
  await page.getByRole("checkbox", { name: "Advanced options", exact: true }).check();
  const ssh = page.locator('[data-setting-index="1"]');
  const ownership = ssh.getByRole("combobox", {
    name: "If the item already exists on the device",
    exact: true,
  });
  if (!(await ownership.isDisabled())) {
    await ownership.click();
    await page
      .locator("[data-slot=select-content][data-open]")
      .getByRole("option", {
        name: "Take over the existing one (needs an approved assignment)",
        exact: true,
      })
      .click();
  }
  await page.getByRole("checkbox", { name: "Advanced options", exact: true }).uncheck();
  await page
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("Publish a reviewed fleet pilot; do not activate devices yet.");
  await record(
    "four-settings",
    "Profile editor / four settings",
    "Package source is reported by a registry-derived synthetic executor. SSH adoption will require approval. Firewall scope is the documentation-only network; employees retain restart control.",
  );
  await page.getByRole("button", { name: "Publish profile", exact: true }).click();
  await page.getByRole("link", { name: "Roll out this version", exact: true }).waitFor({ timeout });
  await record(
    "published",
    "Profiles / exact version handoff",
    "Publication saved a catalog version. No device changed.",
  );
  await openNavigationPage(page, "Profiles");
  await page.getByText("Profile save results", { exact: true }).waitFor({ timeout });
  if (await page.getByText("A profile hasn't finished saving", { exact: true }).count())
    throw new Error("fleet_published_profile_reported_unsaved");
  const saved = page.getByRole("link", {
    name: `View published version: ${profileName}`,
    exact: true,
  });
  await saved.waitFor({ timeout });
  await record(
    "catalog-published",
    "Profiles / completed save feedback",
    "The catalog identifies successful publication and provides its saved version even when it is outside the current list page.",
  );
  await saved.click();
  await page.getByRole("heading", { name: profileName, exact: true }).waitFor({ timeout });
  await page.getByRole("link", { name: "Roll out this version", exact: true }).first().click();
  const proposal = page.getByRole("dialog", { name: "New rollout", exact: true });
  await proposal.waitFor({ timeout });
  await proposal
    .getByRole("button", { name: `Version ${profileName}, version 1`, exact: true })
    .waitFor({ timeout });
  await chooseNamed(ctx, proposal, "Target", group.name, "fleet-group");
  await proposal.getByRole("radio", { name: "In stages", exact: true }).check();
  await proposal.getByRole("textbox", { name: "Stage 1 name", exact: true }).fill("pilot");
  await proposal.getByRole("textbox", { name: "Stage 2 name", exact: true }).fill("fleet");
  await proposal.getByRole("button", { name: "Review impact", exact: true }).click();
  await proposal.locator("[data-impact-summary]").waitFor({ timeout });
  await proposal.getByRole("link", { name: device.Hostname, exact: true }).waitFor({ timeout });
  if (
    !(await proposal.locator("[data-impact-summary]").innerText()).startsWith(
      "Proposed changes on ",
    )
  )
    throw new Error("fleet_impact_promises_execution");
  if (await proposal.getByText(/Resolve the problem before this device changes\./).count())
    await proposal
      .getByRole("row")
      .filter({ has: page.getByRole("link", { name: device.Hostname, exact: true }) })
      .getByText("Needs review", { exact: true })
      .waitFor({ timeout });
  await proposal.getByRole("link", { name: device.Hostname, exact: true }).scrollIntoViewIfNeeded();
  await record(
    "impact",
    "Rollouts / device impact and stages",
    "The real server review names the device, new settings and settings that stop being managed. The pilot precedes a manually advanced fleet stage.",
  );
  const request = proposal.getByRole("button", {
    name: "Request approval to roll out",
    exact: true,
  });
  await request.waitFor({ timeout });
  if (!(await request.isDisabled())) throw new Error("fleet_rollout_reason_not_required");
  await proposal
    .getByRole("textbox", { name: "Reason for this rollout", exact: true })
    .fill(
      "Review the pilot's package, SSH notice, firewall and security update policy before fleet promotion.",
    );
  await request.click();
  await proposal
    .getByText("Waiting for approval from another administrator", { exact: true })
    .waitFor({ timeout });
  await record(
    "approval-requested",
    "Rollouts / approval pending",
    "The rollout waits for a separate administrator. It cannot start from the requester's approval.",
  );
  await proposal.getByRole("button", { name: "Done", exact: true }).click();
  const rolloutName = `${profileName} v1 to ${group.name}`;
  await openNavigationPage(page, "Accounts");
  await page.getByRole("button", { name: "Create account", exact: true }).first().click();
  const accountForm = page.getByRole("dialog", { name: "Create account", exact: true });
  const username = `fleet-approver-${randomUUID().slice(0, 8)}`;
  await accountForm.getByRole("textbox", { name: "Username", exact: true }).fill(username);
  await accountForm.getByRole("combobox", { name: "Role", exact: true }).click();
  await page
    .locator("[data-slot=select-content][data-open]")
    .getByRole("option", { name: "Admin", exact: true })
    .click();
  await accountForm.getByRole("button", { name: "Create account", exact: true }).click();
  const secretRegion = page.getByRole("region", {
    name: "One-time enrollment secret",
    exact: true,
  });
  await secretRegion.waitFor({ timeout });
  const enrollmentSecret = (await secretRegion.locator("code").innerText()).trim();
  ctx.protectSecret(enrollmentSecret);
  await secretRegion.getByRole("button", { name: "Dismiss secret", exact: true }).click();
  const approver = new ChromiumDriver();
  try {
    await approver.open({
      ignoreHTTPSErrors: true,
      actionTimeoutMs: timeout,
      classicScrollbars: true,
    });
    await approver.authenticator([]);
    const account = {
      origin: config.origin,
      username,
      password: `Fleet-${randomUUID()}`,
      enrollmentSecret,
    };
    ctx.protectSecret(account.password);
    const ui = new UI(approver, timeout);
    await approver.goto(config.origin);
    await enroll(ui, account);
    await signIn(ui, account);
    await openNavigationPage(approver.page, "Approvals");
    const approval = approver.page.locator("article").filter({
      has: approver.page.getByRole("heading", { name: `Roll out ${rolloutName}`, exact: true }),
    });
    await approval.getByRole("list", { name: "Rollout stages", exact: true }).waitFor({ timeout });
    await record(
      "approval-review",
      "Approvals / separate administrator review",
      "The approver sees target count, stage shares and the manual fleet gate before deciding.",
      approver.page,
    );
    await approval
      .getByRole("textbox", { name: "Approval decision reason", exact: true })
      .fill(
        "Approve the named pilot only; review device results before advancing to the fleet stage.",
      );
    await approval.getByRole("button", { name: "Approve", exact: true }).click();
    await approval.getByText("Approved", { exact: true }).waitFor({ timeout });
    await record(
      "approved",
      "Approvals / recorded decision",
      "A distinct enrolled administrator approved the exact request. Approval is not an applied device result.",
      approver.page,
    );
  } finally {
    await approver.close();
  }
  await openNavigationPage(page, "Rollouts");
  const rollout = page
    .locator("article")
    .filter({ has: page.getByRole("heading", { name: rolloutName, exact: true }) });
  await rollout.getByRole("button", { name: "Pause", exact: true }).waitFor({ timeout: 120_000 });
  await record(
    "progress",
    "Rollouts / pilot device progress",
    "Progress comes from server device results. Synthetic execution cannot prove native package, firewall or update success.",
  );
  await rollout.getByRole("button", { name: "Pause", exact: true }).click();
  const pause = page.getByRole("dialog", { name: `Pause: ${rolloutName}`, exact: true });
  await pause
    .getByText(
      "No more devices start this change until you resume. Devices that already changed keep it.",
      { exact: true },
    )
    .waitFor();
  await pause
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("Pause after pilot review. Do not send this change to further devices.");
  await record(
    "pause-review",
    "Rollouts / pause consequences",
    "The dialog names the rollout and says existing changes remain. Pause is not rollback.",
  );
  await pause.getByRole("button", { name: "Pause", exact: true }).click();
  await pause.waitFor({ state: "hidden", timeout });
  await rollout.getByText("Paused", { exact: true }).waitFor({ timeout });
  await rollout.getByRole("button", { name: "Resume", exact: true }).waitFor({ timeout });
  const reviewCount = Number(
    await rollout
      .locator("dl > div")
      .filter({ has: page.getByText("Needs review", { exact: true }) })
      .locator("dd")
      .innerText(),
  );
  if (reviewCount > 0)
    await rollout.getByRole("link", { name: device.Hostname, exact: true }).waitFor({ timeout });
  await record(
    "paused",
    "Rollouts / confirmed paused state",
    "The actual control request paused this rollout. No promotion or rollback was sent.",
  );
  return {
    outcome: "completed",
    reason:
      "Created a named group, published all four setting types with a reported approved source, reviewed device impact, requested and obtained a separate administrator's approval for a staged rollout, read real progress, and paused it. Device observations are synthetic, not native qualification.",
  };
}

export const journeys = [
  {
    id: "configure-fleet",
    title: "Configure the fleet with an approved staged rollout",
    run: configureFleet,
  },
];
