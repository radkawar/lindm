// SPDX-License-Identifier: Apache-2.0
import { ChromiumDriver, UI } from "./drivers.mjs";
import { enroll, signIn } from "./journey.mjs";

function requireState(condition, token) {
  if (!condition) throw new Error(token);
}

async function capture(ctx, name, outcome) {
  for (const close of await ctx.page.locator("[data-sonner-toast] [data-close-button]").all()) {
    if (await close.isVisible()) await close.click();
  }
  await ctx.capture(name, {
    screen: "Lost device response",
    taskShaped: "yes",
    generic: "None in the checked decision and handoff.",
    remedy:
      "Preserve named targets, independent approval and the distinction between server acceptance and device results.",
    outcome,
  });
}

async function openAction(page, label) {
  await page.getByRole("main").getByRole("button", { name: "Actions", exact: true }).click();
  await page.getByRole("menuitem", { name: label, exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.waitFor();
  return dialog;
}

async function findDevice(ctx, device) {
  await ctx.visit("/devices");
  const main = ctx.page.getByRole("main");
  await main.getByRole("searchbox", { name: "Search devices" }).fill(device.Hostname);
  await main.getByRole("button", { name: "Search", exact: true }).click();
  await main.getByRole("link", { name: device.Hostname, exact: true }).click();
  await main.getByRole("heading", { name: device.Hostname, exact: true }).waitFor();
}

// A separate human, enrolled through the visible UI. No fabricated session or RPC.
async function secondAdmin(ctx, driver) {
  const accountPage = await ctx.page.context().newPage();
  const username = `lost-device-review-${crypto.randomUUID().slice(0, 8)}`;
  const password = `review-${crypto.randomUUID()}`;
  try {
    await accountPage.goto(`${ctx.config.origin}/accounts?create=true`);
    const dialog = accountPage.getByRole("dialog", { name: "Create account", exact: true });
    await dialog.getByRole("textbox", { name: "Username", exact: true }).fill(username);
    await dialog.getByRole("button", { name: "Create account", exact: true }).click();
    const secret = accountPage.locator('section[aria-label="One-time enrollment secret"] code');
    await secret.waitFor();
    const enrollmentSecret = (await secret.innerText()).trim();
    await driver.open({
      ignoreHTTPSErrors: true,
      actionTimeoutMs: 30_000,
      classicScrollbars: true,
    });
    await driver.authenticator([]);
    const ui = new UI(driver, 30_000);
    const account = { origin: ctx.config.origin, username, password, enrollmentSecret };
    await driver.goto(ctx.config.origin);
    await enroll(ui, account);
    await signIn(ui, account);
    driver.page.setDefaultTimeout(30_000);
    return driver.page;
  } finally {
    await accountPage.close();
  }
}

async function approve(page, origin, heading) {
  await page.goto(`${origin}/approvals`);
  const card = page
    .locator("article")
    .filter({ has: page.getByRole("heading", { name: heading, exact: true }) });
  await card
    .getByRole("textbox")
    .fill("Confirmed the reported lost device and the requested access change.");
  await card.getByRole("button", { name: "Approve", exact: true }).click();
  await card.getByText("Approved", { exact: true }).waitFor();
}

async function lostDevice(ctx) {
  const { page, config } = ctx;
  const route = config.demo.Devices.find((device) => device.ID === config.demo.Routes.DeviceID);
  const offline = config.demo.Devices.find((device) => device.Hostname === "ubuntu-ws-08");
  requireState(route && offline, "lost_device_fixture_missing");
  const driver = new ChromiumDriver();
  try {
    // Hold the real read briefly; no response or recovery state is fabricated.
    const encryptionRead = "**/lindm.admin.v1.AdminService/GetDeviceEncryption";
    let releaseRead;
    const heldRead = new Promise((resolve) => {
      releaseRead = resolve;
    });
    let continued;
    const hold = async (request) => {
      continued = heldRead.then(() => request.continue());
      await continued;
    };
    await page.route(encryptionRead, hold);
    try {
      await findDevice(ctx, route);
      const posture = page.locator('[data-posture-row="encryption"]');
      await posture
        .getByText("Root disk encrypted. Checking the recovery key…", { exact: false })
        .waitFor();
      await posture.getByText("Unknown", { exact: true }).waitFor();
      requireState(
        (await posture.getByText("No recovery key", { exact: true }).count()) === 0,
        "lost_device_loading_claims_missing_key",
      );
    } finally {
      releaseRead();
      await continued;
      await page.unroute(encryptionRead, hold);
    }
    await page.getByText("Accounts locked", { exact: true }).waitFor();
    await capture(
      ctx,
      "overview",
      "Found the laptop by hostname. Contact, root encryption and the existing account lock are visible.",
    );
    const lock = await openAction(page, "Lock sessions and local accounts");
    await lock.getByRole("link", { name: "Review the current lock", exact: true }).waitFor();
    await lock.getByText("Do not undo it while the device is lost.", { exact: false }).waitFor();
    await capture(
      ctx,
      "existing-lock",
      "Existing containment is preserved. The console links to its evidence instead of asking the administrator to undo it.",
    );
    await lock.getByRole("link", { name: "Review the current lock", exact: true }).click();
    await page.getByText("Completed", { exact: true }).waitFor();
    await capture(
      ctx,
      "lock-result",
      "Reviewed the seeded lock result; this is synthetic evidence, not a new native lock.",
    );

    await ctx.visit(`/devices/${route.ID}?tab=encryption`);
    await page.getByRole("button", { name: "Reveal recovery key", exact: true }).click();
    await page
      .getByLabel("Reason", { exact: true })
      .fill("Lost laptop incident: verify recovery access with independent approval.");
    await page.getByLabel("Type the device name to confirm").fill(route.Hostname);
    await page.getByRole("button", { name: "Request approval", exact: true }).click();
    await page.getByRole("button", { name: "Refresh approval status", exact: true }).waitFor();
    requireState(
      await page.getByRole("button", { name: "Reveal recovery key", exact: true }).isDisabled(),
      "lost_device_reveal_before_approval",
    );
    const handoff = page.getByRole("link", { name: "Open approvals in a new tab", exact: true });
    requireState(
      (await handoff.getAttribute("target")) === "_blank",
      "lost_device_handoff_discards_request",
    );
    for (const theme of ["light", "dark"]) {
      await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
      for (const viewport of [
        { name: "desktop", width: 1440, height: 900 },
        { name: "mobile", width: 390, height: 844 },
      ]) {
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        requireState(
          await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          "lost_device_recovery_horizontal_overflow",
        );
        await capture(
          ctx,
          `approval-${theme}-${viewport.name}`,
          "The exact request stays open while another administrator reviews it. All recovery controls fit the viewport.",
        );
      }
    }
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
    const reviewer = await secondAdmin(ctx, driver);
    await approve(reviewer, config.origin, `Reveal recovery key on ${route.Hostname}`);
    await page.bringToFront();
    await page.getByRole("button", { name: "Refresh approval status", exact: true }).click();
    await page.getByText("Approval: approved.", { exact: false }).waitFor();
    await page.getByRole("button", { name: "Reveal recovery key", exact: true }).click();
    await page.locator('[data-revealed-secret] [data-sensitive="true"]').waitFor();
    await capture(
      ctx,
      "recovery-revealed",
      "A second administrator approved the recovery key request. The key is shown briefly and masked in screenshots.",
    );
    await page.getByRole("button", { name: "Hide now", exact: true }).click();
    requireState(
      (await page.locator("[data-revealed-secret]").count()) === 0,
      "lost_device_key_not_hidden",
    );

    await ctx.visit(`/devices/${route.ID}`);
    await page.getByRole("button", { name: "Actions", exact: true }).click();
    await page.getByRole("menuitem", { name: "Wipe encrypted storage", exact: true }).click();
    await page.getByText("Wiping cannot be undone", { exact: true }).waitFor();
    await page
      .getByText("The wipe keeps recovery keys on this server and external header backups.", {
        exact: false,
      })
      .waitFor();
    await capture(
      ctx,
      "wipe-boundary",
      "Reviewed wipe scope, power-off, independent approval, fresh storage requirements and retained recovery copies. No wipe was sent.",
    );

    await findDevice(ctx, offline);
    const offlineLock = await openAction(page, "Lock sessions and local accounts");
    await offlineLock
      .getByLabel("Reason", { exact: true })
      .fill("Lost laptop reported by its user. Review the lock before changing access.");
    await offlineLock.getByRole("button", { name: "Review action", exact: true }).click();
    await offlineLock.getByText("Not ready to send", { exact: true }).waitFor();
    requireState(
      await offlineLock.getByRole("button", { name: "Request approval", exact: true }).isDisabled(),
      "lost_device_offline_lock_not_blocked",
    );
    await offlineLock
      .getByText("This does not erase data or isolate the network.", { exact: false })
      .waitFor();
    await capture(
      ctx,
      "offline-lock",
      "The offline laptop cannot receive a new lock. The server refuses the request; nothing is queued or claimed as protected.",
    );
    await page.keyboard.press("Escape");
    const revoke = await openAction(page, "Revoke device");
    await revoke
      .getByText("This is not a disk wipe or an account lock.", { exact: false })
      .waitFor();
    await revoke
      .getByLabel("Revocation reason", { exact: true })
      .fill(
        "Lost laptop reported by its user. Stop access to lindm while the incident is investigated.",
      );
    await revoke.getByRole("button", { name: "Request revocation approval", exact: true }).click();
    await revoke
      .getByRole("link", { name: "Open approvals to finish revoking once approved", exact: true })
      .waitFor();
    await capture(
      ctx,
      "lost-report",
      "Recorded the lost-device reason and requested independent approval to revoke management access, not to wipe data.",
    );
    await approve(reviewer, config.origin, `Revoke device access on ${offline.Hostname}`);
    await revoke.getByRole("link").click();
    const approved = page.locator("article").filter({
      has: page.getByRole("heading", {
        name: `Revoke device access on ${offline.Hostname}`,
        exact: true,
      }),
    });
    await approved.getByRole("button", { name: "Run now", exact: true }).click();
    await approved.waitFor({ state: "hidden" });
    await ctx.visit(`/devices/${offline.ID}`);
    await page.getByText("Revoked", { exact: true }).first().waitFor();
    await capture(
      ctx,
      "revoked",
      "The lost laptop's credentials are revoked. Local accounts and disk data are not reported as erased.",
    );
    await page.getByRole("tab", { name: "Actions", exact: true }).click();
    await page.getByRole("link", { name: "Open device audit log", exact: true }).click();
    await page.getByRole("heading", { name: "Audit log", exact: true }).waitFor();
    await page.getByText("Revoked device", { exact: true }).waitFor();
    await capture(
      ctx,
      "revocation-audit",
      "The device-scoped audit log records the completed access revocation and its lost-device reason.",
    );
    await ctx.visit(`/devices/${route.ID}?tab=actions`);
    await page.getByRole("link", { name: "Open device audit log", exact: true }).click();
    requireState(
      new URL(page.url()).searchParams.get("deviceId") === route.ID,
      "lost_device_audit_scope_lost",
    );
    await page.getByRole("heading", { name: "Audit log", exact: true }).waitFor();
    await page.getByText("Revealed recovery key", { exact: true }).first().waitFor();
    await capture(
      ctx,
      "audit",
      "Opened the device-scoped audit log from action history and found recovery-key access. Device commands and human audit events remain distinct.",
    );
    return {
      outcome: "blocked",
      reason:
        "The real UI completed second-admin recovery access and lost-device management revocation. It reviewed wipe safeguards and preserved an existing lock. The offline laptop cannot receive a new lock; no native lock or wipe execution is claimed.",
    };
  } finally {
    await driver.close();
  }
}

export const journeys = [{ id: "lost-laptop", title: "Respond to a lost laptop", run: lostDevice }];
