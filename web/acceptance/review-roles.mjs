// SPDX-License-Identifier: Apache-2.0

// Role-scoped console walkthrough: as the owner, an approver (admin) and a
// helpdesk account scoped to the `engineering` label, nothing the console offers
// is then refused. Each visible navigation item opens without an access refusal,
// in-page links only lead to pages that role can open, the device Actions menu is
// never empty, Assign profile needs the grant, a scoped role is not offered to fix
// advisory coverage, and an out-of-scope device says the role lacks access.
// Accounts are created through the owner's real session; no response is fabricated.
import { ChromiumDriver, UI } from "./drivers.mjs";
import { enroll, signIn } from "./journey.mjs";

const refusals = [
  "Access not granted",
  "Something went wrong",
  "Unable to load the console",
  "requires unrestricted",
];

async function rpc(page, method, body) {
  return page.evaluate(
    async ({ method, body }) => {
      const session = await (await fetch("/auth/session", { cache: "no-store" })).json();
      const response = await fetch(`/lindm.admin.v1.AdminService/${method}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrfToken },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(`${method}_${response.status}`);
      return response.json();
    },
    { method, body },
  );
}

async function session(page) {
  return page.evaluate(async () => {
    const value = await (await fetch("/auth/session", { cache: "no-store" })).json();
    return {
      role: value.role,
      permissions: value.permissions ?? [],
      unrestrictedPermissions: value.unrestrictedPermissions ?? [],
    };
  });
}

async function createAccount(page, username, role, scopes) {
  return page.evaluate(
    async ({ username, role, scopes }) => {
      const current = await (await fetch("/auth/session", { cache: "no-store" })).json();
      const response = await fetch("/auth/accounts/create", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-CSRF-Token": current.csrfToken,
        },
        body: JSON.stringify({ username, role, scopes }),
      });
      if (!response.ok) throw new Error(`create_account_${response.status}`);
      return (await response.json()).secret;
    },
    { username, role, scopes },
  );
}

async function deviceIds(page) {
  const response = await rpc(page, "ListDevices", { pageSize: 200 });
  return (response.devices ?? [])
    .filter((device) => device.lifecycleState !== "DEVICE_STATE_REVOKED")
    .map((device) => device.id);
}

async function navigationPaths(page) {
  return page
    .locator('nav[aria-label="Main navigation"] a[href]')
    .evaluateAll((links) => links.map((link) => new URL(link.href).pathname));
}

async function mainText(page) {
  return page.locator("#main").innerText();
}

export async function reviewRoleWalkthroughs({
  ownerPage,
  config,
  visit,
  settle,
  screenshot,
  protectSecret,
}) {
  const suffix = crypto.randomUUID().slice(0, 8);
  const roles = [
    { name: "owner", page: ownerPage },
    { name: "approver", account: { role: "admin", scopes: [] } },
    {
      name: "scoped helpdesk",
      scoped: true,
      // lab/demo/org.json's Engineering provisioning token label.
      account: { role: "helpdesk", scopes: [{ labels: ["department/engineering"] }] },
    },
  ];
  const results = [];
  const drivers = [];
  const fleet = await deviceIds(ownerPage);
  let ownerPages = [];
  try {
    for (const role of roles) {
      const findings = [];
      const screenshots = [];
      const require = (value, message) => {
        if (!value) findings.push(message);
      };
      const prefix = `roles-${role.name.replaceAll(" ", "-")}`;
      let step = "sign in";
      let page = role.page;
      try {
        if (!page) {
          const username = `review-${role.account.role}-${suffix}`;
          const enrollmentSecret = await createAccount(
            ownerPage,
            username,
            role.account.role,
            role.account.scopes,
          );
          protectSecret(enrollmentSecret);
          const password = `review-${crypto.randomUUID()}`;
          protectSecret(password);
          const driver = new ChromiumDriver();
          drivers.push(driver);
          await driver.open({
            ignoreHTTPSErrors: true,
            actionTimeoutMs: 30_000,
            classicScrollbars: true,
          });
          await driver.context.addInitScript(() => localStorage.removeItem("lindm-theme"));
          await driver.authenticator([]);
          const ui = new UI(driver, 30_000);
          const account = { origin: config.origin, username, password, enrollmentSecret };
          await driver.goto(config.origin);
          await enroll(ui, account);
          await signIn(ui, account);
          page = driver.page;
          page.setDefaultTimeout(30_000);
          await page.setViewportSize({ width: 1440, height: 900 });
        }
        const { permissions, unrestrictedPermissions } = await session(page);

        step = "navigation";
        await visit(page, "/dashboard");
        const paths = await navigationPaths(page);
        if (role.name === "owner") ownerPages = paths;
        // Pages the owner can open but this role cannot: links there are refused CTAs.
        const forbidden = ownerPages.filter((path) => !paths.includes(path));
        const inspect = async (where) => {
          // Some loading states are not announced; give every query time to answer
          // (or fail once and be retried) before reading what the role is shown.
          await page.waitForTimeout(2_000);
          await settle(page);
          const text = await mainText(page);
          for (const refusal of refusals)
            require(!text.includes(refusal), `${where} shows "${refusal}"`);
          require((await page.locator('[data-review-state="restricted"]').count()) ===
            0, `${where} renders a restricted page`);
          const targets = await page
            .locator("#main a[href]")
            .evaluateAll((links) =>
              links.filter((link) => link.offsetParent).map((link) => new URL(link.href).pathname),
            );
          for (const target of new Set(targets)) {
            const top = `/${target.split("/")[1]}`;
            require(!forbidden.includes(
              top,
            ), `${where} links to ${target}, which this role can't open`);
          }
        };
        for (const path of paths) {
          step = `navigation ${path}`;
          await visit(page, path);
          await inspect(`nav item ${path}`);
        }

        step = "dashboard";
        await visit(page, "/dashboard");
        await inspect("dashboard");
        if (role.scoped)
          require(!/fix coverage/i.test(
            await mainText(page),
          ), "dashboard offers to fix advisory coverage to a device-scoped role");
        screenshots.push(await screenshot(page, `${prefix}-dashboard.png`, true));

        step = "device";
        const visible = await deviceIds(page);
        const deviceId = visible.includes(config.deviceId) ? config.deviceId : visible[0];
        require(deviceId, "no device is visible to this role");
        if (deviceId) {
          await visit(page, `/devices/${deviceId}`);
          await inspect("device page");
          const actions = page.getByRole("button", { name: "Actions", exact: true });
          if (await actions.count()) {
            await actions.click();
            await settle(page);
            require((await page.getByRole("menuitem").count()) >
              0, "device Actions menu opens empty");
            screenshots.push(await screenshot(page, `${prefix}-device-actions.png`, false));
            await page.keyboard.press("Escape");
          } else {
            screenshots.push(await screenshot(page, `${prefix}-device.png`, true));
          }
          require(permissions.includes("resources.assign") ||
            (await page.getByRole("button", { name: "Assign profile" }).count()) ===
              0, "device page offers Assign profile without resource assignment permission");
        }

        step = "out-of-scope device";
        const outside = fleet.find((id) => !visible.includes(id));
        if (role.scoped) {
          require(outside, "no out-of-scope device exists for the scoped role");
          if (outside) {
            await visit(page, `/devices/${outside}`);
            require(await page
              .getByText("You don't have access to this device", { exact: true })
              .waitFor({ timeout: 10_000 })
              .then(() => true)
              .catch(() => false), "out-of-scope device does not say the role has no access");
            require(!(await mainText(page)).includes(
              "Something went wrong",
            ), 'out-of-scope device shows "Something went wrong"');
            screenshots.push(await screenshot(page, `${prefix}-out-of-scope-device.png`, true));
          }
        }

        step = "assistant access authorization";
        await visit(page, "/settings/assistant-access");
        await settle(page);
        if (unrestrictedPermissions.includes("integrations.manage")) {
          await inspect("assistant access");
          require((await page
            .getByRole("heading", {
              name: "Your tokens",
              exact: true,
            })
            .count()) === 1, "assistant access omits own tokens for an authorized account");
        } else {
          require((await page.locator('[data-review-state="restricted"]').count()) ===
            1, "assistant access does not restrict an account without unrestricted integration management");
          require((await page
            .getByRole("button", {
              name: "Create token",
              exact: true,
            })
            .count()) === 0, "assistant access offers token issuance without permission");
        }
        screenshots.push(await screenshot(page, `${prefix}-assistant-access.png`, true));

        step = "audit";
        await visit(page, "/audit");
        await page.waitForTimeout(2_000);
        await settle(page);
        const auditText = await mainText(page);
        if (paths.includes("/audit")) {
          await inspect("audit log");
        } else {
          require(!auditText.includes(
            "Access not granted",
          ), 'audit log shows "Access not granted"');
          require((await page.getByRole("button", { name: "Export filtered evidence" }).count()) ===
            0, "audit log offers export to a role that can't read it");
        }
        screenshots.push(await screenshot(page, `${prefix}-audit.png`, true));
      } catch (error) {
        // Only the first line: Playwright call logs can echo filled form values.
        findings.push(
          `walkthrough did not complete at step "${step}": ${String(error?.message ?? error).split("\n")[0]}`,
        );
        if (page)
          screenshots.push(await screenshot(page, `${prefix}-failure.png`, true).catch(() => ""));
      }
      results.push({ role: role.name, passed: findings.length === 0, findings, screenshots });
    }
  } finally {
    for (const driver of drivers) await driver.close().catch(() => {});
  }
  return results;
}
