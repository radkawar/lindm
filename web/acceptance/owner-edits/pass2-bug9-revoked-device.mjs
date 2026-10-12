// Owner pass 2, bug 9: a revoked device is read-only. Its page carries a
// "Revoked on <date> by <person>" banner, offers no Actions menu or Assign
// profile, and every mutating tab's controls are disabled. Encryption keeps
// only recovery re-enrollment (plus reveal). Read-only: nothing is clicked
// except tabs and the encryption menu, which is closed again.
export const task = {
  name: "Revoked device is read-only",
  screenId: "owner-pass2-bug9-revoked-device",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "On the revoked demo device the page shows 'Revoked on <date> by <person>', no Actions menu or Assign profile, and no enabled control on Services, Local admin, Actions, Remote assistance or Findings; Encryption offers only recovery re-enrollment.",
};

const mutatingTabs = ["Services", "Local admin", "Actions", "Remote assistance", "Findings"];

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const revoked = demo.Devices.find((device) => device.State === "revoked");
  require(revoked, "Demo fleet has no revoked device");
  const main = page.getByRole("main");

  step(`open revoked ${revoked.Hostname}`);
  await visit(`/devices/${revoked.ID}`);
  const banner = main.locator("[data-review-revoked]");
  await banner.waitFor({ timeout: 30_000 });
  await settle();

  step("banner names when and by whom");
  const title = (await banner.locator('[data-slot="alert-title"]').innerText()).trim();
  require(/^Revoked on \S.* by \S/.test(title), `Revoked banner reads ${JSON.stringify(title)}`);
  require(!/unrecorded/.test(title), `Seeded revocation lost its actor: ${JSON.stringify(title)}`);
  await capture("revoked-device-banner");

  step("no page actions");
  for (const name of ["Actions", "Assign profile"]) {
    require((await main.getByRole("button", { name, exact: true }).count()) ===
      0, `Revoked device still offers '${name}'`);
  }

  step("overview metadata is not editable");
  const overview = main.locator('[role="tabpanel"]:not([hidden])');
  require((await overview.locator("[data-read-only] button:enabled").count()) ===
    0, "Overview metadata still has an enabled control");

  for (const tab of mutatingTabs) {
    step(`${tab} tab has no enabled control`);
    await main.getByRole("tab", { name: tab, exact: true }).click();
    const panel = main.locator('[role="tabpanel"]:not([hidden])');
    await settle();
    const enabled = await panel
      .locator("button:enabled, input:enabled, textarea:enabled, select:enabled")
      .evaluateAll((elements) =>
        elements.map(
          (element) =>
            element.getAttribute("aria-label") || element.textContent?.trim() || element.tagName,
        ),
      );
    require(enabled.length === 0, `${tab} tab has enabled controls: ${JSON.stringify(enabled)}`);
  }
  await main.getByRole("tab", { name: "Actions", exact: true }).click();
  await settle();
  await capture("revoked-device-actions-tab");

  step("encryption offers only recovery re-enrollment");
  await main.getByRole("tab", { name: "Encryption", exact: true }).click();
  const encryption = main.locator('[role="tabpanel"]:not([hidden])');
  await settle();
  for (const name of ["Rotate escrow recovery key", "Bind TPM 2.0 unlock"]) {
    require((await encryption.getByRole("button", { name, exact: true }).count()) ===
      0, `Encryption still offers '${name}'`);
  }
  const more = encryption.getByRole("button", { name: "Other encryption actions" });
  if ((await more.count()) === 1) {
    await more.click();
    const menu = page.getByRole("menu");
    await menu.waitFor({ timeout: 10_000 });
    const items = (await menu.getByRole("menuitem").allInnerTexts()).map((text) => text.trim());
    require(items.every(
      (item) => item === "Recover device enrollment",
    ), `Encryption menu offers ${JSON.stringify(items)}`);
    await page.keyboard.press("Escape");
    await menu.waitFor({ state: "hidden", timeout: 10_000 });
  }
}
