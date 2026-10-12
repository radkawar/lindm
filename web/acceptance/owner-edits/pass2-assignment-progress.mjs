// Owner pass 2, item 1: profile assignments on the live demo device never left
// "Pending / No changes sent yet" because the demo device never asked for
// resource work. State-changing: assigns "Server hardening" to the route device,
// waits until every item has a result and every removed item completed, then
// restores "Workstation baseline" the same way so later checks see the seed.
export const task = {
  name: "Assignment progress on the live demo device",
  screenId: "owner-pass2-assignment-progress",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "After assigning a profile, every item on the present demo device leaves Pending with a result within three check-ins; while items wait, the Services tab says the device has not picked them up and when it last checked in.",
};

const waitingSentence =
  /^Waiting for the device to pick up \d+ items?\. It (last checked in .+|has not checked in yet)\.$/;

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const { DeviceID } = demo.Routes;
  const main = page.getByRole("main");
  const panel = main.locator('[role="tabpanel"]:not([hidden])');
  const waiting = panel.getByTestId("resources-waiting-for-device");

  async function openServices() {
    await visit(`/devices/${DeviceID}?tab=resources`);
    await panel.getByRole("heading", { name: "Assigned profile" }).waitFor({ timeout: 30_000 });
    await settle();
  }

  async function assign(profileName) {
    step(`assign ${profileName}`);
    await visit(`/devices/${DeviceID}`);
    const direct = main.getByRole("button", { name: "Assign profile", exact: true }).first();
    if (await direct.isVisible()) {
      await direct.click();
    } else {
      await main.getByRole("button", { name: "Actions", exact: true }).first().click();
      await page.getByRole("menuitem", { name: "Assign profile", exact: true }).click();
    }
    const dialog = page.getByRole("dialog");
    const picker = dialog.getByLabel("Profile version", { exact: true });
    await picker.waitFor({ timeout: 30_000 });
    await picker.click();
    await page
      .getByRole("option")
      .filter({ hasText: new RegExp(`^${profileName}, version \\d+$`) })
      .first()
      .click();
    await dialog
      .getByLabel("Reason (required)", { exact: true })
      .fill("Owner pass 2 assignment progress check");
    await dialog.getByRole("button", { name: "Save assignment", exact: true }).click();
    await dialog.getByText("Assignment saved.", { exact: false }).waitFor({ timeout: 30_000 });
    await page.keyboard.press("Escape");
  }

  async function awaitProgress(profileName, shot) {
    step(`${profileName} items progress within three check-ins`);
    await openServices();
    if (await waiting.isVisible()) {
      const text = (await waiting.innerText()).trim();
      require(waitingSentence.test(
        text,
      ), `Waiting sentence is not plain (got ${JSON.stringify(text)})`);
      if (shot) await capture("assignment-waiting");
    }
    // The demo device checks in every 30 seconds.
    const deadline = Date.now() + 100_000;
    let settled = false;
    while (!settled && Date.now() < deadline) {
      const text = await panel.innerText();
      settled =
        text.includes(profileName) &&
        !(await main.innerText()).includes("Removing profile items") &&
        !(await waiting.isVisible()) &&
        !text.includes("No changes sent yet") &&
        !/\bNot yet\b/.test(text);
      if (!settled) {
        await page.waitForTimeout(3_000);
        await openServices();
      }
    }
    require(settled, `${profileName} items were still waiting for the device after three check-ins`);
    if (shot) await capture("assignment-progressed");
  }

  await assign("Server hardening");
  await awaitProgress("Server hardening", true);
  await assign("Workstation baseline");
  await awaitProgress("Workstation baseline", false);
}
