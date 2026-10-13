// Owner pass 2, item 1: profile assignments on the live demo device never left
// "Pending / No changes sent yet" because the demo device never asked for
// resource work. State-changing: assigns the organization's "Contractors" profile
// to the route device, waits until every item has a result and every removed
// item completed, then assigns "Company baseline" (lab/demo/org.json) the same way.
// The picker searches every profile by name on the server: with more than 100
// profiles a name beyond the first page is found by typing, without paging.
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

  async function assign(profileName, { searchBeyondFirstPage = false } = {}) {
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
    // The profile picker floats its choices; choosing a profile assigns its latest version.
    const picker = dialog.getByRole("button", { name: /^Profile / });
    await picker.waitFor({ timeout: 30_000 });
    await picker.click();
    const searchBox = page.getByRole("combobox", { name: "Search profile", exact: true });
    if (searchBeyondFirstPage) {
      step("search finds a profile beyond the first 100");
      const more = page.getByRole("button", { name: "More profiles", exact: true });
      await more.waitFor({ timeout: 30_000 });
      await more.click();
      await page
        .getByRole("button", { name: "First profiles", exact: true })
        .waitFor({ timeout: 30_000 });
      const listed = page
        .getByRole("option")
        .filter({ hasText: /Latest version/ })
        .first();
      await listed.waitFor({ timeout: 30_000 });
      const beyond = (await listed.innerText()).split("\n")[0].trim();
      require(beyond !== "", "the second page of profiles named no profile");
      // Typing restarts at the first page of matches; no paging is needed.
      await searchBox.fill(beyond.toUpperCase());
      // Wait for the server's answer, not the loaded page's local matches.
      await page
        .getByRole("status")
        .filter({ hasText: "Loading profiles" })
        .waitFor({ state: "hidden", timeout: 30_000 });
      const found = page
        .getByRole("option")
        .filter({ has: page.getByText(beyond, { exact: true }) });
      await found.first().waitFor({ timeout: 30_000 });
      require(!(await page
        .getByRole("button", { name: "First profiles", exact: true })
        .isVisible()), "searching kept the previous page instead of searching every profile");
      await capture("profile-search-beyond-first-page");
    }
    await searchBox.fill(profileName);
    await page
      .getByRole("option")
      .filter({ has: page.getByText(profileName, { exact: true }) })
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

  await assign("Contractors", { searchBeyondFirstPage: true });
  await awaitProgress("Contractors", true);
  await assign("Company baseline");
  await awaitProgress("Company baseline", false);
}
