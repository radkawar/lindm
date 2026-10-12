// Owner task: the route device's Overview opens with a security posture summary
// whose rows each open their tab, the header carries at most two buttons, users
// and interfaces live under Inventory, and a confirmed account lock reads as plain
// state with one Undo. Read-only: the Undo dialog is opened and dismissed without
// submitting a release.
export const task = {
  name: "Device overview posture",
  screenId: "1d49de1d24977f6f1feda22c",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "On ubuntu-ws-01 the first section of Overview shows encryption, updates, findings, compliance, restrictions and contact, each with a link; no 'may be locked' wording; header has at most two buttons; logged-in users/interfaces moved to Inventory.",
};

// Posture row id, its visible label and the tab its link opens.
const rows = [
  { id: "encryption", label: "Encryption", tab: "Encryption" },
  { id: "updates", label: "Updates", tab: "Inventory" },
  { id: "findings", label: "Findings", tab: "Findings" },
  { id: "compliance", label: "Profile compliance", tab: "Services" },
  { id: "restrictions", label: "Restrictions", tab: "Actions" },
  { id: "contact", label: "Last contact", tab: "Inventory" },
];
const hedge = /may be locked/i;
const interfaceText = /Default-route IP and MAC|Observed network interfaces|Network interfaces/;

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const { DeviceID } = demo.Routes;
  const hostname = demo.Devices.find((device) => device.ID === DeviceID)?.Hostname ?? DeviceID;
  const main = page.getByRole("main");
  const panel = main.locator('[role="tabpanel"]:not([hidden])');
  const openTab = async (name) => {
    await main.getByRole("tab", { name, exact: true }).click();
    await settle();
  };

  step(`open ${hostname}`);
  await visit(`/devices/${DeviceID}`);
  await main.getByRole("heading", { name: hostname, exact: true }).waitFor({ timeout: 30_000 });
  const posture = main.locator("[data-device-posture]");
  await posture.waitFor({ timeout: 30_000 });
  // Row states load independently; wait until none is still checking.
  await page.waitForFunction(
    () => !/Checking|Loading/.test(document.querySelector("[data-device-posture]")?.innerText),
    null,
    { timeout: 30_000 },
  );
  await settle();

  step("posture summary is the first Overview section");
  const overviewTab = main.getByRole("tab", { name: "Overview", exact: true });
  require((await overviewTab.getAttribute("aria-selected")) ===
    "true", "Device page does not open on Overview");
  const firstIsPosture = await panel.evaluate(
    (node) => node.firstElementChild?.hasAttribute("data-device-posture") ?? false,
  );
  require(firstIsPosture, "The first Overview section is not the security posture summary");
  for (const row of rows) {
    const element = posture.locator(`[data-posture-row="${row.id}"]`);
    if (!(await element.isVisible())) {
      require(false, `Posture summary has no ${row.label} row`);
      continue;
    }
    const term = (await element.locator("dt").innerText()).trim();
    require(term === row.label, `Posture row "${row.id}" is labelled ${JSON.stringify(term)}`);
    const state = (await element.locator("dd").first().innerText()).trim();
    require(state !== "", `${row.label} row shows no state`);
  }
  await capture("overview posture");

  step("each posture row link opens its tab");
  for (const row of rows) {
    const element = posture.locator(`[data-posture-row="${row.id}"]`);
    const link = element.getByRole("button", { name: `Open ${row.tab}`, exact: true });
    if (!(await link.isVisible())) {
      require(false, `${row.label} row has no link to its tab`);
      continue;
    }
    await link.click();
    await settle();
    const selected = await main
      .getByRole("tab", { name: row.tab, exact: true })
      .getAttribute("aria-selected");
    require(selected === "true", `${row.label} row link did not open the ${row.tab} tab`);
    await openTab("Overview");
  }

  step("header has at most two buttons");
  const header = await main.locator('[data-review-page="device"]').evaluate((root) => {
    const tablist = root.querySelector('[role="tablist"]');
    const visible = (node) => node.getClientRects().length > 0;
    return [...root.querySelectorAll('button, [role="button"]')]
      .filter(
        (node) =>
          visible(node) &&
          tablist &&
          tablist.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_PRECEDING,
      )
      .map((node) => (node.getAttribute("aria-label") || node.textContent).trim());
  });
  require(header.length <=
    2, `Device header has ${header.length} buttons: ${JSON.stringify(header)}`);
  for (const removed of ["Refresh page", "Preview settings"])
    require(!header.includes(removed), `Device header still shows "${removed}"`);

  step("lock restriction is plain state with one Undo");
  const lock = posture.locator('[data-device-restriction="lock"]');
  if (await lock.isVisible()) {
    const text = (await lock.innerText()).trim();
    if ((await lock.getAttribute("data-confirmed")) === "true") {
      require(/Accounts locked since \S.* by \S.*\./.test(
        text,
      ), `Confirmed lock does not name since/by: ${JSON.stringify(text.split("\n")[0])}`);
      const undo = lock.getByRole("button", { name: /^Undo/ });
      require((await undo.count()) ===
        1, `Lock restriction has ${await undo.count()} Undo actions, expected one`);
      require(await main
        .getByText("Accounts locked", { exact: true })
        .isVisible(), "Confirmed lock has no compact header status");
      if ((await undo.count()) === 1) {
        // Open the release flow to prove Undo is wired, then dismiss it unsent.
        await undo.click();
        const dialog = page.getByRole("dialog");
        await dialog.waitFor({ timeout: 30_000 });
        require(await dialog
          .getByRole("heading", { name: "Undo account lock" })
          .isVisible(), "Undo did not open the account-lock release form");
        await page.keyboard.press("Escape");
        await dialog.waitFor({ state: "hidden", timeout: 30_000 });
      }
    } else {
      require(!/^Accounts locked since/.test(text), "Unconfirmed lock is stated as confirmed");
    }
  }

  step("no hedged lock wording and no lock banner above other tabs");
  require(!hedge.test(await main.innerText()), "Overview shows 'may be locked' wording");
  for (const name of ["Inventory", "Actions", "Findings", "History"]) {
    await openTab(name);
    const text = await main.innerText();
    require(!hedge.test(text), `${name} tab shows 'may be locked' wording`);
    if (name !== "Actions")
      require(!/Accounts locked since/.test(
        text,
      ), `The lock statement is repeated above the ${name} tab`);
  }

  step("logged-in users and interfaces live under Inventory");
  await openTab("Inventory");
  await panel.getByText("Logged-in users").first().waitFor({ timeout: 30_000 });
  const inventory = await panel.innerText();
  require(inventory.includes("Logged-in users"), "Inventory does not show logged-in users");
  require(interfaceText.test(inventory), "Inventory does not show network interfaces");
  await capture("inventory access and reporting");
  await openTab("Overview");
  const overview = await panel.innerText();
  require(!overview.includes("Logged-in users"), "Overview still shows logged-in users");
  require(!interfaceText.test(overview), "Overview still shows network interfaces");
  require(!overview.includes(
    "Access and reporting",
  ), "Overview still leads with Access and reporting");
}
