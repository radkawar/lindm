// Owner task: /enrollment leads with devices waiting for approval, lists only
// active one-time codes by default and keeps history and offline enrollment one
// step away. Read-only: expands and collapses the history, opens and closes the
// offline dialog without creating anything.
export const task = {
  name: "Enrollment active codes",
  screenId: "fa54088f6950506c78ab2da6",
  route: "/enrollment",
  priority: "normal",
  acceptance:
    "On the seed: one active code card is visible by default; a 'Show used and expired (8)' toggle exists; a '1 device waiting for approval' section appears above the code list.",
};

const SHOW = /^Show used and expired \((\d+)\)$/;
const HIDE = /^Hide used and expired \((\d+)\)$/;
const WAITING = /^(\d+) devices? waiting for approval$/;

async function cardStates(cards) {
  const states = [];
  for (const card of await cards.all()) {
    const text = await card.innerText();
    states.push({
      active: (await card.getByText("Active", { exact: true }).count()) === 1,
      unused: /Uses\s+0 \/ \d+/.test(text),
    });
  }
  return states;
}

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  step("open one-time codes");
  await visit("/enrollment");
  const title = main.getByRole("heading", { name: "Enroll a device", exact: true });
  await title.waitFor({ timeout: 30_000 });
  const tab = main.getByRole("tab", { name: "One-time codes", exact: true });
  await tab.click();
  require((await tab.getAttribute("aria-selected")) === "true", "One-time codes tab not selected");
  const panel = main.getByRole("tabpanel", { name: "One-time codes", exact: true });
  const grants = panel.getByRole("region", { name: "One-time enrollment grants", exact: true });
  const history = grants.getByRole("region", { name: "Used and expired codes", exact: true });
  const toggle = grants.getByRole("button", { name: SHOW });
  // The seed's used codes guarantee history, so the toggle marks a loaded list.
  await toggle.waitFor({ timeout: 30_000 });
  await settle();

  step("active codes only by default");
  const defaults = await cardStates(grants.getByRole("article"));
  const stray = defaults.filter((card) => !card.active || !card.unused).length;
  require(stray === 0, `Default list shows ${stray} code(s) that are not active and unused`);
  if (defaults.length === 0) {
    // The seed code lives 15 minutes; an expired one leaves the explicit empty state.
    require((await grants.getByText("No active one-time codes", { exact: true }).count()) ===
      1, "No active code cards and no empty state");
  }
  require((await history.count()) === 0, "Used and expired codes are visible by default");
  const toggleText = (await toggle.innerText()).trim();
  const historyCount = Number(SHOW.exec(toggleText)?.[1] ?? Number.NaN);
  require(historyCount > 0, `History toggle reads "${toggleText}"`);
  require((await toggle.getAttribute("aria-expanded")) ===
    "false", "History toggle is not collapsed by default");

  step("waiting devices above code list");
  const waiting = main.getByRole("heading", { name: WAITING });
  require((await waiting.count()) === 1, "No 'N devices waiting for approval' heading");
  if ((await waiting.count()) === 1) {
    const headingText = (await waiting.innerText()).trim();
    const shown = Number(WAITING.exec(headingText)?.[1] ?? Number.NaN);
    const seeded = (demo?.Devices ?? []).filter((device) => device.State === "pending").length;
    require(shown ===
      seeded, `Heading "${headingText}" does not match ${seeded} pending device(s) in the seed`);
    const section = main.getByRole("region", { name: headingText, exact: true });
    const rows = section.getByRole("article").filter({ hasText: "Awaiting approval" });
    require((await rows.count()) ===
      shown, `Heading says ${shown}, section lists ${await rows.count()} waiting device(s)`);
    const headingBox = await waiting.boundingBox();
    const listBox = await grants.boundingBox();
    require(headingBox !== null &&
      listBox !== null &&
      headingBox.y < listBox.y, "Waiting-for-approval heading is not above the code list");
  }
  require((await main.locator("summary").filter({ hasText: "waiting for approval" }).count()) ===
    0, "Devices waiting for approval is still a collapsed accordion");
  await capture("enrollment-active-codes");

  step("reveal used and expired");
  await toggle.click();
  const hide = grants.getByRole("button", { name: HIDE });
  await hide.waitFor({ timeout: 30_000 });
  await history.waitFor({ timeout: 30_000 });
  await history.getByRole("article").first().waitFor({ timeout: 30_000 });
  await settle();
  require((await hide.getAttribute("aria-expanded")) === "true", "Expanded toggle not marked");
  const revealed = await cardStates(history.getByRole("article"));
  require(revealed.every((card) => !card.active), "History lists a code that is still active");
  if ((await history.getByRole("button", { name: "Next page", exact: true }).count()) === 0) {
    require(revealed.length ===
      historyCount, `Toggle counts ${historyCount} used/expired codes; history shows ${revealed.length}`);
  }
  const activeCount = await grants
    .getByRole("article")
    .filter({ has: page.getByText("Active", { exact: true }) })
    .count();
  require(activeCount ===
    defaults.length, `Default list showed ${defaults.length} code(s), ${activeCount} active code(s) exist`);
  await capture("enrollment-used-and-expired");

  step("collapse used and expired");
  await hide.click();
  await toggle.waitFor({ timeout: 30_000 });
  await history.waitFor({ state: "hidden", timeout: 30_000 });
  require((await grants.getByRole("article").count()) ===
    defaults.length, "Collapsing did not return to active codes only");

  step("offline enrollment link");
  require((await main.locator("summary").filter({ hasText: "offline" }).count()) ===
    0, "Offline enrollment is still an accordion");
  const offline = main.getByRole("button", {
    name: "Enroll devices at offline sites",
    exact: true,
  });
  require((await offline.count()) === 1, "No 'Enroll devices at offline sites' link");
  if ((await offline.count()) === 1) {
    const background = await offline.evaluate(
      (element) => getComputedStyle(element).backgroundColor,
    );
    require(background === "rgba(0, 0, 0, 0)" ||
      background ===
        "transparent", `Offline enrollment control is styled as a primary button (${background})`);
    await offline.click();
    const dialog = page.getByRole("dialog", {
      name: "Enroll devices at offline sites",
      exact: true,
    });
    await dialog.waitFor({ timeout: 30_000 });
    require((await dialog
      .getByText("1. Create an offline authorization", { exact: true })
      .count()) === 1, "Offline dialog does not offer the offline authorization step");
    await capture("enrollment-offline-dialog");
    await page.keyboard.press("Escape");
    await dialog.waitFor({ state: "hidden", timeout: 30_000 });
  }
}
