// SPDX-License-Identifier: Apache-2.0

// Owner pass 2 findings #3 and #4 on the route device's Actions tab. The seed
// sends an Undo account lock the device never picks up, so it expires
// unstarted: the restriction must say the accounts are still locked and offer
// "Undo again", and its history row must read expired, not "waiting". Every
// action appears exactly once, and there is no second history tab. Read-only.
export const task = {
  name: "Expired undo and single action history",
  screenId: "owner-pass2-p2-actions-history",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "Actions tab: 'Accounts locked since <time> by <person>. The undo request expired before the device received it, so the account lock remains active.' with 'Undo again'; the Undo account lock row reads 'Expired before the device received it'; each action is listed once and no separate History tab repeats them.",
};

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const { DeviceID } = demo.Routes;
  const main = page.getByRole("main");

  step("open the route device Actions tab");
  await visit(`/devices/${DeviceID}`);
  require((await main.getByRole("tab", { name: "History", exact: true }).count()) ===
    0, "A separate History tab repeats the action list");
  await main.getByRole("tab", { name: "Actions", exact: true }).click();
  const panel = main.locator('[role="tabpanel"]:not([hidden])');
  const rows = panel.locator("[data-device-action-row]");
  await rows.first().waitFor({ timeout: 30_000 });
  await settle();

  step("expired undo leaves the accounts locked, with Undo again");
  const restriction = panel.locator('[data-device-restriction="lock"]');
  const text = (await restriction.innerText()).replace(/\s+/g, " ");
  require(/Accounts locked since \S.* by \S.*\./.test(text) &&
    text.includes(
      "The undo request expired before the device received it, so the account lock remains active.",
    ), `Lock restriction reads ${JSON.stringify(text)}`);
  require((
    await restriction.getByRole("button", { name: "Undo account lock" }).innerText()
  ).trim() === "Undo again", "Lock restriction does not offer 'Undo again'");

  step("expired undo row reads expired");
  const undoRows = rows.filter({ hasText: "Undo account lock" });
  require((await undoRows.count()) >= 1, "No Undo account lock row in history");
  // The row's own summary; its embedded result holds further disclosures.
  const undo = (await undoRows.first().locator(":scope > summary").innerText()).replace(
    /\s+/g,
    " ",
  );
  require(undo.includes("Expired before the device received it") &&
    !undo.includes("Sent, waiting for device"), `Expired undo row reads ${JSON.stringify(undo)}`);

  step("each action listed once");
  const ids = await rows.evaluateAll((elements) =>
    elements.map((element) => element.getAttribute("data-action-id")),
  );
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  require(duplicates.length === 0, `Actions listed more than once: ${JSON.stringify(duplicates)}`);
  require((await main.locator("[data-device-action-row]").count()) ===
    ids.length, "Action rows render outside the Actions tab as well");

  await capture("actions-expired-undo");
}
