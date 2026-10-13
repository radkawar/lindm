// Owner pass 2 (safety): while a remote-assistance request waits, the viewer
// describes what the user sees (the agent's consent notification and reason)
// instead of an empty black screen; once the admin stops a request nobody
// accepted, the record reads "No one accepted". State-changing: requests one
// view-only session on the demo device and stops it before anyone accepts.
export const task = {
  name: "Assistance waiting panel and unaccepted record",
  screenId: "owner-pass2-safety-assistance",
  route: "/devices/$deviceId/assistance/$sessionId",
  priority: "medium",
  acceptance:
    "Waiting viewer shows 'What the user sees' with the consent notification text and reason, no black screen box; a stopped never-started session shows 'Device user during the session: No one accepted'.",
};

const reasonText = "Owner pass 2 check: show the waiting panel";

async function fact(main, label) {
  const term = main.locator("dt").filter({ hasText: new RegExp(`^${label}$`) });
  if ((await term.count()) !== 1) return null;
  return (await term.locator("xpath=following-sibling::dd[1]").innerText()).trim();
}

export async function check({ page, demo, visit, require, capture, step }) {
  const { DeviceID } = demo.Routes;
  const main = page.getByRole("main");

  step("request view-only assistance");
  await visit(`/devices/${DeviceID}`);
  await main.getByRole("tab", { name: "Remote assistance", exact: true }).click();
  await main
    .getByLabel("Reason (the user sees this; the audit log records it)", { exact: true })
    .fill(reasonText);
  await main.getByRole("button", { name: "Request remote assistance" }).click();
  await page.waitForURL(/\/assistance\/[0-9a-f-]{36}$/, { timeout: 30_000 });

  step("waiting panel describes the user's side");
  const panel = main.locator("[data-assistance-user-side]");
  await panel.waitFor({ timeout: 30_000 });
  const text = await panel.innerText();
  for (const expected of [
    "What the user sees",
    "Remote assistance request",
    "asks to view your screen.",
    `Reason: ${reasonText}`,
    "Allow",
    "Decline",
  ])
    require(text.includes(expected), `Waiting panel lacks ${JSON.stringify(expected)}`);
  require(!(await main
    .getByLabel("Remote screen", { exact: true })
    .isVisible()), "Black shared-screen box is still shown while waiting");
  await capture("pass2-safety-assistance-waiting");

  step("stop before anyone accepts");
  await main.getByRole("button", { name: "Stop session" }).click();
  await main.getByText("Why this session ended", { exact: true }).waitFor({ timeout: 30_000 });
  const user = await fact(main, "Device user during the session");
  require(user !== null &&
    user.startsWith(
      "No one accepted",
    ), `Unstarted record should read 'No one accepted' (got ${JSON.stringify(user)})`);
  await capture("pass2-safety-assistance-ended");
}
