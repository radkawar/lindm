// SPDX-License-Identifier: Apache-2.0

// Owner report 2026-10-12 #4: a headless RHEL server with remote assistance turned
// off offered a request, and the refused request then read "Ended" with facts that
// never happened. The console offers the request only where the server knows of no
// blocker, names the reason otherwise, and shows a refused request as "Couldn't
// start". Read-only: no request is sent.
export const task = {
  name: "Assistance gate before the request",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "The headless assistance-off server shows no request control, one reason line and no form; a device-refused request reads Couldn't start with its remedy, never Ended, and lists no never-happened facts or empty sections; a ready device still offers the request.",
};

const requestControl = /request remote assistance/i;
const neverHappened = [
  "Device user during the session",
  "Control permission during the session",
  "Duration",
];

async function openAssistanceTab(page, main, visit, settle, deviceId) {
  await visit(`/devices/${deviceId}`);
  await main.getByRole("tab", { name: "Remote assistance", exact: true }).click();
  await settle();
  // Readiness loads after the tab opens.
  await page.waitForFunction(
    () =>
      !document
        .querySelector('[role="tabpanel"]:not([hidden])')
        ?.innerText.includes("Checking assistance availability"),
    null,
    { timeout: 30_000 },
  );
}

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const { DeviceID, AssistanceOffDeviceID, RefusedAssistanceDeviceID, RefusedAssistanceSessionID } =
    demo.Routes;
  const main = page.getByRole("main");
  require(Boolean(
    AssistanceOffDeviceID && RefusedAssistanceSessionID,
  ), "Seed lacks the assistance-off device or the refused request");

  step("assistance-off headless server");
  await openAssistanceTab(page, main, visit, settle, AssistanceOffDeviceID);
  const gate = main.locator("[data-assistance-gate]");
  await gate.first().waitFor({ timeout: 30_000 });
  require((await gate.count()) === 1, `Expected one reason line, found ${await gate.count()}`);
  const reason = (await gate.first().innerText()).trim();
  require(reason ===
    "This device has no desktop session to share. Its configuration also disables remote assistance.", `Reason line does not name the missing desktop and disabled assistance: ${reason}`);
  for (const role of ["button", "menuitem", "link"])
    require((await main.getByRole(role, { name: requestControl }).count()) ===
      0, `A ${role} still offers to request remote assistance on the assistance-off device`);
  require((await main.locator('[role="tabpanel"]:not([hidden]) form').count()) ===
    0, "The request form is still rendered on the assistance-off device");

  step("device-refused request record");
  await visit(`/devices/${RefusedAssistanceDeviceID}/assistance/${RefusedAssistanceSessionID}`);
  await main
    .getByRole("heading", { name: "Why it couldn't start", exact: true })
    .waitFor({ timeout: 30_000 });
  const situation = main.locator('section[aria-label="Session situation"]');
  require((await situation.getByText("Couldn't start", { exact: true }).count()) ===
    1, "Refused request is not labelled Couldn't start");
  require((await situation.getByText(/^Ended$/).count()) === 0 &&
    (await main.getByText("Why this session ended", { exact: true }).count()) ===
      0, "Refused request still reads as an ended session");
  for (const label of neverHappened)
    require((await situation
      .locator("dt")
      .filter({ hasText: new RegExp(`^${label}$`) })
      .count()) === 0, `Refused request lists the never-happened fact "${label}"`);
  require((await situation.getByText(/Not reported|Was not granted|Never started/).count()) ===
    0, "Refused request shows a placeholder for something that never happened");
  for (const disclosure of await situation.locator("details").all()) {
    await disclosure.locator("summary").click();
    const body = (await disclosure.innerText())
      .replace((await disclosure.locator("summary").innerText()).trim(), "")
      .trim();
    require(body.length > 0, "Refused request has an empty disclosure section");
    await disclosure.locator("summary").click();
  }
  await capture("refused-request-record");

  step("ready device still offers the request");
  await openAssistanceTab(page, main, visit, settle, DeviceID);
  require((await main.getByRole("button", { name: requestControl }).count()) ===
    1, "The ready route device no longer offers a remote assistance request");
}
