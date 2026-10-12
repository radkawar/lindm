// Owner task: the ended remote-assistance record states duration and the
// support reason, with one expandable section. Read-only.
export const task = {
  name: "Assistance session record",
  screenId: "8c33351b7866ae7205b13d0a",
  route: "/devices/$deviceId/assistance/$sessionId",
  priority: "low",
  acceptance: "Record shows duration and the reason text; only one expandable section remains.",
};

async function fact(main, label) {
  const term = main.locator("dt").filter({ hasText: new RegExp(`^${label}$`) });
  if ((await term.count()) !== 1) return null;
  return (await term.locator("xpath=following-sibling::dd[1]").innerText()).trim();
}

export async function check({ page, demo, visit, require, capture, step }) {
  const { DeviceID, AssistanceSessionID } = demo.Routes;
  const main = page.getByRole("main");
  step("open ended session record");
  await visit(`/devices/${DeviceID}/assistance/${AssistanceSessionID}`);
  await main
    .getByText("Session record. Sharing and control have ended.", { exact: true })
    .waitFor({ timeout: 30_000 });

  step("duration and reason");
  const reason = await fact(main, "Reason shown to the user");
  require(Boolean(reason), "Record does not show the reason shown to the user");
  const duration = await fact(main, "Duration");
  // The seeded record is a completed session, so it has a measured duration.
  require(Boolean(duration) &&
    /^\d+ (sec|min|h)\b/.test(
      duration,
    ), `Record does not show a session duration (got ${JSON.stringify(duration)})`);

  step("single expandable section");
  const details = main.locator("details");
  const disclosures = main.locator("button[aria-expanded]");
  const expandable = (await details.count()) + (await disclosures.count());
  require(expandable === 1, `Expected one expandable section on the record, found ${expandable}`);
  require((await main.locator("details > summary").first().innerText()).trim() ===
    "Session record", "The remaining expandable section is not 'Session record'");
  const record = main.locator("details").first();
  await record.locator("summary").click();
  await record.getByText("Session ID", { exact: false }).waitFor({ timeout: 10_000 });
  await capture("assistance-session-record");
  await record.locator("summary").click();
}
