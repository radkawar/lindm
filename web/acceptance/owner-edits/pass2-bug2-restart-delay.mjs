// Owner pass 2, bug 2: a restart delay of "abc" surfaced a raw protobuf encoder
// error, and -5 / 99999999 passed review with no range shown. The field states
// its proto range, names each invalid value beside the field, and review stays
// blocked; no protobuf or encoder text appears anywhere. Never reviews or sends.
export const task = {
  name: "Restart delay validation",
  screenId: "owner-pass2-bug2-restart-delay",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "The restart delay field shows '0 to 3600 seconds'; typing abc, -5 or 99999999 shows 'Enter a whole number of seconds from 0 to 3600.' beside the field, Review action does not open a review, and no protobuf/encoder text (cannot encode, uint32, NaN, lindm.agent) appears on the page.",
};

const RAW = /protobuf|cannot encode|lindm\.agent|RestartAction|delay_seconds|uint32|\bNaN\b/i;
const FIELD_ERROR = "Enter a whole number of seconds from 0 to 3600.";
const REVIEWED = /^(Checking|Ready to send|Not ready to send|Not checked)$/;

export async function check({ page, demo, visit, require, capture, step }) {
  const deviceId = demo.Routes.DeviceID;
  if (!deviceId) throw new Error("demo route device is missing");
  const main = page.getByRole("main");

  step("open restart form");
  await visit(`/devices/${encodeURIComponent(deviceId)}`);
  await main.getByRole("button", { name: "Actions", exact: true }).click();
  await page.getByRole("menuitem", { name: "Restart device", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Restart device", exact: true });
  await dialog.waitFor({ timeout: 30_000 });
  const delay = dialog.getByRole("textbox", { name: "Delay in seconds (optional)", exact: true });
  await delay.waitFor({ timeout: 30_000 });
  require(await dialog
    .getByText("0 to 3600 seconds. Leave empty to restart now.", { exact: true })
    .isVisible(), "the delay field does not state its 0 to 3600 seconds range");
  await dialog
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("Owner acceptance check: restart delay validation, never sent");

  for (const value of ["abc", "-5", "99999999"]) {
    step(`delay ${value}`);
    await delay.fill(value);
    const error = dialog.getByText(FIELD_ERROR, { exact: true });
    require(await error.isVisible(), `delay ${value} shows no field error with the range`);
    require((await delay.getAttribute("aria-invalid")) ===
      "true", `delay ${value} does not mark the field invalid`);
    await dialog.getByRole("button", { name: "Review action", exact: true }).click();
    require((await dialog.getByText(REVIEWED).count()) === 0, `delay ${value} opened a review`);
    require(!(await dialog
      .getByRole("button", { name: "Send action", exact: true })
      .count()), `delay ${value} offered Send action`);
    require(await dialog
      .getByText(/^Missing before review: .*a delay from 0 to 3600 seconds.*\.$/)
      .first()
      .isVisible(), `delay ${value} does not name the delay as missing before review`);
    const text = await page.evaluate(() => document.body.innerText);
    require(!RAW.test(text), `delay ${value} put protobuf/encoder text on the page`);
    if (value === "abc") await capture("delay-abc-field-error");
  }

  step("valid delay clears the error");
  await delay.fill("30");
  require(!(await dialog
    .getByText(FIELD_ERROR, { exact: true })
    .count()), "a valid delay still shows the field error");
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden", timeout: 10_000 });
}
