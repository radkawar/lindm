// Owner pass 2, ui-pass-2 item 29: a device whose settings came from a rollout
// read "None. The profile was removed." with the raw reason
// target_preview_activation. Read-only: runs before checks that reassign the
// route device.
export const task = {
  name: "Rollout-applied settings name their profiles",
  screenId: "owner-pass2-rollout-head",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "The route device's Services tab names the profile versions its rollout applied ('From rollouts: …') and never shows a removal or the raw target_preview_activation reason for them.",
};

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const { DeviceID } = demo.Routes;
  const panel = page.getByRole("main").locator('[role="tabpanel"]:not([hidden])');
  step("open services");
  await visit(`/devices/${DeviceID}?tab=resources`);
  const heading = panel.getByRole("heading", { name: "Assigned profile" });
  await heading.waitFor({ timeout: 30_000 });
  await settle();
  const card = heading.locator("xpath=..");
  const text = (await card.innerText()).trim();
  require(!text.includes(
    "target_preview_activation",
  ), "The raw target_preview_activation reason is shown");
  require(!text.includes(
    "The profile was removed",
  ), `Rollout-applied settings read as a removal: ${JSON.stringify(text.slice(0, 200))}`);
  require(/From rollouts: .+, version \d+/.test(text) ||
    /, version \d+/.test(
      text,
    ), `The assigned profile is not named: ${JSON.stringify(text.slice(0, 200))}`);
  await capture("rollout-head");
}
