// Owner pass 2, bug 6: the one-time code dialog defaulted to the first registry
// OS (Ubuntu 22.04), then showed an empty disabled command and server-config
// jargon. The OS now defaults to the most common OS among seeded devices; with
// the demo's unpublished agent repository it says in one sentence what blocks
// the command and links to Settings › Agent repository, with no empty command
// field, no disabled copy button and no configuration keys.
//
// State: creates one unused 5-minute one-time code (after the read-only
// Enrollment checks, which count codes). The secret stays in the masked field
// and is forgotten with "Done, forget secret".
export const task = {
  name: "One-time code install command",
  screenId: "owner-pass2-bug6-install-command",
  route: "/enrollment",
  priority: "high",
  acceptance:
    "The OS chooser preselects the seeded fleet's most common OS; with no agent repository it shows one sentence linking to Settings › Agent repository, no command field or copy button, and never 'releaseRepository'.",
};

const timeout = 30_000;

// Labels of the seeded fleet's most common OS (ties all accepted). The demo's
// OS is the registry release name, which is also the chooser label.
function mostCommon(devices) {
  const counts = new Map();
  for (const device of devices) {
    if (device.OS) counts.set(device.OS, (counts.get(device.OS) ?? 0) + 1);
  }
  const top = Math.max(0, ...counts.values());
  return [...counts].filter(([, count]) => count === top).map(([os]) => os);
}

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  const expected = mostCommon(demo?.Devices ?? []);
  if (expected.length === 0) throw new Error("The demo seed reports no device OS");

  step("create one-time code");
  await visit("/enrollment");
  const open = main.getByRole("button", { name: "Create one-time code", exact: true });
  await open.waitFor({ timeout });
  await open.click();
  const creation = page.getByRole("dialog");
  await creation
    .getByLabel("Reason", { exact: true })
    .fill("Owner pass 2: check the install command's default OS");
  await creation.getByRole("button", { name: "Create one-time code", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "One-time enrollment code", exact: true });
  await dialog.waitFor({ timeout });

  try {
    step("default operating system");
    const chooser = dialog.getByLabel("Operating system", { exact: true });
    await chooser.waitFor({ timeout });
    const settings = dialog.getByRole("link", { name: /^Settings › Agent repository/ });
    const command = dialog.getByLabel("Install and enroll command", { exact: true });
    // Wait for the instructions to settle into a command or its blocking reason.
    await settings.or(command).first().waitFor({ timeout });
    await settle();
    const chosen = (await chooser.innerText()).trim();
    require(expected.includes(
      chosen,
    ), `OS defaults to "${chosen}", not the fleet's most common (${expected.join(" or ")})`);

    step("unavailable command is actionable");
    const text = await dialog.innerText();
    require(!text.includes("releaseRepository"), "Dialog shows server configuration keys");
    require(!text.includes(
      "Install command unavailable",
    ), "Dialog still shows a bare 'Install command unavailable'");
    require((await settings.count()) === 1, "No link to Settings › Agent repository");
    if ((await settings.count()) === 1) {
      require((await settings.getAttribute("href")) ===
        "/settings#agent-repository", "Settings link does not target the Agent repository section");
      const sentence = (await settings.locator("xpath=..").innerText()).trim();
      require(sentence.includes(
        chosen,
      ), `Blocking sentence does not name ${chosen}: "${sentence}"`);
      require(sentence.split(/[.;]\s/).length <=
        2, `Blocking reason is more than one sentence: "${sentence}"`);
    }
    require((await command.count()) === 0, "An empty install command field is still shown");
    require((await dialog
      .getByRole("button", { name: "Copy install command", exact: true })
      .count()) === 0, "A disabled 'Copy install command' is still shown");
    await capture("install-command-unavailable");
  } finally {
    await dialog.getByRole("button", { name: "Done, forget secret", exact: true }).click();
    await dialog.waitFor({ state: "hidden", timeout });
  }
}
