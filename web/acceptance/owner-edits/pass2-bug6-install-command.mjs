// SPDX-License-Identifier: Apache-2.0

// The one-time code chooser defaults to the fleet's most common OS.
// The stock fixture now provides signed agent packages. Check its eligible
// command, not an invented missing-publication state. review-enrollment owns
// the independent missing-artifact fixture and its absent command assertion.
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
    "On the stock Ready fixture, the OS chooser preselects the fleet's most common OS; an eligible signed source provides a nonempty command and enabled copy action. Missing-source absence remains covered by the independent review-enrollment missing-artifact fixture.",
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
  const instructions = await page.evaluate(async () => {
    const session = await (await fetch("/auth/session", { cache: "no-store" })).json();
    const response = await fetch("/lindm.admin.v1.AdminService/GetEnrollmentInstructions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrfToken },
      body: "{}",
    });
    if (!response.ok) throw new Error(`GetEnrollmentInstructions_${response.status}`);
    return response.json();
  });
  require(instructions.readiness?.ready === true, "Stock repository is not Ready");

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

    step("ready source provides an eligible command");
    const text = await dialog.innerText();
    require(!text.includes("releaseRepository"), "Dialog shows server configuration keys");
    const platform = (instructions.platforms ?? []).find((entry) => entry.label === chosen);
    require(platform?.readiness?.ready ===
      true, `${chosen} has no eligible signed installation source`);
    require((await settings.count()) === 0, "Ready source incorrectly shows a repository blocker");
    require((await command.count()) === 1, "Ready source provides no install command");
    if ((await command.count()) === 1) {
      require((await command.inputValue()).trim().length >
        0, "Ready source provides an empty command");
      require((await command.getAttribute("readonly")) !== null, "Install command is editable");
    }
    const copy = dialog.getByRole("button", { name: "Copy install command", exact: true });
    require((await copy.count()) === 1 &&
      (await copy.isEnabled()), "Ready command has no enabled copy action");
    await capture("install-command-ready");
  } finally {
    await dialog.getByRole("button", { name: "Done, forget secret", exact: true }).click();
    await dialog.waitFor({ state: "hidden", timeout });
  }
}
