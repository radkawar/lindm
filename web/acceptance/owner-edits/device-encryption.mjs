// SPDX-License-Identifier: Apache-2.0

// Owner task: the route device's Encryption tab leads with one recoverability
// verdict, it says in words whether lindm's recovery key is on the volume (slot numbers only in Details, agreeing with the escrow record), a single volume has
// no picker, Reveal is a real button and sizes avoid raw byte counts. Read-only:
// the secondary menu is opened and closed without choosing an action.
export const task = {
  name: "Encryption recoverability",
  screenId: "6a7a7197023a09e3d1f46bef",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "On ubuntu-ws-01 the tab opens with a single recoverability sentence; 'On the device: lindm's recovery key is in use' is shown while raw key slots appear only in Details and agree with the escrow record; no volume picker shown; Reveal is a button; no raw byte counts visible outside Details.",
};

const verdictPattern = /^(Recoverable|Not recoverable|Unknown): \S/;

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const { DeviceID, RecoveryActionID } = demo.Routes;
  const hostname = demo.Devices.find((device) => device.ID === DeviceID)?.Hostname ?? DeviceID;
  const main = page.getByRole("main");

  step(`open ${hostname} Encryption tab`);
  await visit(`/devices/${DeviceID}`);
  await main.getByRole("tab", { name: "Encryption", exact: true }).click();
  const panel = main.locator('[role="tabpanel"]:not([hidden])');
  await panel.getByText(verdictPattern).first().waitFor({ timeout: 30_000 });
  await settle();

  step("single recoverability sentence first");
  const lines = (await panel.innerText())
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  require(verdictPattern.test(
    lines[0] ?? "",
  ), `Encryption tab does not open with a recoverability sentence (first text: ${JSON.stringify(lines[0])})`);
  const verdicts = lines.filter((line) => verdictPattern.test(line));
  require(verdicts.length ===
    1, `Expected one recoverability sentence, found ${verdicts.length}: ${JSON.stringify(verdicts)}`);
  // The seed escrows a recovery key for this device's root volume.
  if (RecoveryActionID) {
    require(/^Recoverable: recovery key .*escrowed .+, TPM unlock (on|off)$/.test(
      lines[0] ?? "",
    ), `Escrowed device verdict should name escrow age and TPM unlock state (got ${JSON.stringify(lines[0])})`);
  }

  step("escrowed key stated in words; slot numbers only in Details");
  // Owner pass 2: raw slot numbers are diagnostics. The primary facts say whether
  // lindm's recovery key is on the volume; Details keeps the slots, which must agree.
  const facts = await panel.locator("dt").evaluateAll((terms) =>
    terms.map((term) => ({
      label: term.textContent.trim().replace(/:$/, ""),
      value: term.nextElementSibling?.textContent.trim() ?? "",
      details: !!term.closest("details"),
    })),
  );
  const shown = facts.filter((fact) => !fact.details);
  const hidden = facts.filter((fact) => fact.details);
  const onDevice = shown.find((fact) => fact.label === "On the device")?.value ?? "";
  if (RecoveryActionID) {
    require(onDevice ===
      "lindm's recovery key is in use", `Escrow record does not say in words that lindm's recovery key is in use (got ${JSON.stringify(onDevice)})`);
  }
  for (const fact of shown)
    require(!/slot/i.test(
      fact.label,
    ), `Raw key-slot fact '${fact.label}: ${fact.value}' is shown outside Details`);
  const escrowSlot = hidden.find((fact) => fact.label === "Recovery key slot")?.value ?? "";
  if (RecoveryActionID) {
    require(/^\d+$/.test(escrowSlot), "Details does not keep the escrowed recovery key slot");
  }
  if (escrowSlot) {
    for (const fact of hidden.filter((item) => /^key slots/i.test(item.label))) {
      require(!/^none/i.test(
        fact.value,
      ), `'${fact.label}: ${fact.value}' contradicts escrowed recovery key slot ${escrowSlot}`);
      require(fact.value
        .split(",")
        .map((part) => part.trim())
        .includes(
          escrowSlot,
        ), `'${fact.label}: ${fact.value}' omits escrowed recovery key slot ${escrowSlot}`);
    }
  }

  step("no volume picker for a single volume");
  require((await panel.getByRole("combobox").count()) ===
    0, "Encryption tab shows a volume picker");
  for (const name of ["Newest volumes", "Older volumes"]) {
    require((await panel.getByRole("button", { name, exact: true }).count()) ===
      0, `Encryption tab shows '${name}' paging for a single volume`);
  }

  step("Reveal recovery key is a primary button; other actions in a menu");
  require((await panel
    .getByRole("button", { name: "Reveal recovery key", exact: true })
    .count()) === 1, "'Reveal recovery key' is not a button");
  require((await panel.getByRole("link", { name: "Reveal recovery key", exact: true }).count()) ===
    0, "'Reveal recovery key' is still a link");
  const more = panel.getByRole("button", { name: "Other encryption actions" });
  if ((await more.count()) === 1) {
    await more.click();
    const menu = page.getByRole("menu");
    await menu.waitFor({ timeout: 10_000 });
    for (const name of [
      "Rotate escrow recovery key",
      "Bind TPM 2.0 unlock",
      "Recover device enrollment",
    ]) {
      require((await menu.getByRole("menuitem", { name, exact: true }).count()) ===
        1, `Secondary encryption menu lacks '${name}'`);
    }
    await page.keyboard.press("Escape");
    await menu.waitFor({ state: "hidden", timeout: 10_000 });
  } else {
    require(false, "Rotate, Bind TPM and Recover enrollment are not grouped under a menu");
  }
  for (const name of ["Rotate escrow recovery key", "Bind TPM 2.0 unlock"]) {
    require((await panel.getByRole("link", { name, exact: true }).count()) ===
      0, `'${name}' is still an equal-weight link`);
  }

  step("sizes without raw byte counts outside Details");
  const primaryText = await panel.evaluate((element) => {
    const copy = element.cloneNode(true);
    for (const node of copy.querySelectorAll('details, [data-slot="technical-details"]'))
      node.remove();
    return copy.textContent;
  });
  const raw = primaryText.match(
    /\d{4,}\s*bytes|\d{1,3}(?:[,.\u202f ]\d{3})+\s*bytes|bytes\)?\s*:?\s*\d[\d,]{3,}/i,
  );
  require(!raw, `Raw byte count visible outside Details: ${JSON.stringify(raw?.[0])}`);
  const size = shown.find((fact) => fact.label === "Size")?.value ?? "";
  require(/^\d+(\.\d)? (KiB|MiB|GiB|TiB|PiB|EiB)$/.test(
    size,
  ), `Volume size is not in binary units (got ${JSON.stringify(size)})`);
  const disclosures = await panel.locator("details").count();
  require(disclosures <= 1, `Expected one Details disclosure, found ${disclosures}`);

  await capture("device-encryption-recoverability");
}
