// SPDX-License-Identifier: Apache-2.0

// Owner pass 2 finding 7: on the device page, Patch now opened over a hidden
// Assign profile dialog that was still in the DOM, and Review action validated
// the hidden dialog's fields. Closed dialogs unmount their content: the check
// opens Assign profile, closes it, opens Patch now and asserts exactly one
// dialog and one form in the DOM, then submits the empty form and asserts the
// validation lands on Patch now's own Reason. Revoke device closes the same way.
// Read-only: nothing is reviewed, sent or requested.
export const task = {
  name: "Closed dialogs leave the page",
  screenId: "owner-pass2-p2-7-stacked-dialogs",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "After opening and closing Assign profile, Patch now is the only dialog and the only dialog form in the DOM; Review action with an empty reason marks Patch now's Reason, not a hidden field; a closed Revoke device dialog leaves nothing behind.",
};

const timeout = 30_000;

function dialogState() {
  const dialogs = [...document.querySelectorAll('[role="dialog"],[role="alertdialog"]')];
  const active = document.activeElement;
  return {
    titles: dialogs.map((dialog) => dialog.querySelector("h2")?.textContent?.trim() ?? "untitled"),
    forms: dialogs.reduce((count, dialog) => count + dialog.querySelectorAll("form").length, 0),
    assignFields: document.querySelectorAll("#service-assignment-reason").length,
    invalidOutside: [...document.querySelectorAll(":invalid")].filter(
      (node) =>
        node.tagName !== "FORM" &&
        node.closest('[role="dialog"]') &&
        !node.closest('[role="dialog"][data-open]'),
    ).length,
    focusedDialog:
      active?.closest('[role="dialog"]')?.querySelector("h2")?.textContent?.trim() ?? "",
    focusedLabel: active?.id
      ? (document.querySelector(`label[for="${CSS.escape(active.id)}"]`)?.textContent?.trim() ?? "")
      : "",
    focusedInvalid: !!active?.matches?.(":invalid"),
  };
}

export async function check({ page, demo, visit, require, capture, step }) {
  const deviceId = demo?.Routes?.DeviceID;
  if (!deviceId) throw new Error("demo route device is missing");
  const main = page.getByRole("main");
  step("open device");
  await visit(`/devices/${encodeURIComponent(deviceId)}`);
  const assign = main.getByRole("button", { name: "Assign profile", exact: true }).first();
  await assign.waitFor({ timeout });

  step("open and close Assign profile");
  await assign.click();
  const assignDialog = page.getByRole("dialog", { name: "Assign profile", exact: true });
  await assignDialog.waitFor({ timeout });
  await page.keyboard.press("Escape");
  await assignDialog.waitFor({ state: "detached", timeout });
  const closed = await page.evaluate(dialogState);
  require(closed.titles.length ===
    0, `After closing Assign profile the DOM still holds dialog(s): ${closed.titles.join(", ")}`);
  require(closed.assignFields ===
    0, "After closing Assign profile its form fields are still in the DOM");

  step("open Patch now");
  await main.getByRole("button", { name: "Actions", exact: true }).first().click();
  await page.getByRole("menuitem", { name: "Patch now", exact: true }).click();
  const patch = page.getByRole("dialog", { name: "Patch now", exact: true });
  await patch.waitFor({ timeout });
  const open = await page.evaluate(dialogState);
  require(open.titles.length === 1 &&
    open.titles[0] ===
      "Patch now", `With Patch now open the DOM holds ${open.titles.length} dialog(s): ${open.titles.join(", ")}`);
  require(open.forms === 1, `With Patch now open the dialogs hold ${open.forms} forms`);
  require(open.assignFields === 0, "Assign profile's fields are in the DOM behind Patch now");

  step("validation targets Patch now");
  await patch.getByRole("button", { name: "Review action", exact: true }).click();
  const validated = await page.evaluate(dialogState);
  require(validated.focusedDialog === "Patch now" &&
    validated.focusedInvalid, `Review action with an empty reason focused "${validated.focusedLabel || "nothing"}" in "${validated.focusedDialog || "no dialog"}", not an invalid Patch now field`);
  require(/^Reason/.test(
    validated.focusedLabel,
  ), `Review action with an empty reason marked "${validated.focusedLabel}", not Patch now's Reason`);
  require(validated.invalidOutside === 0, "Fields of a closed dialog are being validated");
  await capture("patch now only dialog");
  await page.keyboard.press("Escape");
  await patch.waitFor({ state: "detached", timeout });

  step("open and close Revoke device");
  await main.getByRole("button", { name: "Actions", exact: true }).first().click();
  const revokeItem = page.getByRole("menuitem", { name: "Revoke device", exact: true });
  await revokeItem.click();
  const revoke = page.getByRole("dialog", { name: /^Revoke / });
  await revoke.waitFor({ timeout });
  await page.keyboard.press("Escape");
  await revoke.waitFor({ state: "detached", timeout });
  const after = await page.evaluate(dialogState);
  require(after.titles.length ===
    0, `After closing Revoke device the DOM still holds dialog(s): ${after.titles.join(", ")}`);
}
