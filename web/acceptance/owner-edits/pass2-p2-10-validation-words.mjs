// Owner pass 2, finding 10: forms showed raw validator text ("metadata.labels[4]:
// does not match regex pattern … [string.pattern]", "[string.ip]") and accepted
// values until submit. Each form now names the problem in words beside the field,
// before anything is sent. Nothing is saved, sent or published: the label is
// refused when added, the quarantine stops at Review, and the profile is never
// published.
export const task = {
  name: "Validation in words beside the field",
  screenId: "owner-pass2-p2-10-validation-words",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "An invalid label, quarantine IP and kernel module name each show a worded error under their own field before anything is sent; no page shows rule IDs ([string.pattern]), 'regex pattern' or request field paths.",
};

const timeout = 30_000;
const RAW =
  /\[(?:required|(?:string|bytes|bool|enum|repeated|map|u?int(?:32|64)|double|float)\.[a-z_]+)\]|regex pattern|cannot encode|validation error|\b[a-z_]+(?:\[\d+\])?(?:\.[a-z_]+(?:\[\d+\])?)+:/i;

async function primaryText(main) {
  return main.evaluate((node) => {
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
    const parts = [];
    for (let text = walker.nextNode(); text; text = walker.nextNode()) {
      const parent = text.parentElement;
      if (
        !parent ||
        parent.closest('[data-slot="support-details"],[data-slot="technical-details"],pre')
      )
        continue;
      if (!parent.checkVisibility()) continue;
      parts.push(text.textContent ?? "");
    }
    return parts.join(" ").replace(/\s+/g, " ");
  });
}

export async function check({ page, demo, visit, require, capture, step }) {
  const deviceId = demo.Routes.DeviceID;
  if (!deviceId) throw new Error("demo route device is missing");
  const main = page.getByRole("main");

  step("label refused when added");
  await visit(`/devices/${encodeURIComponent(deviceId)}`);
  await main.getByRole("button", { name: "Edit", exact: true }).first().click();
  await main.getByRole("button", { name: /^Add a label/ }).click();
  await page.getByRole("combobox", { name: "Search add a label" }).fill("bad label!");
  await page.getByRole("option", { name: /Use “bad label!”/ }).click();
  const labelError = main.locator("#metadata-label-error");
  await labelError.waitFor({ timeout });
  require(/can't be a label\. Labels use letters, digits/.test(
    await labelError.innerText(),
  ), "the refused label isn't explained in words");
  require((await main.getByRole("button", { name: "Remove label bad label!" }).count()) ===
    0, "the invalid label was added anyway");
  require(!RAW.test(await primaryText(main)), "raw validation text on the device page");
  await capture("label refused");
  await main.getByRole("button", { name: "Cancel", exact: true }).click();

  step("quarantine IP named under its field");
  await visit(`/devices/${encodeURIComponent(deviceId)}`);
  await main.getByRole("button", { name: "Actions", exact: true }).click();
  await page.getByRole("menuitem", { name: "Quarantine network", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Quarantine network", exact: true });
  await dialog.waitFor({ timeout });
  const endpoints = dialog.getByLabel("Management IPs to keep reachable (one per line)");
  await endpoints.fill("192.0.2.10\nnot-an-ip");
  await dialog
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("ui-review: worded IP validation");
  await dialog.getByRole("button", { name: "Review action", exact: true }).click();
  await dialog.locator('[aria-invalid="true"]').first().waitFor({ timeout });
  require((await endpoints.getAttribute("aria-invalid")) ===
    "true", "the endpoints field isn't marked invalid");
  const describedBy = (await endpoints.getAttribute("aria-describedby")) ?? "";
  require(describedBy !== "", "the endpoints field isn't described by its error");
  if (describedBy) {
    require(/^Not an IP address: not-an-ip\. Enter one IP address per line/.test(
      await dialog.locator(`[id="${describedBy}"]`).innerText(),
    ), "the endpoint error doesn't name the value in words");
  }
  require(!RAW.test(await primaryText(dialog)), "raw validation text on the quarantine form");
  await capture("quarantine endpoint refused");
  await page.keyboard.press("Escape");

  step("kernel module name checked as typed");
  await visit("/profiles/new");
  await main.getByRole("combobox", { name: "Setting type", exact: true }).first().click();
  await page.getByRole("option", { name: "Block kernel modules", exact: true }).click();
  const modules = main.getByLabel("Modules to block", { exact: true });
  await modules.fill("usb_storage\nusb-storage");
  const moduleError = main.getByText(/^Not a module name: usb-storage\./);
  await moduleError.waitFor({ timeout });
  require((await modules.getAttribute("aria-invalid")) ===
    "true", "the module list isn't marked invalid");
  require(!RAW.test(await primaryText(main)), "raw validation text in the profile editor");
  await capture("kernel module refused");
}
