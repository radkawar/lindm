// Owner task: the wipe form states its consequences before any input, names stale
// storage by its age, says what is missing instead of showing a disabled Review
// button, and continues by itself once a requested inventory refresh lands. It
// requests one inventory refresh on the route device (the least-impact action;
// the seeded device completes it on its next check-in, leaving no open action)
// and never selects a target or submits a wipe.
export const task = {
  name: "Wipe consequences and freshness",
  screenId: "ffe469b456a2caca5dbdbd32",
  route: "/devices/$deviceId/actions/new/cryptoErase",
  priority: "high",
  acceptance:
    "Opening the page shows the consequences box before any input; stale storage reads 'Storage info from 12 min ago is too old for a wipe'; after Refresh inventory completes the target list appears without reloading; no disabled full-width button is visible while blocked.",
};

const STALE = /^Storage info from .+ ago is too old for a wipe$/;
const MISSING = /^Missing before review: .+\.$/;
const WAITING = /^Inventory refresh requested\. Waiting for /;
const MARKER = "__lindmOwnerEditWipeForm";

// Visible disabled buttons wider than 60% of main: the "looks like a broken page" pattern.
function wideDisabledButtons(page) {
  return page.evaluate(() => {
    const main = document.querySelector("main");
    const limit = main.getBoundingClientRect().width * 0.6;
    return [...main.querySelectorAll("button")]
      .filter((button) => {
        const box = button.getBoundingClientRect();
        const style = getComputedStyle(button);
        return (
          (button.disabled || button.getAttribute("aria-disabled") === "true") &&
          style.visibility !== "hidden" &&
          style.display !== "none" &&
          box.height > 0 &&
          box.width > limit
        );
      })
      .map((button) => button.innerText.trim() || "unlabelled button");
  });
}

// Where the consequences box sits relative to the first input or button in main.
// While blocked there is no <form>: the target picker and Refresh inventory come first.
function consequencesOrder(page) {
  return page.evaluate(() => {
    const main = document.querySelector("main");
    const box = main.querySelector('[data-slot="action-consequences"]');
    const control = main.querySelector(
      'input, select, textarea, button, [role="combobox"], [role="textbox"]',
    );
    if (!box) return "missing box";
    if (!control) return "no input";
    return box.compareDocumentPosition(control) & Node.DOCUMENT_POSITION_FOLLOWING
      ? "before"
      : "after";
  });
}

export async function check({ page, demo, visit, require, capture, step }) {
  const deviceId = demo.Routes.DeviceID;
  const hostname = demo.Devices.find((device) => device.ID === deviceId)?.Hostname;
  if (!deviceId || !hostname) throw new Error("demo route device or its hostname is missing");

  step("open wipe form");
  await visit(`/devices/${encodeURIComponent(deviceId)}/actions/new/cryptoErase`);
  const main = page.getByRole("main");
  await main
    .getByRole("heading", { level: 1, name: "Wipe encrypted storage", exact: true })
    .waitFor({ timeout: 30_000 });
  const picker = main.getByRole("region", { name: "Observed storage target" });
  await picker.waitFor({ timeout: 30_000 });
  const refresh = picker.getByRole("button", { name: "Refresh inventory", exact: true });
  await refresh.waitFor({ timeout: 30_000 });

  step("consequences before any input");
  const consequences = main.locator('[data-slot="action-consequences"]');
  require(await consequences.isVisible(), "no consequences box is visible on the wipe form");
  const order = await consequencesOrder(page);
  require(order ===
    "before", `consequences box does not precede the first form control (${order})`);
  const box = (await consequences.innerText()).replace(/\s+/g, " ");
  require(/can't be undone/i.test(box), "consequences box does not say the wipe is irreversible");
  require(box.includes(hostname), `consequences box does not name ${hostname}`);
  require(/powers off/i.test(box), "consequences box does not say the device powers off");
  require(/another admin must approve/i.test(
    box,
  ), "consequences box does not say a second admin must approve");
  require(/not destroyed: recovery keys escrowed/i.test(box) &&
    /header backups/i.test(
      box,
    ), "consequences box does not say escrowed keys and header backups are not destroyed");
  require(/must be online/i.test(box) &&
    /expires/i.test(box), "consequences box does not say what happens when the device is offline");
  require(!(await main
    .getByText("Check the device and fill in the details.", { exact: true })
    .count()), "the generic subtitle is still shown");
  require(!(await main
    .locator('[data-slot="technical-details"]')
    .count()), "a Details toggle is still shown before a target is chosen");

  step("stale storage blocks with its age");
  const stale = main.getByText(STALE);
  const wasStale = await stale.isVisible();
  require(wasStale, "storage info was not stale when the page opened, or its text does not match 'Storage info from … ago is too old for a wipe'");
  const missing = main.getByText(MISSING);
  require(await missing.isVisible(), "no inline text names what is missing while review is blocked");
  if (await missing.isVisible())
    require(/storage info/i.test(
      await missing.innerText(),
    ), "the missing-prerequisite text does not name current storage info");
  require(!(await main
    .getByRole("button", { name: "Review action", exact: true })
    .count()), "a Review action button is shown while review is blocked");
  const blockedWide = await wideDisabledButtons(page);
  require(blockedWide.length ===
    0, `disabled full-width buttons while blocked: ${blockedWide.join(", ")}`);
  await capture("stale-blocked");

  step("request inventory refresh");
  await page.evaluate((marker) => {
    window[marker] = "same-document";
  }, MARKER);
  await refresh.click();
  const dialog = page.getByRole("dialog", { name: "Refresh inventory", exact: true });
  await dialog.waitFor({ timeout: 30_000 });
  await dialog
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("Owner acceptance check: refresh storage info before reviewing a wipe");
  await dialog.getByRole("button", { name: "Review action", exact: true }).click();
  await dialog.getByText("Ready to send", { exact: true }).waitFor({ timeout: 30_000 });
  await dialog.getByRole("button", { name: "Send action", exact: true }).click();
  await dialog.waitFor({ state: "hidden", timeout: 30_000 });

  step("wait for fresh storage");
  const waiting = main.getByText(WAITING);
  if (await waiting.isVisible()) {
    const waitingWide = await wideDisabledButtons(page);
    require(waitingWide.length ===
      0, `disabled full-width buttons while waiting for the refresh: ${waitingWide.join(", ")}`);
    await capture("refresh-waiting");
  }
  // The route device answers on its next 30-second check-in; 90 s is the bound.
  const target = picker.getByRole("combobox", { name: "Target", exact: true });
  await target.waitFor({ timeout: 90_000 });
  const marker = await page.evaluate((name) => window[name], MARKER);
  require(marker === "same-document", "the target list appeared only after a page reload");
  require(!(await stale.isVisible()), "the stale storage message is still shown after refresh");
  require((await missing.isVisible()) &&
    (await missing.innerText()).trim() ===
      "Missing before review: a target.", "after the refresh the missing-prerequisite text does not ask only for a target");
  const freshWide = await wideDisabledButtons(page);
  require(freshWide.length ===
    0, `disabled full-width buttons after the refresh: ${freshWide.join(", ")}`);
  await capture("targets-after-refresh");
}
