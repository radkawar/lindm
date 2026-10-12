// Owner edit pass 2 (fleet screens): dashboard, device list, device header,
// Overview, Inventory, Encryption, Actions/History and Findings items from the
// owner's 2026-10-12 feedback. Read-only: tabs are opened, the accept-risk
// disclosure is expanded; nothing is submitted.
export const task = {
  name: "Fleet screens owner pass 2",
  screenId: "fleet-pass-2",
  route: "/devices/$deviceId",
  priority: "high",
  acceptance:
    "Dashboard snapshot time is in the page header and the queue and activity share the width on wide screens; device links and tabs keep clean shareable URLs (?tab=); the device list fits 1440px and is a stacked list at 390px; the device header shows OS/architecture/contact as text, not chips; Overview findings reason is in words and unknown updates offer Request fresh inventory; Inventory leads with system, patch and packages with full hardware collected in one disclosure; Encryption shows no raw key slots, no 'Old key removed' or 'Running from recovery: No'; Actions has no duplicate storage links, no pager for one page, and there is no History tab; Findings is one table row per finding without zero epochs and accepts risk for 7/30/90 days with an unambiguous approval checkbox.",
};

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const { DeviceID } = demo.Routes;
  const main = page.getByRole("main");
  const panel = main.locator('[role="tabpanel"]:not([hidden])');
  const tab = async (name) => {
    await main.getByRole("tab", { name, exact: true }).click();
    await settle();
  };

  step("dashboard header and layout");
  await visit("/dashboard");
  await main
    .getByRole("heading", { name: "Needs review", exact: true })
    .waitFor({ timeout: 30_000 });
  require((await main.getByText(/^Fleet snapshot .*\. Work in your authorized scopes/).count()) ===
    1, "Fleet snapshot time is not in the page header description");
  require((await main.getByRole("link", { name: "Enroll a device" }).count()) ===
    1, "Dashboard has no Enroll a device entry");
  await capture("dashboard");

  step("dashboard profile and patch links open the filtered device list");
  for (const [name, chip, allowed] of [
    ["Show devices with profile items to review", /^Profile: /, /^(Attention|Stale|Unknown)$/],
    ["Show devices needing update follow-up", /^Updates: /, null],
  ]) {
    await visit("/dashboard");
    await main.getByRole("link", { name: new RegExp(`^${name}`) }).click();
    const listed = page.getByRole("table", { name: /Enrolled devices/ });
    await listed.waitFor({ timeout: 30_000 }).catch(() => {});
    const applied = page.getByRole("group", { name: "Applied device filters" });
    const chips = (await applied.getByRole("button").allInnerTexts()).map((text) => text.trim());
    require(chips.some((text) =>
      chip.test(text),
    ), `${name}: no removable filter chip (${chips.join(", ")})`);
    if (allowed) {
      const headers = (await listed.locator("thead th").allInnerTexts()).map((text) => text.trim());
      const column = headers.indexOf("Compliance");
      for (const row of await listed.locator("tbody tr").all()) {
        const cell = (await row.locator("td").nth(column).innerText()).trim();
        require(allowed.test(cell), `${name}: listed a device with compliance "${cell}"`);
      }
    }
  }

  step("device list fits the desktop viewport");
  await visit("/devices");
  const table = page.getByRole("table", { name: /Enrolled devices/ });
  await table.waitFor({ timeout: 30_000 });
  const fit = await table.evaluate((node) => ({
    right: Math.max(
      ...[...node.querySelectorAll("td")].map((cell) => cell.getBoundingClientRect().right),
    ),
    width: window.innerWidth,
  }));
  require(fit.right <=
    fit.width, `device table cells extend to x=${Math.round(fit.right)} beyond ${fit.width}px`);
  const href = await table.locator(`a[href*="${DeviceID}"]`).first().getAttribute("href");
  require(href && !href.includes("?"), `device link carries query parameters: ${href}`);

  step("device header facts are text");
  await visit(`/devices/${DeviceID}`);
  await main.getByRole("tab", { name: "Overview", exact: true }).waitFor({ timeout: 30_000 });
  await settle();
  require((await main.getByText(/· Last contact /).count()) >=
    1, "device header has no OS · architecture · Last contact line");
  const chipText = await main.locator('[data-slot="badge"]').allInnerTexts();
  require(!chipText.some((text) =>
    /x86_64|aarch64|^Contact /.test(text.trim()),
  ), `architecture/contact still rendered as chips: ${chipText.join(" | ")}`);
  require((await main.getByRole("tab", { name: "History", exact: true }).count()) ===
    0, "duplicate History tab is still present");
  const overview = await panel.innerText();
  require(!/[a-z]+_[a-z_]+/.test(overview), "Overview shows a snake_case reason code");
  if (/Updates\s+Unknown/.test(overview))
    require((await panel.getByRole("button", { name: "Request fresh inventory" }).count()) ===
      1, "unknown update status offers no Request fresh inventory action");
  await capture("device overview");

  step("owner and labels: plain owner choice and a review of changes before saving");
  const metadataCard = panel
    .locator('[data-slot="card"]')
    .filter({ has: page.getByText("Owner, labels and attributes", { exact: true }) });
  require((await metadataCard.getByText("Saving replaces all of these at once.").count()) ===
    0, "metadata card still warns 'Saving replaces all of these at once'");
  const edit = metadataCard.getByRole("button", { name: "Edit", exact: true });
  if (await edit.count()) {
    await edit.click();
    require((await metadataCard.getByText("Who owns this device", { exact: true }).count()) ===
      1, "owner type is not a plain choice");
    const owner = metadataCard.locator("#metadata-owner");
    if (await owner.count()) {
      await owner.fill(`${await owner.inputValue()} (check)`);
      await metadataCard.locator("#metadata-reason").fill("Owner pass 2 review check");
      await metadataCard.getByRole("button", { name: "Review changes", exact: true }).click();
      const review = metadataCard.locator('section[aria-labelledby="metadata-review"]');
      await review.waitFor({ timeout: 10_000 }).catch(() => {});
      require(/Owner: .* → .*\(check\)/.test(
        await review.innerText().catch(() => ""),
      ), "review does not show the owner change old → new before saving");
      await capture("metadata review");
    }
    // Leave without saving.
    await metadataCard.getByRole("button", { name: "Cancel", exact: true }).click();
  }

  step("services: plain interval, named actor, one success badge per converged item");
  await tab("Services");
  await panel
    .getByText("Assigned profile", { exact: true })
    .waitFor({ timeout: 30_000 })
    .catch(() => {});
  const services = await panel.innerText();
  require(!/every 1440 minutes/.test(services), "Services still says 'every 1440 minutes'");
  require(!/another administrator/.test(
    services,
  ), "Services names the assigner 'another administrator'");
  for (const row of await panel.locator("table").first().locator("tbody tr").all()) {
    const cells = await row.locator("td").allInnerTexts();
    if (cells.length < 4 || !/^Succeeded/.test(cells[2].trim())) continue;
    require(!/^Succeeded/.test(
      cells[3].trim(),
    ), `Services row repeats Succeeded: ${cells[0].split("\n")[0]}`);
  }
  await capture("services");

  step("tab is kept in the URL");
  await tab("Encryption");
  require(new URL(page.url()).searchParams.get("tab") ===
    "encryption", "open tab is not in the URL");
  const encryption = await panel.innerText();
  for (const noise of ["Old key removed", "Running from recovery", "Key slots in use"])
    require(!encryption.includes(noise), `Encryption still shows "${noise}" outside Details`);
  await capture("device encryption");

  step("inventory order");
  await tab("Inventory");
  const hardware = panel.locator("details > summary", { hasText: "Hardware, storage, network" });
  require((await hardware.count()) === 1, "full hardware collections are not in one disclosure");
  await capture("device inventory");

  step("actions tab");
  await tab("Actions");
  const actions = await panel.innerText();
  require(!actions.includes(
    "Storage and encryption actions",
  ), "Actions tab duplicates the Actions menu links");
  require((await panel.getByRole("button", { name: "Older actions" }).count()) === 0 ||
    !(await panel
      .getByRole("button", { name: "Older actions" })
      .isDisabled()), "Actions tab shows a pager for a single page");

  step("findings table");
  await tab("Findings");
  const rows = panel.locator("[data-finding-row]");
  await rows
    .first()
    .waitFor({ timeout: 30_000 })
    .catch(() => {});
  require((await rows.count()) > 0, "Findings are not table rows");
  require(!/(^|\s)0:\d/.test(await panel.innerText()), "Findings show a zero epoch (0:)");
  const totals = panel.locator("[data-finding-totals]");
  require(/^\d[\d,]* open findings? .*critical .*high/.test(
    (await totals.innerText().catch(() => "")).trim(),
  ), "Findings show no total count with severity breakdown");
  require((await panel.getByLabel("Sort by", { exact: true }).count()) ===
    1, "Findings have no sort control");
  const packageSearch = panel.getByLabel("Search packages", { exact: true });
  require((await packageSearch.count()) === 1, "Findings have no package search");
  if ((await packageSearch.count()) === 1) {
    const before = await rows.count();
    await packageSearch.fill("zz-no-such-package");
    await page
      .waitForFunction(() => !document.querySelector("[data-finding-row]"), null, {
        timeout: 10_000,
      })
      .catch(() => {});
    require((await rows.count()) === 0, "package search does not filter findings on the server");
    await packageSearch.fill("");
    await rows
      .first()
      .waitFor({ timeout: 10_000 })
      .catch(() => {});
    require((await rows.count()) ===
      before, "clearing the package search does not restore findings");
  }
  const accept = panel.getByText("Accept this risk", { exact: true }).first();
  if (await accept.count()) {
    await accept.click();
    require((await page.locator('input[type="datetime-local"]').count()) ===
      0, "accept-risk expiry is still a raw date-time input");
    require((await page.getByText(/valid for one hour/).count()) ===
      0, "approval checkbox still reads 'valid for one hour'");
    await capture("findings accept risk");
    await page.keyboard.press("Escape");
  }

  step("mobile device list");
  await page.setViewportSize({ width: 390, height: 844 });
  await visit("/devices");
  const list = page.getByRole("list", { name: "Devices" });
  await list.waitFor({ timeout: 30_000 });
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  require(overflow <= 0, `mobile device list overflows by ${overflow}px`);
  await capture("devices mobile");
  await page.setViewportSize({ width: 1440, height: 900 });
}
