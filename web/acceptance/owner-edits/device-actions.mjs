// Owner task: the route device's Actions tab lists each past action as one
// collapsed line (what, by whom, when, outcome) that expands to the full result,
// and remote assistance has its own tab instead of sitting below the history.
// Read-only: a row is expanded and collapsed; no assistance request is sent.
export const task = {
  name: "Device action history",
  screenId: "9d0eb9057b0e8cff93a68442",
  route: "/devices/$deviceId",
  priority: "normal",
  acceptance:
    "Actions tab shows each past action as a single row by default; Remote assistance is reachable from the device header or its own tab, not from the bottom of Actions.",
};

const assistanceText = /Remote assistance|Ask to help|Request remote assistance|Session history/;

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const { DeviceID, ActionID } = demo.Routes;
  const hostname = demo.Devices.find((device) => device.ID === DeviceID)?.Hostname ?? DeviceID;
  const main = page.getByRole("main");
  const panel = main.locator('[role="tabpanel"]:not([hidden])');

  step(`open ${hostname} Actions tab`);
  await visit(`/devices/${DeviceID}`);
  await main.getByRole("tab", { name: "Actions", exact: true }).click();
  const list = panel.getByRole("list", { name: "Recent actions" });
  await list.waitFor({ timeout: 30_000 });
  await settle();

  step("each past action is one collapsed line");
  const rows = await list.locator("[data-device-action-row]").evaluateAll((items) =>
    items.map((item) => {
      const summary = item.querySelector("summary");
      // One row: every summary part shares a vertical center and is one text line tall.
      const boxes = [...(summary?.children ?? [])].map((part) => part.getBoundingClientRect());
      const centers = boxes.map((box) => box.top + box.height / 2);
      return {
        open: item.open,
        text: summary?.innerText.replace(/\s+/g, " ").trim() ?? "",
        oneLine:
          boxes.length > 0 &&
          Math.max(...centers) - Math.min(...centers) <= 4 &&
          boxes.every((box) => box.height <= 32),
        outcome: summary?.querySelector('[data-slot="badge"]')?.innerText.trim() ?? "",
      };
    }),
  );
  require(rows.length > 0, "Actions tab lists no past actions on the seeded device");
  for (const [index, row] of rows.entries()) {
    const name = JSON.stringify(row.text);
    require(!row.open, `Action row ${index + 1} is expanded by default (${name})`);
    require(row.oneLine, `Action row ${index + 1} is not a single line (${name})`);
    require(/ by \S/.test(` ${row.text}`), `Action row ${index + 1} does not say who (${name})`);
    require(/\b(ago|just now)\b/.test(
      row.text,
    ), `Action row ${index + 1} does not say when (${name})`);
    require(row.outcome !== "", `Action row ${index + 1} has no outcome (${name})`);
  }
  // The seeded Refresh inventory action is the route action.
  if (ActionID)
    require(rows.some((row) =>
      row.text.includes("Refresh inventory"),
    ), "The seeded Refresh inventory action has no row");
  require(!(await panel.innerText()).includes(
    "Accepted by device",
  ), "Full action fields are visible without expanding a row");
  await capture("actions history");

  step("a row expands to its full fields");
  const first = list.locator("[data-device-action-row]").first();
  // The expanded result nests its own Details disclosures; target the row's summary.
  const summary = first.locator(":scope > summary");
  await summary.click();
  require(await first.evaluate((item) => item.open), "Action row does not expand");
  for (const label of ["Requested by", "Created", "Expires"])
    require(await first
      .getByText(label, { exact: true })
      .first()
      .isVisible(), `Expanded action row has no ${label} field`);
  await capture("actions row expanded");
  await summary.click();
  require(!(await first.evaluate((item) => item.open)), "Action row does not collapse again");

  step("remote assistance is not at the bottom of Actions");
  require(!assistanceText.test(
    await panel.innerText(),
  ), "Actions tab still contains the remote assistance form or session history");

  step("remote assistance has its own tab");
  const tab = main.getByRole("tab", { name: "Remote assistance", exact: true });
  require(await tab.isVisible(), "Device has no Remote assistance tab");
  if (await tab.isVisible()) {
    await tab.click();
    await settle();
    await panel.getByRole("heading", { name: "Session history" }).waitFor({ timeout: 30_000 });
    require(await panel
      .getByRole("button", { name: "Request remote assistance" })
      .isVisible(), "Remote assistance tab has no request form");
    require(await panel
      .getByRole("heading", { name: "Session history" })
      .isVisible(), "Remote assistance tab has no session history");
    await capture("remote assistance tab");
  }
}
