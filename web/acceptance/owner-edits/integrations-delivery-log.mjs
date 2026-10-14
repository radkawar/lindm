// SPDX-License-Identifier: Apache-2.0

// Owner task (pass 2, Integrations): the delivery log listed every webhook
// delivery ("SOC webhook · Delivered · 1 · None"). Failures are listed by
// default and delivered events are counted per destination, expandable.
// Read-only: expands and collapses the delivered list.
export const task = {
  name: "Integrations delivery log failures first",
  screenId: "",
  route: "/integrations",
  priority: "normal",
  acceptance:
    "The Delivery log lists only failed or retrying deliveries (or 'No failed deliveries'), shows 'SOC webhook · N events delivered in the last 24 h' with N > 0, and lists delivered events only after Show delivered.",
};

const FAILURE_STATUS = /^(Failed|Retrying)$/;

export async function check({ page, visit, require, capture, step }) {
  const main = page.getByRole("main");
  step("open delivery log");
  await visit("/integrations");
  const log = main.getByRole("region", { name: "Delivery log" });
  await log.waitFor({ timeout: 30_000 });
  const counts = log.getByRole("list", { name: "Delivered events per destination" });
  await counts.waitFor({ timeout: 30_000 });
  const failures = log.getByRole("table", { name: "Failed deliveries" });
  const empty = log.getByText("No failed deliveries", { exact: true });
  require((await failures.count()) + (await empty.count()) ===
    1, "the default view is not the failures list");
  if ((await failures.count()) === 1) {
    for (const row of await failures.locator("tbody tr").all()) {
      const status = (await row.getByRole("cell").nth(1).innerText()).split("\n")[0].trim();
      require(FAILURE_STATUS.test(status), `failures list shows a '${status}' row`);
    }
  }
  const soc = counts.getByRole("listitem").filter({ hasText: "SOC webhook" });
  const summary = (await soc.innerText()).match(/(\d[\d,]*) events? delivered in the last 24 h/);
  require(summary &&
    Number(summary[1].replaceAll(",", "")) > 0, "no delivered count for SOC webhook");
  require((await log.getByRole("table", { name: "Delivered events" }).count()) ===
    0, "delivered events are listed before Show delivered");
  await capture("integrations-delivery-log");

  step("show delivered");
  await soc.getByRole("button", { name: "Show delivered" }).click();
  const delivered = log.getByRole("table", { name: "Delivered events" });
  await delivered.waitFor({ timeout: 30_000 });
  require((await delivered.locator("tbody tr").count()) > 0, "Show delivered lists nothing");
  await capture("integrations-delivered-expanded");
  await soc.getByRole("button", { name: "Hide delivered" }).click();
}
