// SPDX-License-Identifier: Apache-2.0

// Advisory source copy and per-advisory device column: each incomplete source
// explains its gap once (in its own card, never again in the banner or a
// remedy line), remedies use admin terms with a docs link, server-config keys
// stay inside collapsed Details, and the per-advisory "Not checked" count is
// replaced by where the advisory was found on devices not fully checked.
// Read-only.
export const task = {
  name: "Advisory sources said once",
  screenId: "",
  route: "/advisories",
  priority: "medium",
  acceptance:
    "The incompleteness sentence appears at most once per source on /advisories (never in the banner), no 'advisories.feeds' or 'server configuration' text outside Details, a docs link explains how to add a source, and the advisory table has no 'Not checked' column; devices not fully checked are named in the Affected devices cell.",
};

const gapSentence = /only selected advisories|Missing the complete/;

// Text shown without expanding any collapsed <details>.
function visibleText(root) {
  const parts = [];
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const element = node.parentElement;
    if (!element?.checkVisibility()) continue;
    let collapsed = false;
    let details = element.closest("details");
    while (details && !collapsed) {
      const summary = [...details.children].find((child) => child.tagName === "SUMMARY");
      collapsed = !details.open && !summary?.contains(node);
      details = details.parentElement?.closest("details");
    }
    if (!collapsed) parts.push(node.textContent ?? "");
  }
  return parts.join(" ");
}

export async function check({ page, visit, require, capture, step }) {
  step("open advisories");
  await visit("/advisories");
  const main = page.getByRole("main");
  const sources = main.locator("[data-advisory-source]");
  await sources.first().waitFor({ timeout: 30_000 });
  await main.getByRole("table").waitFor({ timeout: 30_000 });

  step("incompleteness explained once");
  const banner = main.locator("[data-advisory-coverage-banner]");
  if ((await banner.count()) > 0) {
    const bannerText = await banner.evaluate(visibleText);
    require(!gapSentence.test(bannerText), "the banner repeats a source's incompleteness sentence");
  }
  const sourceCount = await sources.count();
  let incomplete = 0;
  for (let index = 0; index < sourceCount; index += 1) {
    const source = sources.nth(index);
    const text = await source.evaluate(visibleText);
    const heading = (await source.getByRole("heading", { level: 3 }).innerText()).trim();
    const said = text.match(/only selected advisories/g)?.length ?? 0;
    require(said <= 1, `the ${heading} source says it has only selected advisories ${said} times`);
    if (said > 0) incomplete += 1;
  }
  const mainText = await main.evaluate(visibleText);
  const total = mainText.match(/only selected advisories/g)?.length ?? 0;
  require(total ===
    incomplete, `the incompleteness sentence appears ${total} times for ${incomplete} incomplete sources`);

  step("no server configuration jargon outside Details");
  const jargon = mainText.match(/advisories\.feeds|server configuration/gi) ?? [];
  require(jargon.length === 0, `server-config jargon shown without Details: ${jargon.join(", ")}`);
  const docs = main.getByRole("link", { name: "Configure advisory sources", exact: true });
  require((await docs.count()) === 1, "no single docs link explains advisory source configuration");
  if ((await docs.count()) === 1) {
    const href = (await docs.getAttribute("href")) ?? "";
    require(href ===
      "/help/engineering.md#advisory-feed-operations", `docs link points elsewhere: ${href}`);
  }

  step("advisory table column means something per advisory");
  const table = main.getByRole("table");
  require((await table.getByRole("columnheader", { name: "Not checked", exact: true }).count()) ===
    0, "the advisory table still has a 'Not checked' column");
  const headers = (await table.getByRole("columnheader").allInnerTexts()).map((text) =>
    text.trim(),
  );
  const affectedIndex = headers.indexOf("Affected devices");
  require(affectedIndex >= 0, `no Affected devices column: ${headers.join(" | ")}`);
  const rows = table.locator("tbody tr");
  const rowCount = await rows.count();
  require(rowCount > 0, "no advisory rows on the seed");
  let named = 0;
  for (let index = 0; index < rowCount; index += 1) {
    const cell = rows.nth(index).getByRole("cell").nth(affectedIndex);
    const text = (await cell.innerText()).trim();
    require(/^\d+$|^(?:\d+\s+)?(?:Also found|Found) on \d+ devices? not fully checked$/.test(
      text,
    ), `Affected devices cell reads "${text}"`);
    const marker = cell.locator("[data-advisory-unconfirmed]");
    if ((await marker.count()) > 0) {
      const count = await marker.getAttribute("data-advisory-unconfirmed");
      require(text.includes(
        `on ${count} device`,
      ), `cell "${text}" disagrees with its count ${count}`);
      named += 1;
    }
  }
  require(named > 0, "the seed shows no advisory found on a device that isn't fully checked");
  await capture("advisories-sources-once");
}
