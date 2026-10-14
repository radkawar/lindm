// SPDX-License-Identifier: Apache-2.0

// Advisory coverage banner: /advisories opens with why devices are unchecked,
// grouped by cause with a remedy each; every Incomplete source names what is
// missing; source URLs stay in collapsed Details; no "No CVEs listed" filler.
// Read-only: the only interaction follows an in-page link to a source card.
export const task = {
  name: "Advisory coverage banner",
  screenId: "fd4cf90ac477abba75376b3c",
  route: "/advisories",
  priority: "high",
  acceptance:
    "On the seed, the page opens with a banner naming the current unchecked-device count and explaining each cause with a remedy; each Incomplete source states what is missing; no URL is visible without expanding Details.",
};

const bannerTitle = /^lindm has not checked (\d+) devices? for advisories$/;
const genericGap = /missing some data/i;

// Text nodes containing an http(s) URL, split into those shown and those inside
// a collapsed <details> (TechnicalDetails is one) or otherwise not rendered.
function urlTexts(root) {
  const shown = [];
  let hidden = 0;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const text = node.textContent ?? "";
    if (!/https?:\/\//i.test(text)) continue;
    const element = node.parentElement;
    let collapsed = !element?.checkVisibility();
    let details = element?.closest("details");
    while (details && !collapsed) {
      const summary = [...details.children].find((child) => child.tagName === "SUMMARY");
      collapsed = !details.open && !summary?.contains(node);
      details = details.parentElement?.closest("details");
    }
    if (collapsed) hidden += 1;
    else shown.push(text.trim().slice(0, 120));
  }
  return { shown, hidden };
}

export async function check({ page, demo, visit, settle, require, capture, step }) {
  step("open advisories");
  await visit("/advisories");
  const main = page.getByRole("main");
  const notChecked = main.locator("[data-advisory-unchecked-count]");
  await notChecked.waitFor({ timeout: 30_000 });
  const unchecked = Number(await notChecked.getAttribute("data-advisory-unchecked-count"));
  require(String(unchecked) ===
    (
      await notChecked.innerText()
    ).trim(), "'Devices not checked' marker disagrees with its visible count");
  // Enrolled and stale demo devices are the active population the count covers.
  const active = demo.Devices.filter((device) => ["enrolled", "stale"].includes(device.State));
  require(unchecked > 0 &&
    unchecked <=
      active.length, `seed shows ${unchecked} of ${active.length} active devices not checked; no banner to check`);

  step("banner leads the page");
  const banner = main.locator("[data-advisory-coverage-banner]");
  await banner.waitFor({ timeout: 30_000 });
  const leads = await main.evaluate((root) => {
    const headings = [...root.querySelectorAll("h1, h2, h3, h4, h5, h6")];
    const visible = headings.filter((heading) => heading.checkVisibility());
    const next = visible[visible.findIndex((heading) => heading.tagName === "H1") + 1];
    return !!next?.closest("[data-advisory-coverage-banner]");
  });
  require(leads, "the coverage banner is not the first content after the page title");
  const title = (await banner.getByRole("heading", { level: 2 }).innerText()).trim();
  const stated = title.match(bannerTitle);
  require(stated &&
    Number(stated[1]) ===
      unchecked, `banner title "${title}" does not state the ${unchecked} not-checked devices`);

  step("banner explains each cause with a remedy");
  const groups = banner.locator("[data-advisory-unchecked-group]");
  const groupCount = await groups.count();
  require(groupCount > 0, "banner names no cause");
  let explained = 0;
  let enabled = 0;
  for (let index = 0; index < groupCount; index += 1) {
    const group = groups.nth(index);
    const devices = Number(await group.getAttribute("data-devices"));
    const lines = (await group.innerText()).split("\n").filter((line) => line.trim());
    require(lines[0]?.includes(
      `${devices} device`,
    ), `cause "${lines[0]}" does not name its device count`);
    // Cause and count, its explanation, then the fix control.
    require(lines.length >= 3, `cause "${lines[0]}" has no explanation`);
    explained += devices;
    const actions = group.locator("a[href], button");
    let groupEnabled = 0;
    for (let item = 0; item < (await actions.count()); item += 1) {
      const action = actions.nth(item);
      const tag = await action.evaluate((node) => node.tagName);
      if (tag === "A" || (await action.isEnabled())) groupEnabled += 1;
    }
    require(groupEnabled > 0, `cause "${lines[0]}" has no enabled fix button or link`);
    enabled += groupEnabled;
  }
  require(enabled > 0, "banner has no enabled button or link that resolves or explains");
  require(explained ===
    unchecked, `banner causes cover ${explained} devices, not the ${unchecked} not checked`);

  step("incomplete sources name what is missing");
  const sources = main.locator("[data-advisory-source]");
  const sourceCount = await sources.count();
  require(sourceCount > 0, "no advisory source cards");
  let incomplete = 0;
  for (let index = 0; index < sourceCount; index += 1) {
    const source = sources.nth(index);
    const label = (await source.locator("[data-advisory-source-badge]").innerText()).trim();
    if (label !== "Incomplete") continue;
    incomplete += 1;
    const heading = await source.getByRole("heading", { level: 3 }).innerText();
    const name = heading.trim().replace(/ \([^)]*\)$/, "");
    const sentence = (await source.locator("[data-advisory-source-status]").innerText()).trim();
    require(/^Missing \S/.test(sentence) &&
      sentence.includes(name) &&
      !genericGap.test(
        sentence,
      ), `Incomplete ${name} source does not say what is missing: "${sentence}"`);
  }
  require(!/Source incomplete for/.test(await banner.innerText()) ||
    incomplete > 0, "banner blames an incomplete source but no source card is Incomplete");

  step("URLs only inside collapsed Details");
  const urls = await main.evaluate(urlTexts);
  require(urls.shown.length ===
    0, `URLs visible without expanding Details: ${urls.shown.join(" | ")}`);
  require(urls.hidden > 0, "no source URL is kept in Details");

  step("no empty CVE line or unknown severity chip");
  require((await main.getByText("No CVEs listed").count()) ===
    0, "'No CVEs listed' is still shown in the advisory table");
  require((await main
    .locator("table")
    .getByText(/^unknown$/i)
    .count()) === 0, "an 'unknown' severity chip is still shown");
  await capture("advisories-coverage-banner");

  step("banner link explains the source gap");
  const sourceLink = banner.getByRole("link", { name: /^Review .+ source$/ }).first();
  if ((await sourceLink.count()) === 0) return;
  await sourceLink.click();
  await page.waitForURL(/#advisory-source-/, { timeout: 30_000 });
  await settle();
  const anchor = decodeURIComponent(new URL(page.url()).hash.slice(1));
  const target = main.locator(`article[id="${anchor}"]`);
  const found = (await target.count()) === 1;
  require(found, `banner link points at a missing source card: #${anchor}`);
  if (!found) return;
  const inView = await target.evaluate((node) => {
    const box = node.getBoundingClientRect();
    return box.bottom > 0 && box.top < window.innerHeight;
  });
  require(inView, "following the banner link did not bring its source card into view");
  const sentence = (await target.locator("[data-advisory-source-status]").innerText()).trim();
  require(/^Missing \S/.test(
    sentence,
  ), `source card reached from the banner does not say what is missing: "${sentence}"`);
  await capture("advisories-source-gap");
}
