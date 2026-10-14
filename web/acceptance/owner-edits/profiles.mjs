// SPDX-License-Identifier: Apache-2.0

// Owner pass 2, Profiles list and detail: no page-size control when every
// profile fits on one page; the "publishing doesn't change devices" hint at most
// once per screen and linking to Rollouts; publishers named, not "Another
// administrator"; a firewall zone named by what it binds, its UUID only in
// Details. Read-only.
export const task = {
  name: "Profiles list and detail",
  screenId: "owner-pass2-profiles",
  route: "/profiles",
  priority: "normal",
  acceptance:
    "With the seeded profiles on one page there is no Page size control; the rollout hint appears at most once per screen and links to Rollouts; Published by names the account; the seeded firewall zone is shown by its interfaces and networks, its UUID only inside Details.",
};

const timeout = 30_000;
// One explicit statement of the publish/rollout relationship.
const HINT = /Publishing does not change devices/g;
const GENERIC_PUBLISHER = /^(You|Another administrator|The system)$/;
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

// Rendered text outside closed <details> (TechnicalDetails is one).
function primaryText(root) {
  return root.evaluate((node) => {
    const parts = [];
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
    for (let text = walker.nextNode(); text; text = walker.nextNode()) {
      const element = text.parentElement;
      if (!element?.checkVisibility()) continue;
      let hidden = false;
      for (let details = element.closest("details"); details;) {
        const summary = [...details.children].find((child) => child.tagName === "SUMMARY");
        if (!details.open && !summary?.contains(text)) hidden = true;
        details = details.parentElement?.closest("details") ?? null;
      }
      if (!hidden) parts.push(text.textContent ?? "");
    }
    return parts.join(" ").replace(/\s+/g, " ");
  });
}

async function hintOnce(main, require, screen) {
  const text = await primaryText(main);
  const count = text.match(HINT)?.length ?? 0;
  require(count <= 1, `${screen} states the publish/rollout hint ${count} times`);
  const hints = main.locator("[data-profile-rollout-hint]");
  require((await hints.count()) <= 1, `${screen} has more than one rollout hint`);
  if ((await hints.count()) === 1) {
    require((await hints.getByRole("link", { name: "Rollouts" }).getAttribute("href"))?.startsWith(
      "/rollouts",
    ), `${screen} hint doesn't link to Rollouts`);
  }
  return (await hints.count()) === 1 ? count : 0;
}

export async function check({ page, demo, visit, require, capture, step }) {
  const main = page.getByRole("main");

  step("profile list");
  await visit("/profiles");
  const rows = main.locator("tbody tr");
  await rows.first().waitFor({ timeout });
  const shown = await rows.count();
  // A page-size choice belongs with the paging controls, and only when there is
  // more than one page: never as a standalone control above a short list.
  const pager = main.getByRole("navigation", { name: "Profile pages" });
  const paged = (await pager.count()) === 1;
  const sizeControls = main.getByRole("combobox", { name: /page size|rows per page/i });
  const outside = await main
    .getByText(/^(Page size|Rows per page)$/)
    .evaluateAll((nodes) => nodes.filter((node) => !node.closest("nav")).length);
  require(outside === 0, "a page-size control stands apart from the paging controls");
  if (paged) {
    require((await pager.getByRole("button", { name: "Next page" }).isEnabled()) ||
      (await pager
        .getByRole("button", { name: /^(First|Previous) page$/ })
        .isEnabled()), "paging controls are shown but none can move");
  } else {
    require((await sizeControls.count()) === 0 &&
      (await main.getByRole("button", { name: /^(First|Previous|Next) page$/ }).count()) ===
        0, `paging or page-size controls are shown for ${shown} profiles on one page`);
  }
  require((await hintOnce(main, require, "the profile list")) ===
    1, "the profile list doesn't say that publishing doesn't change devices");
  const publishers = main.locator("[data-profile-publisher]");
  require((await publishers.count()) === shown, "Published by isn't shown for every profile");
  for (const text of await publishers.allInnerTexts()) {
    const name = text.trim().replace(/ \(you\)$/, "");
    require(!GENERIC_PUBLISHER.test(name) &&
      name !== "", `Published by says "${text.trim()}", not the account's name`);
  }
  require((await main.locator("tbody details").count()) ===
    0, "list rows still carry a Details toggle");
  await capture("profile list");

  step("profile detail");
  await visit(`/profiles/${encodeURIComponent(demo.Routes.ProfileID)}`);
  const version = main.locator("[data-profile-version]");
  await version.waitFor({ timeout });
  await main.locator("[data-profile-publisher]").first().waitFor({ timeout });
  const publisher = (await main.locator("[data-profile-publisher]").first().innerText())
    .replace(/^Published .* by /s, "")
    .replace(/ \(you\)$/, "")
    .trim();
  require(!GENERIC_PUBLISHER.test(publisher) &&
    publisher !== "", `detail Published by says "${publisher}"`);
  await hintOnce(main, require, "the profile page");
  await capture("profile detail");

  step("firewall zone named");
  const firewallProfile = demo.Routes.FirewallProfileID;
  require(firewallProfile, "seed has no firewall-zone profile");
  if (!firewallProfile) return;
  await visit(`/profiles/${encodeURIComponent(firewallProfile)}`);
  await main.locator("[data-profile-version]").waitFor({ timeout });
  // A manager sees the draft; the published settings stay one click away.
  const published = main.locator("[data-profile-published-settings]");
  if ((await published.count()) === 1) await published.locator(":scope > summary").click();
  const setting = main.locator("[data-profile-setting]").first();
  await setting.waitFor({ timeout });
  const zoneText = await primaryText(setting);
  require(/Unnamed zone on wlan0 for 192\.168\.50\.0\/24/.test(
    zoneText,
  ), `firewall zone isn't described by its binding: "${zoneText.slice(0, 160)}"`);
  const pageText = await primaryText(main);
  require(!UUID.test(pageText), `a UUID is visible outside Details: ${pageText.match(UUID)?.[0]}`);
  const editor = main.locator("[data-profile-editor]");
  if ((await editor.count()) === 1) {
    const remove = editor.getByRole("button", { name: /^Remove setting 1: / });
    require(/Unnamed zone on wlan0/.test(
      (await remove.getAttribute("aria-label")) ?? "",
    ), "the editor's zone setting isn't named by its binding");
  }
  await capture("firewall zone named");
}
