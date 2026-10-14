// SPDX-License-Identifier: Apache-2.0

import { openNavigationPage } from "../review-navigation.mjs";

// Owner pass 2, bug 4: after approving the pending device, Enrollment still said
// "1 device waiting for approval / Awaiting approval", even after Refresh. The
// server reported an approved reservation as still pending: the device only
// finishes enrolling once the token's creator runs the approval. Enrollment now
// says it is approved and waiting to finish, right after the decision, without
// a page reload, and Refresh keeps that answer.
//
// State: approves the seed's pending enrollment approval as the review account
// (an independent admin; the seed's owner requested it). Registered last: the
// approvals and enrollment checks before it read the undecided seed. It never
// runs the approved payload, so no device certificate is issued.
export const task = {
  name: "Enrollment updates after approval",
  screenId: "owner-pass2-bug4-enrollment-stale",
  route: "/enrollment",
  priority: "high",
  acceptance:
    "Approve the pending device in the inbox, return to Enrollment in-app: no 'waiting for approval' heading or 'Awaiting approval' row remains; the device shows 'Approved, not finished' under '1 device approved, waiting to finish enrolling', also after Refresh, with no page reload.",
};

const timeout = 30_000;
const WAITING = /^(\d+) devices? waiting for approval/;
const APPROVED = /^1 device approved, waiting to finish enrolling$/;

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  const pendingDevice = (demo?.Devices ?? []).find((device) => device.State === "pending");
  if (!pendingDevice) throw new Error("The demo seed has no pending device");

  step("open enrollment");
  await visit("/enrollment");
  const waiting = main.getByRole("heading", { name: WAITING });
  await waiting.waitFor({ timeout });
  // Any full reload from here on drops this marker.
  await page.evaluate(() => {
    window.__ownerPass2NoReload = true;
  });

  step("approve in the inbox");
  // In-app navigation (client-side links), never a page load.
  await main.locator('a[href="/approvals"]').filter({ hasText: "Open approval inbox" }).click();
  await main.getByRole("heading", { name: "Approval inbox", exact: true }).waitFor({ timeout });
  const articles = main.locator("article");
  await articles.first().waitFor({ timeout });
  // The device ID is only in the card's collapsed Details, so match on DOM text.
  const index = await articles.evaluateAll(
    (nodes, id) =>
      nodes.findIndex(
        (node) =>
          node.querySelector("h3")?.textContent?.startsWith("Approve device enrollment") &&
          node.textContent?.includes(id),
      ),
    pendingDevice.ID,
  );
  if (index < 0) throw new Error("The pending device's enrollment approval is not listed");
  const card = articles.nth(index);
  await card
    .getByRole("textbox", { name: "Approval decision reason" })
    .fill("Owner pass 2: Enrollment must update after this approval");
  await card.getByRole("button", { name: "Approve", exact: true }).click();
  // The list refetches and may reorder; find the card again by its device.
  await page.waitForFunction(
    (id) =>
      [...document.querySelectorAll("main article")].some(
        (node) =>
          node.querySelector("h3")?.textContent?.startsWith("Approve device enrollment") &&
          node.textContent?.includes(id) &&
          node.querySelector("h3")?.nextElementSibling?.textContent?.trim() === "Approved",
      ),
    pendingDevice.ID,
    { timeout },
  );

  step("return to enrollment in-app");
  await openNavigationPage(page, "Enrollment");
  const approved = main.getByRole("heading", { name: APPROVED });
  await approved.waitFor({ timeout });
  await settle();
  const assertApproved = async (when) => {
    require((await main.getByRole("heading", { name: WAITING }).count()) ===
      0, `A 'waiting for approval' heading remains ${when}`);
    require((await main.getByText("Awaiting approval", { exact: true }).count()) ===
      0, `An 'Awaiting approval' row remains ${when}`);
    require((await approved.count()) === 1, `No 'approved, waiting to finish' heading ${when}`);
    const section = main.getByRole("region", { name: APPROVED });
    require((await section.getByText("Approved, not finished", { exact: true }).count()) ===
      1, `The approved device has no 'Approved, not finished' badge ${when}`);
  };
  await assertApproved("after the approval");
  await capture("approved-waiting-to-finish");

  step("refresh keeps the server's answer");
  // The page's one Refresh, in its header, rereads every enrollment list.
  const refresh = main.getByRole("button", { name: "Refresh", exact: true });
  require((await refresh.count()) ===
    1, `Enrollment shows ${await refresh.count()} Refresh buttons`);
  await refresh.first().click();
  await settle();
  await approved.waitFor({ timeout });
  await assertApproved("after Refresh");
  require(await page.evaluate(() => window.__ownerPass2NoReload === true), "The page reloaded");
}
