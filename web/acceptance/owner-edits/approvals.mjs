// Owner task: /approvals lists open requests first, nearest expiry first, with
// decided ones collapsed under "Recent decisions"; destructive requests carry a
// red one-line consequence; undecided fields are hidden; a requester sees why
// they can't approve their own request.
//
// State: the requester clause needs a request made by the review account
// (console-owner), not the seed's owner. It requests approval to reveal the demo
// secret, the least-impact approval-gated request: it changes nothing on any
// device, reveals nothing until another admin approves, and the console asks
// for it with a 10-minute lifetime. The server refuses any decision by the
// requester and has no withdraw, so the request is left to expire; no later
// review step approves it. The check never clicks "Reveal secret".
export const task = {
  name: "Approvals pending first",
  screenId: "d9d718034e2fb5ebeb0c9891",
  route: "/approvals",
  priority: "high",
  acceptance:
    "With the seed: the two pending requests appear above the completed one; the wipe card shows a red one-line consequence with hostname and GiB size; no 'Not decided' text appears; signed in as the requester, Approve is disabled with that reason.",
};

const timeout = 30_000;
const OWN_REQUEST_REASON = "You requested this; another admin must approve";
// Invalid: still pending on the server, but its evidence is gone (reject only).
const OPEN_STATES = ["Pending", "Approved", "Invalid"];

// One entry per approval card, in page order, read from the rendered card.
async function cards(main) {
  return main.locator("article").evaluateAll((articles) =>
    articles.map((article) => {
      const title = article.querySelector("h3");
      const details = article.querySelectorAll('[data-slot="technical-details"]');
      const last = details[details.length - 1];
      const consequence = article.querySelector('[data-slot="consequence"]');
      let expiresAt = "";
      try {
        expiresAt = JSON.parse(last?.querySelector("pre")?.textContent ?? "{}").expiresAt ?? "";
      } catch {
        expiresAt = "";
      }
      let consequenceLines = 0;
      if (consequence) {
        const lineHeight = parseFloat(getComputedStyle(consequence).lineHeight);
        const height = consequence.getBoundingClientRect().height;
        consequenceLines = Number.isFinite(lineHeight) ? Math.round(height / lineHeight) : 0;
      }
      const summary = article.closest("details")?.querySelector("summary")?.textContent ?? "";
      return {
        title: title?.textContent?.trim() ?? "",
        state: title?.nextElementSibling?.textContent?.trim() ?? "",
        recent: summary.includes("Recent decisions"),
        detailsToggles: details.length,
        detailsText: last?.textContent ?? "",
        expiresAt,
        consequence: consequence?.textContent?.trim() ?? "",
        consequenceRed: !!consequence?.classList.contains("text-destructive"),
        consequenceLines,
      };
    }),
  );
}

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  const device = demo.Devices.find((entry) => entry.ID === demo.Routes.DeviceID);
  if (!device?.Hostname) throw new Error("Demo route device has no hostname");

  step("open approvals");
  await visit("/approvals");
  const heading = main.getByRole("heading", { name: "Approval inbox", exact: true });
  await heading.waitFor({ timeout });
  await main.locator("article").first().waitFor({ timeout });
  const listed = await cards(main);
  const states = listed.map((card) => card.state);
  const open = listed.filter((card) => OPEN_STATES.includes(card.state));
  const closed = listed.filter((card) => !OPEN_STATES.includes(card.state));
  const pending = listed.filter((card) => card.state === "Pending");
  require(pending.length > 0, "No pending approval is listed");
  require(states.includes("Completed"), "No completed approval is listed");
  const firstClosed = listed.findIndex((card) => !OPEN_STATES.includes(card.state));
  const lastPending = states.lastIndexOf("Pending");
  require(firstClosed === -1 ||
    lastPending < firstClosed, `A decided request precedes a pending one: ${states.join(", ")}`);
  require(!open.some((card) => card.recent), "An open request is inside Recent decisions");
  const misplaced = closed.filter((card) => !card.recent).map((card) => card.title);
  require(misplaced.length ===
    0, `Decided requests outside Recent decisions: ${misplaced.join(", ")}`);
  const expiries = open.map((card) => Date.parse(card.expiresAt));
  const nearestFirst = expiries.every(
    (value, index) => Number.isFinite(value) && (index === 0 || expiries[index - 1] <= value),
  );
  require(nearestFirst, "Open requests are not ordered nearest expiry first");
  const recentDecisions = main.locator("details").filter({
    has: page.locator("summary", { hasText: "Recent decisions" }),
  });
  require((await recentDecisions.count()) === 1, "Recent decisions disclosure is missing");
  const collapsed = (await recentDecisions.first().getAttribute("open")) === null;
  require(collapsed, "Recent decisions is not collapsed by default");

  step("check destructive consequence");
  const wipe = pending.find(
    (card) =>
      card.title.startsWith("Wipe encrypted storage") && card.title.includes(device.Hostname),
  );
  require(!!wipe, `No pending wipe request for ${device.Hostname} is listed`);
  if (wipe) {
    const line = wipe.consequence;
    require(line.includes(device.Hostname), `Consequence omits ${device.Hostname}: "${line}"`);
    require(/\b\d+(\.\d)? GiB\b/.test(line), `Consequence has no GiB size: "${line}"`);
    require(!/\d{7,}/.test(line), "Consequence shows a raw byte count");
    require(line.includes("cannot be undone"), "Consequence omits irreversibility");
    require(wipe.consequenceRed, "Consequence is not red");
    require(wipe.consequenceLines === 1, `Consequence spans ${wipe.consequenceLines} lines`);
    require(wipe.detailsToggles === 1, `Wipe card has ${wipe.detailsToggles} Details toggles`);
    const exact = /Exact size: [\d,]+ bytes/.test(wipe.detailsText);
    require(exact, "Exact wipe size is not in Details");
  }
  const notDecided = main.getByText("Not decided");
  require((await notDecided.count()) === 0, "'Not decided' text is present on the page");
  await capture("inbox-pending-first");

  step("expand recent decisions");
  // Direct child only: cards inside the disclosure have their own Details summaries.
  const summary = recentDecisions.first().locator(":scope > summary");
  await summary.click();
  const expanded = (await recentDecisions.first().getAttribute("open")) !== null;
  require(expanded, "Recent decisions does not expand");
  require((await notDecided.count()) === 0, "'Not decided' text is present in Recent decisions");
  await capture("recent-decisions-expanded");
  await summary.click();

  step("request approval as the review account");
  // Least-impact approval-gated request; see the header comment.
  await visit(`/secrets/${demo.Routes.SecretID}`);
  const requestApproval = main.getByRole("button", { name: "Request approval", exact: true });
  await requestApproval.waitFor({ timeout });
  const reason = main.locator('textarea[id^="secret-reveal-"][id$="-reason"]');
  const confirmation = main.locator('input[id^="secret-reveal-"][id$="-confirmation"]');
  const confirmationId = await confirmation.getAttribute("id");
  const name = main.locator(`label[for="${confirmationId}"] span`);
  await reason.fill("Owner edit acceptance: a requester must not approve their own request");
  await confirmation.fill((await name.innerText()).trim());
  await requestApproval.click();
  const waiting = main.getByText("Approval: waiting for another admin.");
  await waiting.waitFor({ timeout });
  const approvalItem = main
    .locator('[data-slot="technical-details"] div')
    .filter({ hasText: /^Approval ID:/ })
    .first();
  const approvalId = ((await approvalItem.locator("dd").textContent()) ?? "").trim();
  if (!/^[0-9a-f-]{36}$/.test(approvalId)) throw new Error("The new approval ID was not shown");

  step("check own request");
  await visit("/approvals");
  const articles = main.locator("article");
  await articles.first().waitFor({ timeout });
  // The ID is only in the card's collapsed Details, so match on DOM text.
  const index = await articles.evaluateAll(
    (nodes, id) => nodes.findIndex((node) => node.textContent?.includes(id)),
    approvalId,
  );
  if (index < 0) throw new Error("The new approval request is not listed");
  const own = articles.nth(index);
  const ownIsRecent = await own.evaluate((article) => !!article.closest("details"));
  require(!ownIsRecent, "The new pending request is not among open requests");
  const approve = own.getByRole("button", { name: "Approve", exact: true });
  require((await approve.count()) === 1, "Own request shows no Approve button");
  if ((await approve.count()) === 1) {
    require(await approve.isDisabled(), "Approve is enabled on the viewer's own request");
    const describedBy = (await approve.getAttribute("aria-describedby")) ?? "";
    const description = own.locator(`[id="${describedBy}"]`);
    const explained = describedBy ? ((await description.textContent()) ?? "") : "";
    require(explained.includes(
      OWN_REQUEST_REASON,
    ), "Disabled Approve is not described by its reason");
  }
  const visibleReason = own.getByText(OWN_REQUEST_REASON);
  require((await visibleReason.count()) === 1 &&
    (await visibleReason.isVisible()), `Own request does not show "${OWN_REQUEST_REASON}"`);
  const decisionField = own.getByRole("textbox", { name: "Approval decision reason" });
  require((await decisionField.count()) === 0, "Own request offers a decision reason field");
  await own.scrollIntoViewIfNeeded();
  await settle();
  await capture("requester-approve-disabled");
}
