// Owner pass 2 (Safety → Approvals): an empty decision reason explains why
// Approve and Reject are disabled; a risk acceptance whose finding the device
// no longer reports reads as Invalid with no way to approve it, even with a
// reason; each card states every fact once (no repeated labels, and an open
// wipe's consequence line is not repeated as a Mode/Target/Size block).
//
// State: read-only. Reasons are typed and cleared again; no decision is sent.
// The seed proposes one risk acceptance against a finding UUID that does not
// exist on the device, which the server reports as evidence unavailable.
export const task = {
  name: "Approvals reason hint, invalid evidence and single facts",
  screenId: "owner-pass2-safety-approvals",
  route: "/approvals",
  priority: "high",
  acceptance:
    "With the seed: an empty decision reason shows 'Enter a reason for your decision' describing the disabled Approve and Reject; the risk acceptance whose finding is gone is badged Invalid, explains why, and its Approve stays disabled after a reason is typed; no card repeats a fact label, and the wipe card shows its consequence line without a Mode/Target/Size block.",
};

const timeout = 30_000;
const HINT =
  /^Enter a reason (?:for your decision|to reject this request)\. lindm records the reason in the audit log\.$/;
const EVIDENCE_GONE = "The device no longer reports this finding. You cannot approve this request.";

// Facts per card: every <dt> label (primary and Details), and primary-text
// labels outside Details that would duplicate the consequence line.
function cardFacts(main) {
  return main.locator("article").evaluateAll((articles) =>
    articles.map((article) => {
      const title = article.querySelector("h3")?.textContent?.trim() ?? "";
      const labels = [...article.querySelectorAll("dt")].map((term) =>
        (term.textContent ?? "").trim().replace(/:\s*$/, ""),
      );
      const duplicates = labels.filter((label, index) => labels.indexOf(label) !== index);
      const primary = [...article.querySelectorAll("dt")]
        .filter((term) => !term.closest('[data-slot="technical-details"]'))
        .map((term) => (term.textContent ?? "").trim().replace(/:\s*$/, ""));
      const outside = article.cloneNode(true);
      outside.querySelectorAll('[data-slot="technical-details"]').forEach((node) => node.remove());
      return {
        title,
        state: article.querySelector("h3")?.nextElementSibling?.textContent?.trim() ?? "",
        duplicates,
        primary,
        consequence: !!article.querySelector('[data-slot="consequence"]'),
        modeLine: /\bMode:/.test(outside.textContent ?? ""),
      };
    }),
  );
}

async function describedText(card, control) {
  const ids = ((await control.getAttribute("aria-describedby")) ?? "").split(/\s+/).filter(Boolean);
  const texts = [];
  for (const id of ids)
    texts.push(((await card.locator(`[id="${id}"]`).textContent()) ?? "").trim());
  return texts;
}

export async function check({ page, visit, require, capture, step }) {
  const main = page.getByRole("main");

  step("open approvals");
  await visit("/approvals");
  await main.getByRole("heading", { name: "Approval inbox", exact: true }).waitFor({ timeout });
  await main.locator("article").first().waitFor({ timeout });

  step("check single facts per card");
  const facts = await cardFacts(main);
  for (const card of facts) {
    require(card.duplicates.length ===
      0, `"${card.title}" repeats ${[...new Set(card.duplicates)].join(", ")}`);
    const banned = card.primary.filter((label) => ["Permission", "Target", "Size"].includes(label));
    require(banned.length === 0, `"${card.title}" shows ${banned.join(", ")} beside its title`);
    if (card.consequence)
      require(!card.modeLine, `"${card.title}" repeats its consequence as a Mode block`);
  }
  const wipe = facts.find(
    (card) => card.title.startsWith("Wipe encrypted storage") && card.consequence,
  );
  require(!!wipe, "No open wipe request with a consequence line is listed");

  step("check reason hint");
  const decidable = main
    .locator("article")
    .filter({ has: page.getByRole("textbox", { name: "Approval decision reason" }) })
    .filter({ hasNot: page.locator('[role="alert"]') });
  require((await decidable.count()) > 0, "No request offers a decision to this reviewer");
  if ((await decidable.count()) > 0) {
    const card = decidable.first();
    const field = card.getByRole("textbox", { name: "Approval decision reason" });
    await field.fill("");
    for (const name of ["Approve", "Reject"]) {
      const button = card.getByRole("button", { name, exact: true });
      require(await button.isDisabled(), `${name} is enabled with an empty reason`);
      const described = await describedText(card, button);
      require(described.some((text) =>
        HINT.test(text),
      ), `Disabled ${name} is not described by the reason hint`);
    }
    const hint = card.getByText(HINT);
    require((await hint.count()) === 1 &&
      (await hint.isVisible()), "The reason hint is not visible while the reason is empty");
    // Full-page captures start at scroll zero (fixed header and sidebar).
    await page.evaluate(() => window.scrollTo(0, 0));
    await capture("reason-hint");
    await field.fill("Owner pass 2 acceptance: typed, never submitted");
    require((await card.getByText(HINT).count()) === 0, "The reason hint stays after typing");
    await field.fill("");
  }

  step("check invalid evidence");
  const advisory = main
    .locator("article")
    .filter({ has: page.locator("h3", { hasText: /^Accept advisory risk/ }) });
  const invalid = advisory.filter({
    has: page.locator('[data-slot="badge"]', { hasText: /^Invalid$/ }),
  });
  require((await invalid.count()) >
    0, "No risk acceptance with missing evidence is badged Invalid");
  const stale = await advisory.evaluateAll(
    (articles, explanation) =>
      articles
        .filter((article) => (article.textContent ?? "").includes(explanation))
        .map((article) => article.querySelector('[data-slot="badge"]')?.textContent?.trim() ?? ""),
    EVIDENCE_GONE,
  );
  const unmarked = stale.filter((badge) => badge !== "Invalid");
  require(unmarked.length === 0, `Evidence-gone requests are badged ${unmarked.join(", ")}`);
  if ((await invalid.count()) > 0) {
    const card = invalid.first();
    const explanation = card.getByRole("alert").filter({ hasText: EVIDENCE_GONE });
    require((await explanation.count()) === 1 &&
      (await explanation.isVisible()), "The Invalid request does not explain why");
    const approve = card.getByRole("button", { name: "Approve", exact: true });
    for (let index = 0; index < (await approve.count()); index++)
      require(await approve.nth(index).isDisabled(), "An Invalid request has an enabled Approve");
    const field = card.getByRole("textbox", { name: "Approval decision reason" });
    if ((await field.count()) === 1 && (await approve.count()) === 1) {
      await field.fill("Owner pass 2 acceptance: typed, never submitted");
      require(await approve.isDisabled(), "Approve enables on an Invalid request once a reason is typed");
      const described = await describedText(card, approve);
      require(described.some((text) =>
        text.includes(EVIDENCE_GONE),
      ), "Disabled Approve is not described by the evidence explanation");
      const reject = card.getByRole("button", { name: "Reject", exact: true });
      require(await reject.isEnabled(), "An Invalid request cannot be rejected");
      await field.fill("");
    }
    await page.evaluate(() => window.scrollTo(0, 0));
    await capture("invalid-evidence");
  }
  const runs = main.getByRole("button", { name: "Accept approved risk", exact: true });
  for (let index = 0; index < (await runs.count()); index++) {
    const card = main.locator("article").filter({ has: runs.nth(index) });
    if ((await card.getByText(EVIDENCE_GONE, { exact: false }).count()) > 0)
      require(await runs.nth(index).isDisabled(), "Approved risk with missing evidence can be run");
  }
}
