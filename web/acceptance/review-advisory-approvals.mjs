// Inspect real seeded proposals without approving, rejecting, or accepting risk.
// Filling review reasons makes the missing-evidence safety boundary observable
// rather than passing merely because both controls start disabled on empty input.
export async function reviewAdvisoryControls(page, route) {
  if (route === "/devices/$deviceId/findings") return proposalForm(page);
  if (route !== "/approvals") return [];
  const findings = [];
  for (const fixture of [
    {
      reason: "Review the isolated management-network exposure before the scheduled patch window",
      approvable: true,
    },
    {
      reason: "Review stopped because finding evidence is unavailable",
      approvable: false,
    },
  ]) {
    const card = page.locator("article").filter({ hasText: fixture.reason });
    if ((await card.count()) !== 1) {
      findings.push({
        message: "Expected one real advisory approval fixture",
        elements: [fixture.reason],
      });
      continue;
    }
    const reason = card.getByRole("textbox", { name: "Approval decision reason", exact: true });
    if ((await reason.count()) !== 1) {
      findings.push({
        message: "Independent reviewer controls are unavailable",
        elements: [fixture.reason],
      });
      continue;
    }
    await reason.fill("Review the package, device and expiry before deciding");
    const approve = card.getByRole("button", { name: "Approve", exact: true });
    const reject = card.getByRole("button", { name: "Reject", exact: true });
    if ((await approve.isEnabled()) !== fixture.approvable)
      findings.push({
        message: "Approval availability does not match finding evidence",
        elements: [fixture.reason],
      });
    if (!(await reject.isEnabled()))
      findings.push({
        message: "Unavailable evidence must not prevent rejection",
        elements: [fixture.reason],
      });
    if (!fixture.approvable && (await card.getByRole("alert").count()) === 0)
      findings.push({
        message: "Missing finding evidence has no visible warning",
        elements: [fixture.reason],
      });
  }
  return findings;
}

async function proposalForm(page) {
  const accepted = page.locator("tr").filter({ hasText: "Risk accepted by" });
  if ((await accepted.count()) === 0)
    return [{ message: "No real accepted finding is visible", elements: [] }];
  for (const card of await accepted.all()) {
    if (
      (await card.getByText(/ until /).count()) !== 1 ||
      (await card.getByText(/Acceptance expire[ds]/).count()) !== 0
    )
      return [
        {
          message: "Acceptance expiry must be exact evidence, independent of finding freshness",
          elements: [],
        },
      ];
  }
  const summary = page.getByText("Accept this risk", { exact: true }).first();
  if ((await summary.count()) === 0)
    return [{ message: "No seeded finding offers risk proposal", elements: [] }];
  await summary.click();
  const approval = page.getByRole("checkbox", {
    name: "Ask another administrator to approve first (they have one hour to decide)",
    exact: true,
  });
  if (!(await approval.isChecked()))
    return [{ message: "Risk proposals must default to independent approval", elements: [] }];
  if (
    !(await page.getByRole("button", { name: "Propose risk acceptance", exact: true }).isVisible())
  )
    return [{ message: "Approval-aware proposal action is missing", elements: [] }];
  await page.keyboard.press("Escape");
  return [];
}
