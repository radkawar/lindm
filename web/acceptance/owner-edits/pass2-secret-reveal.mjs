// Owner pass 2 finding 47: a revealed secret has Copy (raw value) and a visible
// auto-hide countdown, like the recovery-key reveal.
//
// The demo has another admin, so the reveal needs approval: the check creates
// an admin who approves in its own browser, then reveals on the review page,
// completing the in-page "Verify it's you" when the server asks for it.
// State (registered late): one new admin account, one approved and consumed
// secret reveal approval (audited).
import {
  createAdmin,
  requireFormRestored,
  requireRevealedAlone,
  revealAfterApproval,
} from "./second-admin.mjs";

const reason = "Owner pass 2 check: copy the value";
const revealName = "Reveal secret";

export const task = {
  name: "Revealed secret has copy and countdown",
  screenId: "owner-pass2-secret-reveal",
  route: "/secrets/$secretId",
  priority: "medium",
  acceptance:
    "A revealed secret shows only the value with a visible 'Hides in N s' countdown, Copy (raw value), Hide now and the recorded reason; the request form returns after hiding.",
};

export async function check({ page, config, demo, visit, require, capture, step }) {
  const { SecretID } = demo.Routes;
  if (!SecretID) throw new Error("Demo seed has no secret");
  const main = page.getByRole("main");

  step("create a second admin to approve");
  const admin = await createAdmin({ page, visit });

  step("open secret");
  await visit(`/secrets/${SecretID}`);
  await main.getByRole("button", { name: revealName }).waitFor({ timeout: 30_000 });
  require(await main
    .getByText("The value disappears after 30 seconds or when you leave this page.")
    .isVisible(), "Reveal does not say when the value hides");

  step("request approval, approve as the second admin, reveal");
  const prompt = (
    await main
      .getByText(/^Type .+ to confirm$/)
      .first()
      .innerText()
  ).trim();
  const name = prompt.replace(/^Type /, "").replace(/ to confirm$/, "");
  await main.getByLabel("Reason", { exact: true }).fill(reason);
  await main.getByLabel(prompt).fill(name);
  const { value, refusal } = await revealAfterApproval({
    page,
    config,
    admin,
    refreshName: "Check approval",
    revealName,
    valueLabel: "Secret value",
    failureTitle: "Secret not revealed",
  });
  if (!value) throw new Error(`The approved reveal did not show the value: ${refusal}`);

  step("only the value while revealed");
  await requireRevealedAlone({ main, require, reason, revealName });

  step("countdown, copy, hide");
  const countdown = (await main.locator("[data-reveal-countdown]").innerText()).trim();
  require(/^Hides in \d+ s\b/.test(
    countdown,
  ), `No visible auto-hide countdown (got ${JSON.stringify(countdown)})`);
  const shown = await value.innerText();
  await main.getByRole("button", { name: "Copy", exact: true }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  require(copied.trim().length > 0 &&
    copied.trim() === shown.trim(), "Copy did not copy the shown value");
  // The demo fixture's disposable secret; the owner asked to see the revealed state.
  await capture("pass2-secret-reveal");
  await main.getByRole("button", { name: "Hide now", exact: true }).click();
  require(!(await value.isVisible()), "Hide now left the value visible");
  await requireFormRestored({ main, require, revealName });
}
