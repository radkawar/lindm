// Owner pass 2 finding 47: a revealed secret has Copy (raw value) and a visible
// auto-hide countdown, like the recovery-key reveal. State-changing: a reveal
// attempt is audited, so this check is registered late.
export const task = {
  name: "Revealed secret has copy and countdown",
  screenId: "owner-pass2-secret-reveal",
  route: "/secrets/$secretId",
  priority: "medium",
  acceptance:
    "A revealed secret shows a visible 'Hides in N s' countdown, a Copy button that copies the raw value, and Hide now.",
};

export async function check({ page, demo, visit, require, capture, step }) {
  const { SecretID } = demo.Routes;
  require(Boolean(SecretID), "Demo seed has no secret");
  const main = page.getByRole("main");

  step("open secret");
  await visit(`/secrets/${SecretID}`);
  const reveal = main.getByRole("button", { name: "Reveal secret" });
  await reveal.waitFor({ timeout: 30_000 });
  require(await main
    .getByText("The value disappears after 30 seconds or when you leave this page.")
    .isVisible(), "Reveal does not say when the value hides");

  step("reveal");
  const prompt = (
    await main
      .getByText(/^Type .+ to confirm$/)
      .first()
      .innerText()
  ).trim();
  const name = prompt.replace(/^Type /, "").replace(/ to confirm$/, "");
  await main.getByLabel("Reason", { exact: true }).fill("Owner pass 2 check: copy the value");
  await main.getByLabel(prompt).fill(name);
  await page.bringToFront();
  await reveal.click();
  const value = main.getByLabel("Secret value", { exact: true });
  const refused = main.getByText(/^(Secret not revealed|Verify your identity)$/).first();
  await value.or(refused).first().waitFor({ timeout: 30_000 });
  if (!(await value.isVisible())) {
    // Revealing needs fresh WebAuthn step-up or a second approver, which a
    // headless review session cannot provide; the refusal must be plain.
    require(!/protobuf|invalid_argument|permission_denied/i.test(
      await main.innerText(),
    ), "Refusal shows raw error text");
    await capture("pass2-secret-reveal-refused");
    return;
  }

  step("countdown, copy, hide");
  const countdown = (await main.locator("[data-reveal-countdown]").innerText()).trim();
  require(/^Hides in \d+ s\b/.test(
    countdown,
  ), `No visible countdown (got ${JSON.stringify(countdown)})`);
  const shown = (await value.innerText()).trim();
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
  await main.getByRole("button", { name: "Copy", exact: true }).click();
  require((await page.evaluate(() => navigator.clipboard.readText())) ===
    shown, "Copy did not copy the shown value");
  await capture("pass2-secret-reveal");
  await main.getByRole("button", { name: "Hide now" }).click();
  require(!(await value.isVisible()), "Hide now left the value visible");
}
