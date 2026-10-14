// SPDX-License-Identifier: Apache-2.0

// Owner decision (pass 2): a reveal needs a second approver whenever another
// enabled admin could approve it; a sole admin reveals alone. The seeded demo
// has two admins (the review owner plus the seeded admin), so the console must
// say why approval is needed next to Reveal on the device Encryption tab and the
// secret page, and route the secret reveal through Request approval. Read-only:
// nothing is requested or revealed.
export const task = {
  name: "Reveal approval rule",
  screenId: "pass2-reveal-approval",
  route: "/secrets/$secretId",
  priority: "high",
  acceptance:
    "With two admins in the demo, Encryption and the secret page show 'Needs approval: another admin can approve.' next to Reveal; the secret's Reveal waits for approval and Request approval is offered.",
};

const RULE = "Needs approval: another admin can approve.";
const timeout = 30_000;

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const { DeviceID, SecretID } = demo.Routes;
  const main = page.getByRole("main");

  step("device Encryption tab states the rule next to Reveal");
  await visit(`/devices/${DeviceID}`);
  await main.getByRole("tab", { name: "Encryption", exact: true }).click();
  const panel = main.locator('[role="tabpanel"]:not([hidden])');
  await panel
    .getByRole("button", { name: "Reveal recovery key", exact: true })
    .waitFor({ timeout });
  await settle();
  const encryptionRule = panel.locator('[data-slot="reveal-approval"]');
  require((await encryptionRule.count()) === 1, "Encryption tab shows no reveal approval rule");
  require((await encryptionRule.first().innerText()).trim() ===
    RULE, `Encryption rule sentence is ${JSON.stringify(await encryptionRule.first().innerText())}`);
  await capture("encryption");

  step("secret page states the rule and routes to approval");
  await visit(`/secrets/${SecretID}`);
  const reveal = main.getByRole("button", { name: "Reveal secret", exact: true });
  await reveal.waitFor({ timeout });
  await settle();
  const secretRule = main.locator('[data-slot="reveal-approval"]');
  require((await secretRule.count()) === 1, "Secret page shows no reveal approval rule");
  require((await secretRule.first().innerText()).trim() ===
    RULE, `Secret rule sentence is ${JSON.stringify(await secretRule.first().innerText())}`);
  require(await reveal.isDisabled(), "Reveal secret is enabled before another admin approves");
  require((await main.getByRole("button", { name: "Request approval", exact: true }).count()) ===
    1, "Secret page does not offer Request approval");
  await secretRule.first().scrollIntoViewIfNeeded();
  await capture("secret");
}
