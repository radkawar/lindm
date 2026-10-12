// Owner tasks on a secret's page: no raw profile-reference JSON, only guidance
// to choose it in a profile; a single-spaced, forgiving typed confirmation that
// still names the secret; Reveal secret and Request approval are not
// equal-weight buttons. Read-only: fields are typed, nothing is sent.
export const task = {
  name: "Secret page reference guidance and reveal confirmation",
  screenId: "",
  route: "/secrets/$secretId",
  priority: "normal",
  acceptance:
    "The Office Wi-Fi page shows no secretId/subjectBindingId/SECRET_PURPOSE JSON (even in Details) and says how to use it from a profile; 'Type Office Wi-Fi to confirm' is single-spaced, accepts 'officewifi' and rejects 'office'; Reveal secret and Request approval differ in visual weight.",
};

const PROFILE = "Office network";

export async function check({ page, demo, visit, settle, require, capture, step }) {
  const timeout = 30_000;
  const main = page.getByRole("main");

  step("open the secret page");
  await visit(`/secrets/${demo.Routes.SecretID}`);
  const reveal = main.getByRole("button", { name: "Reveal secret", exact: true });
  const approval = main.getByRole("button", { name: "Request approval", exact: true });
  await reveal.waitFor({ timeout });
  await main.getByRole("link", { name: PROFILE }).first().waitFor({ timeout });
  await settle();

  step("no raw reference JSON");
  // textContent includes collapsed Details.
  const text = (await main.textContent()) ?? "";
  for (const raw of ["subjectBindingId", "SECRET_PURPOSE_", '"secretId"'])
    require(!text.includes(raw), `The secret page shows raw reference text '${raw}'`);
  // Wi-Fi keys: the editor can't add network connections, and says so.
  const guidance = main.getByRole("link", { name: /^(edit a profile|profile editor)$/ });
  require((await guidance.count()) ===
    1, "The secret page does not say how to use it from a profile");

  step("reveal controls");
  const background = (button) => button.evaluate((node) => getComputedStyle(node).backgroundColor);
  require((await background(reveal)) !==
    (await background(approval)), "Reveal secret and Request approval have equal visual weight");
  const label = main.locator('label[for$="-confirmation"]');
  const gap = await label.evaluate((node) => {
    const text = node.firstChild;
    const name = node.querySelector("span");
    if (!text || text.nodeType !== Node.TEXT_NODE || !name) return null;
    const range = document.createRange();
    range.setStart(text, 0);
    range.setEnd(text, "Type".length);
    return name.getBoundingClientRect().left - range.getBoundingClientRect().right;
  });
  require(gap !== null &&
    gap <
      6, `The confirmation label spaces 'Type' and the name ${gap === null ? "unexpectedly" : `${gap.toFixed(1)}px`} apart`);
  const input = main.locator(`[id="${await label.getAttribute("for")}"]`);
  await input.fill("officewifi");
  require((await input.getAttribute("aria-invalid")) ===
    "false", "Typing the name without capitals or spaces is not accepted");
  await capture("reveal-confirmation-accepted");
  await input.fill("office");
  require((await input.getAttribute("aria-invalid")) ===
    "true", "A partial name is not marked as not matching");
  await input.fill("");
}
