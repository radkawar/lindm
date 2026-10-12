// Owner pass 2 finding 11: a wrong password or unknown username at sign-in said
// "Sign-in required — Your session could not authorize this request." Both now
// say "Username or password is incorrect." with the same server reason, so the
// page reveals nothing about which accounts exist.
//
// State: one refused password attempt for the review account (lockout needs
// five; a later successful sign-in clears it) and one for an unknown name, in a
// separate signed-out browser context. The review session is untouched.
export const task = {
  name: "Sign-in refusal says what to fix",
  screenId: "owner-pass2-p2-11-sign-in-error",
  route: "/",
  priority: "high",
  acceptance:
    "Signed out, a wrong password and an unknown username both show 'Username or password is incorrect.' (identically), never 'Sign-in required' or 'Your session could not authorize this request'.",
};

const timeout = 30_000;
const TITLE = "Username or password is incorrect.";

export async function check({ page, config, require, capture, step }) {
  const context = await page
    .context()
    .browser()
    .newContext({ ignoreHTTPSErrors: true, viewport: page.viewportSize() ?? undefined });
  try {
    const signedOut = await context.newPage();
    const attempt = async (username, password) => {
      await signedOut.goto(`${config.origin}/`);
      const form = signedOut.locator("form").filter({
        has: signedOut.getByRole("button", { name: "Sign in locally", exact: true }),
      });
      await form.waitFor({ timeout });
      await signedOut.getByLabel("Username", { exact: true }).fill(username);
      await signedOut.getByLabel("Password", { exact: true }).fill(password);
      await signedOut.getByRole("button", { name: "Sign in locally", exact: true }).click();
      const alert = form.getByRole("alert").or(form.locator('[data-slot="alert"]')).first();
      await alert.waitFor({ timeout });
      return (await alert.innerText()).replace(/Details for support[\s\S]*/, "").trim();
    };

    step("wrong password");
    // The review account; one refusal is far below the lockout threshold.
    const wrong = await attempt("console-owner", "not the password 123!");
    require(wrong.includes(TITLE), `Wrong password shows "${wrong}"`);
    require(!/Sign-in required|could not authorize/.test(
      wrong,
    ), "Wrong password still says the session could not authorize");
    await capture("wrong-password", signedOut);

    step("unknown username");
    const unknown = await attempt("no-such-admin", "not the password 123!");
    require(unknown === wrong, `Unknown username shows "${unknown}", wrong password "${wrong}"`);
  } finally {
    await context.close();
  }
}
