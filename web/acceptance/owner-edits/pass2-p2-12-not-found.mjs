// Owner pass 2 finding 12: /no-such-page rendered a bare "Not Found" with no
// shell or link home. An unknown address now renders "Page not found" inside
// the signed-in console shell (sidebar navigation intact) with a link to the
// dashboard that works. Read-only.
export const task = {
  name: "Unknown page stays in the console",
  screenId: "owner-pass2-p2-12-not-found",
  route: "/no-such-page",
  priority: "normal",
  acceptance:
    "/no-such-page shows 'Page not found' in the main area of the console shell (sidebar with Dashboard and Devices links), names the address, and 'Go to dashboard' opens the dashboard.",
};

const timeout = 30_000;

export async function check({ page, visit, require, capture, step }) {
  step("open an unknown address");
  await visit("/no-such-page");
  const main = page.getByRole("main");
  const heading = main.getByRole("heading", { name: "Page not found", exact: true });
  await heading.waitFor({ timeout });
  require((await main.getByText("/no-such-page").count()) >
    0, "The page does not name the unknown address");
  for (const name of ["Dashboard", "Devices"]) {
    const link = page.locator(`a[href="/${name.toLowerCase()}"]`).filter({ hasText: name });
    require((await link.count()) >
      0, `The console shell's ${name} link is missing on the unknown page`);
  }
  await capture("not-found-in-shell");

  step("go home");
  await main
    .getByRole("link", { name: "Go to dashboard" })
    .or(main.getByRole("button", { name: "Go to dashboard" }))
    .first()
    .click();
  await page.waitForURL((url) => url.pathname === "/dashboard", { timeout });
}
