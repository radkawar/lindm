// Real profile publication and reload, never an intercepted RPC or native SSH
// claim. Every capture uses the full shared console review checks.
export async function reviewSSHBanner({
  pages,
  combos,
  routes,
  visit,
  settle,
  review,
  screenshot,
}) {
  const failures = [];
  const route = routes.find((item) => item.path === "/profiles/new");
  const notice =
    "Company managed device. Authorized use only.\nThis public notice appears before SSH sign-in.\n" +
    "Contact the service desk if you do not recognize this device. ".repeat(10) +
    "\n";
  for (const [index, { theme, viewport }] of combos.entries()) {
    const page = pages[index];
    let step = "choose SSH sign-in banner";
    try {
      await visit(page, "/profiles/new");
      await page
        .getByLabel("Name", { exact: true })
        .fill(`SSH banner review ${theme} ${viewport.name}`);
      await page
        .getByLabel("Reason", { exact: true })
        .fill("Review public SSH notice; no devices assigned");
      await page.getByLabel("Setting type", { exact: true }).click();
      await page.getByRole("option", { name: "SSH sign-in banner", exact: true }).click();
      const field = page.getByLabel("Notice before SSH sign-in", { exact: true });
      await field.waitFor();
      await review(
        page,
        route,
        { url: "/profiles/new", label: "" },
        theme,
        viewport,
        "SSH banner empty",
      );
      step = "reject empty notice";
      await page.getByRole("button", { name: "Publish profile", exact: true }).click();
      await page
        .locator("[data-setting-errors]")
        .getByText("Enter the notice shown before SSH sign-in.", { exact: true })
        .waitFor();
      await page
        .locator("#profile-draft-errors")
        .getByText("Setting 1 needs changes before publishing.", { exact: true })
        .waitFor();
      if (await page.getByRole("link", { name: "View this version", exact: true }).count())
        throw new Error("Empty banner published");
      await review(
        page,
        route,
        { url: "/profiles/new", label: "" },
        theme,
        viewport,
        "SSH banner invalid",
      );
      step = "enter exact multiline notice";
      await field.fill(notice);
      await page.locator("#profile-draft-errors").waitFor({ state: "detached" });
      await review(
        page,
        route,
        { url: "/profiles/new", label: "" },
        theme,
        viewport,
        "SSH banner draft",
      );
      step = "publish typed profile";
      await page.getByRole("button", { name: "Publish profile", exact: true }).click();
      await page.getByRole("link", { name: "View this version", exact: true }).click();
      step = "reload persisted notice";
      await page.reload({ waitUntil: "domcontentloaded" });
      await settle(page);
      await field.waitFor();
      if ((await field.inputValue()) !== notice) throw new Error("Saved banner bytes changed");
      const version = page.locator("[data-profile-version]");
      await version.getByText("Latest version", { exact: true }).waitFor();
      if (await version.getByText("Older version", { exact: true }).count())
        throw new Error("Pinned latest version is labelled older");
      // Check the fetched revision as well as the editable draft, which can
      // survive reload in the existing publication-outbox recovery state. For a
      // manager the published settings sit in a collapsed section below the draft.
      const published = page.locator("[data-profile-published-settings]");
      if (await published.count()) await published.locator(":scope > summary").click();
      const saved = page
        .locator("[data-profile-setting]")
        .filter({ has: page.getByRole("heading", { name: /^SSH sign-in banner/ }) });
      await saved.getByText("Full setting", { exact: true }).click();
      const record = JSON.parse((await saved.locator("pre").textContent()) ?? "");
      if (record.desired?.sshServer?.bannerText !== notice)
        throw new Error("Saved server revision changed banner bytes");
      await saved.getByText("Full setting", { exact: true }).click();
      await review(
        page,
        { path: "/profiles/$profileId" },
        { url: new URL(page.url()).pathname, label: "" },
        theme,
        viewport,
        "SSH banner saved",
      );
    } catch {
      failures.push(
        `SSH banner ${theme} ${viewport.name}: ${step}; see screenshots/ssh-banner-${theme}-${viewport.name}-failure.png`,
      );
      await screenshot(page, `ssh-banner-${theme}-${viewport.name}-failure.png`, true);
    }
  }
  return failures;
}
