// SPDX-License-Identifier: Apache-2.0

// Settings reports verified repository state, not a simulated missing publication.
// The stock fixture is Ready. Missing-artifact enrollment runs are separate.
export const task = {
  name: "Agent repository grouped readiness",
  screenId: "",
  route: "/settings",
  priority: "normal",
  acceptance:
    "Agent repository states the actual server readiness once with a local Installation guide; Ready, Needs attention and collapsed Not supported yet groups match each platform's eligibility; configuration keys stay in Details. The stock fixture is Ready, not a missing-source test.",
};

const UNSUPPORTED = /^Not supported yet \((\d+)\)$/;

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  step("open settings");
  await visit("/settings");
  const section = main.getByRole("region", { name: "Agent repository", exact: true });
  await section.waitFor({ timeout: 30_000 });
  await section.locator("li").first().waitFor({ timeout: 30_000 });
  await settle();
  const instructions = await page.evaluate(async () => {
    const session = await (await fetch("/auth/session", { cache: "no-store" })).json();
    const response = await fetch("/lindm.admin.v1.AdminService/GetEnrollmentInstructions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrfToken },
      body: "{}",
    });
    if (!response.ok) throw new Error(`GetEnrollmentInstructions_${response.status}`);
    return response.json();
  });
  const platforms = instructions.platforms ?? [];
  const supported = platforms.filter(
    (platform) => platform.support === "ENROLLMENT_PLATFORM_SUPPORT_SUPPORTED",
  );
  const groups = [
    { name: "Ready", platforms: supported.filter((platform) => platform.readiness?.ready) },
    {
      name: "Needs attention",
      platforms: supported.filter((platform) => !platform.readiness?.ready),
    },
    {
      name: "Not supported yet",
      platforms: platforms.filter((platform) => !supported.includes(platform)),
    },
  ];
  require(platforms.length > 0, "The server returned no platform eligibility");

  step("readiness explanation with local guide");
  const primary = await section.innerText();
  const readySentence = "Devices install signed agent packages from this server.";
  require(instructions.readiness?.ready === true, "The stock fixture repository is not Ready");
  require(primary.split(readySentence).length - 1 ===
    1, "Ready repository does not explain its signed package source once");
  const guide = section.getByRole("link", { name: "Installation guide", exact: true });
  require((await guide.count()) === 1, "No Installation guide link");
  if ((await guide.count()) === 1) {
    const target = new URL((await guide.getAttribute("href")) ?? "", page.url());
    require(target.origin === new URL(page.url()).origin &&
      target.pathname === "/help/security-and-operations.md" &&
      target.hash ===
        "#prepare-the-servers-installation-repository", "Installation guide does not target the local repository setup section");
  }
  require(!primary.includes(
    "releaseRepository",
  ), "Primary text names releaseRepository configuration");

  step("group eligibility and order");
  const headings = await section.locator("h3, summary").allInnerTexts();
  const expected = groups.map((group) => `${group.name} (${group.platforms.length})`);
  require(expected.every(
    (text, index) => headings[index]?.trim() === text,
  ), `Groups disagree with platform eligibility or order: ${headings.join(" | ")}`);
  for (const group of groups.slice(0, 2)) {
    const heading = section.getByRole("heading", {
      name: `${group.name} (${group.platforms.length})`,
      exact: true,
    });
    require((await heading.count()) === 1, `Missing ${group.name} group`);
    if ((await heading.count()) !== 1) continue;
    const container = heading.locator("xpath=..");
    const rows = await container.locator("li").allInnerTexts();
    require(rows.length ===
      group.platforms.length, `${group.name} lists the wrong number of platforms`);
    for (const platform of group.platforms)
      require(rows.some((text) =>
        text.includes(platform.label),
      ), `${group.name} omits ${platform.label}`);
    if (!group.platforms.length)
      require((await container
        .getByText(
          group.name === "Ready"
            ? "No platform is installable from this server yet."
            : "Every supported platform is installable.",
          { exact: true },
        )
        .count()) === 1, `${group.name} has no meaningful empty state`);
  }
  const unsupported = section.locator("summary").filter({ hasText: UNSUPPORTED });
  require((await unsupported.count()) === 1, "No Not supported yet disclosure");
  if ((await unsupported.count()) === 1)
    require(!(await unsupported.evaluate(
      (summary) => summary.parentElement?.open === true,
    )), "Not supported yet is expanded by default");

  step("rows say only what differs");
  const rows = await section.locator("li").allInnerTexts();
  const jargon = rows.filter((text) => /releaseRepository|lindmd|restart|Configure/.test(text));
  require(jargon.length ===
    0, `Rows repeat server configuration text: ${jargon.slice(0, 2).join(" | ")}`);
  await capture("agent-repository");

  step("unsupported platforms explain their state");
  if ((await unsupported.count()) === 1) {
    await unsupported.click();
    const container = unsupported.locator("xpath=..");
    require((await container
      .getByText("lindm does not support agent installation on these releases.", { exact: true })
      .count()) === 1, "Unsupported platforms lack an installation consequence");
    const listed = await container.locator("li").allInnerTexts();
    require(listed.length ===
      groups[2].platforms.length, "Unsupported group lists the wrong number of platforms");
    for (const platform of groups[2].platforms)
      require(listed.some((text) =>
        text.includes(platform.label),
      ), `Unsupported group omits ${platform.label}`);
    await capture("agent-repository-not-supported");
    await unsupported.click();
  }
}
