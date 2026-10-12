// Owner task: Settings > Agent repository gives one setup explanation in admin
// terms with a link to the server setup guide, then groups platforms into
// Ready, Supported (needs setup) and a collapsed Not supported yet. Server
// configuration keys appear only inside technical details. Read-only.
export const task = {
  name: "Agent repository grouped readiness",
  screenId: "",
  route: "/settings",
  priority: "normal",
  acceptance:
    "Agent repository shows one setup explanation with a 'Server setup guide' link, then 'Ready', 'Supported, needs setup' and 'Not supported yet' in that order with 'Not supported yet' collapsed; no 'releaseRepository' or per-row server-config sentence outside the details.",
};

const GROUPS = [/^Ready \(\d+\)$/, /^Supported, needs setup \(\d+\)$/];
const UNSUPPORTED = /^Not supported yet \((\d+)\)$/;
const SETUP = "To make a platform installable";

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  step("open settings");
  await visit("/settings");
  const section = main.getByRole("region", { name: "Agent repository", exact: true });
  await section.waitFor({ timeout: 30_000 });
  await section.locator("li").first().waitFor({ timeout: 30_000 });
  await settle();

  step("single setup explanation with guide link");
  const primary = await section.innerText();
  require(primary.split(SETUP).length - 1 ===
    1, `Expected one setup explanation ("${SETUP}…"), found ${primary.split(SETUP).length - 1}`);
  const guide = section.getByRole("link", { name: "Server setup guide", exact: true });
  require((await guide.count()) === 1, "No 'Server setup guide' link");
  if ((await guide.count()) === 1)
    require(/docs\/.+\.md#/.test(
      (await guide.getAttribute("href")) ?? "",
    ), "Setup guide link does not point at a docs section");
  require(!primary.includes(
    "releaseRepository",
  ), "Primary text names releaseRepository configuration");

  step("groups in order");
  const ready = section.getByRole("heading", { name: GROUPS[0] });
  const needsSetup = section.getByRole("heading", { name: GROUPS[1] });
  const unsupported = section.locator("summary").filter({ hasText: UNSUPPORTED });
  require((await ready.count()) === 1, "No 'Ready' group");
  require((await needsSetup.count()) === 1, "No 'Supported, needs setup' group");
  require((await unsupported.count()) === 1, "No 'Not supported yet' disclosure");
  if (
    (await ready.count()) === 1 &&
    (await needsSetup.count()) === 1 &&
    (await unsupported.count()) === 1
  ) {
    const handles = [
      await ready.elementHandle(),
      await needsSetup.elementHandle(),
      await unsupported.elementHandle(),
    ];
    const ordered = await page.evaluate(
      ([a, b, c]) =>
        Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) &&
        Boolean(b.compareDocumentPosition(c) & Node.DOCUMENT_POSITION_FOLLOWING),
      handles,
    );
    require(ordered, "Groups are not in the order Ready, Supported needs setup, Not supported yet");
    const open = await unsupported.evaluate((summary) => summary.parentElement?.open === true);
    require(!open, "'Not supported yet' is expanded by default");
    const count = Number(UNSUPPORTED.exec((await unsupported.innerText()).trim())?.[1] ?? 0);
    require(count >
      0, "The registry's design-only releases are not listed under 'Not supported yet'");
  }

  step("rows say only what differs");
  const rows = await section.locator("li").allInnerTexts();
  const jargon = rows.filter((text) => /releaseRepository|lindmd|restart|Configure/.test(text));
  require(jargon.length ===
    0, `Rows repeat server configuration text: ${jargon.slice(0, 2).join(" | ")}`);
  await capture("agent-repository");

  step("expand not supported yet");
  if ((await unsupported.count()) === 1) {
    await unsupported.click();
    await section.getByText("NixOS", { exact: false }).first().waitFor({ timeout: 10_000 });
    await capture("agent-repository-not-supported");
    await unsupported.click();
  }
}
