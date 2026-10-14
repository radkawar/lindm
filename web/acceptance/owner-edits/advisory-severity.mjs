// SPDX-License-Identifier: Apache-2.0

// Owner task: an advisory whose source publishes no severity (real Ubuntu OSV
// records in the seed's vendor feeds) reads as an honest neutral "Not rated by
// the source", not as an error-looking "Not published" status. Read-only.
export const task = {
  name: "Unrated advisory severity",
  screenId: "owner-pass2-advisory-severity",
  route: "/advisories",
  priority: "normal",
  acceptance:
    "An advisory without a vendor severity shows 'Not rated by the source' in neutral text; no severity cell says 'Not published' or uses an attention/failure colour.",
};

const UNRATED = "Not rated by the source";

export async function check({ page, visit, require, capture, step }) {
  step("open advisories");
  await visit("/advisories");
  const main = page.getByRole("main");
  const table = main
    .locator("table")
    .filter({ has: page.getByRole("columnheader", { name: "Severity" }) });
  await table.first().waitFor({ timeout: 30_000 });

  step("severity cells");
  let foundUnrated = false;
  for (let position = 0; position < 100; position += 1) {
    const cells = await table.first().evaluate((node) => {
      const headers = [...node.querySelectorAll("thead th")].map((th) => th.textContent?.trim());
      const column = headers.indexOf("Severity");
      return [...node.querySelectorAll("tbody tr")].map((row) => {
        const cell = row.children[column];
        const marker = cell?.querySelector("[data-advisory-severity]");
        const style = marker ? getComputedStyle(marker) : null;
        const muted = document.createElement("span");
        muted.className = "text-muted-foreground";
        document.body.append(muted);
        const mutedColor = getComputedStyle(muted).color;
        muted.remove();
        return {
          advisory: row.children[0]?.textContent?.trim().split(/\s/)[0] ?? "",
          text: marker?.textContent?.trim() ?? "",
          kind: marker?.getAttribute("data-advisory-severity") ?? "",
          neutral: !!style && style.color === mutedColor,
        };
      });
    });
    require(cells.length > 0, "the advisory table has no rows");
    for (const cell of cells) {
      require(!/not published/i.test(
        cell.text,
      ), `${cell.advisory} severity still says "${cell.text}"`);
      require(cell.kind !==
        "", `${cell.advisory} severity cell is not a rated or unrated severity`);
      if (cell.kind === "unrated") {
        require(cell.text === UNRATED, `${cell.advisory} unrated severity reads "${cell.text}"`);
        require(cell.neutral, `${cell.advisory} unrated severity is not neutral muted text`);
      }
    }
    foundUnrated = cells.some((cell) => cell.kind === "unrated");
    if (foundUnrated || position === 99) break;
    const next = main
      .getByRole("navigation", { name: "Advisory pages", exact: true })
      .getByRole("button", { name: "Next page", exact: true });
    if (!(await next.isEnabled())) break;
    const previous = await table.first().locator("tbody tr a").first().getAttribute("href");
    await next.click();
    await page.waitForFunction(
      (before) => {
        const current = document
          .querySelector("#advisory-findings tbody tr a")
          ?.getAttribute("href");
        return current && current !== before;
      },
      previous,
      { timeout: 30_000 },
    );
  }
  require(foundUnrated, "no advisory without a vendor severity is listed within 100 reviewed advisory pages");
  await capture("advisory-unrated-severity");
}
