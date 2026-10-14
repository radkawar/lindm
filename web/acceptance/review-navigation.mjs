// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 lindm contributors

// Follow the shell's visible controls, not direct routes, so task journeys cover
// work-area selection and mobile disclosures as well as destination pages.
export async function openNavigationPage(page, label) {
  const desktop = page.viewportSize().width >= 768;
  if (desktop) {
    const destination = page
      .locator("[data-shell-pages]")
      .getByRole("link", { name: label, exact: true });
    const toggle = page.getByRole("button", { name: "Toggle page navigation", exact: true });
    if ((await toggle.getAttribute("aria-expanded")) === "false") await toggle.click();
    if (await destination.isVisible()) return destination.click();
    const areas = await page
      .locator("[data-shell-rail] [data-work-area]")
      .evaluateAll((links) => links.map((link) => link.getAttribute("data-work-area")));
    for (const area of areas) {
      await page.locator(`[data-shell-rail] [data-work-area="${area}"]`).click();
      await page.getByRole("navigation", { name: `${area} pages`, exact: true }).waitFor();
      if (await destination.isVisible()) return destination.click();
    }
  } else {
    const dialog = page.getByRole("dialog", { name: "Navigation", exact: true });
    if (!(await dialog.isVisible()))
      await page.getByRole("button", { name: "Toggle navigation", exact: true }).click();
    const destination = dialog.getByRole("link", { name: label, exact: true });
    if (await destination.isVisible()) return destination.click();
    const disclosures = dialog.locator("details");
    for (let index = 0; index < (await disclosures.count()); index += 1) {
      const disclosure = disclosures.nth(index);
      await disclosure.locator("summary").click();
      if (await destination.isVisible()) return destination.click();
      await disclosure.locator("summary").click();
    }
  }
  throw new Error(`Navigation does not expose ${label}`);
}
