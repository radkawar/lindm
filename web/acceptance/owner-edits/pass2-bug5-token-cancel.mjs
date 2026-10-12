// Owner pass 2, bug 5: the provisioning token dialog's Cancel was zero-size or
// covered at the bottom of the expanded dialog, so only Esc closed it. With the
// optional settings expanded, on a scrolled page, at desktop and phone widths,
// Create and Cancel stay inside the viewport and a real pointer click on Cancel
// closes the dialog. Read-only: nothing is created.
export const task = {
  name: "Provisioning token dialog Cancel is clickable",
  screenId: "owner-pass2-bug5-token-cancel",
  route: "/enrollment",
  priority: "high",
  acceptance:
    "With 'Settings for enrolled devices' expanded on a scrolled page (desktop and 390px), Create provisioning token and Cancel are visible inside the viewport and a real click on Cancel closes the dialog.",
};

const timeout = 30_000;
const DIALOG = "Create a provisioning token";

function inside(box, viewport) {
  return (
    box !== null &&
    box.width > 0 &&
    box.height > 0 &&
    box.x >= 0 &&
    box.y >= 0 &&
    box.x + box.width <= viewport.width &&
    box.y + box.height <= viewport.height
  );
}

export async function check({ page, visit, settle, require, capture, step }) {
  const main = page.getByRole("main");
  const original = page.viewportSize();
  if (!original) throw new Error("The review page has no fixed viewport");
  try {
    for (const viewport of [original, { width: 390, height: 844 }]) {
      const label = viewport.width < 640 ? "mobile" : "desktop";
      step(`open dialog (${label})`);
      await page.setViewportSize(viewport);
      await visit("/enrollment");
      const open = main.getByRole("button", { name: "Create provisioning token", exact: true });
      await open.waitFor({ timeout });
      await settle();
      // The owner hit this on a scrolled page.
      await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
      await open.click();
      const dialog = page.getByRole("dialog", { name: DIALOG, exact: true });
      await dialog.waitFor({ timeout });

      step(`expand optional settings (${label})`);
      await dialog.locator("summary").filter({ hasText: "Settings for enrolled devices" }).click();
      await dialog.getByText("Custom attributes (JSON)").waitFor({ timeout });
      await settle();
      const cancel = dialog.getByRole("button", { name: "Cancel", exact: true });
      const create = dialog.getByRole("button", { name: "Create provisioning token", exact: true });
      require(inside(
        await cancel.boundingBox(),
        viewport,
      ), `Cancel is not fully on screen (${label})`);
      require(inside(
        await create.boundingBox(),
        viewport,
      ), `Create is not fully on screen (${label})`);
      await capture(`expanded-${label}`);

      step(`real click on Cancel (${label})`);
      // No force: Playwright's hit test fails if anything covers Cancel.
      await cancel.click({ timeout: 5_000 });
      await dialog.waitFor({ state: "hidden", timeout });
    }
  } finally {
    await page.setViewportSize(original);
  }
}
