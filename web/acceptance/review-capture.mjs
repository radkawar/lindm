// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 lindm contributors

// The review configures classic scrollbars. Chromium's screenshot capture can
// leave them hidden: a later input then adds a horizontal scrollbar's height to
// a table and moves following content, even though opening the popup did not.
// Restore the configured browser state before any subsequent geometry baseline.
export async function captureReviewPNG(page, options) {
  try {
    return await page.screenshot({ ...options, type: "png" });
  } finally {
    // A viewport refresh does not rebuild fixed-width table scrollbars. Render
    // both scrollbar-width states through CSSOM, then remove only our sheet.
    await page.evaluate(async () => {
      const renderFrames = () =>
        new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)));
      const sheet = new CSSStyleSheet();
      sheet.replaceSync("* { scrollbar-width: none !important; }");
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
      try {
        await renderFrames();
      } finally {
        document.adoptedStyleSheets = document.adoptedStyleSheets.filter(
          (candidate) => candidate !== sheet,
        );
      }
      await renderFrames();
    });
  }
}
