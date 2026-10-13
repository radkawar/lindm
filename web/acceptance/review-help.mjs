// Bundled references can exceed Chromium's practical single-image capture size.
// Keep complete document evidence in consecutive bounded images, not a truncated
// "full page" or a larger timeout for one enormous raster.
const captureHeight = 8_192;

export async function captureHelpDocument({ page, prefix, screenshot }) {
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.evaluate(() => document.fonts.ready);
  const dimensions = await page.evaluate(() => ({
    width: document.documentElement.scrollWidth,
    height: document.documentElement.scrollHeight,
  }));
  const viewportScreenshot = await screenshot(page, `${prefix}.png`, false);
  const fullScreenshots = [];
  const viewport = page.viewportSize();
  try {
    for (let y = 0; y < dimensions.height; y += captureHeight) {
      const height = Math.min(captureHeight, dimensions.height - y);
      // Even a clipped fullPage capture expands Chromium's document surface.
      // Help has no pinned console shell or viewport-height layout: capture
      // consecutive physical viewports instead, without the enormous surface.
      await page.setViewportSize({ width: viewport.width, height });
      const offset = await page.evaluate((y) => {
        window.scrollTo(0, y);
        return window.scrollY;
      }, y);
      if (offset !== y) throw new Error("help_capture_offset_changed");
      fullScreenshots.push({
        y,
        height,
        screenshot: await screenshot(
          page,
          `${prefix}-part-${fullScreenshots.length + 1}.png`,
          false,
        ),
      });
    }
  } finally {
    await page.setViewportSize(viewport);
    await page.evaluate(() => window.scrollTo(0, 0));
  }
  return { dimensions, viewportScreenshot, fullScreenshots };
}
