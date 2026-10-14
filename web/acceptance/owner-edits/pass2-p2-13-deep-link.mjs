// SPDX-License-Identifier: Apache-2.0

// Owner pass 2 finding 13: a deep link opened while signed out landed on / and
// the destination was lost after sign-in. Signed out, the console now keeps the
// requested path in the sign-in URL; once a session exists the home route opens
// that path (the same step that runs right after password + passkey sign-in),
// or the path remembered across an organization sign-in round trip. Only a
// same-origin console path is honoured.
//
// Read-only: a separate signed-out context, then navigation in the review page.
export const task = {
  name: "Sign-in keeps the requested page",
  screenId: "owner-pass2-p2-13-deep-link",
  route: "/devices",
  priority: "high",
  acceptance:
    "Signed out, /devices?namePrefix=ubuntu shows sign-in with that path kept; signed in, /?next=… opens it, a remembered organization sign-in path opens it, and //evil.example or https://evil.example open the dashboard instead.",
};

const timeout = 30_000;
const TARGET = "/devices?namePrefix=ubuntu";

export async function check({ page, config, require, capture, step }) {
  step("signed-out deep link");
  const context = await page
    .context()
    .browser()
    .newContext({ ignoreHTTPSErrors: true, viewport: page.viewportSize() ?? undefined });
  try {
    const signedOut = await context.newPage();
    await signedOut.goto(`${config.origin}${TARGET}`);
    await signedOut
      .getByRole("button", { name: "Sign in locally", exact: true })
      .waitFor({ timeout });
    const url = new URL(signedOut.url());
    require(url.pathname === "/", `Signed-out deep link did not reach sign-in: ${url.pathname}`);
    const kept = new URL(url.searchParams.get("next") ?? "/", config.origin);
    require(kept.pathname === "/devices" &&
      kept.searchParams.get("namePrefix") ===
        "ubuntu", `Sign-in URL keeps "${url.searchParams.get("next")}", not ${TARGET}`);
    await capture("signed-out-sign-in", signedOut);
  } finally {
    await context.close();
  }

  const landing = async (href) => {
    await page.goto(`${config.origin}${href}`);
    await page.waitForURL((current) => current.pathname !== "/", { timeout });
    await page.getByRole("main").getByRole("heading", { level: 1 }).first().waitFor({ timeout });
    return new URL(page.url());
  };
  // The device list may add its default search parameters; the kept filter counts.
  const isTarget = (url) =>
    url.pathname === "/devices" && url.searchParams.get("namePrefix") === "ubuntu";

  step("after sign-in: kept path");
  const opened = await landing(`/?next=${encodeURIComponent(TARGET)}`);
  require(isTarget(
    opened,
  ), `After sign-in the console opened ${opened.pathname}${opened.search}, not ${TARGET}`);
  await capture("opened-requested-page");

  step("after organization sign-in: remembered path");
  await page.evaluate((target) => sessionStorage.setItem("lindm-next-path", target), TARGET);
  const remembered = await landing("/");
  require(isTarget(
    remembered,
  ), `After the organization round trip the console opened ${remembered.pathname}${remembered.search}`);
  const leftover = await page.evaluate(() => sessionStorage.getItem("lindm-next-path"));
  require(leftover === null, "The remembered path was not cleared after use");

  step("foreign destinations are refused");
  for (const next of ["//evil.example/devices", "https://evil.example/", "/\\evil.example"]) {
    const refused = await landing(`/?next=${encodeURIComponent(next)}`);
    require(refused.pathname ===
      "/dashboard", `next=${next} opened ${refused.pathname}, not the dashboard`);
  }
}
