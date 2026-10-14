// SPDX-License-Identifier: Apache-2.0

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { chromium } from "playwright";
import { privateDirectory } from "./private-files.mjs";

const exec = promisify(execFile);

// Only the exact public CA fetched over the owned guest's pinned SSH channel is
// imported. Neither this API nor its caller accepts Chromium TLS override flags.
export async function launchTrustedDeploymentBrowser(config) {
  const home = join(config.privateDirectory, "browser-home");
  const store = join(home, ".pki", "nssdb");
  await privateDirectory(store);
  try {
    await exec("certutil", ["-L", "-d", `sql:${store}`], { timeout: 10_000 });
  } catch {
    await exec("certutil", ["-N", "--empty-password", "-d", `sql:${store}`], { timeout: 10_000 });
  }
  await exec(
    "certutil",
    ["-A", "-d", `sql:${store}`, "-n", "lindm-owned-deployment", "-t", "C,,", "-i", config.caFile],
    { timeout: 10_000 },
  );
  const browser = await chromium.launch({
    channel: "chromium",
    headless: true,
    timeout: 30_000,
    env: { ...process.env, HOME: home },
  });
  try {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 1000 },
      ignoreHTTPSErrors: false,
    });
    return { browser, context };
  } catch (error) {
    await browser.close();
    throw error;
  }
}
