// SPDX-License-Identifier: Apache-2.0

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { fromJson } from "@bufbuild/protobuf";
import { TimestampSchema, timestampDate } from "@bufbuild/protobuf/wkt";
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

export async function requireInitialVendorDownload(page, source) {
  const notice = page.locator(
    `[id="advisory-source-${source.id}"] [data-advisory-initial-download="downloading"]`,
  );
  await notice.getByText("Downloading first vulnerability data", { exact: true }).waitFor();
  await notice.getByText("Download progress is not reported.", { exact: false }).waitFor();
  const displayedStart = await notice.locator("time").getAttribute("datetime");
  const expectedStart = timestampDate(
    fromJson(TimestampSchema, source.refreshStartedAt),
  ).toISOString();
  if (displayedStart !== expectedStart)
    throw new Error("initial_vendor_download_start_not_displayed");
}

export async function requirePackageInventoryCard(page) {
  const card = page.locator('[data-slot="card"]').filter({
    has: page.getByText("From the device's latest package list.", { exact: true }),
  });
  await card.getByText("Installed packages", { exact: true }).waitFor();
}

// Observe the original UI fetch, not a second API call or CDP's ephemeral
// response resource. Only these three read-only replies enter lab memory.
export async function observeDeploymentRPCs(page, origin) {
  await page.addInitScript(
    ({ origin }) => {
      const methods = new Set(["ListDevicePackages", "ListAdvisoryFeeds", "ListDeviceFindings"]);
      const replies = Object.create(null);
      Object.defineProperty(window, "__lindmDeploymentReplies", { value: replies });
      const fetch = window.fetch.bind(window);
      window.fetch = async (...args) => {
        const response = await fetch(...args);
        const url = new URL(response.url);
        const method = url.pathname.split("/").at(-1);
        if (
          url.origin !== origin ||
          !methods.has(method) ||
          url.pathname !== `/lindm.admin.v1.AdminService/${method}`
        )
          return response;
        const entry = { status: response.status, reason: response.headers.get("lindm-reason") };
        if (response.ok) {
          try {
            entry.body = await response.clone().json();
          } catch {
            entry.failure = "native_rpc_body_capture_failed";
          }
        }
        replies[method] = entry;
        return response;
      };
    },
    { origin: new URL(origin).origin },
  );
}

export async function readDeploymentPage(driver, origin, path, method) {
  await driver.goto(`${origin}${path}`);
  await driver.page.waitForFunction(
    (method) => Object.hasOwn(window.__lindmDeploymentReplies ?? {}, method),
    method,
    { timeout: 30_000 },
  );
  const reply = await driver.page.evaluate(
    (method) => window.__lindmDeploymentReplies[method],
    method,
  );
  if (reply.failure) throw new Error(reply.failure);
  if (reply.status < 200 || reply.status >= 300) {
    const safe = /^[a-z][a-z0-9_]{0,127}$/.test(reply.reason ?? "") ? `_${reply.reason}` : "";
    throw new Error(`${method.toLowerCase()}_query_http_${reply.status}${safe}`);
  }
  return reply.body;
}

// Public failure evidence contains only a finite error category and an owned
// script position. Playwright messages, URLs and call arguments can be secrets.
export function deploymentBrowserFailure(error) {
  const message = String(error?.message ?? "");
  if (/^[a-z][a-z0-9_]+$/.test(message)) return message;
  const category = [
    [/net::ERR_ABORTED/, "navigation_aborted"],
    [/Execution context was destroyed/, "context_destroyed"],
    [
      /No (resource with given identifier found|data found for resource with given identifier)/i,
      "response_body_unavailable",
    ],
    [/strict mode violation/, "ambiguous_locator"],
    [/Target page, context or browser has been closed/, "browser_closed"],
  ].find(([pattern]) => pattern.test(message))?.[1];
  const kind = ["TypeError", "SyntaxError", "TimeoutError", "ProtocolError"].includes(error?.name)
    ? error.name.toLowerCase()
    : "opaque";
  const position = String(error?.stack ?? "").match(
    /^\s+at [^\n]*\/(deploy(?:-browser)?|drivers)\.mjs:(\d{1,4}):\d{1,4}\)?$/m,
  );
  const location = position ? `_${position[1].replaceAll("-", "_")}_${Number(position[2])}` : "";
  return `deployment_browser_failed_${category ?? kind}${location}`;
}

const evaluatedStates = new Set([
  "ADVISORY_FINDING_STATE_AFFECTED",
  "ADVISORY_FINDING_STATE_ACCEPTED",
  "ADVISORY_FINDING_STATE_CLEAR",
  "ADVISORY_FINDING_STATE_PARTIAL",
]);

function count(value) {
  if (!/^\d+$/.test(String(value ?? "0"))) throw new Error("invalid_findings_count");
  const number = Number(value ?? 0);
  if (!Number.isSafeInteger(number)) throw new Error("invalid_findings_count");
  return number;
}

// Evaluate actual browser RPC replies without turning a queued download, an
// unknown assessment or an empty unconfigured source list into successful proof.
// Pending results are read-only observations; callers must never refresh/import.
export function assessDeploymentFindings(inventory, sources, findings, config, now = Date.now()) {
  const pending = (reason, feed) => ({ ready: false, reason, feed });
  if (!inventory.snapshotId || !inventory.packages?.length)
    return pending("live_package_inventory_missing");
  const expected = config.advisorySources ?? [];
  const candidates = (sources.feeds ?? []).filter((feed) =>
    expected.some(
      (source) =>
        source.distro === feed.distro &&
        source.release === feed.release &&
        source.source_url === feed.sourceUrl &&
        source.platform_stream === (feed.platformStream ?? ""),
    ),
  );
  if (candidates.length === 0) return pending("automatic_vendor_feed_unconfigured");
  const freshness = findings.freshness;
  const feed = candidates.find((source) => source.id === freshness?.feedId) ?? candidates[0];
  if (feed.error) return pending("vendor_feed_refresh_failed", feed);
  if (
    !feed.fresh ||
    !/^[a-f0-9]{64}$/.test(feed.sourceSha256 ?? "") ||
    count(feed.advisoryCount) === 0 ||
    !(Date.parse(feed.checkedAt) <= now) ||
    !(Date.parse(feed.expiresAt) > now)
  )
    return pending(
      feed.refreshing ? "vendor_feed_download_in_progress" : "vendor_feed_unpublished_or_stale",
      feed,
    );
  if (
    !freshness ||
    freshness.snapshotId !== inventory.snapshotId ||
    freshness.feedId !== feed.id ||
    freshness.sourceSha256 !== feed.sourceSha256 ||
    !(Date.parse(freshness.inventoryAt) <= now) ||
    !(Date.parse(freshness.inventoryExpiresAt) > now) ||
    !(Date.parse(freshness.feedExpiresAt) > now) ||
    !evaluatedStates.has(freshness.state)
  )
    return pending("current_vendor_inventory_evaluation_missing");
  const partial = freshness.state === "ADVISORY_FINDING_STATE_PARTIAL";
  const uncovered = count(freshness.uncoveredPackages);
  if ((partial && (!uncovered || !freshness.reason)) || (!partial && uncovered))
    throw new Error("vendor_coverage_label_inconsistent");
  const totals = Object.fromEntries(
    ["open", "critical", "high", "medium", "low", "unrated", "accepted"].map((key) => [
      key,
      count(findings.totals?.[key]),
    ]),
  );
  if (totals.open !== totals.critical + totals.high + totals.medium + totals.low + totals.unrated)
    throw new Error("vendor_finding_totals_inconsistent");
  const visible = findings.findings ?? [];
  if (
    visible.some(
      (finding) =>
        finding.feedId !== feed.id ||
        !["ADVISORY_FINDING_STATE_AFFECTED", "ADVISORY_FINDING_STATE_ACCEPTED"].includes(
          finding.state,
        ),
    )
  )
    return pending("vendor_findings_unknown");
  if (totals.open + totals.accepted > 0 && visible.length === 0)
    throw new Error("vendor_findings_not_observed");
  return {
    ready: true,
    feed,
    evidence: {
      snapshot_id: inventory.snapshotId,
      inventory_sequence: count(inventory.sequence),
      feed_id: feed.id,
      source: {
        distro: feed.distro,
        release: feed.release,
        source_url: feed.sourceUrl,
        platform_stream: feed.platformStream ?? "",
      },
      source_sha256: feed.sourceSha256,
      feed_checked_at: feed.checkedAt,
      feed_expires_at: feed.expiresAt,
      advisory_count: count(feed.advisoryCount),
      inventory_at: freshness.inventoryAt,
      inventory_expires_at: freshness.inventoryExpiresAt,
      observed_at: new Date(now).toISOString(),
      state: freshness.state,
      reason: freshness.reason ?? "",
      uncovered_packages: uncovered,
      complete_coverage: !partial,
      totals,
    },
  };
}
