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

export async function requireInitialVendorDownload(page, source) {
  const notice = page.locator(
    `[id="advisory-source-${source.id}"] [data-advisory-initial-download="downloading"]`,
  );
  await notice.getByText("Downloading first vulnerability data", { exact: true }).waitFor();
  await notice.getByText("Download progress is not reported.", { exact: false }).waitFor();
  const displayedStart = await notice.locator("time").getAttribute("datetime");
  if (displayedStart !== new Date(source.refreshStartedAt).toISOString())
    throw new Error("initial_vendor_download_start_not_displayed");
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
