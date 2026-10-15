// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as createHTTPServer } from "node:http";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { chromium } from "playwright";
import {
  assessDeploymentFindings,
  deploymentBrowserFailure,
  launchTrustedDeploymentBrowser,
  observeDeploymentRPCs,
  readDeploymentPage,
  requireInitialVendorDownload,
  requirePackageInventoryCard,
} from "./deploy-browser.mjs";

const exec = promisify(execFile);

test("native deployment browser trusts its supplied CA but rejects unknown roots and names", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "lindm-native-browser-tls-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const openssl = (args) => exec("openssl", args, { cwd: directory, timeout: 10_000 });
  await openssl([
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-sha256",
    "-days",
    "1",
    "-subj",
    "/CN=owned-native-ca",
    "-keyout",
    "ca.key",
    "-out",
    "ca.crt",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
  ]);
  await openssl([
    "req",
    "-new",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-subj",
    "/CN=localhost",
    "-keyout",
    "server.key",
    "-out",
    "server.csr",
  ]);
  await writeFile(
    join(directory, "server.ext"),
    "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n",
    { mode: 0o600 },
  );
  await openssl([
    "x509",
    "-req",
    "-in",
    "server.csr",
    "-CA",
    "ca.crt",
    "-CAkey",
    "ca.key",
    "-CAcreateserial",
    "-sha256",
    "-days",
    "1",
    "-extfile",
    "server.ext",
    "-out",
    "server.crt",
  ]);
  await openssl([
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-sha256",
    "-days",
    "1",
    "-subj",
    "/CN=localhost",
    "-keyout",
    "unknown.key",
    "-out",
    "unknown.crt",
    "-addext",
    "subjectAltName=DNS:localhost",
  ]);
  async function serve(name) {
    const server = createServer(
      {
        key: await readFile(join(directory, `${name}.key`)),
        cert: await readFile(join(directory, `${name}.crt`)),
      },
      (_request, response) => response.end("native TLS verified"),
    );
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    t.after(
      () =>
        new Promise((resolve, reject) => {
          server.closeAllConnections();
          server.close((error) => (error ? reject(error) : resolve()));
        }),
    );
    return server.address().port;
  }
  const trustedPort = await serve("server");
  const unknownPort = await serve("unknown");
  const { browser, context } = await launchTrustedDeploymentBrowser({
    privateDirectory: directory,
    caFile: join(directory, "ca.crt"),
  });
  t.after(() => browser.close());
  const page = await context.newPage();
  await page.goto(`https://localhost:${trustedPort}`);
  assert.equal(await page.locator("body").textContent(), "native TLS verified");
  const source = { id: "ubuntu-native", refreshStartedAt: "2026-10-15T02:34:00.000600Z" };
  await page.setContent(
    `<article id="advisory-source-${source.id}">
      <div role="status" data-advisory-initial-download="downloading">
        <p class="font-medium">Downloading first vulnerability data</p>
        <p>Download progress is not reported.</p>
        <time datetime="2026-10-15T02:34:00.001Z">Actual start</time>
      </div>
    </article>`,
  );
  await requireInitialVendorDownload(page, source);
  for (const [wire, displayed] of [
    ["2026-10-15T02:34:00.000499Z", "2026-10-15T02:34:00.000Z"],
    ["2026-10-15T02:34:00.999600Z", "2026-10-15T02:34:01.000Z"],
  ]) {
    await page
      .locator("time")
      .evaluate((node, value) => node.setAttribute("datetime", value), displayed);
    await requireInitialVendorDownload(page, { ...source, refreshStartedAt: wire });
  }
  await assert.rejects(
    requireInitialVendorDownload(page, { ...source, refreshStartedAt: "2026-10-15T02:35:00Z" }),
    /initial_vendor_download_start_not_displayed/,
  );
  await page.setContent(`
    <div data-slot="card">
      <div data-slot="card-title">Installed packages</div>
      <div data-slot="card-description">The latest complete package list.</div>
    </div>
    <div data-slot="card">
      <div data-slot="card-title">Installed packages</div>
      <div data-slot="card-description">From the device's latest package list.</div>
    </div>
  `);
  assert.equal(await page.locator('[data-slot="card-title"]').count(), 2);
  await requirePackageInventoryCard(page);
  await page
    .getByText("From the device's latest package list.", { exact: true })
    .evaluate((node) => node.remove());
  page.setDefaultTimeout(150);
  await assert.rejects(requirePackageInventoryCard(page), /Timeout/);
  page.setDefaultTimeout(30_000);
  await assert.rejects(page.goto(`https://localhost:${unknownPort}`), /ERR_CERT_AUTHORITY_INVALID/);
  await assert.rejects(
    page.goto(`https://127.0.0.1:${trustedPort}`),
    /ERR_CERT_COMMON_NAME_INVALID/,
  );
});

function nativeFindingsReply() {
  const now = Date.parse("2026-10-15T12:00:00Z");
  const source = {
    distro: "ubuntu",
    release: "24.04",
    source_url: "https://vendor.invalid/real-export.zip",
    platform_stream: "",
  };
  const feed = {
    id: "automatically-selected-vendor",
    distro: source.distro,
    release: source.release,
    sourceUrl: source.source_url,
    sourceSha256: "a".repeat(64),
    fresh: true,
    checkedAt: "2026-10-15T11:58:00Z",
    expiresAt: "2026-10-16T11:58:00Z",
    advisoryCount: "123",
  };
  return {
    now,
    config: { advisorySources: [source] },
    inventory: {
      snapshotId: "b0b7a78e-07b1-419b-80ae-bd95e67d6694",
      sequence: "4",
      packages: [{ name: "native-package", version: "1", architecture: "amd64" }],
    },
    sources: { feeds: [feed] },
    findings: {
      freshness: {
        snapshotId: "b0b7a78e-07b1-419b-80ae-bd95e67d6694",
        feedId: feed.id,
        sourceSha256: feed.sourceSha256,
        inventoryAt: "2026-10-15T11:59:00Z",
        inventoryExpiresAt: "2026-10-16T11:59:00Z",
        feedExpiresAt: feed.expiresAt,
        state: "ADVISORY_FINDING_STATE_CLEAR",
      },
      totals: {},
    },
  };
}

test("native findings waits for actual publication and matching evaluation", () => {
  const assess = (reply) =>
    assessDeploymentFindings(
      reply.inventory,
      reply.sources,
      reply.findings,
      reply.config,
      reply.now,
    );
  assert.equal(
    assess(nativeFindingsReply()).ready,
    true,
    "a real clear result needs no invented CVE",
  );
  for (const mutate of [
    (r) => (r.sources.feeds = []),
    (r) => (r.sources.feeds[0].error = "network_failure"),
    (r) => (r.sources.feeds[0].sourceUrl = "https://different.invalid/export"),
    (r) => (r.sources.feeds[0].platformStream = "eus"),
    (r) => (r.sources.feeds[0].sourceSha256 = ""),
    (r) => (r.sources.feeds[0].advisoryCount = "0"),
    (r) => (r.sources.feeds[0].expiresAt = "2026-10-14T00:00:00Z"),
    (r) => (r.inventory.packages = []),
    (r) => (r.findings.freshness.snapshotId = "old-snapshot"),
    (r) => (r.findings.freshness.sourceSha256 = "b".repeat(64)),
    (r) => (r.findings.freshness.state = "ADVISORY_FINDING_STATE_UNKNOWN"),
    (r) => (r.findings.freshness.inventoryExpiresAt = "2026-10-14T00:00:00Z"),
  ]) {
    const reply = nativeFindingsReply();
    mutate(reply);
    assert.equal(assess(reply).ready, false);
  }
  const downloading = nativeFindingsReply();
  downloading.sources.feeds[0].fresh = false;
  downloading.sources.feeds[0].sourceSha256 = "";
  downloading.sources.feeds[0].checkedAt = undefined;
  downloading.sources.feeds[0].refreshing = true;
  assert.equal(assess(downloading).reason, "vendor_feed_download_in_progress");
  const partial = nativeFindingsReply();
  partial.findings.freshness.state = "ADVISORY_FINDING_STATE_PARTIAL";
  partial.findings.freshness.reason = "package_origin_uncovered";
  partial.findings.freshness.uncoveredPackages = "9";
  const proof = assess(partial);
  assert.equal(proof.ready, true);
  assert.equal(proof.evidence.complete_coverage, false);
  assert.equal(proof.evidence.uncovered_packages, 9);
  partial.findings.freshness.uncoveredPackages = "0";
  assert.throws(() => assess(partial), /vendor_coverage_label_inconsistent/);
});

test("current incomplete publication is neither unpublished nor stale and never qualifies unknown", () => {
  const reply = nativeFindingsReply();
  const assess = () =>
    assessDeploymentFindings(
      reply.inventory,
      reply.sources,
      reply.findings,
      reply.config,
      reply.now,
    );
  const feed = reply.sources.feeds[0];
  feed.fresh = false;
  feed.rejectedRecords = [
    {
      id: "CVE-2026-1234 / vendor-document.json",
      reason: "product_reference_unresolved",
      unscoped: true,
      packageNames: [],
    },
  ];
  reply.findings.freshness.state = "ADVISORY_FINDING_STATE_UNKNOWN";
  reply.findings.freshness.reason = "feed_partial_coverage";
  assert.equal(assess().reason, "vendor_feed_incomplete");
  assert.equal(assess().ready, false);
  // Incomplete publication cannot qualify, even with an evaluated partial device result.
  reply.findings.freshness.state = "ADVISORY_FINDING_STATE_CLEAR";
  assert.equal(assess().ready, false);
  feed.rejectedRecords[0].unscoped = false;
  feed.rejectedRecords[0].packageNames = ["native-package"];
  reply.findings.freshness.state = "ADVISORY_FINDING_STATE_PARTIAL";
  reply.findings.freshness.reason = "source_record_rejected";
  reply.findings.freshness.uncoveredPackages = "1";
  assert.equal(assess().ready, false);
  assert.equal(assess().reason, "vendor_feed_incomplete");
  // A complete current publication may still leave explicitly scoped components unknown.
  feed.fresh = true;
  assert.equal(assess().ready, true);
  assert.equal(assess().evidence.complete_coverage, false);
  reply.findings.freshness.sourceSha256 = "b".repeat(64);
  assert.equal(assess().ready, false);
  feed.expiresAt = "2026-10-14T00:00:00Z";
  assert.equal(assess().reason, "vendor_feed_stale_or_invalid");
  feed.sourceSha256 = "";
  assert.equal(assess().reason, "vendor_feed_unpublished");
});

test("native findings never publishes exception text or cursor authority", () => {
  const reply = nativeFindingsReply();
  reply.inventory.pageToken = "private-cursor";
  reply.findings.findings = [
    {
      feedId: reply.sources.feeds[0].id,
      state: "ADVISORY_FINDING_STATE_ACCEPTED",
      exception: { reason: "private-operator-text" },
    },
  ];
  reply.findings.totals = { accepted: "1" };
  const proof = assessDeploymentFindings(
    reply.inventory,
    reply.sources,
    reply.findings,
    reply.config,
    reply.now,
  );
  assert.equal(proof.ready, true);
  assert.equal(proof.evidence.totals.accepted, 1);
  assert.equal(JSON.stringify(proof.evidence).includes("private-"), false);
  reply.findings.findings[0].state = "ADVISORY_FINDING_STATE_UNKNOWN";
  assert.equal(
    assessDeploymentFindings(
      reply.inventory,
      reply.sources,
      reply.findings,
      reply.config,
      reply.now,
    ).ready,
    false,
  );
});

test("native browser failure evidence retains only safe categories and owned source positions", () => {
  const secret = "private-token-and-origin";
  for (const [message, category] of [
    [`page.goto: net::ERR_ABORTED at https://${secret}/`, "navigation_aborted"],
    [`Execution context was destroyed: ${secret}`, "context_destroyed"],
    [`No resource with given identifier found: ${secret}`, "response_body_unavailable"],
    [`strict mode violation: ${secret}`, "ambiguous_locator"],
    [`Target page, context or browser has been closed: ${secret}`, "browser_closed"],
  ]) {
    const error = new Error(message);
    error.stack = `${message}\n    at readPage (file:///private/${secret}/deploy.mjs:198:23)`;
    assert.equal(
      deploymentBrowserFailure(error),
      `deployment_browser_failed_${category}_deploy_198`,
    );
    assert.equal(deploymentBrowserFailure(error).includes(secret), false);
  }
  const error = new TypeError(secret);
  error.stack = `TypeError: ${secret}\n    at handler (https://${secret}/untrusted.mjs:12:8)`;
  assert.equal(deploymentBrowserFailure(error), "deployment_browser_failed_typeerror");
  assert.equal(
    deploymentBrowserFailure(new Error("vendor_finding_does_not_match_native_inventory")),
    "vendor_finding_does_not_match_native_inventory",
  );
});

test("native screenshots have an independent invocation scope instead of overwriting earlier phases", async () => {
  const script = await readFile(new URL("./deploy.mjs", import.meta.url), "utf8");
  assert.match(script, /const captureScope = randomUUID\(\);/);
  assert.match(script, /\$\{config\.phase\}-\$\{captureScope\}-\$\{name\}\.png/);
  assert.doesNotMatch(script, /\$\{config\.phase\}-\$\{name\}\.png/);
});

test("native RPC evidence passively captures real UI fetches across repeated Chromium navigations", async (t) => {
  let calls = 0;
  let refuse = false;
  const body = { snapshotId: "actual-snapshot", packages: [{ name: "native-package" }] };
  const server = createHTTPServer((request, response) => {
    if (request.url === "/lindm.admin.v1.AdminService/ListDevicePackages") {
      calls++;
      response.writeHead(refuse ? 403 : 200, {
        "Content-Type": "application/json",
        "lindm-reason": "scope_denied",
      });
      response.end(JSON.stringify(refuse ? { secret: "not-evidence" } : body));
    } else {
      response.writeHead(200, { "Content-Type": "text/html" });
      response.end(`<script>
        fetch("/lindm.admin.v1.AdminService/ListDevicePackages", {method:"POST"})
          .then(response => response.json())
          .then(body => document.body.textContent = JSON.stringify(body));
      </script>`);
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ channel: "chromium", headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await observeDeploymentRPCs(page, origin);
  const driver = { page, goto: (url) => page.goto(url, { waitUntil: "domcontentloaded" }) };
  for (let index = 0; index < 4; index++) {
    assert.deepEqual(
      await readDeploymentPage(
        driver,
        origin,
        `/inventory?namePrefix=package-${index}`,
        "ListDevicePackages",
      ),
      body,
    );
    await page.getByText(JSON.stringify(body), { exact: true }).waitFor();
    assert.equal(calls, index + 1, "observer never sends another RPC");
  }
  refuse = true;
  await assert.rejects(
    readDeploymentPage(driver, origin, "/inventory?denied", "ListDevicePackages"),
    { message: "listdevicepackages_query_http_403_scope_denied" },
  );
  assert.equal(calls, 5, "HTTP refusal is never retried");
  assert.equal(
    await page.evaluate(() =>
      JSON.stringify(window.__lindmDeploymentReplies).includes("not-evidence"),
    ),
    false,
    "error bodies never enter evidence memory",
  );
});

test("native RPC capture uses Chromium's canonical default HTTPS port without accepting other origins", async (t) => {
  const browser = await chromium.launch({ channel: "chromium", headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const body = { snapshotId: "canonical-origin", packages: [{ name: "actual-package" }] };
  await page.route(/^https:\/\/console\.example(?::8443)?\//, async (route) => {
    if (new URL(route.request().url()).pathname.startsWith("/lindm.admin.v1.AdminService/")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(body),
      });
    } else {
      await route.fulfill({
        status: 200,
        contentType: "text/html",
        body: `<script>fetch("/lindm.admin.v1.AdminService/ListDevicePackages", {method:"POST"})
          .then(response => response.json()).then(body => document.body.textContent=JSON.stringify(body));</script>`,
      });
    }
  });
  await observeDeploymentRPCs(page, "https://console.example:443");
  const driver = { page, goto: (url) => page.goto(url, { waitUntil: "domcontentloaded" }) };
  assert.deepEqual(
    await readDeploymentPage(
      driver,
      "https://console.example:443",
      "/inventory",
      "ListDevicePackages",
    ),
    body,
  );
  await page.goto("https://console.example:8443/inventory");
  await page.getByText(JSON.stringify(body), { exact: true }).waitFor();
  assert.deepEqual(await page.evaluate(() => Object.keys(window.__lindmDeploymentReplies)), []);
});
