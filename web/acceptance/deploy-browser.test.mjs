// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import {
  assessDeploymentFindings,
  launchTrustedDeploymentBrowser,
  requireInitialVendorDownload,
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
  const source = { id: "ubuntu-native", refreshStartedAt: "2026-10-15T02:34:00.000Z" };
  await page.setContent(
    `<article id="advisory-source-${source.id}">
      <div role="status" data-advisory-initial-download="downloading">
        <p class="font-medium">Downloading first vulnerability data</p>
        <p>Download progress is not reported.</p>
        <time datetime="${source.refreshStartedAt}">Actual start</time>
      </div>
    </article>`,
  );
  await requireInitialVendorDownload(page, source);
  await assert.rejects(
    requireInitialVendorDownload(page, { ...source, refreshStartedAt: "2026-10-15T02:35:00Z" }),
    /initial_vendor_download_start_not_displayed/,
  );
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
