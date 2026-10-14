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
import { launchTrustedDeploymentBrowser } from "./deploy-browser.mjs";

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
  await assert.rejects(page.goto(`https://localhost:${unknownPort}`), /ERR_CERT_AUTHORITY_INVALID/);
  await assert.rejects(
    page.goto(`https://127.0.0.1:${trustedPort}`),
    /ERR_CERT_COMMON_NAME_INVALID/,
  );
});
