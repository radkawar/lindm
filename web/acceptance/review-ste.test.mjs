// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { chromium } from "playwright";
import { installProbes } from "./review-probes.mjs";

// This suite exercises the production probe against rendered DOM, including
// inline markup. It needs the same installed Chromium as ui-review.
test("STE copy probe enforces primary copy and same-origin links", async () => {
  const rules = JSON.parse(await readFile(new URL("./copy-rules.json", import.meta.url), "utf8"));
  rules.vocabulary = JSON.parse(
    await readFile(new URL("../src/lib/vocabulary.json", import.meta.url), "utf8"),
  );
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.route("https://console.invalid/**", (route) =>
      route.fulfill({ contentType: "text/html", body: "<main></main>" }),
    );
    await page.goto("https://console.invalid/");
    const inspect = async (html) => {
      await page.setContent(html);
      await page.evaluate(() => {
        delete window.__review;
      });
      await page.evaluate(installProbes, rules);
      return page.evaluate(() => window.__review.copy().map((finding) => finding.rule));
    };
    assert.ok((await inspect("<p>The request is accepted.</p>")).includes("STE passive voice"));
    assert.ok((await inspect("<button>Delete machine</button>")).includes('STE use "device"'));
    assert.deepEqual(await inspect("<p>Service drop-in</p>"), []);
    assert.ok((await inspect("<button>Drop device</button>")).includes('STE use "remove"'));
    assert.deepEqual(
      await inspect(
        "<p>Review <span><code>Delete machine nativePackage</code></span> the device.</p>",
      ),
      [],
    );
    assert.ok((await inspect("<p>Device group profile policy</p>")).includes("STE noun cluster"));
    const sentence = `Select ${Array.from({ length: 20 }, () => "the").join(" ")} <strong>device</strong>.`;
    assert.ok((await inspect(`<p>${sentence}</p>`)).includes("STE sentence length"));
    const extraWords = Array.from({ length: 20 }, () => "the").join(" ");
    assert.ok((await inspect(`<p>Disable ${extraWords}.</p>`)).includes("STE sentence length"));
    assert.ok(
      (await inspect(`<p data-ste-procedure>If ${extraWords}.</p>`)).includes(
        "STE sentence length",
      ),
    );
    assert.ok(!(await inspect(`<p>The ${extraWords}.</p>`)).includes("STE sentence length"));
    assert.ok(
      (await inspect(`<p>The ${extraWords} other four words here remain.</p>`)).includes(
        "STE sentence length",
      ),
    );
    const date = "Oct 14, 4:25 AM British Summer Time · 30 min ago";
    const dates = ["Checked", "Evidence", "Expires"]
      .map((label) => `<div><dt>${label}</dt><dd>${date}</dd></div>`)
      .join("");
    assert.deepEqual(
      await inspect(
        `<ul><li><h3>Server HTTPS certificate</h3><span>Check confirmed</span><p>The certificate has current evidence.</p><dl>${dates}</dl></li></ul>`,
      ),
      [],
    );
    assert.ok(
      (await inspect(`<ul><li><p>${sentence}</p></li></ul>`)).includes("STE sentence length"),
    );
    assert.ok(
      (
        await inspect(
          `<dl><dt>Evidence</dt><dd>The ${extraWords} other four words here remain.</dd></dl>`,
        )
      ).includes("STE sentence length"),
    );
    assert.ok(
      (await inspect(`<p>Select ${extraWords} <a href="/help">device</a>.</p>`)).includes(
        "STE sentence length",
      ),
    );
    assert.equal(
      (await inspect("<div role='alert'><p>The request is accepted.</p></div>")).filter(
        (rule) => rule === "STE passive voice",
      ).length,
      1,
    );
    assert.ok(
      !(
        await inspect(
          '<p data-ste-exempt="passive-voice: Historical vendor quotation">The request is accepted.</p>',
        )
      ).includes("STE passive voice"),
    );
    assert.ok(
      (await inspect('<p data-ste-exempt="passive-voice:">The request is accepted.</p>')).includes(
        "STE passive voice",
      ),
    );
    assert.ok(
      (await inspect('<a href="https://github.com/example/project">Help</a>')).includes(
        "external console link",
      ),
    );
    assert.ok(
      (await inspect('<a hidden href="https://github.com/example/project">Help</a>')).includes(
        "external console link",
      ),
    );
    assert.deepEqual(await inspect('<a href="/help/design.md">Help</a>'), []);
    assert.deepEqual(
      await inspect(
        '<a data-console-link="vendor-advisory" href="https://ubuntu.com/security/CVE-2026-1">Vendor advisory</a>',
      ),
      [],
    );
    assert.deepEqual(
      await inspect(
        '<a data-console-link="vendor-advisory" href="https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip">Vendor advisory data</a>',
      ),
      [],
    );
    assert.ok(
      (
        await inspect(
          '<a href="https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip">Help</a>',
        )
      ).includes("external console link"),
    );
    assert.ok(
      (
        await inspect(
          '<a data-console-link="vendor-advisory" href="https://storage.googleapis.com/Ubuntu/all.zip">Vendor advisory data</a>',
        )
      ).includes("external console link"),
    );
    assert.ok(
      (
        await inspect(
          '<a data-console-link="vendor-advisory" href="https://ubuntu.com.evil.invalid/">Vendor advisory</a>',
        )
      ).includes("external console link"),
    );
    assert.deepEqual(await inspect("<p>Review the device.</p><button>Remove device</button>"), []);
  } finally {
    await browser.close();
  }
});
