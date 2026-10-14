// SPDX-License-Identifier: Apache-2.0
// Source licensing policy and deterministic generated-output postprocessor.
import { execFileSync } from "node:child_process";
import { open, readFile, writeFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { projectLicense } from "./project-license.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const mode = process.argv[2] ?? "check";
if (!["check", "generated"].includes(mode)) {
  throw new Error("usage: node test/tooling/license-headers.mjs [check|generated]");
}
const extensions = new Set([".go", ".ts", ".tsx", ".proto", ".sql", ".sh", ".mjs"]);
// Landing applies deletions before staging them; cached names can be absent.
const deleted = new Set(
  execFileSync("git", ["ls-files", "--deleted", "-z"], { cwd: root, encoding: "utf8" })
    .split("\0")
    .filter(Boolean),
);
const paths = [
  ...new Set(
    execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], {
      cwd: root,
      encoding: "utf8",
    })
      .split("\0")
      .filter((path) => path && !deleted.has(path)),
  ),
];
let failed = false;
for (const path of paths) {
  const extension = extname(path);
  // Detect shell sources irrespective of suffix, without loading binary fixtures.
  const absolute = resolve(root, path);
  if (!extensions.has(extension)) {
    const file = await open(absolute, "r");
    let beginning;
    try {
      const buffer = Buffer.alloc(128);
      const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
      beginning = buffer.toString("utf8", 0, bytesRead);
    } finally {
      await file.close();
    }
    if (!/^#![^\n]*\b(?:ba|da|k|z)?sh\b/.test(beginning)) continue;
  }
  const source = await readFile(absolute, "utf8");
  const shell = /^#![^\n]*\b(?:ba|da|k|z)?sh\b/.test(source);
  if (!extensions.has(extension) && !shell) continue;
  // Unmodified copied GPL shell source is an aggregation-only test fixture.
  // Its original GPL-2.0-or-later notice and provenance must not be replaced.
  if (path === "internal/advisory/feed/testdata/arch-vercmptest.txt") {
    if (
      !source.includes("Copyright (c) 2008 by Dan McGee") ||
      !source.includes("either version 2 of the License")
    ) {
      console.error(`${path}: missing retained upstream GPL notice`);
      failed = true;
    }
    continue;
  }
  const generated =
    /^\/\/ (?:Code generated|@generated)\b/m.test(source) || path === "web/src/routeTree.gen.ts";
  if (mode === "generated" && !generated) continue;
  const prefix = extension === ".sql" ? "--" : shell || extension === ".sh" ? "#" : "//";
  const header = `${prefix} SPDX-License-Identifier: ${projectLicense}`;
  const lines = source.split("\n");
  const insertion = source.startsWith("#!") ? 1 : 0;
  if (lines[insertion] === header) continue;
  if (mode === "generated") {
    // This is a generation stage, not a handwritten change to derived sources.
    if (lines[insertion].startsWith(`${prefix} SPDX-License-Identifier:`)) {
      lines[insertion] = header;
    } else {
      lines.splice(insertion, 0, header, "");
    }
    await writeFile(absolute, lines.join("\n"));
  } else {
    console.error(`${path}: expected ${header} immediately after any shebang`);
    failed = true;
  }
}
if (failed) process.exitCode = 1;
