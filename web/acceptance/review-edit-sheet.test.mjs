import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { editManifest } from "./review-edit-sheet.mjs";

const importer = fileURLToPath(new URL("./review-import.mjs", import.meta.url));
const run = promisify(execFile);

function result(route, variant, screenshots) {
  return {
    route,
    url: route,
    variant,
    theme: "light",
    viewport: "desktop",
    passed: true,
    screenshots,
    checks: {},
  };
}

// Regression: enrollment and settings captures recorded only viewport and
// details screenshots, so every generated sheet failed import.
test("generator refuses a capture without a full-page screenshot", () => {
  const report = {
    startedAt: "2026-10-12T00:00:00.000Z",
    results: [
      result("/settings", "published repository-readiness", {
        viewport: "screenshots/settings.png",
        details: "screenshots/settings-details.png",
      }),
    ],
  };
  assert.throws(
    () => editManifest(report),
    /capture has no valid full-page screenshot: \/settings published repository-readiness/,
  );
  report.results[0].screenshots.full = "screenshots/settings-full.png";
  const manifest = editManifest(report);
  assert.equal(manifest.screens[0].captures[0].screenshot, "screenshots/settings-full.png");
});

test("importer accepts the generated sheet only with its screenshots beside it", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "lindm-edit-sheet-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const manifest = editManifest({
    startedAt: "2026-10-12T00:00:00.000Z",
    results: [
      result("/dashboard", "", {
        full: "screenshots/dashboard-full.png",
        dialogs: ["screenshots/dashboard-dialog-1.png"],
      }),
    ],
  });
  const fields = {
    whatChanged: "Queue leads.",
    needsMe: "Coverage.",
    consequences: "Truthful.",
    redundancy: "Accordions.",
    action: "Promote coverage.",
    acceptance: "Coverage item visible.",
    assignee: "console agents",
  };
  const annotations = {
    version: 1,
    runId: manifest.runId,
    author: "owner",
    annotations: [{ screenId: manifest.screens[0].id, ...fields, priority: "high" }],
  };
  const sheet = join(directory, "edit-sheet.json");
  const owner = join(directory, "owner-annotations.json");
  await writeFile(sheet, JSON.stringify(manifest), { mode: 0o600 });
  await writeFile(owner, JSON.stringify(annotations), { mode: 0o600 });
  await mkdir(join(directory, "screenshots"), { mode: 0o700 });
  await writeFile(join(directory, "screenshots/dashboard-full.png"), "png", { mode: 0o600 });

  await assert.rejects(run(process.execPath, [importer, sheet, owner, join(directory, "a")]), {
    stderr: /Annotation import failed: manifest_screenshot_missing/,
  });
  await writeFile(join(directory, "screenshots/dashboard-dialog-1.png"), "png", { mode: 0o600 });
  const { stdout } = await run(process.execPath, [importer, sheet, owner, join(directory, "b")]);
  assert.match(stdout, /Imported 1 owner-authored task records/);
});
