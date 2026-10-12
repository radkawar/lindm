#!/usr/bin/env node
// Local owner-authored annotations -> private, actionable task records. No network,
// issue tracker mutation, inferred approval or model-generated owner feedback.
import { lstat, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { readPrivateJSON, writePrivateJSON } from "./private-files.mjs";
import { annotationFields, screenshotReference } from "./review-edit-sheet.mjs";

process.umask(0o077);

function object(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  )
    throw new Error("unexpected_or_missing_fields");
}

function text(value, max, empty = false) {
  if (typeof value !== "string" || value.length > max || (!empty && !value.trim()))
    throw new Error("invalid_text_field");
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if ((code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 127)
      throw new Error("invalid_text_field");
  }
  return value.trim();
}

function manifestScreens(manifest) {
  object(manifest, ["version", "runId", "startedAt", "contactSheet", "screens"]);
  if (
    manifest.version !== 1 ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(
      text(manifest.runId, 36),
    ) ||
    manifest.contactSheet !== "index.html" ||
    !Array.isArray(manifest.screens) ||
    manifest.screens.length > 500
  )
    throw new Error("invalid_manifest");
  text(manifest.startedAt, 40);
  const screens = new Map();
  for (const screen of manifest.screens) {
    object(screen, ["id", "route", "url", "variant", "captures"]);
    if (!/^[a-f0-9]{24}$/.test(text(screen.id, 24)) || screens.has(screen.id))
      throw new Error("invalid_or_duplicate_screen");
    for (const name of ["route", "url"]) {
      text(screen[name], 2048);
      if (!screen[name].startsWith("/") || screen[name].startsWith("//"))
        throw new Error("invalid_screen_route");
    }
    text(screen.variant, 200, true);
    if (!Array.isArray(screen.captures) || screen.captures.length > 16)
      throw new Error("invalid_capture_count");
    for (const capture of screen.captures) {
      object(capture, ["theme", "viewport", "screenshot", "dialogs", "machinePassed", "coverage"]);
      if (
        !["light", "dark"].includes(capture.theme) ||
        !["desktop", "mobile"].includes(capture.viewport) ||
        typeof capture.machinePassed !== "boolean" ||
        !["semantic", "structural", "uncontracted", "unavailable"].includes(capture.coverage) ||
        !Array.isArray(capture.dialogs) ||
        capture.dialogs.length > 32
      )
        throw new Error("invalid_capture");
      screenshotReference(capture.screenshot);
      capture.dialogs.forEach(screenshotReference);
    }
    screens.set(screen.id, screen);
  }
  return screens;
}

// The generator writes a full-page screenshot for every capture; a sheet whose
// evidence is missing beside it is not the canonical run evidence.
async function requireScreenshots(manifestPath, screens) {
  const directory = dirname(manifestPath);
  for (const screen of screens.values())
    for (const capture of screen.captures)
      for (const path of [capture.screenshot, ...capture.dialogs]) {
        const stat = await lstat(join(directory, path)).catch(() => null);
        if (!stat?.isFile()) throw new Error("manifest_screenshot_missing");
      }
}

try {
  if (process.argv.length !== 5)
    throw new Error(
      "usage: node web/acceptance/review-import.mjs EDIT_SHEET_JSON ANNOTATIONS_JSON NEW_OUTPUT_DIR",
    );
  const [manifestPath, annotationsPath, output] = process.argv
    .slice(2)
    .map((path) => resolve(path));
  const manifest = await readPrivateJSON(manifestPath);
  const screens = manifestScreens(manifest);
  await requireScreenshots(manifestPath, screens);
  const source = await readPrivateJSON(annotationsPath);
  object(source, ["version", "runId", "author", "annotations"]);
  if (
    source.version !== 1 ||
    source.runId !== manifest.runId ||
    !Array.isArray(source.annotations) ||
    !source.annotations.length ||
    source.annotations.length > 500
  )
    throw new Error("annotations_require_matching_run_and_1_to_500_records");
  const author = text(source.author, 120);
  const seen = new Set();
  const annotations = source.annotations.map((item) => {
    object(item, ["screenId", ...Object.keys(annotationFields), "priority"]);
    if (!screens.has(item.screenId) || seen.has(item.screenId))
      throw new Error("unknown_or_duplicate_annotation_screen");
    seen.add(item.screenId);
    if (!["low", "normal", "high", "urgent"].includes(item.priority))
      throw new Error("invalid_task_priority");
    return {
      screenId: item.screenId,
      ...Object.fromEntries(
        Object.keys(annotationFields).map((key) => [
          key,
          text(item[key], key === "assignee" ? 120 : 2000),
        ]),
      ),
      priority: item.priority,
    };
  });
  const tasks = annotations.map((item) => {
    const screen = screens.get(item.screenId);
    return {
      id: `${manifest.runId}:${item.screenId}`,
      status: "open",
      source: "owner-annotation",
      author,
      assignee: item.assignee,
      priority: item.priority,
      action: item.action,
      acceptance: item.acceptance,
      route: screen.route,
      variant: screen.variant,
      evidence: { manifest: manifestPath, screenId: item.screenId, captures: screen.captures },
      observations: Object.fromEntries(
        ["whatChanged", "needsMe", "consequences", "redundancy"].map((key) => [key, item[key]]),
      ),
    };
  });
  // Require a new output directory: neither evidence nor previous owner edits can
  // be overwritten by a mistyped path. All validation precedes filesystem writes.
  await mkdir(output, { mode: 0o700 });
  await writePrivateJSON(join(output, "annotations.json"), { ...source, author, annotations });
  await writePrivateJSON(join(output, "tasks.json"), {
    version: 1,
    runId: manifest.runId,
    importedAt: new Date().toISOString(),
    approval: "not_requested_or_inferred",
    tasks,
  });
  console.log(`Imported ${tasks.length} owner-authored task records; no review approval inferred.`);
} catch (error) {
  // Do not echo input or filesystem paths containing owner observations.
  const message =
    error instanceof SyntaxError
      ? "invalid_json"
      : error?.code
        ? `filesystem_${error.code}`
        : error.message;
  console.error(`Annotation import failed: ${message}`);
  process.exitCode = 1;
}
