// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { END_HEADINGS } from "./assistance-end.mjs";

// The lane's end-cause probe must match every end heading the viewer renders:
// it read only "Why this session ended" and timed out on a refused request's
// "Why it couldn't start" (pop2404-assistance-dbg-01).
test("end-cause probe headings are exactly the viewer's end headings", async () => {
  const viewer = await readFile(
    new URL("../src/features/assistance/viewer.tsx", import.meta.url),
    "utf8",
  );
  const rendered = /\{failed \? "([^"]+)" : ended \? "([^"]+)" : "[^"]+"\}/.exec(viewer);
  assert.ok(rendered, "viewer end heading expression not found");
  assert.deepEqual([...END_HEADINGS].sort(), [rendered[1], rendered[2]].sort());
});

test("control consent copy never promises a view-only downgrade on every desktop", async () => {
  const [panel, viewer] = await Promise.all(
    ["panel", "viewer"].map((name) =>
      readFile(new URL(`../src/features/assistance/${name}.tsx`, import.meta.url), "utf8"),
    ),
  );
  assert.doesNotMatch(panel, /can allow keyboard and mouse control, or choose viewing only/);
  assert.doesNotMatch(viewer, /You can allow viewing only in the system dialog/);
  assert.match(panel, /Some desktops cannot allow viewing only for a control request/);
  assert.match(viewer, /may grant the shared screen and control together/);
  assert.doesNotMatch(viewer, /their desktop asks which screen to share/);
});

test("qualification remedies distinguish unknown consent and do not promise unsupported VIEW", async () => {
  const display = await readFile(
    new URL("../src/features/assistance/display.tsx", import.meta.url),
    "utf8",
  );
  assert.match(
    display,
    /notification_actions_unverified:\s*"[^"]*implementation has not been verified/,
  );
  assert.match(display, /desktop_runtime_unqualified:\s*"[^"]*reviewed assistance tuple/);
  assert.doesNotMatch(display, /Request view only instead/);
  assert.match(display, /This desktop may also require it for viewing/);
});
