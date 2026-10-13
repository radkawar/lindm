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
