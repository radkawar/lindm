// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import {
  enabledModes,
  limitedLabels,
  onLabels,
} from "../src/features/assistance/capability-modes.ts";

test("every capability's offered choices have distinct labels", () => {
  for (const field of Object.keys(limitedLabels)) {
    const labels = enabledModes(field, "off").map((mode) =>
      mode === "limited" ? limitedLabels[field] : onLabels[field],
    );
    assert.equal(new Set(labels).size, labels.length, field);
  }
});

test("password-prompt guidance offers one choice and keeps a stored on", () => {
  assert.deepEqual(enabledModes("elevation", "off"), ["limited"]);
  assert.deepEqual(enabledModes("elevation", "limited"), ["limited"]);
  assert.deepEqual(enabledModes("elevation", "on"), ["on"]);
  assert.deepEqual(enabledModes("clipboard", "off"), ["limited", "on"]);
});
