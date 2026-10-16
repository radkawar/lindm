// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { sourceRetrySummary } from "../src/features/advisories/source-retries.ts";

test("latest-refresh retry count includes zero and preserves uint64 precision", () => {
  assert.equal(sourceRetrySummary(0n), "Retries for latest refresh: 0");
  assert.equal(sourceRetrySummary(4n), "Retries for latest refresh: 4");
  assert.equal(
    sourceRetrySummary(18446744073709551615n),
    "Retries for latest refresh: 18446744073709551615",
  );
});
