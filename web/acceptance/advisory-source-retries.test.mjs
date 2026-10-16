// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import {
  sourceRetrySummary,
  sourceVendorRaceRefetchSummary,
} from "../src/features/advisories/source-retries.ts";

test("latest-refresh retry count includes zero and preserves uint64 precision", () => {
  assert.equal(sourceRetrySummary(0n), "Retries for latest refresh: 0");
  assert.equal(sourceRetrySummary(4n), "Retries for latest refresh: 4");
  assert.equal(
    sourceRetrySummary(18446744073709551615n),
    "Retries for latest refresh: 18446744073709551615",
  );
});

test("vendor publication race refetches stay distinct and preserve uint64 precision", () => {
  assert.equal(
    sourceVendorRaceRefetchSummary(0n),
    "Vendor publication race refetches for latest refresh: 0",
  );
  assert.equal(
    sourceVendorRaceRefetchSummary(2n),
    "Vendor publication race refetches for latest refresh: 2",
  );
  assert.equal(
    sourceVendorRaceRefetchSummary(18446744073709551615n),
    "Vendor publication race refetches for latest refresh: 18446744073709551615",
  );
  assert.notEqual(sourceRetrySummary(2n), sourceVendorRaceRefetchSummary(2n));
});
