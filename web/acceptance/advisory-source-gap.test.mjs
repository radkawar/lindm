// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { rejectedDocumentDetails, sourceGap } from "../src/features/advisories/source-gap.ts";

test("incomplete current vendor data reports unusable document scope and preserves exact cause in Details", () => {
  const record = {
    id: "CVE-2026-1234 / csaf/vendor-document.json",
    reason: "product_reference_unresolved: product-17",
    unscoped: true,
    packageNames: [],
  };
  const gap = sourceGap("Red Hat Enterprise Linux 9", [record]);
  assert.match(gap.missing, /published.*incomplete:.*1 unusable vendor document/);
  assert.doesNotMatch(gap.missing, /stale|expired|unpublished/);
  assert.match(gap.remedy, /exposure remains unknown/);
  assert.deepEqual(rejectedDocumentDetails(record), [
    { label: "Document / CVE", value: record.id },
    { label: "Reported cause", value: record.reason },
  ]);
  const scoped = { ...record, unscoped: false, packageNames: ["openssl"] };
  assert.match(sourceGap("RHEL 9", [scoped]).missing, /current.*complete advisory list/);
  assert.match(
    sourceGap("RHEL 9", [record, { ...record, unscoped: false }]).missing,
    /2 unusable vendor documents/,
  );
  assert.doesNotMatch(gap.missing, /product_reference_unresolved|product-17/);
});
