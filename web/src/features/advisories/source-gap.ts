// SPDX-License-Identifier: Apache-2.0

// Empty package scope is conservative even when an older publisher omitted unscoped.
type RejectedDocument = { id: string; reason: string; unscoped: boolean; packageNames: string[] };

export function rejectedDocumentDetails(record: RejectedDocument) {
  return [
    { label: "Document / CVE", value: record.id || "Not reported" },
    { label: "Reported cause", value: record.reason },
  ];
}

export function sourceGap(os: string, records: RejectedDocument[]) {
  const unscoped = records.filter((record) => record.unscoped || record.packageNames.length === 0);
  if (unscoped.length === 0) {
    return {
      missing: `The published ${os} vulnerability data is current but does not cover the complete advisory list.`,
      remedy: `Review the source configuration and provide a complete ${os} vendor snapshot.`,
    };
  }
  const documents =
    unscoped.length === 1
      ? "1 unusable vendor document"
      : `${unscoped.length} unusable vendor documents`;
  return {
    missing: `The published ${os} vulnerability data is incomplete: affected components are not fully identified in ${documents}.`,
    remedy: `Review the document and CVE details below. ${os} exposure remains unknown until the affected components can be determined.`,
  };
}
