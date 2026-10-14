// SPDX-License-Identifier: Apache-2.0

// Only explicit user-initiated file delivery. The URL is an opaque local Blob
// handle, never a credential-bearing network URL; it is immediately revoked.
export function downloadEnrollmentFile(name: string, content: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: "application/octet-stream" }));
  const link = document.createElement("a");
  try {
    link.href = url;
    link.download = name;
    document.body.append(link);
    link.click();
  } finally {
    link.remove();
    URL.revokeObjectURL(url);
  }
}
