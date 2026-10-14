// SPDX-License-Identifier: Apache-2.0
// Independently authored PE32+ fixture construction; no vendor executable bytes.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const output = join(root, "internal/agent/recoveryboot/testdata/authenticode");
const temporary = mkdtempSync(join(tmpdir(), "lindm-authenticode-fixtures-"));
const image = Buffer.alloc(0x600);
const pe = 0x80;
const optional = pe + 24;
image.write("MZ", 0, "ascii");
image.writeUInt32LE(pe, 0x3c);
image.write("PE\0\0", pe, "ascii");
image.writeUInt16LE(0x8664, pe + 4); // AMD64.
image.writeUInt16LE(2, pe + 6); // Two sections.
image.writeUInt16LE(240, pe + 20); // PE32+ optional header.
image.writeUInt16LE(0x22, pe + 22); // Executable, large-address-aware.
image.writeUInt16LE(0x20b, optional);
image.writeUInt32LE(0x200, optional + 4); // Code size.
image.writeUInt32LE(0x200, optional + 8); // Initialized data size.
image.writeUInt32LE(0x1000, optional + 16); // Entry point.
image.writeUInt32LE(0x1000, optional + 20); // Code base.
image.writeUInt32LE(0x1000, optional + 32); // Section alignment.
image.writeUInt32LE(0x200, optional + 36); // File alignment.
image.writeUInt32LE(0x3000, optional + 56); // Image size.
image.writeUInt32LE(0x200, optional + 60); // Header size.
image.writeUInt16LE(10, optional + 68); // EFI application.
image.writeUInt32LE(16, optional + 108); // Data directory count.
const section = optional + 240;
for (const [index, name, rva, offset, characteristics] of [
  [0, ".text", 0x1000, 0x200, 0x60000020],
  [1, ".data", 0x2000, 0x400, 0xc0000040],
]) {
  const at = section + index * 40;
  image.write(name, at, "ascii");
  image.writeUInt32LE(0x200, at + 8);
  image.writeUInt32LE(rva, at + 12);
  image.writeUInt32LE(0x200, at + 16);
  image.writeUInt32LE(offset, at + 20);
  image.writeUInt32LE(characteristics, at + 36);
}
image.set([0x31, 0xc0, 0xc3], 0x200); // xor eax,eax; ret. Not a bootable recovery image.
image.write("lindm independently authored Authenticode test fixture", 0x400, "ascii");

try {
  writeFileSync(join(output, "unsigned.efi"), image, { mode: 0o644 });
  for (const name of ["signer", "other"]) {
    const key = join(temporary, `${name}.key`);
    const certificate = join(output, `${name}.pem`);
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-days",
        "36500",
        "-subj",
        `/CN=lindm fictional ${name} fixture/`,
        "-keyout",
        key,
        "-out",
        certificate,
      ],
      { stdio: "ignore", timeout: 60000 },
    );
    execFileSync(
      "sbsign",
      [
        "--key",
        key,
        "--cert",
        certificate,
        "--output",
        join(output, name === "signer" ? "signed.efi" : "other-signed.efi"),
        join(output, "unsigned.efi"),
      ],
      { stdio: "inherit", timeout: 60000 },
    );
  }
  const files = ["unsigned.efi", "signed.efi", "other-signed.efi", "signer.pem", "other.pem"];
  const hashes = files.map(
    (name) =>
      `${createHash("sha256")
        .update(readFileSync(join(output, name)))
        .digest("hex")}  ${name}`,
  );
  writeFileSync(
    join(output, "provenance.txt"),
    [
      "SPDX-License-Identifier: Apache-2.0",
      "Authored for lindm; independently constructed synthetic PE32+ test data.",
      "Source: test/tooling/generate-authenticode-fixtures.mjs",
      "Generate: node test/tooling/generate-authenticode-fixtures.mjs",
      "Requirements: Node, OpenSSL, sbsigntool (sbsign).",
      "No vendor firmware or executable bytes are included.",
      "The x86 instructions and PE fields are authored from the file-format contract.",
      "Two unrelated ephemeral test keys sign the same image; private keys are removed.",
      "Certificates are fictional test trust, not project release or operational keys.",
      "Signatures/certificates change on regeneration; the unsigned input is deterministic.",
      "Test mutations retain fixed PE offset 0x80 and section data through offset 0x500.",
      "Tool output does not imply qualification of a real EFI loader or platform.",
      "",
      ...hashes,
      "",
    ].join("\n"),
    { mode: 0o644 },
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
