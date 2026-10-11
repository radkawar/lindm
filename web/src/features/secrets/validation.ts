import { createRegistry, type DescMessage, type MessageShape } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";

const validator = createValidator({ registry: createRegistry(audit_reason) });

// Material rules are regular expressions; show what to enter instead of the pattern.
const materialHints: readonly (readonly [string, string])[] = [
  [
    "material.password_hash",
    "Enter a crypt(3) hash, not the password: yescrypt ($y$…), SHA-512 ($6$…) or bcrypt ($2b$…).",
  ],
  [
    "material.wifi_psk",
    "Enter an 8 to 63 character printable WPA passphrase or a 64-digit hexadecimal PSK.",
  ],
];

function describe(violation: { toString(): string }): string {
  const text = violation.toString();
  return materialHints.find(([path]) => text.startsWith(path))?.[1] ?? text;
}

// Violation text names fields and rules only; it never echoes submitted material.
export function validateRequest<T extends DescMessage>(schema: T, message: MessageShape<T>) {
  const result = validator.validate(schema, message);
  if (result.kind === "invalid") throw new Error(result.violations.map(describe).join("; "));
  if (result.kind === "error") throw new Error(`Validation failed: ${result.error.message}`);
}
