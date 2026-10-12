import { createRegistry, type DescMessage, type MessageShape } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";

const validator = createValidator({ registry: createRegistry(audit_reason) });

// The server's own buf.validate rules, checked before a request leaves the browser.
// Returns the violations in one sentence, or "" when the message is valid.
export function capabilityProblem<T extends DescMessage>(
  schema: T,
  message: MessageShape<T>,
): string {
  const result = validator.validate(schema, message);
  if (result.kind === "invalid")
    return result.violations.map((violation) => violation.toString()).join("; ");
  if (result.kind === "error") return `The request couldn't be checked: ${result.error.message}`;
  return "";
}
