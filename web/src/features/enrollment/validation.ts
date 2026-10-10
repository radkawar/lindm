import { createRegistry, type DescMessage, type MessageShape } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import { audit_reason } from "../../../gen/lindm/validation/v1/string_rules_pb";
import { Code, ConnectError } from "@connectrpc/connect";
import { toRpcFailure } from "@/lib/errors";

const validator = createValidator({ registry: createRegistry(audit_reason) });

export function validateEnrollment<T extends DescMessage>(schema: T, message: MessageShape<T>) {
  const result = validator.validate(schema, message);
  if (result.kind === "invalid")
    throw new Error(result.violations.map((violation) => violation.toString()).join("; "));
  if (result.kind === "error")
    throw new Error(`Enrollment validation failed: ${result.error.message}`);
}

export function enrollmentFailure(error: unknown, submitted: boolean) {
  return toRpcFailure(
    submitted
      ? error
      : new ConnectError(
          error instanceof Error ? error.message : "Invalid enrollment input.",
          Code.InvalidArgument,
        ),
  );
}
