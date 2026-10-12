import { createRegistry, toBinary, type DescMessage, type MessageShape } from "@bufbuild/protobuf";
import { pathToString } from "@bufbuild/protobuf/reflect";
import { createValidator, ValidationError, type Violation } from "@bufbuild/protovalidate";
import { audit_reason } from "../../gen/lindm/validation/v1/string_rules_pb";

// The browser's one check of an outgoing request: the protos' buf.validate rules,
// then whether protobuf can encode it at all (a NaN or negative uint32 passes the
// rules but cannot be encoded). Both become field errors in plain words, so
// protobuf type names and encoder text never reach the page. The server
// enforces the same rules; this only answers earlier and without ambiguity.

export type FieldError = {
  // Field path from the request root ("spec.restart.delay_seconds"), or the
  // qualified field when only the encoder reported it.
  path: string;
  // Proto field name, for a form to place the message beside its input.
  field: string;
  message: string;
};

export class RequestInvalidError extends Error {
  override name = "RequestInvalidError";
  readonly fields: readonly FieldError[];

  constructor(fields: readonly FieldError[]) {
    super(fields.map((field) => field.message).join(" "));
    this.fields = fields;
  }
}

// Messages for specific paths (or path prefixes) where the rule text alone,
// such as a regular expression, wouldn't tell the user what to enter.
export type FieldHints = Readonly<Record<string, string>>;

const validator = createValidator({ registry: createRegistry(audit_reason) });
const ENCODE_FAILURE = /cannot encode (?:field )?([\w.]+)\.(\w+) to (?:binary|JSON): ([^\n]*)/;

// "delay_seconds" → "Delay seconds": the proto field name in plain words.
function fieldLabel(field: string) {
  const words = field.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function describeViolation(violation: Violation, hints?: FieldHints): FieldError {
  const path = pathToString(violation.field);
  const field = /(\w+)(?:\[[^\]]*\])*$/.exec(path)?.[1] ?? "";
  const hint =
    hints?.[path] ??
    Object.entries(hints ?? {}).find(
      ([prefix]) => path.startsWith(`${prefix}.`) || path.startsWith(`${prefix}[`),
    )?.[1];
  const text = (field ? `${fieldLabel(field)}: ${violation.message}` : violation.message).trim();
  return { path, field, message: hint ?? (/[.!?]$/.test(text) ? text : `${text}.`) };
}

export function describeViolations(violations: readonly Violation[], hints?: FieldHints) {
  return violations.map((violation) => describeViolation(violation, hints).message).join(" ");
}

function encodeProblem(qualifiedField: string, field: string, reason: string): FieldError {
  // Encoder reasons read "invalid uint32: NaN" or "expected uint32, got …".
  const kind = /\b(u?int(?:32|64)|s?fixed(?:32|64)|sint(?:32|64)|float(?:32)?|double)\b/.exec(
    reason,
  )?.[1];
  const remedy = !kind
    ? "check this value and try again"
    : kind.startsWith("float") || kind === "double"
      ? "enter a number"
      : kind.startsWith("u") || kind.startsWith("fixed")
        ? "enter a whole number, 0 or more"
        : "enter a whole number";
  return { path: qualifiedField, field, message: `${fieldLabel(field)}: ${remedy}.` };
}

// Recognizes a client-side request failure in any wrapping the console sees:
// a RequestInvalidError, a protovalidate ValidationError, a protobuf encoder
// error, or a Connect error caused by one. Server responses are never matched.
export function requestProblem(
  error: unknown,
  hints?: FieldHints,
): RequestInvalidError | undefined {
  for (let current = error, depth = 0; current instanceof Error && depth < 3; depth++) {
    if (current instanceof RequestInvalidError) return current;
    if (current instanceof ValidationError)
      return new RequestInvalidError(
        current.violations.map((violation) => describeViolation(violation, hints)),
      );
    const encode = current.name === "ConnectError" ? null : ENCODE_FAILURE.exec(current.message);
    if (encode) {
      const [, typeName, field, reason] = encode;
      return new RequestInvalidError([encodeProblem(`${typeName}.${field}`, field, reason)]);
    }
    current = current.cause;
  }
  return undefined;
}

// Returns the request's problems, or undefined when it can be sent. A rule the
// browser cannot evaluate is left to the server rather than blocking the user.
export function checkRequest<T extends DescMessage>(
  schema: T,
  message: MessageShape<T>,
  hints?: FieldHints,
): RequestInvalidError | undefined {
  const result = validator.validate(schema, message);
  if (result.kind === "invalid")
    return new RequestInvalidError(
      result.violations.map((violation) => describeViolation(violation, hints)),
    );
  try {
    toBinary(schema, message);
  } catch (error) {
    return (
      requestProblem(error, hints) ??
      new RequestInvalidError([{ path: "", field: "", message: "Check the form and try again." }])
    );
  }
  return undefined;
}

export function validateRequest<T extends DescMessage>(
  schema: T,
  message: MessageShape<T>,
  hints?: FieldHints,
) {
  const problem = checkRequest(schema, message, hints);
  if (problem) throw problem;
}

// Text for a form's inline error: client-side problems in plain words, other
// errors by their own message.
export function formErrorMessage(error: unknown, fallback = "Check the form and try again.") {
  return requestProblem(error)?.message ?? (error instanceof Error ? error.message : fallback);
}
