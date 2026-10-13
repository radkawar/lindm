import { createRegistry, toBinary, type DescMessage, type MessageShape } from "@bufbuild/protobuf";
import { pathToString } from "@bufbuild/protobuf/reflect";
import { createValidator, ValidationError, type Violation } from "@bufbuild/protovalidate";
import type { Violation as ViolationProto } from "@bufbuild/protovalidate/gen/buf/validate/validate_pb.js";
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
  return describe(pathToString(violation.field), violation.ruleId, violation.message, hints);
}

// A server refusal's buf.validate violation, in the same words as the browser's check.
export function describeViolationProto(violation: ViolationProto, hints?: FieldHints): FieldError {
  const path = (violation.field?.elements ?? [])
    .map((element, index) => {
      const name = `${index > 0 ? "." : ""}${element.fieldName}`;
      switch (element.subscript.case) {
        case undefined:
          return name;
        case "stringKey":
          return `${name}[${JSON.stringify(element.subscript.value)}]`;
        default:
          return `${name}[${String(element.subscript.value)}]`;
      }
    })
    .join("");
  return describe(path, violation.ruleId, violation.message, hints);
}

function describe(path: string, ruleId: string, ruleMessage: string, hints?: FieldHints) {
  const field = /(\w+)(?:\[[^\]]*\])*$/.exec(path)?.[1] ?? "";
  const hint =
    hints?.[path] ??
    Object.entries(hints ?? {}).find(
      ([prefix]) => path.startsWith(`${prefix}.`) || path.startsWith(`${prefix}[`),
    )?.[1];
  if (hint) return { path, field, message: hint };
  const entry = /\[(\d+)\]$/.exec(path)?.[1];
  const label = field
    ? `${fieldLabel(field)}${entry === undefined ? "" : ` (entry ${Number(entry) + 1})`}`
    : "This value";
  return { path, field, message: violationText(label, ruleId, ruleMessage) };
}

// Standard rule IDs ("string.pattern", "uint32.gte_lte") in words. Their default
// messages quote regular expressions and type names, so they never reach the page.
// Custom CEL rules carry a message their proto author wrote for people.
export function violationText(label: string, ruleId: string, ruleMessage: string): string {
  const [family = "", rule = ""] = ruleId.split(".");
  const [first = "", second = ""] = ruleMessage.match(/-?\d+(?:\.\d+)?/g) ?? [];
  if (ruleId === "required") return `${label} is required.`;
  if (STANDARD_RULE_FAMILIES[family] !== true) {
    const text = ruleMessage.trim();
    if (text === "" || RAW_VALIDATION_TEXT.test(text)) return `${label} isn't valid.`;
    const sentence = text.charAt(0).toUpperCase() + text.slice(1);
    return /[.!?]$/.test(sentence) ? sentence : `${sentence}.`;
  }
  switch (rule) {
    case "min_len":
    case "min_bytes":
      return first === "1" || first === ""
        ? `${label} is required.`
        : `${label} is too short: use at least ${first} characters.`;
    case "max_len":
    case "max_bytes":
      return `${label} is too long: use at most ${first} characters.`;
    case "len":
    case "len_bytes":
      return `${label} must be exactly ${first} characters.`;
    case "pattern":
    case "prefix":
    case "suffix":
    case "contains":
    case "not_contains":
      return `${label} contains characters or a format that isn't allowed.`;
    case "ip":
    case "ipv4":
    case "ipv6":
      return `${label}: enter an IP address, such as 192.0.2.10.`;
    case "ip_prefix":
    case "ip_with_prefixlen":
    case "ipv4_prefix":
    case "ipv6_prefix":
    case "ipv4_with_prefixlen":
    case "ipv6_with_prefixlen":
      return `${label}: enter a network, such as 192.0.2.0/24.`;
    case "hostname":
    case "host_and_port":
    case "address":
      return `${label}: enter a host name, such as host.example.com.`;
    case "uri":
    case "uri_ref":
      return `${label}: enter a full address, such as https://example.com/path.`;
    case "email":
      return `${label}: enter an email address.`;
    case "uuid":
    case "tuuid":
    case "defined_only":
    case "in":
    case "not_in":
    case "const":
      return `${label}: choose one of the offered values.`;
    case "min_items":
    case "min_pairs":
      return first === "1" || first === ""
        ? `${label}: add at least one.`
        : `${label}: add at least ${first}.`;
    case "max_items":
    case "max_pairs":
      return `${label}: use at most ${first}.`;
    case "unique":
      return `${label}: remove the repeated entries.`;
    case "gte_lte":
    case "gt_lt":
    case "gte_lt":
    case "gt_lte":
      return `${label} must be between ${first} and ${second}.`;
    case "gte":
      return `${label} must be ${first} or more.`;
    case "gt":
      return `${label} must be more than ${first}.`;
    case "lte":
      return `${label} must be ${first} or less.`;
    case "lt":
      return `${label} must be less than ${first}.`;
    default:
      return `${label} isn't valid.`;
  }
}

const STANDARD_RULE_FAMILIES: Record<string, true> = {
  string: true,
  bytes: true,
  bool: true,
  enum: true,
  repeated: true,
  map: true,
  any: true,
  duration: true,
  timestamp: true,
  double: true,
  float: true,
  int32: true,
  int64: true,
  uint32: true,
  uint64: true,
  sint32: true,
  sint64: true,
  fixed32: true,
  fixed64: true,
  sfixed32: true,
  sfixed64: true,
};

// Validator and encoder wording that must never reach primary text: rule IDs in
// brackets, regular-expression and type-name messages, request field paths.
export const RAW_VALIDATION_TEXT =
  /\[(?:required|(?:string|bytes|bool|enum|repeated|map|u?int(?:32|64)|s?fixed(?:32|64)|sint(?:32|64)|double|float|duration|timestamp)\.[a-z_]+)\]|regex pattern|cannot encode|validation error|\b(?=[\w.[\]]*(?:_|\[\d+\]))[a-z_]+(?:\[\d+\])?(?:\.[a-z_]+(?:\[\d+\])?)+:/;

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
      new RequestInvalidError([
        { path: "", field: "", message: "Check the form. Retry the request." },
      ])
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
export function formErrorMessage(error: unknown, fallback = "Check the form. Retry the request.") {
  const message =
    requestProblem(error)?.message ?? (error instanceof Error ? error.message : fallback);
  return RAW_VALIDATION_TEXT.test(message) ? fallback : message;
}
