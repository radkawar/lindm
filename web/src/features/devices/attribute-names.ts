import {
  AttributeType,
  type AttributeDefinition,
} from "../../../gen/lindm/admin/v1/inventory_management_pb";

// One human name per attribute type, in the table, the form and device editors.
export const ATTRIBUTE_TYPE_LABEL: Record<AttributeType, string> = {
  [AttributeType.UNSPECIFIED]: "Unknown",
  [AttributeType.STRING]: "Text",
  [AttributeType.INT]: "Whole number",
  [AttributeType.BOOL]: "Yes/no",
  [AttributeType.ENUM]: "List of values",
};

// Definitions saved before display names existed are shown by key.
export function attributeName(definition: Pick<AttributeDefinition, "key" | "displayName">) {
  return definition.displayName || definition.key;
}

const KEY_PATTERN = /^[a-z][a-z0-9_.-]*$/;

// "Cost center" → "cost-center": the key devices and filters use.
export function keyFromName(name: string) {
  return name
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/^[^a-z]+/, "")
    .replace(/-+$/, "")
    .slice(0, 64);
}

export type DefinitionFieldErrors = Partial<
  Record<"displayName" | "key" | "enumValues" | "reason", string>
>;

// Mirrors AttributeDefinition's proto rules in words, so admins never see a
// validator message.
export function definitionFieldErrors(input: {
  displayName: string;
  key: string;
  type: AttributeType;
  enumValues: string[];
  reason: string;
}): DefinitionFieldErrors {
  const errors: DefinitionFieldErrors = {};
  if (!input.displayName) errors.displayName = "Enter a name, for example Cost center.";
  else if (input.displayName.length > 128) errors.displayName = "Use at most 128 characters.";
  if (!input.key) errors.key = "Enter a key, for example cost-center.";
  else if (input.key.length > 64) errors.key = "Use at most 64 characters.";
  else if (!KEY_PATTERN.test(input.key))
    errors.key =
      "Start with a lowercase letter and use only lowercase letters, digits, hyphens, underscores or dots.";
  if (input.type === AttributeType.ENUM) {
    const seen = new Set<string>();
    const repeated = input.enumValues.filter((value) => seen.size === seen.add(value).size);
    if (!input.enumValues.length) errors.enumValues = "Enter at least one allowed value.";
    else if (input.enumValues.length > 64) errors.enumValues = "Use at most 64 allowed values.";
    else if (repeated.length)
      errors.enumValues = `Each value can appear once; repeated: ${[...new Set(repeated)].join(", ")}.`;
    else if (input.enumValues.some((value) => value.length > 128))
      errors.enumValues = "Each value can be at most 128 characters.";
  }
  if (!input.reason) errors.reason = "Enter a reason for the audit log.";
  return errors;
}
