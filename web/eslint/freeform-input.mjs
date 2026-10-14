// SPDX-License-Identifier: Apache-2.0

// lindm/freeform-input: a text-like console input is either an explicitly
// declared free-text value (data-freeform="<why the value is genuinely new>") or
// it should be a SearchPicker/SelectField over real server values. The type
// exemptions and the existing-entity label pattern are shared with the ui-review
// runtime probe through web/acceptance/copy-rules.json (docs/engineering.md,
// "Free-text inputs").
import copyRules from "../acceptance/copy-rules.json" with { type: "json" };

const config = copyRules.freeformInput;
const exemptTypes = new Set(config.exemptTypes);
const domainLabel = new RegExp(config.domainLabel, "i");
const searchLabel = new RegExp(config.searchLabel, "i");
const checked = new Set([
  "Input",
  "Textarea",
  "input",
  "textarea",
  "InputGroupInput",
  "InputGroupTextarea",
  "SidebarInput",
]);
const labelElements = new Set(["Label", "label", "FieldLabel"]);

// Same normalization as the probe in web/acceptance/review-probes.mjs.
export function normalizeLabel(value) {
  return value
    .toLowerCase()
    .replace(/\([^)]*\)/g, " ")
    .replace(/[\u2026:*?!.,;"'`_/-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/(?:^| )(?:optional|required)$/, "")
    .trim();
}

function elementName(node) {
  return node.name.type === "JSXIdentifier" ? node.name.name : "";
}

function attribute(opening, name) {
  return opening.attributes.find(
    (item) =>
      item.type === "JSXAttribute" && item.name.type === "JSXIdentifier" && item.name.name === name,
  );
}

// The literal strings an attribute value can take: a string, a template
// literal's static text, or both branches of a conditional. null when any part
// is computed.
function literals(value) {
  if (!value) return null;
  if (value.type === "Literal") return typeof value.value === "string" ? [value.value] : null;
  if (value.type === "JSXExpressionContainer") return literals(value.expression);
  if (value.type === "TemplateLiteral")
    return value.expressions.length === 0 ? [value.quasis[0].value.cooked ?? ""] : null;
  if (value.type === "ConditionalExpression") {
    const a = literals(value.consequent);
    const b = literals(value.alternate);
    return a && b ? [...a, ...b] : null;
  }
  return null;
}

// A data-freeform value is valid when every way it can evaluate is a non-empty
// string literal or a call to a reason helper (a schema-driven form computes
// one reason per field). Identifiers and other expressions are rejected: they
// too easily carry operator input, such as the reason the user is typing.
function declaredReason(value) {
  if (!value) return false;
  if (value.type === "JSXExpressionContainer") return declaredReason(value.expression);
  if (value.type === "CallExpression") return true;
  if (value.type === "ConditionalExpression")
    return declaredReason(value.consequent) && declaredReason(value.alternate);
  const text = literals(value);
  return !!text && text.every((item) => item.trim() !== "");
}

// Static label text for heuristics: template literals contribute their static parts.
function labelText(value) {
  if (!value) return "";
  if (value.type === "Literal") return typeof value.value === "string" ? value.value : "";
  if (value.type === "JSXExpressionContainer") return labelText(value.expression);
  if (value.type === "TemplateLiteral")
    return value.quasis.map((q) => q.value.cooked ?? "").join(" ");
  return "";
}

function childrenText(element, skip) {
  let text = "";
  for (const child of element.children) {
    if (child === skip) continue;
    if (child.type === "JSXText") text += child.value;
    else if (child.type === "JSXExpressionContainer") text += ` ${labelText(child.expression)} `;
    else if (child.type === "JSXElement") text += ` ${childrenText(child, skip)} `;
  }
  return text;
}

function containsNode(outer, inner) {
  return outer.range[0] <= inner.range[0] && inner.range[1] <= outer.range[1];
}

// The nearest enclosing function (component), or the program.
function scopeOf(node) {
  let scope = node.parent;
  while (scope && !/Function/.test(scope.type) && scope.type !== "Program") scope = scope.parent;
  return scope;
}

// A stable key for an id/htmlFor value: literal text file-wide, or a computed
// expression's source within its component (each component's `id` is its own).
function idKey(element, value, sourceCode) {
  if (!value) return "";
  if (value.type === "Literal") return `"${value.value}"`;
  if (value.type === "JSXExpressionContainer") {
    const expression = value.expression;
    if (expression.type === "Literal") return `"${expression.value}"`;
    if (expression.type === "TemplateLiteral" && expression.expressions.length === 0)
      return `"${expression.quasis[0].value.cooked}"`;
    return `${scopeOf(element).range[0]}:${sourceCode.getText(expression)}`;
  }
  return "";
}

function readOnlyLiteral(opening) {
  const value = attribute(opening, "readOnly");
  if (!value) return false;
  if (value.value === null) return true;
  return (
    value.value.type === "JSXExpressionContainer" &&
    value.value.expression.type === "Literal" &&
    value.value.expression.value === true
  );
}

export const freeformInput = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Require text-like inputs to declare why their value is free text, and reject free text for existing entities.",
    },
    schema: [],
    messages: {
      undeclared:
        '{{element}} is free text without a declaration. Choose existing values with a SearchPicker or SelectField, or add data-freeform="<why the value is genuinely new>".',
      empty:
        "data-freeform must be a non-empty string literal (or a reason helper call) naming why the value is free text.",
      domain:
        '{{element}} labelled "{{label}}" refers to values that already exist. Use a SearchPicker over server values or a SelectField, not free text.',
    },
  },
  create(context) {
    const sourceCode = context.sourceCode;
    const inputs = [];
    const labels = [];
    return {
      JSXElement(node) {
        const name = elementName(node.openingElement);
        if (checked.has(name)) inputs.push(node);
        if (labelElements.has(name)) labels.push(node);
      },
      "Program:exit"() {
        const forLabels = new Map();
        for (const label of labels) {
          const key = idKey(label, attribute(label.openingElement, "htmlFor")?.value, sourceCode);
          if (key) forLabels.set(key, `${forLabels.get(key) ?? ""} ${childrenText(label)}`);
        }
        for (const node of inputs) {
          const opening = node.openingElement;
          const element = elementName(opening);
          const textarea = /textarea/i.test(element);
          const type = attribute(opening, "type");
          if (!textarea && type) {
            const values = literals(type.value);
            if (values && values.every((value) => exemptTypes.has(value.toLowerCase()))) continue;
          }
          if (readOnlyLiteral(opening)) continue;
          const sources = [
            labelText(attribute(opening, "aria-label")?.value),
            labelText(attribute(opening, "placeholder")?.value),
            labelText(attribute(opening, "name")?.value),
          ];
          const id = idKey(node, attribute(opening, "id")?.value, sourceCode);
          if (id && forLabels.has(id)) sources.push(forLabels.get(id));
          for (const label of labels)
            if (containsNode(label, node)) sources.push(childrenText(label, node));
          const normalized = sources.map(normalizeLabel).filter(Boolean);
          const typeValues = type ? literals(type.value) : null;
          const search =
            (typeValues?.length === 1 && typeValues[0] === "search") ||
            normalized.some((value) => searchLabel.test(value));
          const domain = search ? undefined : normalized.find((value) => domainLabel.test(value));
          if (domain) {
            context.report({
              node: opening,
              messageId: "domain",
              data: { element, label: domain },
            });
            continue;
          }
          const declared = attribute(opening, "data-freeform");
          if (!declared) {
            context.report({ node: opening, messageId: "undeclared", data: { element } });
            continue;
          }
          if (!declaredReason(declared.value))
            context.report({ node: declared, messageId: "empty" });
        }
      },
    };
  },
};

export default { rules: { "freeform-input": freeformInput } };
