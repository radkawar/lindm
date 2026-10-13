import { colourProperty, rawColour, rawTailwindColour } from "./colour-values.mjs";

function name(node) {
  if (!node) return "";
  return node.name ?? (typeof node.value === "string" ? node.value : "");
}

function styleContext(node) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (parent.type === "Property") return parent.key !== node && colourProperty(name(parent.key));
    if (parent.type === "JSXAttribute") return colourProperty(name(parent.name));
    if (parent.type === "AssignmentExpression") {
      const target = parent.left;
      return target.type === "MemberExpression" && colourProperty(name(target.property));
    }
    if (parent.type === "VariableDeclarator")
      return /(?:colou?rs?|palette|fill|stroke|background)$/i.test(name(parent.id));
    if (parent.type === "CallExpression") {
      const method = parent.callee.type === "MemberExpression" ? name(parent.callee.property) : "";
      if (["setProperty", "setAttribute"].includes(method))
        return parent.arguments[0] !== node && colourProperty(name(parent.arguments[0]));
    }
    if (["ExpressionStatement", "ReturnStatement", "Program"].includes(parent.type)) return false;
  }
  return false;
}

function initializer(node) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (parent.type === "VariableDeclarator") return parent;
    if (["ExpressionStatement", "ReturnStatement", "Program"].includes(parent.type)) break;
  }
  return null;
}

export const noRawColours = {
  meta: {
    type: "problem",
    docs: { description: "Keep console colours in the semantic palette in globals.css" },
    schema: [],
    messages: {
      raw: "Raw colour {{colour}} is not allowed here. Use a semantic theme token from globals.css.",
    },
  },
  create(context) {
    const strings = [];
    const source = context.sourceCode;
    return {
      Literal(node) {
        if (typeof node.value === "string") strings.push({ node, value: node.value });
      },
      TemplateElement(node) {
        strings.push({ node, value: node.value.cooked ?? node.value.raw });
      },
      "Program:exit"() {
        for (const { node, value } of strings) {
          // Utilities and attribute selectors carry their own style context.
          let colour = rawTailwindColour(value);
          if (!colour) {
            let style = styleContext(node);
            const declaration = initializer(node);
            if (!style && declaration) {
              // Also cover `const ink = "red"; <path stroke={ink} />` and arrays
              // of chart colours, without rejecting unrelated strings/IDs.
              style = source
                .getDeclaredVariables(declaration)
                .some((variable) =>
                  variable.references.some((reference) => styleContext(reference.identifier)),
                );
            }
            if (style) colour = rawColour(value);
          }
          if (colour) context.report({ node, messageId: "raw", data: { colour } });
        }
      },
    };
  },
};

export default { rules: { "no-raw-colours": noRawColours } };
