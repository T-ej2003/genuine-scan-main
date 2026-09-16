import ts from "typescript";

// Only discard a conditional suffix when every branch is empty or starts a query.
const querySuffix = (node) => {
  if (ts.isConditionalExpression(node)) return querySuffix(node.whenTrue) && querySuffix(node.whenFalse);
  if (ts.isStringLiteralLike(node)) return node.text === "" || node.text.startsWith("?");
  return ts.isTemplateExpression(node) && node.head.text.startsWith("?");
};

export const literalPath = (node, source) => {
  if (ts.isStringLiteralLike(node)) return node.text;
  if (!ts.isTemplateExpression(node)) return null;
  let value = node.head.text;
  for (const [index, span] of node.templateSpans.entries()) {
    if (value.includes("?")) return value.split("?")[0];
    const expression = span.expression.getText(source).replace(/\s+/g, " ");
    if (expression === "BASE_URL") { value += span.literal.text; continue; }
    if (index === node.templateSpans.length - 1 && span.literal.text === "" && querySuffix(span.expression)) return value || null;
    if (["endpoint", "url", "query"].includes(expression) || expression.includes("params.toString()")) return value || null;
    value += `:${expression.replace(/\W+/g, "_")}${span.literal.text}`;
  }
  return value.split("?")[0];
};
