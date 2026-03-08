import * as React from "react";

const normalizeTooltipText = (value: string) => {
  const cleaned = value.replace(/\s+/g, " ").trim();
  if (!cleaned) return undefined;
  return cleaned.length > 180 ? `${cleaned.slice(0, 177).trimEnd()}...` : cleaned;
};

const extractText = (node: React.ReactNode): string => {
  if (typeof node === "string" || typeof node === "number") {
    return String(node);
  }

  if (Array.isArray(node)) {
    return node.map((child) => extractText(child)).join(" ");
  }

  if (!React.isValidElement(node)) {
    return "";
  }

  return extractText((node.props as { children?: React.ReactNode }).children);
};

export const resolveTooltipText = (params: {
  tooltip?: string | false;
  title?: string;
  ariaLabel?: string;
  children?: React.ReactNode;
}) => {
  if (params.tooltip === false) return undefined;

  const direct =
    (typeof params.tooltip === "string" ? normalizeTooltipText(params.tooltip) : undefined) ||
    (typeof params.title === "string" ? normalizeTooltipText(params.title) : undefined) ||
    (typeof params.ariaLabel === "string" ? normalizeTooltipText(params.ariaLabel) : undefined);

  if (direct) return direct;

  return normalizeTooltipText(extractText(params.children));
};
