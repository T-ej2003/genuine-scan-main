import { domainToASCII } from "node:url";

const UNQUOTED_LOCAL_RE = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/;
const QUOTED_LOCAL_RE = /^"(?:[\x20-\x21\x23-\x5B\x5D-\x7E]|\\[\x20-\x7E])+"$/;
const DOMAIN_LABEL_RE = /^[A-Za-z0-9-]{1,63}$/;

const isValidLocalPart = (value: string) => {
  if (!value || value.length > 64) return false;
  if (UNQUOTED_LOCAL_RE.test(value)) {
    if (value.startsWith(".") || value.endsWith(".")) return false;
    if (value.includes("..")) return false;
    return true;
  }
  return QUOTED_LOCAL_RE.test(value);
};

const isValidAsciiDomain = (value: string) => {
  if (!value || value.length > 255) return false;
  if (value.startsWith(".") || value.endsWith(".")) return false;

  const labels = value.split(".");
  if (!labels.length) return false;

  for (const label of labels) {
    if (!label) return false;
    if (!DOMAIN_LABEL_RE.test(label)) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }

  return true;
};

export const normalizeEmailAddress = (input: unknown): string | null => {
  const raw = String(input || "").trim();
  if (!raw) return null;
  if (raw.length > 320) return null;
  if (/[\r\n\t]/.test(raw)) return null;

  const atIndex = raw.lastIndexOf("@");
  if (atIndex <= 0 || atIndex >= raw.length - 1) return null;
  if (raw.indexOf("@") !== atIndex) return null;

  const localPart = raw.slice(0, atIndex).trim();
  const domainPart = raw.slice(atIndex + 1).trim();

  if (!isValidLocalPart(localPart)) return null;

  const asciiDomain = domainToASCII(domainPart).toLowerCase();
  if (!isValidAsciiDomain(asciiDomain)) return null;

  const normalized = `${localPart.toLowerCase()}@${asciiDomain}`;
  if (normalized.length > 254) return null;
  return normalized;
};

export const isValidEmailAddress = (input: unknown) => normalizeEmailAddress(input) !== null;
