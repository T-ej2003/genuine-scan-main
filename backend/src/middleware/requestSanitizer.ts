import { NextFunction, Request, Response } from "express";

const CONTROL_CHAR_REGEX = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const MAX_NESTED_DEPTH = 10;
const MAX_OBJECT_KEYS = 250;
const MAX_ARRAY_ITEMS = 500;

const isPlainObject = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

const sanitizeString = (value: string) => value.replace(CONTROL_CHAR_REGEX, "");

// Apply lightweight structural sanitization before route-level schema validation.
export const sanitizeUnknownInput = (value: unknown, path = "input", depth = 0): unknown => {
  if (depth > MAX_NESTED_DEPTH) {
    throw new Error(`${path} is too deeply nested.`);
  }

  if (typeof value === "string") {
    return sanitizeString(value);
  }

  if (value == null || typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_ITEMS) {
      throw new Error(`${path} contains too many items.`);
    }
    return value.map((entry, index) => sanitizeUnknownInput(entry, `${path}[${index}]`, depth + 1));
  }

  if (!isPlainObject(value)) {
    throw new Error(`${path} contains an unsupported object type.`);
  }

  const entries = Object.entries(value);
  if (entries.length > MAX_OBJECT_KEYS) {
    throw new Error(`${path} contains too many fields.`);
  }

  const sanitized: Record<string, unknown> = {};
  for (const [rawKey, rawValue] of entries) {
    const key = sanitizeString(String(rawKey || ""));
    if (!key) {
      throw new Error(`${path} contains an empty field name.`);
    }
    if (FORBIDDEN_KEYS.has(key)) {
      throw new Error(`${path}.${key} is not allowed.`);
    }
    sanitized[key] = sanitizeUnknownInput(rawValue, `${path}.${key}`, depth + 1);
  }

  return sanitized;
};

export const sanitizeRequestInput = (req: Request, res: Response, next: NextFunction) => {
  try {
    const mutableReq = req as Request & {
      body: unknown;
      query: Request["query"];
      params: Request["params"];
    };

    mutableReq.body = sanitizeUnknownInput(req.body, "body");
    mutableReq.query = sanitizeUnknownInput(req.query, "query") as Request["query"];
    mutableReq.params = sanitizeUnknownInput(req.params, "params") as Request["params"];
    next();
  } catch (error) {
    return res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : "Invalid request payload.",
    });
  }
};
