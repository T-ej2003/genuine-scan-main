function reject(label, message) {
  throw new Error(`${label} ${message}`);
}

export function normalizeIamPolicyDocument(value, label = "IAM policy document") {
  let document = value;
  if (typeof value === "string") {
    try {
      document = JSON.parse(value);
    } catch {
      try {
        document = JSON.parse(decodeURIComponent(value));
      } catch {
        reject(label, "is malformed.");
      }
    }
  }
  if (!document || typeof document !== "object" || Array.isArray(document)) reject(label, "must be a JSON object.");
  return document;
}
