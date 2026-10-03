export const validateException = (entry, today, scopes = ["root", "backend"]) => {
  const required = ["scope", "package", "advisory", "rationale", "owner", "expiresOn"];
  const missing = required.find((key) => typeof entry?.[key] !== "string" || !entry[key].trim());
  if (missing) return `missing ${missing}`;
  if (!scopes.includes(entry.scope)) return "invalid acceptance scope";
  if (/[*?]/.test(entry.package) || /[*?]/.test(entry.advisory)) return "wildcards are forbidden";
  if (!/^(?:GHSA-[A-Z0-9-]+|npm:\d+)$/i.test(entry.advisory)) return "advisory must be an exact GHSA or npm ID";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(entry.expiresOn)) return "expiresOn must be YYYY-MM-DD";
  if (!Number.isFinite(Date.parse(entry.expiresOn)) || new Date(entry.expiresOn).toISOString().slice(0, 10) !== entry.expiresOn) return "invalid expiry date";
  if (entry.expiresOn <= today) return `expired on ${entry.expiresOn}`;
  return null;
};
