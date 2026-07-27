import fs from "node:fs";
import path from "node:path";

export const RESTRICTED_OWNER_SOURCE_EXCLUSIONS = Object.freeze([
  {
    path: "backend/src/rls-waves/session-c/c04/operatorProcedures.sql",
    reason: "operator-only source is not registered in the runtime named-function inventory or generated package",
  },
]);

const lineAt = (source, offset) => source.slice(0, offset).split("\n").length;

const prohibited = Object.freeze([
  ["%ROWTYPE", /%ROWTYPE/gi],
  ["RETURNING *", /\bRETURNING\s+\*/gi],
  [
    "direct table SELECT *",
    /\bSELECT\s+\*\s+(?:INTO\s+(?:STRICT\s+)?[A-Za-z_][A-Za-z0-9_]*\s+)?FROM\s+public\."[^"]+"/gi,
  ],
  [
    "direct table alias wildcard",
    /\bSELECT\s+([A-Za-z_][A-Za-z0-9_]*)\.\*(?=[^;]*\bFROM\s+public\."[^"]+"\s+(?:AS\s+)?\1\b)/gi,
  ],
  [
    "direct whole-row JSON serialization",
    /\b(?:to_jsonb|row_to_json|jsonb_agg|json_agg)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)(?=[^;]*\bFROM\s+public\."[^"]+"\s+(?:AS\s+)?\1\b)/gi,
  ],
  [
    "untyped record field target",
    /\bSELECT\b[^;]*(?<!INSERT )\bINTO\s+(?:STRICT\s+)?[A-Za-z_][A-Za-z0-9_]*\./gi,
  ],
]);

export const validateRestrictedOwnerProjections = ({
  repoRoot,
  contracts,
  additionalSources = ["backend/src/rls-waves/session-c/c03/c03Boundary.sql"],
}) => {
  const sourcePaths = [...new Set([
    ...contracts.map((contract) => contract.definitionLocation),
    ...additionalSources,
  ])].sort();
  const excluded = new Set(RESTRICTED_OWNER_SOURCE_EXCLUSIONS.map((entry) => entry.path));
  for (const entry of RESTRICTED_OWNER_SOURCE_EXCLUSIONS) {
    if (sourcePaths.includes(entry.path)) {
      throw new Error(`Restricted-owner SQL exclusion became active: ${entry.path}`);
    }
    if (!entry.reason || !fs.existsSync(path.join(repoRoot, entry.path))) {
      throw new Error(`Restricted-owner SQL exclusion is stale or undocumented: ${entry.path}`);
    }
  }

  const findings = [];
  for (const relativePath of sourcePaths) {
    if (excluded.has(relativePath)) continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
    for (const [kind, expression] of prohibited) {
      for (const match of source.matchAll(expression)) {
        findings.push(`${relativePath}:${lineAt(source, match.index)} ${kind}`);
      }
    }
  }
  if (findings.length) {
    throw new Error(`Restricted-owner SQL must use explicit reviewed projections:\n${findings.join("\n")}`);
  }
  return { sourcePaths, excludedSources: [...excluded] };
};
