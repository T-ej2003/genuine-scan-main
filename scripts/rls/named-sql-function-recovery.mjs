#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import { repoRoot } from "./lib/program-inventory.mjs";
import { buildNamedSqlFunctionInventory } from "./named-sql-function-inventory.mjs";

export const namedSqlFunctionRecoveryPath = path.join(repoRoot, "documents/security/rls-program/generated/named-sql-function-recovery.json");
export const namedSqlFunctionRecoveryReviewPath = path.join(repoRoot, "documents/security/rls-program/NAMED_SQL_FUNCTION_RECOVERY.md");

const run = (command, args) => {
  const result = spawnSync(command, args, { cwd: repoRoot, encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : "";
};
const trackedFiles = () => run("git", ["ls-files"]).split("\n").filter((file) => /\.(?:sql|psql|ts|js|mjs|md|json)$/i.test(file));
const source = (file) => fs.readFileSync(path.join(repoRoot, file), "utf8");
const definitionPattern = (functionName) => new RegExp(`CREATE\\s+OR\\s+REPLACE\\s+FUNCTION\\s+${functionName.replace(".", "\\.")}\\s*\\(`, "i");
const isFixture = (file) => /(?:^|\/)(?:test|tests|fixture)(?:\/|\.|-)/i.test(file);
const isDeployableSql = (file) => /^(?:backend\/src\/rls-waves\/|backend\/prisma\/migrations\/|scripts\/rls\/sql\/source\/).+\.(?:sql|psql)$/i.test(file);
const securityMetadata = (text) => ({
  securityMode: /SECURITY\s+DEFINER/i.test(text) ? "SECURITY DEFINER" : /SECURITY\s+INVOKER/i.test(text) ? "SECURITY INVOKER" : null,
  safeSearchPath: /SET\s+search_path\s*=\s*pg_catalog/i.test(text),
  publicRevoked: /REVOKE\s+ALL\s+ON\s+FUNCTION[\s\S]*?FROM\s+PUBLIC/i.test(text),
  grantsPresent: /GRANT\s+EXECUTE\s+ON\s+FUNCTION/i.test(text),
});
const definitionSlice = (text, functionName) => {
  const start = text.search(definitionPattern(functionName));
  if (start < 0) return "";
  const end = text.indexOf("$fn$;", start);
  return text.slice(start, end < 0 ? text.length : end + 5);
};
const returnType = (definition) => definition.match(/\)\s*RETURNS\s+(.+?)\s+LANGUAGE\s+/is)?.[1].replace(/\s+/g, " ").trim() || null;
const definitionHistoryIndex = (functionNames) => {
  const commits = run("git", ["log", "--all", "--format=%H", "-G", "CREATE[[:space:]]+OR[[:space:]]+REPLACE[[:space:]]+FUNCTION", "--", "*.sql", "*.psql"])
    .split("\n").filter(Boolean);
  const index = new Map(functionNames.map((name) => [name, []]));
  for (const commit of commits) {
    const diff = run("git", ["show", "--format=", commit, "--", "*.sql", "*.psql"]);
    for (const functionName of functionNames) if (diff.includes(functionName)) index.get(functionName).push(commit);
  }
  return index;
};

const classify = ({ functionName, files, historyCommits }) => {
  const production = files.filter((file) => isDeployableSql(file) && definitionPattern(functionName).test(source(file)));
  const fixtures = files.filter((file) => isFixture(file) && definitionPattern(functionName).test(source(file)));
  const references = files.filter((file) => /\.(?:sql|psql)$/i.test(file) && !isFixture(file) && definitionPattern(functionName).test(source(file)));
  if (production.length) return { classification: "production definition recovered", definitionLocation: production[0], deployable: true };
  if (fixtures.length) return { classification: "fixture-only definition", definitionLocation: fixtures[0], deployable: false };
  if (references.length) return { classification: "external migration reference recovered", definitionLocation: references[0], deployable: false };
  if (historyCommits.length) return { classification: "repository contract only", definitionLocation: null, deployable: false };
  return { classification: "no definition found", definitionLocation: null, deployable: false };
};

export const buildNamedSqlFunctionRecovery = () => {
  const inventory = buildNamedSqlFunctionInventory();
  const files = trackedFiles();
  const historyByFunction = definitionHistoryIndex(inventory.functions.map((entry) => entry.functionName));
  const functions = inventory.functions.map((entry) => {
    const matchingFiles = files.filter((file) => source(file).includes(entry.functionName));
    const historyCommits = historyByFunction.get(entry.functionName) || [];
    const recovered = classify({ functionName: entry.functionName, files: matchingFiles, historyCommits });
    const definition = recovered.definitionLocation ? source(recovered.definitionLocation) : "";
    const body = definitionSlice(definition, entry.functionName);
    const grants = matchingFiles.filter((file) => new RegExp(`GRANT\\s+EXECUTE\\s+ON\\s+FUNCTION\\s+${entry.functionName.replace(".", "\\.")}`, "i").test(source(file)) && !isFixture(file));
    const revokes = matchingFiles.filter((file) => new RegExp(`REVOKE\\s+ALL\\s+ON\\s+FUNCTION\\s+${entry.functionName.replace(".", "\\.")}.*?FROM\\s+PUBLIC`, "is").test(source(file)) && !isFixture(file));
    const metadata = { ...securityMetadata(body), grantsPresent: grants.length > 0, publicRevoked: revokes.length > 0 };
    return {
      functionName: entry.functionName,
      signature: entry.signature,
      callers: entry.callers,
      canonicalWorkflowIds: entry.canonicalWorkflowIds,
      classification: recovered.classification,
      definitionLocation: recovered.definitionLocation,
      originatingCommit: historyCommits[0] || null,
      historyCommits,
      deployable: recovered.deployable,
      definitionChecksum: body ? crypto.createHash("sha256").update(body).digest("hex") : null,
      returnType: returnType(body),
      matchesCurrentPrismaSchema: null,
      signatureMatchesRepositoryCall: entry.signature ? null : null,
      securityMetadata: recovered.definitionLocation ? metadata : null,
      requiresAdaptation: !recovered.deployable || !metadata.safeSearchPath || !metadata.publicRevoked || !metadata.grantsPresent,
      candidateLocations: matchingFiles.filter((file) => /\.(?:sql|psql)$/i.test(file)).sort(),
      grantLocations: grants.sort(),
      revokeLocations: revokes.sort(),
    };
  }).sort((a, b) => a.functionName.localeCompare(b.functionName));
  return { schemaVersion: 1, generatedFrom: ["git ls-files", "git log --all -S", "named-sql-function-inventory"], functions };
};

const markdown = (report) => {
  const counts = Object.groupBy(report.functions, ({ classification }) => classification);
  const lines = ["# Named SQL function recovery", "", "Generated from tracked source and all local Git refs. Fixture SQL is evidence only and is never deployable production SQL.", "", ...Object.keys(counts).sort().map((key) => `- ${key}: ${counts[key].length}`), "", "| Function | Classification | Definition | Commit | Deployable |", "|---|---|---|---|---|", ...report.functions.map((item) => `| \`${item.functionName}\` | ${item.classification} | ${item.definitionLocation || "none"} | ${item.originatingCommit?.slice(0, 12) || "none"} | ${item.deployable ? "yes" : "no"} |`), ""];
  return lines.join("\n");
};

export const writeNamedSqlFunctionRecovery = (report = buildNamedSqlFunctionRecovery()) => {
  fs.writeFileSync(namedSqlFunctionRecoveryPath, `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(namedSqlFunctionRecoveryReviewPath, markdown(report));
  return report;
};

if (import.meta.url === `file://${process.argv[1]}`) {
  const report = writeNamedSqlFunctionRecovery();
  console.log(JSON.stringify(Object.fromEntries(Object.entries(Object.groupBy(report.functions, ({ classification }) => classification)).map(([name, entries]) => [name, entries.length]))));
}
