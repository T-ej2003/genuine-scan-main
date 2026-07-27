#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { scanProductionAccess, validateProtectedTransactionClients } from "./rls/lib/program-inventory.mjs";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const allowlistPath = path.join(repoRoot, "scripts/security-scope-allowlist.json");
const allowlist = fs.existsSync(allowlistPath)
  ? JSON.parse(fs.readFileSync(allowlistPath, "utf8"))
  : { allowedFindings: [] };

const protectedModels = new Set([
  "auditLog",
  "batch",
  "incident",
  "licensee",
  "notification",
  "qRCode",
  "user",
]);
const riskyMethods = new Set([
  "findUnique",
  "findFirst",
  "findMany",
  "update",
  "delete",
  "deleteMany",
  "updateMany",
  "count",
  "aggregate",
  "groupBy",
]);
const riskyCallRe = /(?:prisma|tx|db|pr)\.([A-Za-z0-9_]+)\.(findUnique|findFirst|findMany|update|delete|deleteMany|updateMany|count|aggregate|groupBy)\s*\(/g;

const toRel = (file) => path.relative(repoRoot, file).replace(/\\/g, "/");
const safeCommentRe = /scope-guardrail-ignore/;
const allowedFindings = allowlist.allowedFindings || [];
const centralScopedHelperFiles = new Set(["backend/src/services/accessControlService.ts"]);
const usedAllowlistEntries = new Set();

const validateAllowlist = () => {
  const problems = [];
  if (Array.isArray(allowlist.ignoredFiles) && allowlist.ignoredFiles.length > 0) {
    problems.push("ignoredFiles is not allowed; use exact allowedFindings entries.");
  }
  if (Array.isArray(allowlist.ignoredPrefixes) && allowlist.ignoredPrefixes.length > 0) {
    problems.push("ignoredPrefixes is not allowed; use exact allowedFindings entries.");
  }

  const seen = new Set();
  for (const [idx, entry] of allowedFindings.entries()) {
    const methods = Array.isArray(entry.methods) ? entry.methods : entry.method ? [entry.method] : [];
    const key = `${entry.path || ""}:${entry.model || ""}:${methods.join("|")}`;
    if (seen.has(key)) problems.push(`duplicate allowlist entry at index ${idx}: ${key}`);
    seen.add(key);
    if (!entry.path || entry.path.includes("*")) problems.push(`allowlist entry ${idx} must use an exact path.`);
    if (!entry.model || entry.model.includes("*")) problems.push(`allowlist entry ${idx} must use an exact Prisma model.`);
    if (!methods.length || methods.some((method) => method === "*" || !riskyMethods.has(method))) {
      problems.push(`allowlist entry ${idx} must use exact protected methods.`);
    }
    if (!entry.reason || String(entry.reason).trim().length < 24) {
      problems.push(`allowlist entry ${idx} needs a specific reason.`);
    }
    if (!entry.cannotWidenAccess || String(entry.cannotWidenAccess).trim().length < 40) {
      problems.push(`allowlist entry ${idx} needs cannotWidenAccess documentation.`);
    }
    if (!entry.followUp || String(entry.followUp).trim().length < 20) {
      problems.push(`allowlist entry ${idx} needs an owner/follow-up note.`);
    }
  }

  if (problems.length > 0) {
    console.error("Invalid Prisma scope allowlist:");
    for (const problem of problems) console.error(`- ${problem}`);
    process.exit(1);
  }
};

validateAllowlist();

const isAllowedFinding = ({ file, model, method }) =>
  allowedFindings.some((entry, idx) => {
    if (entry.path !== file) return false;
    if (entry.model !== model) return false;
    const methods = Array.isArray(entry.methods) ? entry.methods : entry.method ? [entry.method] : [];
    if (!methods.includes(method)) return false;
    usedAllowlistEntries.add(idx);
    return true;
  });

const walk = (dir, out = []) => {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!["dist", "node_modules", ".prisma"].includes(entry.name)) walk(full, out);
    } else if (entry.isFile() && /\.(ts|tsx|js|mjs|cjs)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
};

const sampleIndex = process.argv.indexOf("--sample");
const canonicalAccessKeys = new Set();
if (sampleIndex < 0) {
  const workflowManifest = JSON.parse(fs.readFileSync(path.join(repoRoot, "documents/security/rls-program/workflows.json"), "utf8"));
  const accessScan = scanProductionAccess();
  validateProtectedTransactionClients(workflowManifest, accessScan);
  const accessById = new Map(accessScan.accesses.map((access) => [access.id, access]));
  for (const workflow of workflowManifest.workflows.filter((item) => item.contextBoundaryStatus === "implemented" && item.sameTransactionGuarantee === true)) {
    for (const evidence of workflow.supportingEvidence) {
      const access = accessById.get(evidence.accessId);
      const model = access.prismaModel[0].toLowerCase() + access.prismaModel.slice(1);
      canonicalAccessKeys.add(`${access.sourceFile}:${access.line}:${model}:${access.method}`);
    }
  }
}
const files =
  sampleIndex >= 0
    ? [path.resolve(process.argv[sampleIndex + 1])]
    : [
        ...walk(path.join(repoRoot, "backend/src/controllers")),
        ...walk(path.join(repoRoot, "backend/src/services")),
      ];

const findings = [];
for (const file of files) {
  const rel = toRel(file);
  const source = fs.readFileSync(file, "utf8");
  const lines = source.split(/\r?\n/);
  for (const [lineIdx, line] of lines.entries()) {
    riskyCallRe.lastIndex = 0;
    let match;
    while ((match = riskyCallRe.exec(line))) {
      const [, model, method] = match;
      if (!protectedModels.has(model) || !riskyMethods.has(method)) continue;
      if (canonicalAccessKeys.has(`${rel}:${lineIdx + 1}:${model}:${method}`)) continue;
      const previous = lines.slice(Math.max(0, lineIdx - 3), lineIdx + 1).join("\n");
      if (safeCommentRe.test(previous)) continue;
      if (centralScopedHelperFiles.has(rel)) continue;
      if (sampleIndex < 0 && isAllowedFinding({ file: rel, model, method })) continue;
      findings.push({ file: rel, line: lineIdx + 1, model, method, text: line.trim() });
    }
  }
}

if (sampleIndex < 0) {
  const unused = allowedFindings
    .map((entry, idx) => ({ entry, idx }))
    .filter(({ idx }) => !usedAllowlistEntries.has(idx));
  if (unused.length > 0) {
    console.error("Unused Prisma scope allowlist entries found:");
    for (const { entry, idx } of unused) {
      const methods = Array.isArray(entry.methods) ? entry.methods.join(",") : entry.method || "";
      console.error(`- #${idx} ${entry.path} ${entry.model}.${methods}`);
    }
    console.error("\nRemove stale allowlist entries so the scope guardrail stays narrow.");
    process.exit(1);
  }
}

if (findings.length > 0) {
  console.error("Potential unscoped Prisma access patterns found:");
  for (const finding of findings) {
    console.error(`- ${finding.file}:${finding.line} prisma.${finding.model}.${finding.method} -> ${finding.text}`);
  }
  console.error("\nUse central access-control helpers or add a documented allowlist entry for existing legacy-safe code.");
  process.exit(1);
}

console.log("Prisma scope guardrails passed.");
