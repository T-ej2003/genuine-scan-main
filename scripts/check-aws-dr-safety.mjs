import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const scanRoots = [".github/workflows", "scripts", "ops/deploy", "documents/ops"];
const allowedRoute53Apply = new Set([
  "scripts/dr/apply-route53-change.sh",
  "scripts/dr/apply-route53-rollback.sh",
]);
const allowedApplyWorkflow = ".github/workflows/aws-dr-apply.yml";
const gatedApplyScripts = new Map([
  [
    "scripts/dr/apply-route53-change.sh",
    {
      confirmation: "I_APPROVE_MANUAL_DNS_CUTOVER",
      environment: "dr-dns-cutover",
    },
  ],
  [
    "scripts/dr/apply-route53-rollback.sh",
    {
      confirmation: "I_APPROVE_MANUAL_DNS_ROLLBACK",
      environment: "dr-dns-rollback",
    },
  ],
  [
    "scripts/dr/apply-db-restore-approved.sh",
    {
      confirmation: "I_APPROVE_DB_RESTORE_TO_RECOVERY_TARGET",
      environment: "dr-db-restore",
    },
  ],
  [
    "scripts/dr/object-storage-write-test-approved.sh",
    {
      confirmation: "I_APPROVE_OBJECT_STORAGE_WRITE_TEST",
      environment: "dr-object-storage-write-test",
    },
  ],
]);
const selfPath = "scripts/check-aws-dr-safety.mjs";

const dangerousPatterns = [
  { id: "rds-delete", pattern: /\baws\s+rds\s+delete[-\w]*/i },
  { id: "rds-failover", pattern: /\baws\s+rds\s+failover[-\w]*/i },
  { id: "s3-rb", pattern: /\baws\s+s3\s+rb\b/i },
  { id: "s3-rm-recursive", pattern: /\baws\s+s3\s+rm\b[^\n]*--recursive/i },
  { id: "docker-system-prune", pattern: /\bdocker\s+system\s+prune\b/i },
  { id: "docker-volume-rm", pattern: /\bdocker\s+volume\s+rm\b/i },
  { id: "rm-docker-data", pattern: /\brm\s+-rf\s+\/var\/lib\/docker\b/i },
  { id: "rm-root", pattern: /\brm\s+-rf\s+\/(?:\s|$)/i },
  { id: "drop-database", pattern: /\bDROP\s+DATABASE\b/i },
  { id: "truncate-table", pattern: /\bTRUNCATE\s+TABLE\b/i },
  { id: "mc-rm-recursive", pattern: /\bmc\s+rm\b[^\n]*--recursive/i },
  { id: "minio-decommission", pattern: /\bminio\s+decommission\b/i },
];

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return walk(fullPath);
    return [fullPath];
  });
}

function toRepoPath(filePath) {
  return path.relative(root, filePath).split(path.sep).join("/");
}

function isWorkflowOrExecutable(repoPath) {
  return (
    repoPath.startsWith(".github/workflows/") ||
    repoPath.endsWith(".sh") ||
    repoPath.endsWith(".mjs") ||
    repoPath.endsWith(".js") ||
    repoPath.endsWith(".yml") ||
    repoPath.endsWith(".yaml")
  );
}

function lineNumber(source, index) {
  return source.slice(0, index).split("\n").length;
}

function applyScriptReferences(source, scriptPath) {
  return source
    .split("\n")
    .map((line, index) => ({ line, lineNumber: index + 1 }))
    .filter(({ line }) => line.includes(scriptPath))
    .filter(({ line }) => {
      const trimmed = line.trim();
      return !trimmed.startsWith("#") && !trimmed.startsWith("echo ");
    });
}

const findings = [];

for (const scanRoot of scanRoots) {
  for (const filePath of walk(path.join(root, scanRoot))) {
    const repoPath = toRepoPath(filePath);
    if (repoPath === selfPath) continue;

    const source = fs.readFileSync(filePath, "utf8");
    const isDocs = repoPath.startsWith("documents/ops/");
    const isExecutable = isWorkflowOrExecutable(repoPath);

    if (isExecutable) {
      const route53Regex = /\baws\s+route53\s+change-resource-record-sets\b/gi;
      for (const match of source.matchAll(route53Regex)) {
        if (!allowedRoute53Apply.has(repoPath)) {
          findings.push({
            repoPath,
            line: lineNumber(source, match.index ?? 0),
            message: "Route 53 mutation is only allowed in the approved gated DR apply scripts.",
          });
          continue;
        }

        const requiredConfirmation = repoPath.endsWith("apply-route53-change.sh")
          ? "CONFIRM_DNS_CUTOVER"
          : "CONFIRM_DNS_ROLLBACK";
        if (!source.includes(requiredConfirmation)) {
          findings.push({
            repoPath,
            line: lineNumber(source, match.index ?? 0),
            message: `Route 53 mutation must be gated by ${requiredConfirmation}.`,
          });
        }
      }

      for (const [scriptPath, gate] of gatedApplyScripts.entries()) {
        const references = applyScriptReferences(source, scriptPath);
        if (references.length === 0) continue;
        if (repoPath !== allowedApplyWorkflow) {
          findings.push({
            repoPath,
            line: references[0].lineNumber,
            message: `${scriptPath} may only be called from ${allowedApplyWorkflow}.`,
          });
          continue;
        }
        if (!source.includes(gate.confirmation) || !source.includes(gate.environment)) {
          findings.push({
            repoPath,
            line: references[0].lineNumber,
            message: `${scriptPath} must be protected by ${gate.environment} and ${gate.confirmation}.`,
          });
        }
      }
    }

    if (isDocs || !isExecutable) continue;

    for (const rule of dangerousPatterns) {
      const match = rule.pattern.exec(source);
      if (match) {
        findings.push({
          repoPath,
          line: lineNumber(source, match.index),
          message: `Dangerous DR automation pattern blocked: ${rule.id}.`,
        });
      }
    }
  }
}

if (findings.length > 0) {
  console.error("AWS DR safety scanner found blocked automation:");
  for (const finding of findings) {
    console.error(`- ${finding.repoPath}:${finding.line} ${finding.message}`);
  }
  process.exit(1);
}

console.log("AWS DR safety scanner passed.");
