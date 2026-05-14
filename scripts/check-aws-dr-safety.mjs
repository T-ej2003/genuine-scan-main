import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const scanRoots = [".github/workflows", "scripts", "ops/deploy", "documents/ops"];
const allowedRoute53Apply = new Set([
  "scripts/dr/apply-route53-change.sh",
  "scripts/dr/apply-route53-rollback.sh",
  "scripts/dr/apply-regional-alb-entrypoint-approved.sh",
]);
const dnsApplyWorkflow = ".github/workflows/aws-dr-dns-apply.yml";
const snapshotApplyWorkflow = ".github/workflows/aws-dr-snapshot-apply.yml";
const dbApplyWorkflow = ".github/workflows/aws-dr-db-apply.yml";
const cleanupApplyWorkflow = ".github/workflows/aws-dr-cleanup-apply.yml";
const objectStorageApplyWorkflow = ".github/workflows/aws-dr-object-storage-apply.yml";
const albApplyWorkflow = ".github/workflows/aws-dr-alb-apply.yml";
const hardeningApplyWorkflow = ".github/workflows/aws-dr-hardening-apply.yml";
const operationsWorkflow = ".github/workflows/aws-dr-operations.yml";
const applyWorkflowPaths = new Set([
  dnsApplyWorkflow,
  snapshotApplyWorkflow,
  dbApplyWorkflow,
  cleanupApplyWorkflow,
  objectStorageApplyWorkflow,
  albApplyWorkflow,
  hardeningApplyWorkflow,
]);
const allowedRdsRestoreScripts = new Set([
  "scripts/dr/apply-db-restore-approved.sh",
  "scripts/dr/apply-region-local-db-restore-approved.sh",
]);
const allowedRdsSnapshotCopyScripts = new Set([
  "scripts/dr/apply-cross-region-snapshot-copy-approved.sh",
]);
const allowedRdsDeleteScripts = new Set([
  "scripts/dr/cleanup-recovery-db-approved.sh",
]);
const allowedRdsSnapshotDeleteScripts = new Set([
  "scripts/dr/cleanup-dr-snapshot-approved.sh",
]);
const standbyRecoveredDbTestFiles = new Set([
  ".github/workflows/aws-dr-standby-db-test.yml",
  "ops/deploy/test-standby-recovered-db.yml",
  "ops/deploy/rollback-standby-db-env.yml",
  "scripts/dr/test-standby-recovered-db.sh",
  "scripts/dr/rollback-standby-db-env.sh",
]);
const gatedApplyScripts = new Map([
  [
    "scripts/dr/apply-route53-change.sh",
    {
      confirmation: "I_APPROVE_MANUAL_DNS_CUTOVER",
      environment: "dr-dns-cutover",
      workflow: dnsApplyWorkflow,
    },
  ],
  [
    "scripts/dr/apply-route53-rollback.sh",
    {
      confirmation: "I_APPROVE_MANUAL_DNS_ROLLBACK",
      environment: "dr-dns-rollback",
      workflow: dnsApplyWorkflow,
    },
  ],
  [
    "scripts/dr/apply-db-restore-approved.sh",
    {
      confirmation: "I_APPROVE_DB_RESTORE_TO_RECOVERY_TARGET",
      environment: "dr-db-restore",
      workflow: dbApplyWorkflow,
    },
  ],
  [
    "scripts/dr/object-storage-write-test-approved.sh",
    {
      confirmation: "I_APPROVE_OBJECT_STORAGE_WRITE_TEST",
      environment: "dr-object-storage-write-test",
      workflow: objectStorageApplyWorkflow,
    },
  ],
  [
    "scripts/dr/apply-cross-region-snapshot-copy-approved.sh",
    {
      confirmation: "I_APPROVE_CROSS_REGION_SNAPSHOT_COPY",
      environment: "dr-db-restore",
      workflow: snapshotApplyWorkflow,
    },
  ],
  [
    "scripts/dr/apply-region-local-db-restore-approved.sh",
    {
      confirmation: "I_APPROVE_REGION_LOCAL_DB_RESTORE",
      environment: "dr-db-restore",
      workflow: dbApplyWorkflow,
    },
  ],
  [
    "scripts/dr/cleanup-recovery-db-approved.sh",
    {
      confirmation: "I_APPROVE_RECOVERY_DB_CLEANUP",
      environment: "dr-recovery-cleanup",
      workflow: cleanupApplyWorkflow,
    },
  ],
  [
    "scripts/dr/apply-regional-alb-entrypoint-approved.sh",
    {
      confirmation: "I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY",
      environment: "dr-alb-entrypoint-apply",
      workflow: albApplyWorkflow,
    },
  ],
  [
    "scripts/dr/apply-regional-cloudwatch-alarms-approved.sh",
    {
      confirmation: "I_APPROVE_CLOUDWATCH_ALARM_APPLY",
      environment: "dr-hardening-apply",
      workflow: hardeningApplyWorkflow,
    },
  ],
  [
    "scripts/dr/apply-alb-access-logs-approved.sh",
    {
      confirmation: "I_APPROVE_ALB_ACCESS_LOGS_APPLY",
      environment: "dr-hardening-apply",
      workflow: hardeningApplyWorkflow,
    },
  ],
  [
    "scripts/dr/apply-waf-count-mode-approved.sh",
    {
      confirmation: "I_APPROVE_WAF_COUNT_MODE_APPLY",
      environment: "dr-hardening-apply",
      workflow: hardeningApplyWorkflow,
    },
  ],
  [
    "scripts/dr/apply-asg-launch-template-approved.sh",
    {
      confirmation: "I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH",
      environment: "dr-hardening-apply",
      workflow: hardeningApplyWorkflow,
    },
  ],
]);
const selfPath = "scripts/check-aws-dr-safety.mjs";
const mutationOperationNames = [
  "apply-route53-change",
  "apply-route53-rollback",
  "apply-db-restore-approved",
  "object-storage-write-test-approved",
  "apply-cross-region-snapshot-copy-approved",
  "apply-region-local-db-restore-approved",
  "cleanup-recovery-db-approved",
  "cleanup-dr-snapshot-approved",
  "apply-regional-alb-entrypoint-approved",
  "apply-cloudwatch-alarms",
  "apply-alb-access-logs",
  "apply-waf-count-mode",
  "apply-asg-launch-template-approved",
];

const dangerousPatterns = [
  { id: "rds-failover", pattern: /\baws\s+rds\s+failover[-\w]*/i },
  { id: "s3-rb", pattern: /\baws\s+s3\s+rb\b/i },
  { id: "s3-rm-recursive", pattern: /\baws\s+s3\s+rm\b[^\n]*--recursive/i },
  { id: "s3api-delete-object", pattern: /\baws\s+s3api\s+delete-object\b/i },
  { id: "s3api-put-object", pattern: /\baws\s+s3api\s+put-object\b/i },
  { id: "docker-system-prune", pattern: /\bdocker\s+system\s+prune\b/i },
  { id: "docker-volume-rm", pattern: /\bdocker\s+volume\s+rm\b/i },
  { id: "rm-docker-data", pattern: /\brm\s+-rf\s+\/var\/lib\/docker\b/i },
  { id: "rm-root", pattern: /\brm\s+-rf\s+\/(?:\s|$)/i },
  { id: "drop-database", pattern: /\bDROP\s+DATABASE\b/i },
  { id: "truncate-table", pattern: /\bTRUNCATE\s+TABLE\b/i },
  { id: "mc-rm-recursive", pattern: /\bmc\s+rm\b[^\n]*--recursive/i },
  { id: "minio-decommission", pattern: /\bminio\s+decommission\b/i },
  { id: "elbv2-delete-load-balancer", pattern: /\baws\s+elbv2\s+delete-load-balancer\b/i },
  { id: "elbv2-delete-target-group", pattern: /\baws\s+elbv2\s+delete-target-group\b/i },
  { id: "elbv2-delete-listener", pattern: /\baws\s+elbv2\s+delete-listener\b/i },
  { id: "acm-delete-certificate", pattern: /\baws\s+acm\s+delete-certificate\b/i },
  { id: "route53-delete-hosted-zone", pattern: /\baws\s+route53\s+delete-hosted-zone\b/i },
  { id: "cloudwatch-delete-alarms", pattern: /\baws\s+cloudwatch\s+delete-alarms\b/i },
  { id: "wafv2-delete-web-acl", pattern: /\baws\s+wafv2\s+delete-web-acl\b/i },
  { id: "wafv2-disassociate-web-acl", pattern: /\baws\s+wafv2\s+disassociate-web-acl\b/i },
  { id: "autoscaling-delete-auto-scaling-group", pattern: /\baws\s+autoscaling\s+delete-auto-scaling-group\b/i },
  { id: "autoscaling-terminate-instance", pattern: /\baws\s+autoscaling\s+terminate-instance-in-auto-scaling-group\b/i },
  { id: "ec2-terminate-instances", pattern: /\baws\s+ec2\s+terminate-instances\b/i },
  { id: "ec2-delete-launch-template", pattern: /\baws\s+ec2\s+delete-launch-template\b/i },
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
      return !trimmed.startsWith("#") && !trimmed.startsWith("echo ") && !trimmed.startsWith("printf ");
    });
}

function executableLineReferences(source, pattern) {
  return source
    .split("\n")
    .map((line, index) => ({ line, lineNumber: index + 1 }))
    .filter(({ line }) => pattern.test(line))
    .filter(({ line }) => {
      const trimmed = line.trim();
      return !trimmed.startsWith("#") && !trimmed.startsWith("echo ");
    });
}

function workflowDispatchInputCount(source) {
  const lines = source.split("\n");
  let workflowDispatchIndent = null;
  let inputsIndent = null;
  let count = 0;

  for (const line of lines) {
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    const indent = line.match(/^ */)?.[0].length ?? 0;

    if (workflowDispatchIndent === null) {
      if (/^\s*workflow_dispatch:\s*$/.test(line)) {
        workflowDispatchIndent = indent;
      }
      continue;
    }

    if (indent <= workflowDispatchIndent) break;

    if (inputsIndent === null) {
      if (/^\s*inputs:\s*$/.test(line)) {
        inputsIndent = indent;
      }
      continue;
    }

    if (indent <= inputsIndent) break;
    if (indent === inputsIndent + 2 && /^\s*[A-Za-z_][A-Za-z0-9_-]*:\s*$/.test(line)) {
      count += 1;
    }
  }

  return count;
}

function hasWorkflowDispatch(source) {
  return /^\s*workflow_dispatch:\s*$/m.test(source);
}

function hasPushOrPullRequestTrigger(source) {
  return /^\s*(push|pull_request):\s*$/m.test(source);
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
      if (repoPath.startsWith(".github/workflows/aws-dr-") && repoPath.endsWith(".yml")) {
        const inputCount = workflowDispatchInputCount(source);
        if (inputCount > 25) {
          findings.push({
            repoPath,
            line: 1,
            message: `workflow_dispatch defines ${inputCount} inputs; GitHub allows at most 25.`,
          });
        }
      }

      if (applyWorkflowPaths.has(repoPath)) {
        if (!hasWorkflowDispatch(source)) {
          findings.push({
            repoPath,
            line: 1,
            message: "DR apply workflows must be workflow_dispatch only.",
          });
        }
        if (hasPushOrPullRequestTrigger(source)) {
          findings.push({
            repoPath,
            line: 1,
            message: "DR apply workflows must not define push or pull_request triggers.",
          });
        }
      }

      if (repoPath === operationsWorkflow) {
        for (const operationName of mutationOperationNames) {
          if (source.includes(operationName)) {
            findings.push({
              repoPath,
              line: 1,
              message: `Read-only DR operations workflow must not expose mutation operation ${operationName}.`,
            });
          }
        }
      }

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
          : repoPath.endsWith("apply-route53-rollback.sh")
            ? "CONFIRM_DNS_ROLLBACK"
            : "CONFIRM_REGIONAL_ALB_APPLY";
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
        if (repoPath !== gate.workflow) {
          findings.push({
            repoPath,
            line: references[0].lineNumber,
            message: `${scriptPath} may only be called from ${gate.workflow}.`,
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

      const s3RmRegex = /\baws\s+s3\s+rm\b/gi;
      for (const match of source.matchAll(s3RmRegex)) {
        if (repoPath !== "scripts/dr/object-storage-write-test-approved.sh") {
          findings.push({
            repoPath,
            line: lineNumber(source, match.index ?? 0),
            message: "aws s3 rm is only allowed in the approved object storage write-test cleanup script.",
          });
        }
      }

      const rdsRestoreReferences = executableLineReferences(
        source,
        /\baws\s+rds\s+restore[-\w]*/i,
      );
      if (rdsRestoreReferences.length > 0 && !allowedRdsRestoreScripts.has(repoPath)) {
        findings.push({
          repoPath,
          line: rdsRestoreReferences[0].lineNumber,
          message: "RDS restore commands are only allowed in the approved gated DB restore script.",
        });
      }

      const rdsCopySnapshotReferences = executableLineReferences(
        source,
        /\baws\s+rds\s+copy-db-snapshot\b/i,
      );
      if (rdsCopySnapshotReferences.length > 0 && !allowedRdsSnapshotCopyScripts.has(repoPath)) {
        findings.push({
          repoPath,
          line: rdsCopySnapshotReferences[0].lineNumber,
          message: "RDS snapshot copy commands are only allowed in the approved gated snapshot copy script.",
        });
      }

      const rdsDeleteReferences = executableLineReferences(
        source,
        /\baws\s+rds\s+delete-db-instance\b/i,
      );
      if (rdsDeleteReferences.length > 0) {
        if (!allowedRdsDeleteScripts.has(repoPath)) {
          findings.push({
            repoPath,
            line: rdsDeleteReferences[0].lineNumber,
            message: "RDS delete-db-instance is only allowed in the approved gated recovery cleanup script.",
          });
        } else if (
          !source.includes("I_APPROVE_RECOVERY_DB_CLEANUP") ||
          !source.includes("I_APPROVE_SKIP_FINAL_SNAPSHOT")
        ) {
          findings.push({
            repoPath,
            line: rdsDeleteReferences[0].lineNumber,
            message: "Recovery DB cleanup must require cleanup and final-snapshot/skip confirmations.",
          });
        }
      }

      const rdsDeleteSnapshotReferences = executableLineReferences(
        source,
        /\baws\s+rds\s+delete-db-snapshot\b/i,
      );
      if (rdsDeleteSnapshotReferences.length > 0) {
        if (!allowedRdsSnapshotDeleteScripts.has(repoPath)) {
          findings.push({
            repoPath,
            line: rdsDeleteSnapshotReferences[0].lineNumber,
            message: "RDS delete-db-snapshot is only allowed in the approved gated DR snapshot cleanup script.",
          });
        } else if (!source.includes("I_APPROVE_DR_SNAPSHOT_CLEANUP")) {
          findings.push({
            repoPath,
            line: rdsDeleteSnapshotReferences[0].lineNumber,
            message: "DR snapshot cleanup must require I_APPROVE_DR_SNAPSHOT_CLEANUP.",
          });
        }
      }

      if (repoPath === cleanupApplyWorkflow) {
        if (!source.includes("dr-recovery-cleanup")) {
          findings.push({
            repoPath,
            line: 1,
            message: "Cleanup workflow must use the dr-recovery-cleanup protected environment.",
          });
        }
        if (!source.includes("I_APPROVE_RECOVERY_DB_CLEANUP") || !source.includes("I_APPROVE_DR_SNAPSHOT_CLEANUP")) {
          findings.push({
            repoPath,
            line: 1,
            message: "Cleanup workflow must include both DB and snapshot cleanup confirmation phrases.",
          });
        }
      }

      if (repoPath === albApplyWorkflow) {
        if (!source.includes("dr-alb-entrypoint-apply")) {
          findings.push({
            repoPath,
            line: 1,
            message: "ALB apply workflow must use the dr-alb-entrypoint-apply protected environment.",
          });
        }
        if (!source.includes("I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY")) {
          findings.push({
            repoPath,
            line: 1,
            message: "ALB apply workflow must include I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY.",
          });
        }
      }

      if (repoPath === hardeningApplyWorkflow) {
        const requiredHardeningTokens = [
          "dr-hardening-apply",
          "I_APPROVE_CLOUDWATCH_ALARM_APPLY",
          "I_APPROVE_ALB_ACCESS_LOGS_APPLY",
          "I_APPROVE_WAF_COUNT_MODE_APPLY",
          "I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH",
        ];
        for (const token of requiredHardeningTokens) {
          if (!source.includes(token)) {
            findings.push({
              repoPath,
              line: 1,
              message: `Hardening apply workflow must include ${token}.`,
            });
          }
        }
      }

      if (repoPath === "scripts/dr/apply-waf-count-mode-approved.sh") {
        if (/\bBlock\s*:\s*\{\s*\}/.test(source) || /"Block"\s*:/.test(source)) {
          findings.push({
            repoPath,
            line: 1,
            message: "WAF hardening apply must remain COUNT mode only; Block actions are not allowed.",
          });
        }
        if (!source.includes("--cli-binary-format raw-in-base64-out")) {
          findings.push({
            repoPath,
            line: 1,
            message: "WAF hardening apply must pass --cli-binary-format raw-in-base64-out for ByteMatchStatement SearchString JSON.",
          });
        }
      }

      if (repoPath === "scripts/dr/apply-regional-alb-entrypoint-approved.sh" &&
        !source.includes("I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY")) {
        findings.push({
          repoPath,
          line: 1,
          message: "Regional ALB apply script must require I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY.",
        });
      }

      if (repoPath === cleanupApplyWorkflow || repoPath.includes("cleanup-recovery") || repoPath.includes("cleanup-dr-snapshot")) {
        const productionTargetExample = executableLineReferences(
          source,
          /target_(db|snapshot)_identifier:\s*mscqr-prod-db|TARGET_(DB|SNAPSHOT)_IDENTIFIER=mscqr-prod-db/i,
        );
        if (productionTargetExample.length > 0) {
          findings.push({
            repoPath,
            line: productionTargetExample[0].lineNumber,
            message: "Cleanup automation must not use mscqr-prod-db as a cleanup target example.",
          });
        }
      }

      if (standbyRecoveredDbTestFiles.has(repoPath)) {
        const passwordEchoReferences = executableLineReferences(
          source,
          /\becho\b[^\n]*(RECOVERED_DB_PASSWORD|recovered_db_password|recovered_database_url|DATABASE_URL)/i,
        );
        if (passwordEchoReferences.length > 0) {
          findings.push({
            repoPath,
            line: passwordEchoReferences[0].lineNumber,
            message: "Standby recovered DB test automation must not print recovered DB passwords or DATABASE_URL values.",
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
