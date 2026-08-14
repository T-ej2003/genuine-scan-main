import crypto from "node:crypto";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { readFreshProtectedMainIdentity, readStageBProtectedMainCheckout } from "../aws/stage-b-deployment-identity.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic } from "../aws/stage-b-artifact-contract.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const FORBIDDEN_COMMAND = /(?:terraform\s+(?:apply|state\b)|ecs:(?:RegisterTaskDefinition|UpdateService|DeregisterTaskDefinition)|aws\s+ecs\s+(?:register-task-definition|update-service|deregister-task-definition)|MFA|PutSecretValue)/i;

export const READ_ONLY_CHECKS = Object.freeze([
  Object.freeze({ id: "source-guardrails", command: "npm", args: ["run", "verify:guardrails:source"] }),
  Object.freeze({ id: "release-evidence-references", command: "npm", args: ["run", "check:release-evidence-refs"] }),
  Object.freeze({ id: "stage-b-artifact-contract", command: "npm", args: ["run", "stage-b:artifact-contract:verify"] }),
  Object.freeze({ id: "stage-b-capability-graph", command: "npm", args: ["run", "stage-b:capability-graph:verify"] }),
  Object.freeze({ id: "stage-b-deployment-closure", command: "npm", args: ["run", "stage-b:deployment-closure:pull-request"] }),
  Object.freeze({ id: "production-onboarding-contract", command: "npm", args: ["run", "test:production-onboarding-contract"] }),
  Object.freeze({ id: "typecheck", command: "npm", args: ["run", "typecheck"] }),
  Object.freeze({ id: "changed-file-lint", command: "npm", args: ["run", "lint:changed"] }),
  Object.freeze({ id: "diff-check", command: "git", args: ["diff", "--check", "HEAD^", "HEAD"] }),
]);

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const text = (value) => Buffer.isBuffer(value) ? value.toString("utf8") : String(value || "");
const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const gitBytes = (cwd, args) => execFileSync("git", args, { cwd, encoding: null, stdio: ["ignore", "pipe", "pipe"] });

export function canonicalSourceTreeSha256(entries = []) {
  const normalized = entries
    .map(({ mode, path: filePath, blobSha256 }) => ({ mode: String(mode), path: String(filePath), blobSha256: String(blobSha256) }))
    .sort((left, right) => left.path.localeCompare(right.path));
  return sha256(Buffer.from(JSON.stringify(normalized)));
}

export function assertReadOnlyMode({ mode, environment = process.env } = {}) {
  if (mode !== "read-only" || environment.MSCQR_DEPLOYMENT_MODE !== "read-only") {
    throw new Error("MSCQR production readiness requires MSCQR_DEPLOYMENT_MODE=read-only.");
  }
}

export function assertReadOnlySourceIdentity({ sourceSha, currentHead, originMainHead, isAncestor, porcelainStatus = "", repositoryState } = {}) {
  if (!SHA.test(String(sourceSha || ""))) throw new Error("Requested source SHA must be a full 40-character SHA.");
  if (currentHead !== sourceSha || originMainHead !== sourceSha) throw new Error("Requested source SHA does not equal checked-out HEAD and freshly fetched origin/main.");
  if (isAncestor !== true || porcelainStatus) throw new Error("Requested source checkout is not a clean protected-main checkout.");
  if (repositoryState?.shallow || repositoryState?.mergeInProgress || repositoryState?.rebaseInProgress || repositoryState?.cherryPickInProgress) {
    throw new Error("Requested source checkout has incomplete history or an in-progress repository operation.");
  }
  return true;
}

export function assertReadOnlyCheckPlan(checks = READ_ONLY_CHECKS) {
  for (const check of checks) {
    const commandLine = [check.command, ...check.args].join(" ");
    if (FORBIDDEN_COMMAND.test(commandLine)) throw new Error(`Read-only check contains a forbidden mutation boundary: ${check.id}.`);
  }
  return checks;
}

function runCheck(command, args, { cwd, environment }) {
  const started = Date.now();
  try {
    const stdout = execFileSync(command, args, {
      cwd,
      env: environment,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 32 * 1024 * 1024,
    });
    return { status: 0, stdout, stderr: "", durationMs: Date.now() - started };
  } catch (error) {
    return { status: typeof error.status === "number" ? error.status : 1, stdout: text(error.stdout), stderr: text(error.stderr || error.message), durationMs: Date.now() - started };
  }
}

function checkResult(id, command, args, result) {
  const stderr = text(result.stderr);
  return {
    id,
    command: [command, ...args].join(" "),
    status: result.status === 0 ? "PASS" : "FAIL",
    exitCode: result.status,
    durationMs: result.durationMs,
    stdoutSha256: sha256(text(result.stdout)),
    stderrSha256: sha256(stderr),
    failureClass: result.status === 0 ? null : /ENOSPC|no space left/i.test(stderr) ? "ENVIRONMENT_ENOSPC" : "CHECK_FAILED",
  };
}

function optionalIdentity(environment) {
  const imageReleaseSha = environment.MSCQR_IMAGE_RELEASE_SHA || null;
  const backendImageDigest = environment.MSCQR_BACKEND_IMAGE_DIGEST || null;
  if (imageReleaseSha !== null && !SHA.test(imageReleaseSha)) throw new Error("MSCQR_IMAGE_RELEASE_SHA must be a full SHA when supplied.");
  if (backendImageDigest !== null && !DIGEST.test(backendImageDigest)) throw new Error("MSCQR_BACKEND_IMAGE_DIGEST must be a SHA256 digest when supplied.");
  return { imageReleaseSha, backendImageDigest };
}

function writeReport(outputPath, repositoryRoot, report) {
  const resolved = assertStageBArtifactPath({ artifactPath: outputPath, repositoryRoot, label: "Production readiness evidence", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(resolved), repositoryRoot, create: true, normalize: true, label: "Production readiness evidence directory" });
  return writeStageBPrivateFileAtomic({ filePath: resolved, bytes: Buffer.from(`${JSON.stringify(report, null, 2)}\n`), repositoryRoot, label: "Production readiness evidence" });
}

export function runReadOnlyReadiness({ cwd = ROOT, sourceSha, outputPath, environment = process.env, runGit = (args) => git(cwd, args), readGitBytes = (args) => gitBytes(cwd, args), run = runCheck, checks = READ_ONLY_CHECKS } = {}) {
  assertReadOnlyMode({ mode: "read-only", environment });
  assertReadOnlyCheckPlan(checks);
  if (!path.isAbsolute(outputPath || "")) throw new Error("Production readiness evidence requires an absolute output path.");
  const identity = { sourceSha, currentHead: null, originMainHead: null, isAncestor: false, porcelainStatus: "blocked", repositoryState: {} };
  const checkResults = [];
  let blockedReason = null;
  try {
    const fresh = environment.MSCQR_TRUSTED_MAIN_SHA ? null : readFreshProtectedMainIdentity({ cwd, expectedSourceSha: sourceSha, run: runGit });
    const checkout = readStageBProtectedMainCheckout({ cwd, fetchOriginMain: false, run: runGit });
    const trustedMainSha = environment.MSCQR_TRUSTED_MAIN_SHA || fresh?.freshRemoteMainSha || checkout.originMainHead;
    assertReadOnlySourceIdentity({ sourceSha, currentHead: checkout.currentHead, originMainHead: trustedMainSha, isAncestor: checkout.isAncestor, porcelainStatus: checkout.porcelainStatus, repositoryState: checkout.repositoryState });
    if (checkout.originMainHead !== trustedMainSha) throw new Error("Local origin/main does not match the trusted bootstrap SHA.");
    identity.currentHead = checkout.currentHead;
    identity.originMainHead = trustedMainSha;
    identity.isAncestor = checkout.isAncestor;
    identity.porcelainStatus = checkout.porcelainStatus;
    identity.repositoryState = checkout.repositoryState;
    const treeEntries = runGit(["ls-tree", "-r", "--full-tree", "HEAD"])
      .split("\n")
      .filter(Boolean)
      .map((entry) => {
        const match = /^(\d+)\s+blob\s+([a-f0-9]+)\t(.+)$/.exec(entry);
        if (!match) throw new Error("Protected source tree contains an unsupported entry.");
        return { mode: match[1], path: match[3], blobSha256: sha256(readGitBytes(["cat-file", "blob", match[2]])) };
      });
    identity.sourceTreeSha256 = canonicalSourceTreeSha256(treeEntries);
  } catch (error) {
    blockedReason = `SOURCE_IDENTITY_FAILED:${error.message}`;
  }

  const { imageReleaseSha, backendImageDigest } = optionalIdentity(environment);
  if (!blockedReason) {
    for (const check of checks) {
      const result = run(check.command, check.args, { cwd, environment: { ...environment, MSCQR_DEPLOYMENT_MODE: "read-only", ENFORCE_LINT_CHANGED: "true", LINT_CHANGED_BASE_REF: environment.LINT_CHANGED_BASE_REF || "HEAD^", CI: "1" } });
      const summarized = checkResult(check.id, check.command, check.args, result);
      checkResults.push(summarized);
      if (summarized.status !== "PASS" && !blockedReason) blockedReason = `${summarized.id}:${summarized.failureClass}`;
    }
  }
  const report = {
    schemaVersion: 2,
    mode: "read-only",
    sourceSha,
    sourceTreeSha256: identity.sourceTreeSha256 || null,
    sourceTreeIdentity: { algorithm: "SHA-256", type: "canonical-tracked-content", encoding: "hex" },
    toolingSha: sourceSha,
    originMainSha: identity.originMainHead,
    imageReleaseSha,
    backendImageDigest,
    workflowRunId: environment.GITHUB_RUN_ID || null,
    checks: checkResults,
    readiness: { status: blockedReason ? "BLOCKED" : "READ_ONLY_PROOF_COMPLETE", blockedReason },
    mutationReachable: false,
    requiredNextMutationBoundary: "HUMAN_REVIEW_AND_PHASE_2_ENABLEMENT",
    generatedAt: new Date().toISOString(),
  };
  writeReport(outputPath, cwd, report);
  return report;
}

function parseCli(argv) {
  const parsed = parseArgs({ args: argv, options: { mode: { type: "string" }, "source-sha": { type: "string" }, output: { type: "string" } }, strict: true });
  if (parsed.values.mode !== "read-only" || !parsed.values["source-sha"] || !parsed.values.output) throw new Error("Usage: --mode read-only --source-sha <full SHA> --output <absolute path>");
  return { mode: parsed.values.mode, sourceSha: parsed.values["source-sha"], outputPath: parsed.values.output };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const args = parseCli(process.argv.slice(2));
    const report = runReadOnlyReadiness({ sourceSha: args.sourceSha, outputPath: args.outputPath, environment: process.env });
    process.stdout.write(`${JSON.stringify({ readiness: report.readiness, sourceSha: report.sourceSha, output: args.outputPath })}\n`);
    if (report.readiness.status !== "READ_ONLY_PROOF_COMPLETE") process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
