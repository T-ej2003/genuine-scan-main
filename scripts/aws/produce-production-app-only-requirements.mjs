import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { assertSecurityRebaselineInventory } from "./production-security-rebaseline-inventory.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));

// Source-only producer: no AWS credentials, DB secrets or production connection.
// Reuses the canonical production-package certification on the exact isolated
// repository harness, including its restoration and zero-role-residue checks.
export function produceAppOnlyRequirements({ sourceSha, candidateSourceSha }) {
  for (const sha of [sourceSha, candidateSourceSha]) assert.match(sha || "", /^[a-f0-9]{40}$/);
  assertProtectedCheckout({ sourceSha, repositoryRoot: root });
  assertAppOnlyCandidateAncestor({ sourceSha, candidateSourceSha });
  const [instance] = JSON.parse(execFileSync("docker", ["inspect", "mscqr-p2-auth-security-postgres"], { encoding: "utf8", timeout: 10000 }));
  assert.equal(instance.Config.Labels["com.docker.compose.project"], "mscqr-p2-auth-security");
  assert.equal(instance.Config.Labels["com.docker.compose.service"], "p2-postgres");
  assert.equal(instance.Config.Image, "postgres:18.4");
  assert.ok(Object.hasOwn(instance.HostConfig.Tmpfs, "/var/lib/postgresql"));
  assert.deepEqual(instance.HostConfig.PortBindings["5432/tcp"], [{ HostIp: "127.0.0.1", HostPort: "55432" }]);
  execFileSync(process.execPath, ["scripts/p2-test-db-tls.mjs"], { cwd: root, timeout: 60000, stdio: ["ignore", "pipe", "pipe"] });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-requirements-"));
  fs.chmodSync(directory, 0o700);
  const artifactPath = path.join(directory, "app-only-requirements.json");
  const securityRebaselinePath = path.join(directory, "security-rebaseline-canonical.json");
  // Deliberately omit inherited production credentials and DB configuration.
  const env = Object.fromEntries(["PATH", "HOME", "TMPDIR", "DOCKER_HOST", "DOCKER_CONTEXT"].filter((key) => process.env[key]).map((key) => [key, process.env[key]]));
  Object.assign(env, { NODE_ENV: "test", MSCQR_PRODUCTION_PACKAGE_POSTGRES18_TEST: "true",
    MSCQR_PRODUCTION_PACKAGE_POSTGRES18_ADMIN_URL: "postgresql://mscqr_p2_test@127.0.0.1:55432/mscqr_p2_admin_test",
    MSCQR_APP_ONLY_CANDIDATE_SOURCE_SHA: candidateSourceSha, MSCQR_APP_ONLY_REQUIREMENTS_PATH: artifactPath,
    MSCQR_SECURITY_REBASELINE_CANONICAL_PATH: securityRebaselinePath });
  execFileSync(process.execPath, ["--test", "scripts/tests/production-full-rls-package-postgres18.test.mjs"], {
    cwd: root, env, timeout: 10 * 60 * 1000, maxBuffer: 16 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
  });
  assertProtectedCheckout({ sourceSha, repositoryRoot: root });
  const artifact = readStageBPrivateFileBytes({ filePath: artifactPath, repositoryRoot: root });
  const requirements = assertAppOnlyRequirements(JSON.parse(artifact.bytes), { sourceSha, candidateSourceSha, repositoryRoot: root });
  const securityArtifact = readStageBPrivateFileBytes({ filePath: securityRebaselinePath, repositoryRoot: root });
  const securityInventory = assertSecurityRebaselineInventory(JSON.parse(securityArtifact.bytes), { protectedMainSha: sourceSha, candidateSourceSha });
  assert.equal(securityInventory.kind, "PRODUCTION_SECURITY_REBASELINE_CANONICAL_INVENTORY");
  assert.equal(securityInventory.appOnlyRequirementsSha256, requirements.requirementsSha256);
  return { artifactPath, artifactSha256: artifact.sha256, requirementsSha256: requirements.requirementsSha256,
    securityRebaselinePath, securityRebaselineSha256: securityArtifact.sha256, canonicalSecurityCatalogueSha256: securityInventory.catalogueSha256 };
}

export function assertAppOnlyCandidateAncestor({ sourceSha, candidateSourceSha, repositoryRoot = root, run = execFileSync }) {
  for (const sha of [sourceSha, candidateSourceSha]) assert.match(sha || "", /^[a-f0-9]{40}$/);
  if (candidateSourceSha !== sourceSha) run("git", ["merge-base", "--is-ancestor", candidateSourceSha, sourceSha], { cwd: repositoryRoot, timeout: 30000, stdio: "ignore" });
  return true;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    assert.equal(process.argv.length, 4, "Expected exact protected and candidate source SHAs");
    process.stdout.write(`${JSON.stringify(produceAppOnlyRequirements({ sourceSha: process.argv[2], candidateSourceSha: process.argv[3] }))}\n`);
  } catch {
    // Child errors may contain connection diagnostics. Preserve fail-closed
    // status without forwarding raw environment/connection strings into logs.
    process.stderr.write("Canonical app-only requirements production failed; no compatibility authorization produced.\n");
    process.exitCode = 1;
  }
}
