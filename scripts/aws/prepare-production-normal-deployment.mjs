#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { classifyProductionChanges, classifyProductionComponentRanges, PRODUCTION_RELEASE_CLASS } from "./production-deployment-classification.mjs";
import { createProductionComponentDeploymentStateClient, stateHash } from "./production-component-deployment-state.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const SHA = /^[a-f0-9]{40}$/;
const COMPONENTS = Object.freeze(["backend", "frontend", "database", "security"]);
const normalDependencies = Object.freeze({ backend: [], frontend: [] });

const git = (args, cwd) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const assertAncestor = (ancestor, candidate, cwd) => {
  assert.match(ancestor || "", SHA); assert.match(candidate || "", SHA);
  try { git(["merge-base", "--is-ancestor", ancestor, candidate], cwd); } catch { throw new Error(`Component state source ${ancestor} is not protected-main history of ${candidate}.`); }
};
const rangeFiles = (baseline, candidate, cwd) => git(["diff", "--name-only", "-z", `${baseline}..${candidate}`], cwd).split("\0").filter(Boolean);

export function buildProductionNormalDeploymentPlan({ sourceSha, state, readRange, isAncestor } = {}) {
  assert.match(sourceSha || "", SHA); assert.equal(typeof readRange, "function"); assert.equal(typeof isAncestor, "function");
  for (const name of COMPONENTS) {
    const component = state?.components?.[name];
    if (component) { assert.match(component.sourceSha || "", SHA); assert.equal(isAncestor(component.sourceSha, sourceSha), true, `${name} baseline is not an ancestor of the candidate`); }
  }
  for (const name of ["backend", "frontend"]) assert.ok(state.components[name], `${name} deployment state has not been bootstrapped.`);
  const files = Object.fromEntries(COMPONENTS.map((name) => [name, state.components[name] ? readRange(state.components[name].sourceSha, sourceSha) : []]));
  // A component's own range can contain an already-completed stronger-lane
  // commit. Remove only those previously-recorded sensitive paths, and retain
  // any path changed again after that stronger baseline.
  for (const component of ["backend", "frontend"]) for (const stronger of ["security", "database"]) {
    const baseline = state.components[component]?.sourceSha, established = state.components[stronger]?.sourceSha;
    if (!baseline || !established || !isAncestor(baseline, established) || !isAncestor(established, sourceSha)) continue;
    const establishedFiles = new Set(readRange(baseline, established)); const newerFiles = new Set(readRange(established, sourceSha));
    files[component] = files[component].filter((file) => !(establishedFiles.has(file) && !newerFiles.has(file)
      && classifyProductionChanges([file]).releaseClass !== PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION));
  }
  const classification = classifyProductionComponentRanges({ backendFiles: files.backend, frontendFiles: files.frontend, securityFiles: files.security, databaseFiles: files.database });
  for (const component of ["backend", "frontend"].filter((name) => classification[name])) {
    for (const dependency of normalDependencies[component]) {
      assert.ok(state.components[dependency], `${component} deployment requires authenticated ${dependency} component state.`);
      // A sensitive change after the component's state baseline has already
      // failed closed above. An empty range means its stronger lane succeeded.
      assert.equal(files[dependency].some((file) => /(?:^|\/)(?:security|auth|mfa|rbac|csrf|tenant|rls|iam|kms|policy|grant|role|migration|schema|network)(?:\/|\.|-|_)/i.test(file)), false, `${component} deployment has an undeployed stronger-lane dependency.`);
    }
  }
  const componentBaselines = Object.fromEntries(COMPONENTS.map((name) => [name, state.components[name]?.sourceSha || null]));
  return Object.freeze({ schemaVersion: 1, kind: "NORMAL_COMPONENT_DEPLOYMENT_PREPARATION", sourceSha, stateGeneration: state.generation, stateSha256: stateHash(state), componentBaselines,
    componentFiles: Object.freeze({ backendFiles: files.backend, frontendFiles: files.frontend, securityFiles: files.security, databaseFiles: files.database }), classification });
}

export function prepareProductionNormalDeployment({ sourceSha, repositoryRoot, client, gitRun = git } = {}) {
  assert.match(sourceSha || "", SHA); assert.equal(typeof repositoryRoot, "string");
  const state = client.read(); assert.ok(state, "Production component deployment state is not bootstrapped.");
  return buildProductionNormalDeploymentPlan({ sourceSha, state,
    isAncestor: (ancestor, candidate) => { try { gitRun(["merge-base", "--is-ancestor", ancestor, candidate], repositoryRoot); return true; } catch { return false; } },
    readRange: (baseline, candidate) => gitRun(["diff", "--name-only", "-z", `${baseline}..${candidate}`], repositoryRoot).split("\0").filter(Boolean),
  });
}

function main() {
  const output = process.argv.slice(2).find((value) => value.startsWith("--output="))?.slice("--output=".length);
  assert.ok(output && path.isAbsolute(output), "A fixed absolute output path is required.");
  assert.deepEqual(process.argv.slice(2), [`--output=${output}`]);
  assert.match(process.env.GITHUB_SHA || "", SHA);
  assertGithubOidcReleaseDeployerEnvironment();
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: "eu-west-2" });
  const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  assert.equal(git(["rev-parse", "HEAD"], repositoryRoot), process.env.GITHUB_SHA);
  assert.equal(git(["rev-parse", "refs/remotes/origin/main"], repositoryRoot), process.env.GITHUB_SHA);
  const plan = prepareProductionNormalDeployment({ sourceSha: process.env.GITHUB_SHA, repositoryRoot, client: createProductionComponentDeploymentStateClient({ run }) });
  fs.writeFileSync(output, `${JSON.stringify(plan)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({ sourceSha: plan.sourceSha, classification: plan.classification })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main();
