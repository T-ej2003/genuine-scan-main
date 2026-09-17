#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { classifyProductionChanges, classifyProductionComponentRanges, PRODUCTION_RELEASE_CLASS } from "./production-deployment-classification.mjs";
import { assertProductionComponentDeploymentState, createProductionComponentDeploymentStateClient, stateHash } from "./production-component-deployment-state.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { COMPLETED_EMERGENCY_PATHS } from "./production-completed-emergency-work.mjs";

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
  assert.match(sourceSha || "", SHA); assertProductionComponentDeploymentState(state); assert.equal(typeof readRange, "function"); assert.equal(typeof isAncestor, "function");
  const baselineOf = (component) => component?.establishedThroughSha || component?.sourceSha;
  for (const name of COMPONENTS) {
    const component = state?.components?.[name];
    if (component) { assert.match(baselineOf(component) || "", SHA); assert.equal(isAncestor(baselineOf(component), sourceSha), true, `${name} baseline is not an ancestor of the candidate`); }
  }
  for (const name of ["backend", "frontend"]) assert.ok(state.components[name], `${name} deployment state has not been bootstrapped.`);
  const files = Object.fromEntries(COMPONENTS.map((name) => [name, state.components[name] ? readRange(baselineOf(state.components[name]), sourceSha) : []]));
  for (const [mode, completion] of Object.entries(state.completedEmergencyWork || {})) {
    const established = completion.sourceSha;
    assert.equal(isAncestor(established, sourceSha), true, "Emergency completion is not protected-main history");
    assert.equal(isAncestor(established, baselineOf(state.components.backend)), true, "Emergency completion is ahead of authenticated backend state");
    if (mode !== "backend-health-recovery")
      assert.ok(state.components.security && isAncestor(established, state.components.security.sourceSha), "Rotation completion is ahead of authenticated security state");
    const newerFiles = new Set(readRange(established, sourceSha));
    for (const component of COMPONENTS) {
      const baseline = baselineOf(state.components[component]);
      if (!baseline || !isAncestor(baseline, established)) continue;
      const completedFiles = new Set(readRange(baseline, established));
      files[component] = files[component].filter((file) => !(COMPLETED_EMERGENCY_PATHS[mode].includes(file)
        && completedFiles.has(file) && !newerFiles.has(file)
        && classifyProductionChanges([file]).releaseClass === PRODUCTION_RELEASE_CLASS.EMERGENCY_RECOVERY));
    }
  }
  // Component baselines can lag an already-completed stronger or recovery
  // transition. Remove only a prior sensitive path whose terminal component
  // state proves it was established; a later edit remains in the range.
  for (const component of COMPONENTS) for (const establishedComponent of COMPONENTS) {
    const baseline = baselineOf(state.components[component]), established = baselineOf(state.components[establishedComponent]);
    // A rotation establishes its own security identity, not arbitrary IAM/RBAC
    // work that happens to precede it. Only its explicit paths were cleared above.
    if (establishedComponent === "security" && Object.entries(state.completedEmergencyWork || {}).some(([mode, proof]) => mode.startsWith("rotation-")
      && proof.sourceSha === established && proof.evidenceSha256 === state.components.security?.releaseIdentity)) continue;
    if (!baseline || !established || !isAncestor(baseline, established) || !isAncestor(established, sourceSha)) continue;
    const establishedFiles = new Set(readRange(baseline, established)); const newerFiles = new Set(readRange(established, sourceSha));
    files[component] = files[component].filter((file) => {
      if (!establishedFiles.has(file) || newerFiles.has(file)) return true;
      const classification = classifyProductionChanges([file]);
      const releaseClass = classification.releaseClass;
      return !(releaseClass === PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE
        && (establishedComponent === "security" || (establishedComponent === "database" && classification.database)));
    });
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
  const componentBaselines = Object.fromEntries(COMPONENTS.map((name) => [name, baselineOf(state.components[name]) || null]));
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

// A concurrent terminal may advance an unrelated component between the
// classifier and deploy jobs. Reuse only a freshly-read plan whose candidate,
// classification, and affected-component predecessors are unchanged.
export function assertRevalidatedProductionNormalDeploymentPlan(initial, current) {
  for (const value of [initial, current]) {
    assert.equal(value?.kind, "NORMAL_COMPONENT_DEPLOYMENT_PREPARATION"); assert.match(value?.sourceSha || "", SHA);
  }
  assert.equal(current.sourceSha, initial.sourceSha, "Revalidated deployment source changed.");
  assert.deepEqual(current.classification, initial.classification, "Component-state revalidation changed the release classification.");
  for (const name of ["backend", "frontend"].filter((component) => current.classification[component]))
    assert.equal(current.componentBaselines?.[name], initial.componentBaselines?.[name], `Concurrent update changed the ${name} predecessor; reprepare release.`);
  return current;
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
