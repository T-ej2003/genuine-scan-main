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
import { readProductionGitChanges } from "./production-git-source-range.mjs";

const SHA = /^[a-f0-9]{40}$/;
const COMPONENTS = Object.freeze(["backend", "frontend", "database", "security"]);
const normalDependencies = Object.freeze({ backend: [], frontend: [] });
// Only inputs of the selected production image can be carried from its old
// component SHA into a normal release. Other components keep their old baseline.
const imageInputs = Object.freeze({
  backend: [
    /^backend\/(?:src\/|prisma\/|scripts\/|tests\/|local-print-agent\/releases\/|docker\/start-runtime\.sh$)/,
    /^backend\/(?:Dockerfile|package(?:-lock)?\.json|prisma\.config\.ts|tsconfig\.json)$/,
    /^shared\/|^\.dockerignore$|^docker\/base-image-identities\.json$/,
    /^scripts\/(?:smoke-release\.mjs|lib\/staging-smoke-totp\.mjs|security\/production-rotation-state-inventory\.mjs|aws\/(?:production-green-stage-b-contract|production-app-only-(?:database-verifier|verifier-runtime|requirements-runtime)|production-security-rebaseline-transport|production-rls-catalogue-probe-(?:config|runtime))\.mjs)$/,
    /^documents\/security\/mscqr_staging_rls_shared_batch_phase_(?:apply|rollback|verify)_2026-07-15\.sql$/,
  ],
  frontend: [
    /^(?:src|public|shared|scripts)\//,
    /^\.dockerignore$|^docker\/base-image-identities\.json$|^docker\/nginx-entrypoint\.sh$/,
    /^(?:Dockerfile\.ecs-frontend|components\.json|eslint\.config\.js|index\.html|postcss\.config\.js|tailwind\.config\.ts|nginx\.ecs-frontend\.conf|package(?:-lock)?\.json|vite\.config\.[^/]+|vitest\.config\.[^/]+|tsconfig[^/]*\.json)$/,
  ],
});
export const isNormalImageInput = (name, file) => imageInputs[name].some((pattern) => pattern.test(file));
export const isNormalHostTooling = (file) => /^(?:\.github\/workflows\/(?:production-deploy|production-normal-deployment-operation|production-green-backend-recovery-operation|production-historical-green-completion-operation)\.yml$|\.github\/actions\/|scripts\/(?:aws\/|lib\/|security\/|rls\/lib\/|smoke-release\.mjs$)|infra\/aws\/terraform\/lambda\/production-rls-approval-broker\/|backend\/scripts\/security\/)/.test(file);

const git = (args, cwd) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const assertAncestor = (ancestor, candidate, cwd) => {
  assert.match(ancestor || "", SHA); assert.match(candidate || "", SHA);
  try { git(["merge-base", "--is-ancestor", ancestor, candidate], cwd); } catch { throw new Error(`Component state source ${ancestor} is not protected-main history of ${candidate}.`); }
};
export function buildProductionNormalDeploymentPlan({ sourceSha, state, readRange, readStructural, isAncestor, pushFiles, pushChangedFiles, pushPaired } = {}) {
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
      files[component] = files[component].filter((file) => (pushFiles !== undefined && isNormalHostTooling(file)) || !(COMPLETED_EMERGENCY_PATHS[mode].includes(file)
        && completedFiles.has(file) && !newerFiles.has(file)
        && [PRODUCTION_RELEASE_CLASS.EMERGENCY_RECOVERY, PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE].includes(classifyProductionChanges([file]).releaseClass)));
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
      if (pushFiles !== undefined && (isNormalHostTooling(file) || (["backend", "frontend"].includes(component) && isNormalImageInput(component, file)))) return true;
      if (!establishedFiles.has(file) || newerFiles.has(file)) return true;
      let classification;
      try { classification = classifyProductionChanges([file]); } catch { return true; }
      const releaseClass = classification.releaseClass;
      return !(releaseClass === PRODUCTION_RELEASE_CLASS.SECURITY_INFRASTRUCTURE
        && (establishedComponent === "security" || (establishedComponent === "database" && classification.database)));
    });
  }
  // A protected-main push selects the components; historical changes to the
  // other image remain pending and cannot authorize their deployment here.
  let push;
  if (pushFiles !== undefined) {
    assert.equal(typeof readStructural, "function", "Normal deployment requires Git structural-change evidence.");
    assert.ok(Array.isArray(pushChangedFiles) && pushChangedFiles.every((file) => pushFiles.includes(file)), "Normal deployment requires independently observed current-push changes.");
    assert.ok(Array.isArray(pushPaired), "Normal deployment requires current-push rename and copy evidence.");
    assert.equal(pushPaired.some((change) => change.status === "R"), false, "Current-push renames require stronger-lane completion.");
    assert.equal(pushPaired.some((change) => change.status === "C" && ["backend", "frontend"].some((name) => isNormalImageInput(name, change.paths[0]) && !isNormalImageInput(name, change.paths[1]))), false,
      "Cross-component copies require stronger-lane completion.");
    push = classifyProductionChanges(pushFiles);
    assert.equal(push.releaseClass, PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION, "The protected-main push is not eligible for normal deployment.");
    assert.equal(push.worker, false, "Worker changes require the stronger lane.");
    for (const name of ["backend", "frontend"].filter((component) => push[component])) {
      const currentPush = new Set(pushChangedFiles);
      const structural = readStructural(baselineOf(state.components[name]), sourceSha);
      assert.equal(structural.some((change) => ["A", "D"].includes(change.status) && change.paths.some((file) => isNormalImageInput(name, file) && !currentPush.has(file))), false,
        "Historical image input addition or deletion requires stronger-lane completion.");
      const pending = files[name].filter(isNormalHostTooling);
      if (!pending.length) continue;
      const established = state.components.security?.sourceSha;
      const provenance = state.componentProvenance?.security;
      assert.ok(established && provenance?.lane === "SECURITY_INFRASTRUCTURE" && provenance.workflow === "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main"
        && /^[a-f0-9]{64}$/.test(state.components.security.releaseIdentity || "") && isAncestor(baselineOf(state.components[name]), established), "Pending deployment workflow or tooling requires authenticated stronger-lane completion.");
      const completed = new Set(readRange(baselineOf(state.components[name]), established));
      const newer = new Set(readRange(established, sourceSha));
      assert.equal(pending.some((file) => !completed.has(file) || newer.has(file)), false, "Deployment workflow or tooling changed after stronger-lane authorization.");
      files[name] = files[name].filter((file) => !isNormalHostTooling(file) || isNormalImageInput(name, file));
    }
    for (const name of ["backend", "frontend"])
      files[name] = push[name] ? files[name].filter((file) => isNormalImageInput(name, file)) : [];
    const selectedImageInput = (file) => (push.backend && isNormalImageInput("backend", file)) || (push.frontend && isNormalImageInput("frontend", file));
    files.security = files.security.filter(selectedImageInput);
    files.database = files.database.filter((file) => selectedImageInput(file) || /\.sql$/i.test(file));
  }
  const classification = classifyProductionComponentRanges({ backendFiles: files.backend, frontendFiles: files.frontend, securityFiles: files.security, databaseFiles: files.database });
  if (push) {
    for (const name of ["backend", "frontend"]) assert.equal(classification[name], push[name], `The ${name} source range does not match the protected-main push.`);
  }
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

export function prepareProductionNormalDeployment({ sourceSha, repositoryRoot, client, gitRun = git, pushFiles, pushChangedFiles, pushPaired } = {}) {
  assert.match(sourceSha || "", SHA); assert.equal(typeof repositoryRoot, "string");
  const state = client.read(); assert.ok(state, "Production component deployment state is not bootstrapped.");
  const changes = new Map();
  const range = (baseline, candidate) => {
    const key = `${baseline}..${candidate}`;
    if (!changes.has(key)) changes.set(key, readProductionGitChanges(baseline, candidate, repositoryRoot, gitRun));
    return changes.get(key);
  };
  return buildProductionNormalDeploymentPlan({ sourceSha, state, pushFiles, pushChangedFiles, pushPaired,
    isAncestor: (ancestor, candidate) => { try { gitRun(["merge-base", "--is-ancestor", ancestor, candidate], repositoryRoot); return true; } catch { return false; } },
    readRange: (baseline, candidate) => range(baseline, candidate).paths,
    readStructural: (baseline, candidate) => range(baseline, candidate).structural,
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
  assert.equal(process.env.GITHUB_EVENT_NAME, "push", "Normal preparation requires a protected-main push.");
  assertGithubOidcReleaseDeployerEnvironment();
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: "eu-west-2" });
  const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  assert.equal(git(["rev-parse", "HEAD"], repositoryRoot), process.env.GITHUB_SHA);
  assert.equal(git(["rev-parse", "refs/remotes/origin/main"], repositoryRoot), process.env.GITHUB_SHA);
  const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"));
  assert.equal(event.ref, "refs/heads/main");
  assert.equal(event.after, process.env.GITHUB_SHA);
  const before = SHA.test(event.before || "") && !/^0+$/.test(event.before) ? event.before : git(["rev-parse", "HEAD^"], repositoryRoot);
  assertAncestor(before, process.env.GITHUB_SHA, repositoryRoot);
  const push = readProductionGitChanges(before, process.env.GITHUB_SHA, repositoryRoot);
  const plan = prepareProductionNormalDeployment({ sourceSha: process.env.GITHUB_SHA, repositoryRoot, client: createProductionComponentDeploymentStateClient({ run }),
    pushFiles: push.paths, pushChangedFiles: [...new Set(push.structural.flatMap((change) => change.paths))], pushPaired: push.paired });
  fs.writeFileSync(output, `${JSON.stringify(plan)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({ sourceSha: plan.sourceSha, classification: plan.classification })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main();
