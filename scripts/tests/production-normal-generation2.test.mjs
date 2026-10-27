import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import { buildProductionNormalDeploymentPlan, isNormalImageInput, isNormalHostTooling } from "../aws/prepare-production-normal-deployment.mjs";
import { readProductionGitChanges } from "../aws/production-git-source-range.mjs";
import { classifyProductionChanges } from "../aws/production-deployment-classification.mjs";
import { assertProductionComponentDeploymentState } from "../aws/production-component-deployment-state.mjs";
import { buildNormalReleasePlan, executeNormalComponentTransaction } from "../aws/production-normal-release.mjs";
import { assertNormalImageIdentity } from "../aws/production-normal-image-contract.mjs";
import { assertEcrRepositoryProtection } from "../aws/verify-production-ecr-repository-protection.mjs";
import { NORMAL_RECEIPT_WORKFLOW } from "../aws/production-normal-receipt-contract.mjs";

const fixture = JSON.parse(fs.readFileSync(new URL("./fixtures/production-normal-generation2.json", import.meta.url)));
const target = "e".repeat(40);
const changed = "backend/src/services/batchService.ts";
const digest = `sha256:${"b".repeat(64)}`;
const imageRef = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`;
const candidateArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:38";
const state = () => structuredClone(assertProductionComponentDeploymentState(fixture.state));
const lineage = [fixture.state.components.frontend.establishedThroughSha, fixture.state.components.backend.establishedThroughSha, fixture.sourceSha, target];
const authorizedState = () => {
  const current = state();
  current.generation = 3; current.updatedByLane = "SECURITY_INFRASTRUCTURE";
  current.components.security = { sourceSha: fixture.sourceSha, releaseIdentity: "a".repeat(64) };
  current.componentProvenance.security = { lane: "SECURITY_INFRASTRUCTURE", workflow: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", githubRunId: "123", generation: 3, updatedAt: current.updatedAt };
  return assertProductionComponentDeploymentState(current);
};
const range = (base, source) => {
  if (base === source) return [];
  if (base === fixture.sourceSha && source === target) return [changed];
  const name = Object.entries(fixture.state.components).find(([, component]) => component?.establishedThroughSha === base)?.[0];
  if (source !== target && source !== fixture.sourceSha) return [];
  assert.ok(name === "backend" || name === "frontend", `Unexpected component source range ${base}..${source}`);
  return source === target ? [...fixture.sourceRanges[name], changed] : fixture.sourceRanges[name];
};
const prepare = (pushFiles, readRange = range, current = authorizedState()) => buildProductionNormalDeploymentPlan({
  sourceSha: target, state: current, pushFiles, pushChangedFiles: pushFiles, pushPaired: [], readRange, readStructural: () => [], isAncestor: (ancestor, candidate) => lineage.indexOf(ancestor) >= 0 && lineage.indexOf(ancestor) <= lineage.indexOf(candidate),
});

test("authenticated generation-2 snapshot retains exact deployed sources and recovery identity", () => {
  const current = state();
  assert.equal(fixture.sourceSha, "dc7623302ddbfe4f92108a1f6e4b2fed43d8ac39");
  assert.equal(current.generation, 2);
  assert.equal(current.components.backend.establishedThroughSha, "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec");
  assert.equal(current.components.frontend.establishedThroughSha, "b7e0f171c716d5ba6d5a13da096bd87d9b638867");
  assert.equal(current.componentProvenance.backend.githubRunId, fixture.recoveryRunId);
  assert.equal(current.componentProvenance.frontend.githubRunId, fixture.frontendBootstrapRunId);
  assert.equal(current.normalDeploymentReceipt, undefined);
  assert.ok(fixture.sourceRanges.frontend.includes(".gitleaks-baseline.json"));
  assert.ok(fixture.sourceRanges.frontend.includes("src/contexts/AuthContext.tsx"));
  assert.throws(() => prepare([changed], range, current), /Pending deployment workflow or tooling requires authenticated stronger-lane completion/);
});

test("backend-only eligible push carries no unrelated frontend source or infrastructure changes", () => {
  const initial = authorizedState();
  const plan = prepare([changed]);
  assert.equal(plan.stateGeneration, 3);
  assert.deepEqual({ backend: plan.classification.backend, frontend: plan.classification.frontend }, { backend: true, frontend: false });
  assert.deepEqual(plan.componentFiles.backendFiles, [changed]);
  assert.deepEqual(plan.componentFiles.frontendFiles, []);
  assert.deepEqual(plan.componentFiles.securityFiles, [changed]);
  assert.deepEqual(plan.componentFiles.databaseFiles, []);
  assert.deepEqual(authorizedState(), initial, "Planning must not advance component state");
});

test("undeployed frontend security code remains pending and cannot enter normal frontend activation", () => {
  assert.throws(() => prepare(["src/App.tsx"], (base, source) => [...range(base, source), "src/App.tsx"]), /Sensitive or ambiguous changes/);
  assert.throws(() => prepare(["src/contexts/AuthContext.tsx"]), /protected-main push is not eligible/);
  assert.throws(() => prepare(["infra/aws/terraform/main.tf"]), /protected-main push is not eligible/);
  assert.throws(() => prepare([changed], () => []), /backend source range does not match/);
});

test("pending privileged workflow and imported tooling require exact stronger-lane source", () => {
  for (const file of [".github/workflows/production-deploy.yml", ".github/workflows/production-normal-deployment-operation.yml", ".github/workflows/production-green-backend-recovery-operation.yml", ".github/workflows/production-historical-green-completion-operation.yml", "scripts/aws/publish-ecs-images.sh", "scripts/rls/lib/clean-room-source-contract.mjs", ".github/actions/local/action.yml"])
    assert.equal(isNormalHostTooling(file), true);
  for (const [file, push] of [[".github/workflows/production-deploy.yml", [changed]], [".github/workflows/production-deploy.yml", ["src/App.tsx"]], [".github/workflows/production-normal-deployment-operation.yml", [changed]], [".github/workflows/production-green-backend-recovery-operation.yml", [changed]], [".github/workflows/production-historical-green-completion-operation.yml", [changed]], ["scripts/aws/publish-ecs-images.sh", [changed]]]) {
    const later = (base, source) => source === target ? [...range(base, source), ...push, file] : range(base, source);
    assert.throws(() => prepare(push, later), /changed after stronger-lane authorization/, `${file}: ${push.join(",")}`);
  }
  const wrong = authorizedState(); wrong.componentProvenance.security.workflow = NORMAL_RECEIPT_WORKFLOW;
  assert.throws(() => prepare([changed], range, wrong), /requires authenticated stronger-lane completion/);
});

test("tooling that is also a runtime image input cannot be cleared by a security-only completion", () => {
  const copied = "scripts/aws/production-app-only-verifier-runtime.mjs";
  const historical = (base, source) => base === fixture.state.components.backend.establishedThroughSha && [fixture.sourceSha, target].includes(source)
    ? [...range(base, source), copied] : range(base, source);
  assert.throws(() => prepare([changed], historical), /Sensitive or ambiguous changes/);
});

test("authorized component baselines permit later backend, frontend, and combined application releases", () => {
  const current = authorizedState();
  current.components.frontend.sourceSha = fixture.sourceSha;
  current.components.frontend.establishedThroughSha = fixture.sourceSha;
  current.componentProvenance.frontend = { ...current.componentProvenance.security };
  assertProductionComponentDeploymentState(current);
  for (const push of [[changed], ["src/App.tsx"], [changed, "src/App.tsx"]]) {
    const plan = buildProductionNormalDeploymentPlan({ sourceSha: target, state: current, pushFiles: push, pushChangedFiles: push, pushPaired: [],
      readRange: (base, source) => source === target && base === fixture.sourceSha ? push : range(base, source),
      readStructural: () => [], isAncestor: (left, right) => lineage.indexOf(left) >= 0 && lineage.indexOf(left) <= lineage.indexOf(right),
    });
    assert.equal(plan.classification.backend, push.includes(changed));
    assert.equal(plan.classification.frontend, push.includes("src/App.tsx"));
  }
});

test("a reviewed current-push runtime deletion remains eligible while an older deletion is rejected", () => {
  const deleted = "backend/src/services/qrService.ts";
  const changes = [{ status: "D", paths: [deleted] }];
  const options = { sourceSha: target, state: authorizedState(), readRange: (base, source) => source === target ? [...range(base, source), deleted] : range(base, source),
    readStructural: () => changes, isAncestor: (left, right) => lineage.indexOf(left) >= 0 && lineage.indexOf(left) <= lineage.indexOf(right) };
  assert.equal(buildProductionNormalDeploymentPlan({ ...options, pushFiles: [deleted], pushChangedFiles: [deleted], pushPaired: [] }).classification.backend, true);
  assert.throws(() => buildProductionNormalDeploymentPlan({ ...options, pushFiles: [changed], pushChangedFiles: [changed], pushPaired: [] }), /Historical image input addition or deletion/);
});

test("normal preparation rejects missing independent push evidence", () => {
  const options = { sourceSha: target, state: authorizedState(), pushFiles: [changed], readRange: range, readStructural: () => [],
    isAncestor: (left, right) => lineage.indexOf(left) >= 0 && lineage.indexOf(left) <= lineage.indexOf(right) };
  assert.throws(() => buildProductionNormalDeploymentPlan({ ...options, pushPaired: [] }), /independently observed current-push changes/);
  assert.throws(() => buildProductionNormalDeploymentPlan({ ...options, pushChangedFiles: [changed] }), /rename and copy evidence/);
});

test("real Git copies distinguish unchanged sources, authenticated sources, and current modifications", () => {
  for (const [component, source, destination] of [
    ["backend", "backend/src/services/batchService.ts", "backend/src/services/qrService.ts"],
    ["frontend", "src/App.tsx", "src/main.tsx"],
  ]) for (const caseName of ["historical", "authenticated", "modified"]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-normal-copy-"));
    const git = (args) => execFileSync("git", args, { cwd: directory, encoding: "utf8" }).trim();
    const write = (file, content) => { const location = path.join(directory, file); fs.mkdirSync(path.dirname(location), { recursive: true }); fs.writeFileSync(location, content); };
    try {
      git(["init", "-q"]); git(["config", "user.email", "test@mscqr.invalid"]); git(["config", "user.name", "MSCQR Test"]);
      write("README.md", "baseline\n");
      if (caseName === "authenticated") write(source, "export const runtime = 'authenticated';\n");
      git(["add", "-A"]); git(["commit", "-qm", "baseline"]); const base = git(["rev-parse", "HEAD"]);
      if (caseName !== "authenticated") { write(source, "export const runtime = 'historical';\n"); git(["add", "-A"]); git(["commit", "-qm", "undeployed historical addition"]); }
      const historical = git(["rev-parse", "HEAD"]);
      write(destination, fs.readFileSync(path.join(directory, source)));
      if (caseName === "modified") write(source, "export const runtime = 'modified in current push';\n");
      git(["add", "-A"]); git(["commit", "-qm", "copy source"]); const current = git(["rev-parse", "HEAD"]);
      const cumulative = readProductionGitChanges(base, current, directory);
      const push = readProductionGitChanges(historical, current, directory);
      assert.deepEqual(new Set(push.paths), new Set([source, destination]), "Git copy detection must expose both identities");
      assert.deepEqual(new Set(push.structural.flatMap((change) => change.paths)), new Set(caseName === "modified" ? [source, destination] : [destination]), "Only changed paths belong to the current push");
      const currentState = authorizedState();
      if (component === "frontend") {
        currentState.components.frontend.sourceSha = fixture.sourceSha;
        currentState.components.frontend.establishedThroughSha = fixture.sourceSha;
        currentState.componentProvenance.frontend = { ...currentState.componentProvenance.security };
      }
      const build = () => buildProductionNormalDeploymentPlan({ sourceSha: target, state: currentState, pushFiles: push.paths, pushChangedFiles: push.structural.flatMap((change) => change.paths), pushPaired: push.paired,
        readRange: (left, right) => right === target && (component === "backend" || left === fixture.sourceSha) ? [...range(left, right), ...cumulative.paths] : range(left, right),
        readStructural: () => cumulative.structural, isAncestor: (left, right) => lineage.indexOf(left) >= 0 && lineage.indexOf(left) <= lineage.indexOf(right),
      });
      if (caseName === "historical") assert.throws(build, /Historical image input addition or deletion/, component);
      else assert.equal(build().classification[component], true, `${component} ${caseName}`);
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  }
});

test("real Git rename, copy, and deletion ranges retain both identities and block historical structural image changes", () => {
  const scenarios = [
    { name: "backend to unknown", from: "backend/src/services/qrService.ts", to: "archive/qrService.ts", operation: "rename" },
    { name: "frontend to unknown", from: "src/App.tsx", to: "archive/App.tsx", operation: "rename" },
    { name: "unknown to backend", from: "archive/legacy.ts", to: "backend/src/services/qrService.ts", operation: "rename" },
    { name: "cross component", from: "backend/src/services/qrService.ts", to: "src/pages/Batches.tsx", operation: "rename" },
    { name: "backend deletion", from: "backend/src/services/qrService.ts", operation: "delete" },
    { name: "unknown frontend copy", from: "archive/legacy.ts", to: "src/pages/Batches.tsx", operation: "copy" },
    { name: "cross component copy", from: "backend/src/services/qrService.ts", to: "src/pages/Batches.tsx", operation: "copy" },
  ];
  for (const scenario of scenarios) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-normal-rename-"));
    const git = (args) => execFileSync("git", args, { cwd: directory, encoding: "utf8" }).trim();
    const write = (file) => { const location = path.join(directory, file); fs.mkdirSync(path.dirname(location), { recursive: true }); fs.writeFileSync(location, "export const fixture = 'source-bound production image input';\n"); };
    try {
      git(["init", "-q"]); git(["config", "user.email", "test@mscqr.invalid"]); git(["config", "user.name", "MSCQR Test"]);
      write(scenario.from); git(["add", "-A"]); git(["commit", "-qm", "baseline"]); const base = git(["rev-parse", "HEAD"]);
      if (scenario.operation === "rename") { fs.mkdirSync(path.dirname(path.join(directory, scenario.to)), { recursive: true }); fs.renameSync(path.join(directory, scenario.from), path.join(directory, scenario.to)); }
      else if (scenario.operation === "copy") { fs.mkdirSync(path.dirname(path.join(directory, scenario.to)), { recursive: true }); fs.copyFileSync(path.join(directory, scenario.from), path.join(directory, scenario.to)); }
      else fs.rmSync(path.join(directory, scenario.from));
      git(["add", "-A"]); git(["commit", "-qm", scenario.name]); const changedSha = git(["rev-parse", "HEAD"]);
      const observed = readProductionGitChanges(base, changedSha, directory);
      assert.ok(observed.paths.includes(scenario.from), scenario.name);
      if (scenario.to) assert.ok(observed.paths.includes(scenario.to), scenario.name);
      if (scenario.operation === "rename" || scenario.name === "cross component copy")
        assert.throws(() => buildProductionNormalDeploymentPlan({ sourceSha: target, state: authorizedState(), pushFiles: observed.paths,
          pushChangedFiles: observed.structural.flatMap((change) => change.paths), pushPaired: observed.paired,
          readRange: range, readStructural: () => observed.structural, isAncestor: (left, right) => lineage.indexOf(left) >= 0 && lineage.indexOf(left) <= lineage.indexOf(right),
        }), scenario.operation === "rename" ? /Current-push renames/ : /Cross-component copies/, scenario.name);
      if (scenario.to?.startsWith("archive/")) assert.throws(() => classifyProductionChanges(observed.paths), /Ambiguous production change paths/, scenario.name);
      if (scenario.operation === "copy") assert.ok(observed.paths.includes(scenario.from), "Copied source path is required");
      const selected = scenario.from.startsWith("src/") || scenario.to?.startsWith("src/") ? "frontend" : "backend";
      const pushed = selected === "frontend" ? ["src/main.tsx"] : [changed];
      const structural = observed.structural;
      assert.equal(structural.some(({ status, paths }) => ["A", "D"].includes(status) && paths.some((file) => isNormalImageInput(selected, file) && !pushed.includes(file))), true, scenario.name);
      assert.throws(() => buildProductionNormalDeploymentPlan({ sourceSha: target, state: authorizedState(), pushFiles: pushed, pushChangedFiles: pushed, pushPaired: [],
        readRange: (left, right) => selected === "frontend" && right === target ? [...range(left, right), "src/main.tsx"] : range(left, right),
        readStructural: () => structural, isAncestor: (left, right) => lineage.indexOf(left) >= 0 && lineage.indexOf(left) <= lineage.indexOf(right),
      }), /Historical image input addition or deletion/, scenario.name);
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  }
});

test("selected backend security or unknown image inputs fail closed before publication", () => {
  for (const path of ["backend/src/middleware/auth.ts", "backend/prisma/schema.prisma", "backend/scripts/new-security-gate.mjs", "scripts/security/production-rotation-state-inventory.mjs", "scripts/aws/production-app-only-verifier-runtime.mjs", "scripts/aws/production-security-rebaseline-transport.mjs", "scripts/aws/production-rls-catalogue-probe-runtime.mjs", "documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql"])
    assert.throws(() => prepare([changed], (base, source) => [...range(base, source), path]), /Sensitive or ambiguous changes|Ambiguous production change paths|changed after stronger-lane authorization/, path);
  assert.throws(() => prepare([changed], (base, source) => [...range(base, source), "backend/src/controllers/newUnclassifiedController.ts"]), /Ambiguous production change paths/);
});

test("normal image input map covers every direct COPY in both production targets", () => {
  const source = fs.readFileSync(new URL("../../backend/Dockerfile", import.meta.url), "utf8");
  const backend = source.split(/^FROM .* AS production-rls-executor$/m)[0];
  assert.notEqual(backend, source, "Backend runtime stage boundary changed");
  const frontend = fs.readFileSync(new URL("../../Dockerfile.ecs-frontend", import.meta.url), "utf8");
  for (const [name, dockerfile] of [["backend", backend], ["frontend", frontend]]) {
    const sources = dockerfile.split("\n").filter((line) => line.startsWith("COPY ") && !line.includes("--from=")).map((line) => line.match(/^COPY (?:--\S+ )*(\S+)/)?.[1]);
    assert.ok(sources.length > 10 && sources.every(Boolean));
    for (const entry of sources) {
      const example = entry.replaceAll("*", "-lock") + (entry.includes(".") || entry.endsWith("json") ? "" : "/fixture");
      assert.equal(isNormalImageInput(name, example), true, `${name} COPY source is absent from the normal image map: ${entry}`);
    }
  }
  assert.match(fs.readFileSync(new URL("../aws/publish-ecs-images.sh", import.meta.url), "utf8"), /backend\|worker\) printf 'runtime'/);
});

test("protected push workflow preserves approval, ECR guard, publication, attestation and terminal receipt order", () => {
  const caller = yaml.load(fs.readFileSync(new URL("../../.github/workflows/production-deploy.yml", import.meta.url), "utf8"));
  const workflow = yaml.load(fs.readFileSync(new URL("../../.github/workflows/production-normal-deployment-operation.yml", import.meta.url), "utf8"));
  assert.deepEqual(caller.on.push.branches, ["main"]);
  assert.equal(caller.concurrency.group, "production-deploy");
  assert.match(caller.jobs.deploy.uses, /production-normal-deployment-operation\.yml@[a-f0-9]{40}$/);
  assert.equal(workflow.jobs.deploy.environment, "production-normal-deploy");
  const steps = workflow.jobs.deploy.steps;
  const position = (name) => steps.findIndex((step) => step.name === name);
  const tooling = steps[position("Authenticate caller and reviewed host tooling before credentials")];
  assert.ok(tooling && position("Authenticate caller and reviewed host tooling before credentials") < steps.findIndex((step) => step.uses?.startsWith("aws-actions/configure-aws-credentials@")));
  assert.equal(tooling.if, undefined);
  assert.match(tooling.run, /git ls-tree -r HEAD[\s\S]*sha256sum/);
  assert.match(tooling.run, /production-deploy\.yml@refs\/heads\/main/);
  assert.match(tooling.run, /test "\$GITHUB_SHA" = "\$\(git rev-parse HEAD\)"/);
  assert.match(tooling.run, /git status --porcelain --untracked-files=all/);
  const expected = ["Reconcile and prepare component-state transaction", "Authenticate live deployment baseline", "Bind authoritative deployment route", "Require protected ECR repositories before publication", "Publish immutable backend image", "Bind backend digest", "Scan published images", "Sign and attest published images", "Execute coordinated normal component transaction", "Preserve normal transaction journal"];
  assert.ok(expected.every((name) => position(name) >= 0), "Normal workflow is missing a required stage");
  assert.deepEqual(expected.map(position), [...expected.map(position)].sort((a, b) => a - b));
  assert.match(steps[position("Require protected ECR repositories before publication")].run, /verify-production-ecr-repository-protection\.mjs mscqr-backend/);
  assert.match(steps[position("Sign and attest published images")].run, /verify-release-artifacts\.sh/);
  assert.match(steps[position("Execute coordinated normal component transaction")].run, /production-normal-release\.mjs --source-sha/);
  assert.match(steps[position("Preserve normal transaction journal")].if, /always\(\)/);
});

test("eligible release preserves ECR guard, image provenance, health, receipt and generation CAS", async () => {
  const preparation = prepare([changed]);
  const repository = { repositoryName: "mscqr-backend", registryId: "368992683803", repositoryArn: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend", repositoryUri: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend", imageTagMutability: "IMMUTABLE", imageScanningConfiguration: { scanOnPush: true } };
  const policy = { Statement: [{ Effect: "Deny", Principal: "*", Action: ["ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:PutLifecyclePolicy"] }] };
  assert.throws(() => assertEcrRepositoryProtection({ repository: "mscqr-backend", description: repository, lifecyclePolicy: { rules: [] }, repositoryPolicy: policy, caller: { Account: "368992683803" } }), /Automated ECR lifecycle expiration/);
  assertEcrRepositoryProtection({ repository: "mscqr-backend", description: repository, lifecyclePolicy: null, repositoryPolicy: policy, caller: { Account: "368992683803" } });
  assert.equal(assertNormalImageIdentity({ service: "backend", sourceSha: target, repository, image: { repositoryName: "mscqr-backend", registryId: "368992683803", imageTags: [target], imageDigest: digest }, labels: { "org.opencontainers.image.revision": target, "org.opencontainers.image.title": "mscqr-backend" }, platforms: ["linux/amd64"] }), imageRef);
  const plan = buildNormalReleasePlan({ sourceSha: target, componentFiles: preparation.componentFiles, images: { backend: imageRef } });
  let stored = authorizedState(), live = stored.components.backend, healthy = true;
  const writes = [], journal = [];
  const client = { read: () => structuredClone(stored), advance: (previous, next) => {
    assert.equal(previous.generation, stored.generation, "Generation CAS failed");
    assert.equal(previous.components.backend.taskDefinitionArn, stored.components.backend.taskDefinitionArn);
    stored = structuredClone(next); writes.push({ generation: next.generation, phase: next.normalDeploymentReceipt?.phase || "COMMITTED" });
  } };
  const candidate = { sourceSha: target, establishedThroughSha: target, imageDigest: digest, taskDefinitionArn: candidateArn, desiredCount: 2 };
  const deploy = async (_, { recordCandidate }) => { await recordCandidate(candidateArn); live = candidate; return { result: { candidateTaskDefinition: candidateArn, deployedBackendDigest: digest }, rollback: async () => { live = fixture.state.components.backend; } }; };
  const verifyCandidates = async (components) => {
    assert.deepEqual(live, components.backend, "ECS readback differs from intended component");
    assert.equal(healthy, true, "Application or ALB health failed");
    assert.deepEqual(components.frontend, fixture.state.components.frontend, "Frontend must remain untouched");
  };
  const run = () => executeNormalComponentTransaction({ plan, sourceSha: target, state: authorizedState(), stateClient: client,
    backend: { deploy, rollback: (value) => value.rollback() }, frontend: {}, verifyCandidates,
    smoke: async () => { assert.equal(healthy, true); }, writeJournal: async (entry) => journal.push(entry.status),
    isAncestor: () => true, writerContext: { updatedByWorkflow: NORMAL_RECEIPT_WORKFLOW, githubRunId: "123" },
  });
  const result = await run();
  assert.deepEqual(writes.map((entry) => entry.phase), ["PREPARED", "PREPARED", "VERIFIED", "COMMITTED"]);
  assert.equal(result.componentState.generation, 7);
  assert.equal(stored.components.backend.taskDefinitionArn, candidateArn);
  assert.deepEqual(stored.components.frontend, fixture.state.components.frontend);
  assert.equal(stored.normalDeploymentReceipt, undefined);
  assert.ok(journal.includes("STATE_COMMITTED"));
  stored = authorizedState(); live = stored.components.backend;
  healthy = false;
  await assert.rejects(run(), /Application or ALB health failed/);
  assert.equal(stored.generation, 3, "Failed pre-mutation health cannot write a receipt");
});
