import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { buildProductionNormalDeploymentPlan, isNormalImageInput } from "../aws/prepare-production-normal-deployment.mjs";
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
const range = (base, source) => {
  if (source !== target) return [];
  const name = Object.entries(fixture.state.components).find(([, component]) => component?.establishedThroughSha === base)?.[0];
  assert.ok(name === "backend" || name === "frontend", "Unexpected component source range");
  return [...fixture.sourceRanges[name], changed];
};
const prepare = (pushFiles, readRange = range) => buildProductionNormalDeploymentPlan({
  sourceSha: target, state: state(), pushFiles, readRange, isAncestor: () => true,
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
});

test("backend-only eligible push carries no unrelated frontend source or infrastructure changes", () => {
  const initial = state();
  const plan = prepare([changed]);
  assert.equal(plan.stateGeneration, 2);
  assert.deepEqual({ backend: plan.classification.backend, frontend: plan.classification.frontend }, { backend: true, frontend: false });
  assert.deepEqual(plan.componentFiles.backendFiles, [changed]);
  assert.deepEqual(plan.componentFiles.frontendFiles, []);
  assert.deepEqual(plan.componentFiles.securityFiles, []);
  assert.deepEqual(plan.componentFiles.databaseFiles, []);
  assert.deepEqual(state(), initial, "Planning must not advance component state");
});

test("undeployed frontend security code remains pending and cannot enter normal frontend activation", () => {
  assert.throws(() => prepare(["src/App.tsx"], (base, source) => [...range(base, source), "src/App.tsx"]), /Sensitive or ambiguous changes/);
  assert.throws(() => prepare(["src/contexts/AuthContext.tsx"]), /protected-main push is not eligible/);
  assert.throws(() => prepare(["infra/aws/terraform/main.tf"]), /protected-main push is not eligible/);
  assert.throws(() => prepare([changed], () => []), /backend source range does not match/);
});

test("selected backend security or unknown image inputs fail closed before publication", () => {
  for (const path of ["backend/src/middleware/auth.ts", "backend/prisma/schema.prisma", "backend/scripts/new-security-gate.mjs", "scripts/security/production-rotation-state-inventory.mjs", "scripts/aws/production-app-only-verifier-runtime.mjs", "scripts/aws/production-security-rebaseline-transport.mjs", "scripts/aws/production-rls-catalogue-probe-runtime.mjs", "documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql"])
    assert.throws(() => prepare([changed], (base, source) => [...range(base, source), path]), /Sensitive or ambiguous changes|Ambiguous production change paths/, path);
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
  const workflow = yaml.load(fs.readFileSync(new URL("../../.github/workflows/production-deploy.yml", import.meta.url), "utf8"));
  assert.deepEqual(workflow.on.push.branches, ["main"]);
  assert.equal(workflow.concurrency.group, "production-deploy");
  assert.equal(workflow.jobs.deploy.environment, "production-normal-deploy");
  const steps = workflow.jobs.deploy.steps;
  const position = (name) => steps.findIndex((step) => step.name === name);
  const tooling = steps[position("Authenticate reviewed normal deployment tooling")];
  assert.ok(tooling && position("Authenticate reviewed normal deployment tooling") < steps.findIndex((step) => step.uses?.startsWith("aws-actions/configure-aws-credentials@")));
  assert.equal(tooling.if, "needs.classify.outputs.release_class == 'NORMAL_APPLICATION'");
  const root = new URL("../../", import.meta.url);
  const tree = execFileSync("git", ["ls-tree", "-r", "HEAD", "--", "scripts/aws", "scripts/lib", "scripts/security", "scripts/smoke-release.mjs", "infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs"], { cwd: root });
  assert.match(tooling.run, new RegExp(createHash("sha256").update(tree).digest("hex")));
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
  const policy = { Statement: [{ Effect: "Deny", Principal: "*", Resource: "*", Action: ["ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:PutLifecyclePolicy"] }] };
  assert.throws(() => assertEcrRepositoryProtection({ repository: "mscqr-backend", description: repository, lifecyclePolicy: { rules: [] }, repositoryPolicy: policy, caller: { Account: "368992683803" } }), /Automated ECR lifecycle expiration/);
  assertEcrRepositoryProtection({ repository: "mscqr-backend", description: repository, lifecyclePolicy: null, repositoryPolicy: policy, caller: { Account: "368992683803" } });
  assert.equal(assertNormalImageIdentity({ service: "backend", sourceSha: target, repository, image: { repositoryName: "mscqr-backend", registryId: "368992683803", imageTags: [target], imageDigest: digest }, labels: { "org.opencontainers.image.revision": target, "org.opencontainers.image.title": "mscqr-backend" }, platforms: ["linux/amd64"] }), imageRef);
  const plan = buildNormalReleasePlan({ sourceSha: target, componentFiles: preparation.componentFiles, images: { backend: imageRef } });
  let stored = state(), live = stored.components.backend, healthy = true;
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
  const run = () => executeNormalComponentTransaction({ plan, sourceSha: target, state: state(), stateClient: client,
    backend: { deploy, rollback: (value) => value.rollback() }, frontend: {}, verifyCandidates,
    smoke: async () => { assert.equal(healthy, true); }, writeJournal: async (entry) => journal.push(entry.status),
    isAncestor: () => true, writerContext: { updatedByWorkflow: NORMAL_RECEIPT_WORKFLOW, githubRunId: "123" },
  });
  const result = await run();
  assert.deepEqual(writes.map((entry) => entry.phase), ["PREPARED", "PREPARED", "VERIFIED", "COMMITTED"]);
  assert.equal(result.componentState.generation, 6);
  assert.equal(stored.components.backend.taskDefinitionArn, candidateArn);
  assert.deepEqual(stored.components.frontend, fixture.state.components.frontend);
  assert.equal(stored.normalDeploymentReceipt, undefined);
  assert.ok(journal.includes("STATE_COMMITTED"));
  stored = state(); live = stored.components.backend;
  healthy = false;
  await assert.rejects(run(), /Application or ALB health failed/);
  assert.equal(stored.generation, 2, "Failed pre-mutation health cannot write a receipt");
});
