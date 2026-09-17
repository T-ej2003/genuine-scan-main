import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { executeIsolatedTerraform } from "../aws/component-terraform-runner.mjs";
import { terraformExecution } from "../aws/component-terraform-isolation.mjs";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const request = mode => ({ mode, credentials: { AccessKeyId: "disposable-key-fixture", SecretAccessKey: "disposable-secret-fixture", SessionToken: "disposable-token-fixture" },
  expiresAt: new Date(Date.now() + 900000).toISOString(), plan: mode === "apply" ? Buffer.from("exact-reviewed-plan") : null });

// Explicit test seam: simulated Terraform, real production container/agent and
// stdio controller. No AWS endpoint or real credential is used by this test.
async function fixture({ failOperation = "" } = {}) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-component-terraform-inputs-")));
  fs.chmodSync(directory, 0o700);
  const files = {};
  for (const name of ["agent", "isolation", "network"]) files[name === "agent" ? "agent.mjs" : `component-terraform-${name}.mjs`] = fs.readFileSync(new URL(`../aws/component-terraform-${name}.mjs`, import.meta.url));
  for (const name of ["main.tf", "providers.tf", "versions.tf", ".terraform.lock.hcl"]) files[`root/${name}`] = Buffer.from("public-source-fixture");
  files["terraform.rc"] = Buffer.from("public-cli-fixture");
  const architecture = process.arch === "arm64" ? "arm64" : "amd64";
  files[`providers/registry.terraform.io/hashicorp/aws/terraform-provider-aws_6.65.0_linux_${architecture}.zip`] = Buffer.from("unused-provider-fixture");
  files.terraform = Buffer.from(`#!/usr/bin/env node
import fs from 'node:fs';
import assert from 'node:assert/strict';
const args = process.argv.slice(3), operation = args[0];
assert.equal(process.env.AWS_ACCESS_KEY_ID, 'disposable-key-fixture');
assert.equal(process.env.AWS_SECRET_ACCESS_KEY, 'disposable-secret-fixture');
assert.equal(process.env.AWS_SESSION_TOKEN, 'disposable-token-fixture');
assert.equal(process.env.AWS_PROFILE, undefined);
assert.equal(process.env.AWS_CONFIG_FILE, undefined);
assert.equal(process.env.TF_WORKSPACE, 'default');
assert.equal(process.env.TF_CLI_CONFIG_FILE, '/inputs/terraform.rc');
assert(process.env.HTTPS_PROXY.startsWith('http://127.0.0.1:'));
assert.equal(process.env.AWS_EC2_METADATA_DISABLED, 'true');
if (operation === ${JSON.stringify(failOperation)}) process.exit(1);
if (operation === 'version') process.stdout.write(JSON.stringify({terraform_version:'1.15.8'}));
else if (operation === 'init') {
  assert(args.includes('-lockfile=readonly'));
  fs.writeFileSync('/work/data/terraform.tfstate', JSON.stringify({backend:{type:'s3',config:{fixture:true}}}));
} else if (operation === 'validate') process.stdout.write(JSON.stringify({valid:true}));
else if (operation === 'workspace') process.stdout.write('default\\n');
else if (operation === 'plan' && args.some(arg => arg.startsWith('-out='))) fs.writeFileSync('/work/activation.tfplan','exact-reviewed-plan');
else if (operation === 'show') process.stdout.write(JSON.stringify({fixture:true}));
else if (operation === 'apply') assert.equal(fs.readFileSync(args.at(-1),'utf8'),'exact-reviewed-plan');
else assert(['fmt','plan'].includes(operation));
`);
  for (const [name, value] of Object.entries(files)) {
    const target = path.join(directory, name); fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    fs.writeFileSync(target, value, { mode: name === "terraform" ? 0o555 : 0o444 });
  }
  const manifest = { schemaVersion: 1, architecture, terraformVersion: "1.15.8", providerVersion: "6.65.0", image: terraformExecution.image,
    files: Object.fromEntries(Object.entries(files).map(([name, value]) => [name, hash(value)])) };
  const bytes = Buffer.from(JSON.stringify(manifest)); fs.writeFileSync(path.join(directory, "manifest.json"), bytes, { mode: 0o444 });
  return { directory, manifestSha256: hash(bytes), dispose: () => fs.rmSync(directory, { recursive: true }) };
}

for (const mode of ["prepare", "apply"]) test(`actual isolated ${mode} orchestration uses scoped pipe credentials and exact saved bytes`, { skip: process.env.COMPONENT_CONTAINER_TESTS !== "1", timeout: 30000 }, async () => {
  const checkpoints = [];
  const result = await executeIsolatedTerraform(request(mode), { prepare: fixture, checkpoint: async value => { checkpoints.push(value); } });
  assert.deepEqual(checkpoints[0], { type: "checkpoint", stage: "backend", backend: { type: "s3", config: { fixture: true } }, workspace: "default" });
  if (mode === "prepare") {
    assert.equal(checkpoints.length, 2); assert.equal(checkpoints[1].stage, "plan");
    assert.deepEqual(result, { type: "result", plan: Buffer.from("exact-reviewed-plan").toString("base64"), planSha256: hash("exact-reviewed-plan"), planJson: { fixture: true } });
  } else {
    assert.deepEqual(checkpoints[1], { type: "checkpoint", stage: "apply", planSha256: hash("exact-reviewed-plan"), planJson: { fixture: true } });
    assert.deepEqual(result, { type: "result", appliedPlanSha256: hash("exact-reviewed-plan"), driftVerified: true });
  }
});

for (const operation of ["init", "plan", "apply"]) test(`isolated failure during ${operation} closes the owned container without replay`, { skip: process.env.COMPONENT_CONTAINER_TESTS !== "1", timeout: 30000 }, async () => {
  let count = 0;
  await assert.rejects(executeIsolatedTerraform(request(operation === "apply" ? "apply" : "prepare"), {
    prepare: () => fixture({ failOperation: operation }), checkpoint: async () => { count++; },
  }), /reconcile remote state/);
  assert(count <= 2);
});

test("rejected apply checkpoint cannot reach the exact saved-plan apply", { skip: process.env.COMPONENT_CONTAINER_TESTS !== "1", timeout: 30000 }, async () => {
  await assert.rejects(executeIsolatedTerraform(request("apply"), { prepare: fixture,
    checkpoint: async value => { if (value.stage === "apply") throw new Error("approval rejected"); },
  }), /reconcile remote state/);
});

for (const mutate of [value => { value.mode = "shell"; }, value => { value.credentials.AWS_PROFILE = "administrator"; }, value => { value.expiresAt = "2099-01-01T00:00:00Z"; }, value => { value.plan = "/arbitrary/path"; }]) {
  test("malformed execution input fails before preparing source or starting Docker", async () => {
    const input = request("prepare"); mutate(input);
    await assert.rejects(executeIsolatedTerraform(input, { checkpoint: async () => assert.fail(), prepare: async () => assert.fail("must not prepare") }));
  });
}
