import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import test from "node:test";
import path from "node:path";

import {
  evaluatePrivateInputSource,
  evaluatePrivateInputs,
} from "../check-staging-private-inputs.mjs";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const safeTemplate = `
account_id = "123456789012"
vpc_id = "vpc-REDACTED"
public_subnet_ids = ["subnet-REDACTED-a", "subnet-REDACTED-b"]
app_private_subnet_ids = ["subnet-REDACTED-a", "subnet-REDACTED-b"]
db_private_subnet_ids = ["subnet-REDACTED-a", "subnet-REDACTED-b"]
allowed_operator_cidrs = ["x.x.x.x/32"]
backend_image_uri = "ACCOUNT_ID.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend:STAGING_TAG"
staging_secret_arns = {
  database_url = "arn:aws:secretsmanager:eu-west-2:ACCOUNT_ID:secret:mscqr/staging/database-url-REDACTED"
}
`;

test("missing tfvars returns blocked_missing_private_tfvars without failing non-strict", () => {
  const result = spawnSync(process.execPath, ["scripts/check-staging-private-inputs.mjs"], {
    cwd: repoRoot,
    encoding: "utf8",
  });

  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.status, "blocked_missing_private_tfvars");
  assert.equal(parsed.foundTfvarsFile, false);
  assert.equal(parsed.rawValuesPrinted, false);
});

test("redacted safe template passes required structure", () => {
  const result = evaluatePrivateInputSource(safeTemplate);

  assert.equal(Object.values(result.requiredKeysPresent).every(Boolean), true);
  assert.deepEqual(result.blockers, []);
});

test("production-looking values are refused", () => {
  const result = evaluatePrivateInputSource(`${safeTemplate}\n# mscqr-prod-db-proxy\n`);

  assert(result.blockers.includes("production_fragment:prod"));
  assert(result.blockers.includes("production_fragment:mscqr-prod"));
  assert(result.blockers.includes("production_fragment:mscqr-prod-db-proxy"));
});

test("broad operator CIDRs are refused", () => {
  const result = evaluatePrivateInputSource(safeTemplate.replace('["x.x.x.x/32"]', '["0.0.0.0/0", "10.0.0.0/16"]'));

  assert(result.blockers.includes("operator_cidr_world_open"));
  assert(result.blockers.includes("operator_cidr_too_broad_ipv4"));
});

test("multiline broad operator CIDRs are refused", () => {
  const result = evaluatePrivateInputSource(safeTemplate.replace('["x.x.x.x/32"]', '[\n  "10.0.0.0/16",\n]'));

  assert(result.blockers.includes("operator_cidr_too_broad_ipv4"));
});

test("gitignore coverage is asserted", () => {
  const result = evaluatePrivateInputs({ root: repoRoot });

  assert.equal(result.gitIgnored["infra/terraform/staging-api/staging.auto.tfvars"], true);
  assert.equal(result.gitIgnored["infra/terraform/staging-api/example.local.tfvars"], true);
});

test("safe JSON output does not include raw private-looking values", () => {
  const result = spawnSync(process.execPath, ["scripts/check-staging-private-inputs.mjs"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  const privateLookingVpc = ["vpc", "12345678"].join("-");
  const privateLookingSubnet = ["subnet", "12345678"].join("-");

  assert.equal(result.stdout.includes(privateLookingVpc), false);
  assert.equal(result.stdout.includes(privateLookingSubnet), false);
  assert.equal(result.stdout.includes("arn:aws:secretsmanager"), false);
  assert.equal(result.stdout.includes("x.x.x.x/32"), false);
});

test("force-added private tfvars are blocked even when gitignored", () => {
  const tempRoot = fs.mkdtempSync(path.join(process.env.TMPDIR || "/tmp", "mscqr-private-inputs-git-"));
  try {
    const tfRoot = path.join(tempRoot, "infra/terraform/staging-api");
    fs.mkdirSync(tfRoot, { recursive: true });
    fs.writeFileSync(
      path.join(tempRoot, ".gitignore"),
      [
        "infra/terraform/staging-api/staging.auto.tfvars",
        "infra/terraform/staging-api/terraform.tfvars",
        "infra/terraform/staging-api/*.local.tfvars",
        "",
      ].join("\n"),
      "utf8",
    );
    fs.writeFileSync(path.join(tfRoot, "staging.auto.tfvars"), safeTemplate, "utf8");
    assert.equal(spawnSync("git", ["init"], { cwd: tempRoot, stdio: "ignore" }).status, 0);
    assert.equal(spawnSync("git", ["add", ".gitignore"], { cwd: tempRoot, stdio: "ignore" }).status, 0);
    assert.equal(spawnSync("git", ["add", "-f", "infra/terraform/staging-api/staging.auto.tfvars"], { cwd: tempRoot, stdio: "ignore" }).status, 0);

    const result = evaluatePrivateInputs({ root: tempRoot });

    assert.equal(result.status, "blocked_private_tfvars_invalid");
    assert.equal(result.trackedPrivateTfvarsCount, 1);
    assert(result.blockerCodes.includes("private_tfvars_tracked_or_staged"));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
