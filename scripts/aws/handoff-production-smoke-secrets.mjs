import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
export const SMOKE_REPOSITORY = "T-ej2003/genuine-scan-main";
export const SMOKE_ENVIRONMENT = "production-normal-deploy";
export const FORBIDDEN_SMOKE_SECRETS = Object.freeze(["PRODUCTION_SMOKE_ADMIN_MFA_CODE", "PRODUCTION_SMOKE_VERIFY_CODE"]);
const sourceNames = Object.freeze({
  MSCQR_CANARY_ORDINARY_EMAIL: "PRODUCTION_SMOKE_LOGIN_EMAIL",
  MSCQR_CANARY_ORDINARY_PASSWORD: "PRODUCTION_SMOKE_LOGIN_PASSWORD",
  MSCQR_CANARY_ORDINARY_MFA_SECRET: "PRODUCTION_SMOKE_ADMIN_MFA_SECRET",
});

export function smokeSecretHandoffContract(root = repositoryRoot) {
  const template = JSON.parse(fs.readFileSync(path.join(root, "infra/aws/terraform/production-green-stage-b/task-definitions/green-application-canary.json"), "utf8"));
  const secrets = new Map(template.containerDefinitions?.[0]?.secrets?.map(({ name, valueFrom }) => [name, valueFrom]));
  const contract = Object.entries(sourceNames).map(([sourceName, destination]) => {
    const arn = secrets.get(sourceName);
    assert.match(arn || "", /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/production\/rls-green\/phase2\/canary\/ordinary-(?:email|password|mfa-secret)-[A-Za-z0-9]{6}$/);
    return Object.freeze({ sourceName, secretId: arn.replace(/^arn:[^:]+:secretsmanager:[^:]+:[^:]+:secret:/, "").replace(/-[A-Za-z0-9]{6}$/, ""), arn, destination });
  });
  assert.deepEqual(contract.map(({ destination }) => destination).sort(), Object.values(sourceNames).sort());
  return Object.freeze(contract);
}

const parse = (value) => JSON.parse(Buffer.isBuffer(value) ? value.toString("utf8") : value);
const secretBytes = (value) => {
  const bytes = Buffer.from(value);
  const end = bytes.at(-1) === 10 ? bytes.length - (bytes.at(-2) === 13 ? 2 : 1) : bytes.length;
  assert.ok(end > 0 && end <= 65536, "Smoke secret value is empty or oversized");
  return bytes.subarray(0, end);
};

export function executeSmokeSecretHandoff({ awsProfile, run, contract }) {
  const aws = (args, options) => run("aws", ["--profile", awsProfile, ...args, "--no-cli-pager"], options);
  const caller = parse(aws(["sts", "get-caller-identity", "--output", "json"]));
  assert.equal(caller.Account, "368992683803");
  assert.equal(caller.Arn, "arn:aws:iam::368992683803:root");
  const list = () => new Set(parse(run("gh", ["secret", "list", "--repo", SMOKE_REPOSITORY, "--env", SMOKE_ENVIRONMENT, "--json", "name"])).map(({ name }) => name));
  const before = list();
  for (const name of FORBIDDEN_SMOKE_SECRETS) assert.equal(before.has(name), false, `${name} must remain unset`);
  for (const entry of contract) {
    const metadata = parse(aws(["secretsmanager", "describe-secret", "--region", "eu-west-2", "--secret-id", entry.secretId, "--output", "json"]));
    assert.equal(metadata.Name, entry.secretId); assert.equal(metadata.ARN, entry.arn);
  }
  const installed = [];
  for (const entry of contract) {
    const output = aws(["secretsmanager", "get-secret-value", "--region", "eu-west-2", "--secret-id", entry.arn, "--query", "SecretString", "--output", "text"]);
    const value = secretBytes(output);
    try {
      run("gh", ["secret", "set", entry.destination, "--repo", SMOKE_REPOSITORY, "--env", SMOKE_ENVIRONMENT, "--body", "-"], { input: value, stdio: ["pipe", "pipe", "pipe"] });
    } finally { value.fill(0); if (Buffer.isBuffer(output)) output.fill(0); }
    installed.push(entry.destination);
  }
  const present = list();
  assert.ok(installed.every((name) => present.has(name)), "Smoke secret readback is incomplete");
  for (const name of FORBIDDEN_SMOKE_SECRETS) assert.equal(present.has(name), false, `${name} must remain unset`);
  return { status: "DEDICATED_SMOKE_SECRETS_INSTALLED", repository: SMOKE_REPOSITORY, environment: SMOKE_ENVIRONMENT, installed: installed.sort(), forbiddenAbsent: [...FORBIDDEN_SMOKE_SECRETS] };
}

export function handoffProductionSmokeSecrets({ sourceSha, awsProfile, run = (command, args, options = {}) => execFileSync(command, args, { ...options, maxBuffer: 1024 * 1024 }), root = repositoryRoot }) {
  assertProtectedCheckout({ sourceSha, repositoryRoot: root });
  return executeSmokeSecretHandoff({ awsProfile, run, contract: smokeSecretHandoffContract(root) });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: { "source-sha": { type: "string" }, "aws-profile": { type: "string" } }, strict: true });
    assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/); assert.ok(values["aws-profile"]);
    process.stdout.write(`${JSON.stringify(handoffProductionSmokeSecrets({ sourceSha: values["source-sha"], awsProfile: values["aws-profile"] }))}\n`);
  } catch { process.stderr.write("Smoke secret handoff failed closed; no secret value was logged.\n"); process.exitCode = 1; }
}
