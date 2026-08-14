#!/usr/bin/env node
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCanonicalBackendRecovery, STAGE_B_BACKEND_RECOVERY } from "./stage-b-task-definition-recovery-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const run = (command, args, env) => execFileSync(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

export async function runCanonicalRecoveryCli(argv = process.argv.slice(2), { exec = run } = {}) {
  if (!argv.includes("--execute")) throw new Error("Recovery is mutation-capable; --execute is required and must be explicitly reviewed after merge.");
  const sourceSha = required(argv, "--source-sha");
  const bindingsPath = required(argv, "--bindings");
  const terraformRoot = path.resolve(required(argv, "--terraform-root"));
  const evidencePath = path.resolve(required(argv, "--evidence-out"));
  const profile = required(argv, "--aws-profile");
  if (!/^[a-f0-9]{40}$/.test(sourceSha)) throw new Error("--source-sha must be a full protected-main SHA.");
  if (path.resolve(evidencePath) === path.resolve(bindingsPath)) throw new Error("Recovery evidence and bindings must be distinct files.");
  const bindings = JSON.parse(fs.readFileSync(bindingsPath, "utf8"));
  const env = { ...process.env, AWS_PROFILE: profile, AWS_REGION: "eu-west-2", AWS_DEFAULT_REGION: "eu-west-2" };
  const terraform = (args) => JSON.parse(exec("terraform", [`-chdir=${terraformRoot}`, ...args], env));
  const aws = (args) => JSON.parse(exec("aws", [...args, "--region", "eu-west-2", "--profile", profile, "--output", "json"], env));
  const readState = async () => terraform(["state", "pull"]);
  const newest = async () => {
    const result = aws(["ecs", "list-task-definitions", "--family-prefix", STAGE_B_BACKEND_RECOVERY.family, "--status", "ACTIVE", "--sort", "DESC"]);
    if (!Array.isArray(result.taskDefinitionArns) || result.taskDefinitionArns.length === 0) throw new Error("No ACTIVE backend candidate revisions were returned.");
    return result.taskDefinitionArns[0];
  };
  const register = async ({ taskDefinition, tags }) => aws(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify({ ...taskDefinition, tags })]);
  const describe = async (arn) => aws(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]);
  const removeState = async ({ address, expectedArn }) => {
    if (address !== STAGE_B_BACKEND_RECOVERY.address || expectedArn !== STAGE_B_BACKEND_RECOVERY.predecessorArn) throw new Error("Recovery attempted an unreviewed Terraform state removal.");
    exec("terraform", [`-chdir=${terraformRoot}`, "state", "rm", "-lock-timeout=60s", address], env);
  };
  const importState = async ({ address, arn }) => {
    if (address !== STAGE_B_BACKEND_RECOVERY.address || !/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/.test(arn || "")) throw new Error("Recovery attempted an unreviewed Terraform state import.");
    exec("terraform", [`-chdir=${terraformRoot}`, "import", "-lock-timeout=60s", address, arn], env);
  };
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, readState, register, describe, newest, removeState, importState });
  if (fs.existsSync(evidencePath)) throw new Error("Recovery evidence output already exists.");
  fs.writeFileSync(evidencePath, `${JSON.stringify(result.evidence, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({ status: "reconciled", replacementArn: result.registration.arn, evidenceSha256: result.evidence.evidenceSha256, stateSerialAfter: result.reconciliation.stateSerialAfter })}\n`);
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { await runCanonicalRecoveryCli(); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
