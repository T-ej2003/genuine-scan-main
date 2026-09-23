#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { gzipSync, gunzipSync } from "node:zlib";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { createProductionAwsCredentialEnvironment, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { B01_PREREQUISITE, assertB01LivePredecessor, attestBridgeDiff, buildB01ExecutorDefinition, buildB01PrerequisiteReceipt, canonicalJson, canonicalSha256 } from "./production-b01-prerequisite-contract.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const require = createRequire(import.meta.url);
const runtimePath = fileURLToPath(new URL("./production-b01-prerequisite-executor.cjs", import.meta.url));
const runtime = require(runtimePath);
const AUTH_OWNER = ["mscqr", "prd", "rls", "phase2", "auth", "owner"].join("_"),
  SCHEMA_OWNER = ["mscqr", "prd", "rls", "phase2", "owner"].join("_"), PREAUTH = ["mscqr", "prd", "rls", "phase2", "preauth"].join("_");
const CERT_AUTH_OWNER = "mscqr_rls_cert_auth_owner", CERT_PREAUTH = "mscqr_rls_cert_preauth";
const sourcePath = "backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql";
const generatedPolicyPath = "scripts/rls/sql/generated/30-policies.sql";
const policyStatePath = "scripts/aws/production-b01-prerequisite-policy-state.json";
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const relevantRoles = [
  { name: AUTH_OWNER, login: false }, { name: SCHEMA_OWNER, login: false }, { name: PREAUTH, login: true },
].sort((a, b) => a.name.localeCompare(b.name)).map((role) => ({ ...role, superuser: false, inherit: false, create_role: false,
  create_database: false, replication: false, bypass_rls: false }));

const functionSql = (source, name) => {
  const marker = `CREATE OR REPLACE FUNCTION app_auth.${name}(`, start = source.indexOf(marker), end = source.indexOf("\n$fn$;", start);
  assert.ok(start >= 0 && end > start && source.indexOf(marker, start + 1) < 0, `Canonical ${name} function is absent or ambiguous.`);
  return source.slice(start, end + 6);
};
const functionBody = (sql) => { const start = sql.indexOf(" AS $fn$\n"); assert.ok(start > 0 && sql.endsWith("\n$fn$;")); return sql.slice(start + 8, -5); };
const functionRow = (name, sql, { arguments: args, preauth = false } = {}) => ({ name, arguments: args, owner: AUTH_OWNER,
  language: "plpgsql", result: name === "finalize_refresh_token_rotation" ? "TABLE(finalized boolean)" : "void", kind: "f",
  security_definer: true, leakproof: false, strict: false, volatility: "v", parallel: "u",
  proconfig: ["search_path=pg_catalog, public"], body: functionBody(sql), public_execute: false, preauth_execute: preauth,
  acl: [`${AUTH_OWNER}|${AUTH_OWNER}|EXECUTE|f`, ...(preauth ? [`${PREAUTH}|${AUTH_OWNER}|EXECUTE|f`] : [])].sort() });

function policyRows(source, canonical) {
  assert.equal(canonical.schemaVersion, 1); assert.equal(canonical.postgresMajor, 18); assert.equal(canonical.policies.length, 65);
  const metadata = [];
  const lines = source.split("\n");
  for (let index = 0; index < lines.length; index++) {
    const match = /^CREATE POLICY "(b01_[^"]+)" ON public\."([^"]+)" AS (PERMISSIVE|RESTRICTIVE) FOR (SELECT|INSERT|UPDATE|DELETE) TO "mscqr_(?:rls_cert|prd_rls_phase2)_auth_owner" (?:USING|WITH CHECK) \(.+\);$/.exec(lines[index]);
    if (!match) continue;
    const comment = new RegExp(`^COMMENT ON POLICY "${match[1]}" ON public\\."${match[2]}" IS '(.+)';$`).exec(lines[index + 1]);
    assert.ok(comment, `Policy ${match[1]} comment is absent.`);
    metadata.push({ schema: "public", table: match[2], name: match[1], command: ({ SELECT: "r", INSERT: "a", UPDATE: "w", DELETE: "d" })[match[4]],
      permissive: match[3] === "PERMISSIVE", roles: [AUTH_OWNER], comment: comment[1] });
  }
  const sorted = (rows) => rows.sort((a, b) => a.table.localeCompare(b.table) || a.name.localeCompare(b.name));
  assert.equal(new Set(metadata.map(({ name }) => name)).size, metadata.length);
  assert.deepEqual(sorted(metadata), sorted(canonical.policies.map(({ using_sha256: _using, with_check_sha256: _check, ...policy }) => policy)));
  for (const policy of canonical.policies) {
    assert.match(policy.using_sha256 || policy.with_check_sha256 || "", /^[a-f0-9]{64}$/);
    if (policy.command === "r" || policy.command === "d") { assert.match(policy.using_sha256 || "", /^[a-f0-9]{64}$/); assert.equal(policy.with_check_sha256, null); }
    if (policy.command === "a") { assert.equal(policy.using_sha256, null); assert.match(policy.with_check_sha256 || "", /^[a-f0-9]{64}$/); }
    if (policy.command === "w") { assert.match(policy.using_sha256 || "", /^[a-f0-9]{64}$/); assert.match(policy.with_check_sha256 || "", /^[a-f0-9]{64}$/); }
  }
  return sorted(structuredClone(canonical.policies));
}

export function canonicalB01Prerequisite({ repositoryRoot = root, readOld = (file) => execFileSync("git", ["show", `${B01_PREREQUISITE.rlsDeltaOriginSha}^:${file}`], { cwd: repositoryRoot, encoding: "utf8" }) } = {}) {
  const current = fs.readFileSync(path.join(repositoryRoot, sourcePath), "utf8"), old = readOld(sourcePath);
  const bind = functionSql(current, "b01_bind_predecessor"), oldBind = functionSql(old, "b01_bind_predecessor");
  const finalizer = functionSql(current, "finalize_refresh_token_rotation");
  const policySource = fs.readFileSync(path.join(repositoryRoot, generatedPolicyPath), "utf8");
  const policyState = JSON.parse(fs.readFileSync(path.join(repositoryRoot, policyStatePath), "utf8"));
  const successorPolicies = policyRows(policySource, policyState);
  const policy = successorPolicies.find(({ name }) => name === "b01_auditlogoutbox_select"); assert.ok(policy);
  const policyCreate = policySource.split("\n").find((line) => line.startsWith('CREATE POLICY "b01_auditlogoutbox_select"'))
    .replaceAll(CERT_AUTH_OWNER, AUTH_OWNER).replaceAll(CERT_PREAUTH, PREAUTH);
  const policyComment = policySource.split("\n").find((line) => line.startsWith('COMMENT ON POLICY "b01_auditlogoutbox_select"'));
  const baseCatalogue = { rls: true, forced: true, table_owner: SCHEMA_OWNER, schema_owner: AUTH_OWNER, owner_set: true, schema_owner_set: true,
    table_acl: ["DELETE", "INSERT", "MAINTAIN", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"]
      .map((privilege) => `${SCHEMA_OWNER}|${SCHEMA_OWNER}|${privilege}|f`),
    payload_column_acl: [`${AUTH_OWNER}|${SCHEMA_OWNER}|INSERT|f`, `${AUTH_OWNER}|${SCHEMA_OWNER}|SELECT|f`] };
  const predecessor = { roles: relevantRoles, functions: [functionRow("b01_bind_predecessor", oldBind, { arguments: "p_token_id text, p_user_id text, p_organization_id text, p_operation text" })],
    policies: successorPolicies.filter(({ name }) => name !== "b01_auditlogoutbox_select"), catalogue: { ...baseCatalogue, payload_column_select: true } };
  const successor = { roles: relevantRoles, functions: [functionRow("b01_bind_predecessor", bind, { arguments: "p_token_id text, p_user_id text, p_organization_id text, p_operation text" }),
      functionRow("finalize_refresh_token_rotation", finalizer, { arguments: "p_token_id text, p_hashes text[], p_user_id text, p_finalized_at timestamp without time zone, p_request_id text", preauth: true })].sort((a, b) => a.name.localeCompare(b.name)),
    policies: successorPolicies, catalogue: { ...baseCatalogue, payload_column_select: true } };
  const mutations = [
    ["bind-predecessor", bind], ["finalizer", finalizer],
    ["public-revoke", "REVOKE ALL ON FUNCTION app_auth.finalize_refresh_token_rotation(text,text[],text,timestamp without time zone,text) FROM PUBLIC"],
    ["preauth-execute", `GRANT EXECUTE ON FUNCTION app_auth.finalize_refresh_token_rotation(text,text[],text,timestamp without time zone,text) TO ${PREAUTH}`],
    ["payload-select", `GRANT SELECT (payload) ON TABLE public.\"AuditLogOutbox\" TO ${AUTH_OWNER}`],
    ["select-policy", policyCreate], ["select-policy-comment", policyComment],
  ].map(([name, sql]) => Object.freeze({ name, sql, sha256: hash(sql) }));
  const predecessorRlsIdentity = canonicalSha256(predecessor), successorRlsIdentity = canonicalSha256(successor);
  return Object.freeze({ predecessor, successor, mutations, predecessorBindSql: oldBind, predecessorRlsIdentity, successorRlsIdentity });
}

export function buildB01ExecutorInput({ deploymentSourceSha, databaseHostname, repositoryRoot = root } = {}) {
  assert.match(deploymentSourceSha || "", /^[a-f0-9]{40}$/); assert.match(databaseHostname || "", /^[a-z0-9.-]+$/);
  const delta = canonicalB01Prerequisite({ repositoryRoot });
  const executorSource = fs.readFileSync(path.join(repositoryRoot, path.relative(root, runtimePath)), "utf8");
  const contract = { rlsDeltaOriginSha: B01_PREREQUISITE.rlsDeltaOriginSha, deploymentSourceSha,
    migrationSetDigest: B01_PREREQUISITE.migrationSetDigest, sourceContractSha256: B01_PREREQUISITE.sourceContractSha256,
    predecessorRlsIdentity: delta.predecessorRlsIdentity, successorRlsIdentity: delta.successorRlsIdentity,
    executorSourceSha256: hash(executorSource), mutations: delta.mutations };
  const envelope = { databaseHostname, contract, contractSha256: canonicalSha256(contract) };
  const bytes = Buffer.from(canonicalJson(envelope)); assert.ok(bytes.length < 128 * 1024);
  const payload = gzipSync(bytes, { level: 9, mtime: 0 }).toString("base64");
  return Object.freeze({ command: ["-e", executorSource, payload, hash(bytes)], contract, contractSha256: envelope.contractSha256,
    commandSha256: canonicalSha256(["-e", executorSource, payload, hash(bytes)]) });
}

export function authenticateB01Result(message, contract) {
  const value = JSON.parse(message), { evidenceSha256, ...body } = value; assert.equal(evidenceSha256, canonicalSha256(body));
  assert.equal(body.kind, "PRODUCTION_B01_PREREQUISITE_RESULT"); assert.equal(body.rlsDeltaOriginSha, B01_PREREQUISITE.rlsDeltaOriginSha);
  assert.equal(body.contractSha256, canonicalSha256(contract)); assert.equal(body.predecessorRlsIdentity, contract.predecessorRlsIdentity);
  assert.equal(body.successorRlsIdentity, contract.successorRlsIdentity); assert.equal(body.liveRlsIdentity, contract.successorRlsIdentity);
  assert.ok(body.status === "APPLIED" && body.writeCount === 7 || body.status === "ALREADY_CONVERGED" && body.writeCount === 0); return value;
}

export function authenticateB01ExecutorCommand({ command, deploymentSourceSha, repositoryRoot = root } = {}) {
  assert.equal(command?.length, 4); assert.equal(command[0], "-e");
  const executorSource = fs.readFileSync(path.join(repositoryRoot, path.relative(root, runtimePath)), "utf8"); assert.equal(command[1], executorSource);
  const bytes = gunzipSync(Buffer.from(command[2], "base64"), { maxOutputLength: 128 * 1024 });
  assert.equal(hash(bytes), command[3]); const envelope = JSON.parse(bytes); assert.equal(canonicalJson(envelope), bytes.toString("utf8"));
  const expected = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname: envelope.databaseHostname, repositoryRoot });
  assert.deepEqual(command, expected.command); assert.deepEqual(envelope.contract, expected.contract); assert.equal(envelope.contractSha256, expected.contractSha256);
  return expected;
}

export const executeB01Transaction = runtime.executeB01Transaction;
export const collectB01State = runtime.collectB01State;

export async function applyProductionB01Prerequisite({ deploymentSourceSha, awsProfile, receiptOut, repositoryRoot = root,
  run = (file, args, options) => execFileSync(file, args, options), wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), now = () => new Date() } = {}) {
  assertProtectedCheckout({ sourceSha: deploymentSourceSha, repositoryRoot });
  const bridgeDiffAttestation = attestBridgeDiff({ deploymentSourceSha, repositoryRoot });
  const env = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: awsProfile });
  const aws = (args, timeout = 30000) => JSON.parse(run(productionAwsExecutable(), [...args, "--output", "json", "--no-cli-pager"], { env, encoding: "utf8", timeout, maxBuffer: 8 * 1024 * 1024 }));
  const caller = aws(["sts","get-caller-identity"]); assert.equal(caller.Account, APP_ONLY.account); assert.equal(caller.Arn, `arn:aws:iam::${APP_ONLY.account}:root`);
  const service = aws(["ecs","describe-services","--region",APP_ONLY.region,"--cluster",APP_ONLY.cluster,"--services",APP_ONLY.service]).services?.[0];
  const liveDefinition = aws(["ecs","describe-task-definition","--region",APP_ONLY.region,"--task-definition",service.taskDefinition]).taskDefinition;
  const imageDigest = B01_PREREQUISITE.executorImage.split("@")[1];
  const repository = aws(["ecr","describe-repositories","--region",APP_ONLY.region,"--repository-names","mscqr-backend"]).repositories?.[0];
  const imageDetails = aws(["ecr","describe-images","--region",APP_ONLY.region,"--repository-name","mscqr-backend","--image-ids",`imageDigest=${imageDigest}`]).imageDetails;
  assertB01LivePredecessor({ service, taskDefinition: liveDefinition, repository, imageDetails });
  const database = aws(["rds","describe-db-instances","--region",APP_ONLY.region,"--db-instance-identifier",B01_PREREQUISITE.databaseIdentifier]).DBInstances?.[0];
  assert.equal(database?.DBInstanceIdentifier, B01_PREREQUISITE.databaseIdentifier); assert.equal(database?.DBInstanceStatus, "available");
  const databaseHostname = database.Endpoint?.Address;
  const built = buildB01ExecutorInput({ deploymentSourceSha, databaseHostname, repositoryRoot });
  const definition = buildB01ExecutorDefinition(built.command);
  assertProtectedCheckout({ sourceSha: deploymentSourceSha, repositoryRoot });
  const registered = aws(["ecs","register-task-definition","--region",APP_ONLY.region,"--cli-input-json",JSON.stringify(definition)]).taskDefinition;
  const taskDefinitionArn = registered?.taskDefinitionArn; assert.match(taskDefinitionArn || "", new RegExp(`/${B01_PREREQUISITE.executorFamily}:[1-9][0-9]*$`));
  const readback = aws(["ecs","describe-task-definition","--region",APP_ONLY.region,"--task-definition",taskDefinitionArn,"--include","TAGS"]);
  assertEcsTaskDefinitionReadback({ definition: { ...readback.taskDefinition, tags: readback.tags || [] }, taskDefinitionArn, expected: definition, label: "B01 prerequisite" });
  const launched = aws(["ecs","run-task","--region",APP_ONLY.region,"--cli-input-json",JSON.stringify({ cluster: APP_ONLY.clusterArn, taskDefinition: taskDefinitionArn,
    launchType: "FARGATE", count: 1, enableExecuteCommand: false, clientToken: canonicalSha256({ deploymentSourceSha, taskDefinitionArn }), networkConfiguration: appOnlyVerifierNetwork() })]);
  assert.deepEqual(launched.failures || [], []); assert.equal(launched.tasks?.length, 1); const taskArn = launched.tasks[0].taskArn;
  let task; for (let attempt = 0; attempt < 60; attempt++) { const response = aws(["ecs","describe-tasks","--region",APP_ONLY.region,"--cluster",APP_ONLY.cluster,"--tasks",taskArn]); assert.deepEqual(response.failures || [], []); task = response.tasks?.[0]; if (task?.lastStatus === "STOPPED") break; await wait(5000); }
  assert.equal(task?.lastStatus, "STOPPED", "B01 prerequisite timed out; reconcile read-only and do not retry.");
  const stream = `b01-prerequisite/${B01_PREREQUISITE.executorContainer}/${taskArn.split("/").at(-1)}`; let message;
  for (let attempt = 0; attempt < 12 && !message; attempt++) { const logs = aws(["logs","get-log-events","--region",APP_ONLY.region,"--log-group-name",B01_PREREQUISITE.logGroup,"--log-stream-name",stream,"--start-from-head","--limit","10"]); if (logs.events?.length) { assert.equal(logs.events.length, 1); message = logs.events[0].message; } else await wait(5000); }
  assert.ok(message); assert.equal(task.containers?.[0]?.exitCode, 0); const result = authenticateB01Result(message, built.contract);
  const observedAt = now(), executedAt = new Date(result.executedAt); assert.ok(Number.isFinite(executedAt.getTime()) && observedAt.getTime() - executedAt.getTime() >= 0 && observedAt.getTime() - executedAt.getTime() < 5 * 60 * 1000);
  const receipt = buildB01PrerequisiteReceipt({ deploymentSourceSha, predecessorRlsIdentity: result.predecessorRlsIdentity,
    successorRlsIdentity: result.successorRlsIdentity, liveRlsIdentity: result.liveRlsIdentity, executorSourceSha256: built.contract.executorSourceSha256,
    executorContractSha256: built.contractSha256, executorCommandSha256: built.commandSha256, executionResult: result.status, writeCount: result.writeCount, taskArn, taskDefinitionArn, bridgeDiffAttestation,
    executedAt: executedAt.toISOString(), expiresAt: new Date(executedAt.getTime() + B01_PREREQUISITE.maxReceiptAgeMs).toISOString() });
  fs.writeFileSync(receiptOut, `${canonicalJson(receipt)}\n`, { mode: 0o600, flag: "wx" }); return receipt;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try { const { values } = parseArgs({ options: { "deployment-source-sha": { type: "string" }, "aws-profile": { type: "string" }, "receipt-out": { type: "string" } }, strict: true });
    const result = await applyProductionB01Prerequisite({ deploymentSourceSha: values["deployment-source-sha"], awsProfile: values["aws-profile"], receiptOut: values["receipt-out"] });
    process.stdout.write(`${JSON.stringify({ status: result.executionResult, receiptSha256: result.receiptSha256 })}\n`);
  } catch { process.stderr.write("Production B01 prerequisite failed closed; reconcile before any retry.\n"); process.exitCode = 1; }
}
