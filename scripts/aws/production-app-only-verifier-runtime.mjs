#!/usr/bin/env node
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { inflateSync } from "node:zlib";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { compareCompactAppOnlyRequirements } from "./production-app-only-requirements-runtime.mjs";
import { collectAppOnlyDatabaseCatalogue } from "./production-app-only-database-verifier.mjs";
import { validateConfiguration } from "../../backend/scripts/production-read-only-database-config.mjs";

const CONTRACT_VERSION = "app-only-database-verifier-v1";
const REQUIREMENT_NAMES = ["policies", "roles", "routines", "schemas", "tables"];
const IDENTITY_FIELDS = ["account", "candidateDigest", "candidateSourceSha", "clusterArn", "databaseHostname", "predecessorBackendDigest", "predecessorTaskDefinition", "region", "serviceArn", "sourceSha", "verifierImageDigest"];
export function parseVerifierPayload(encoded) {
  assert.equal(typeof encoded, "string");
  assert.ok(encoded.length > 0 && encoded.length <= 48000);
  assert.match(encoded, /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
  const compressed = Buffer.from(encoded, "base64"); assert.equal(compressed.toString("base64"), encoded);
  const payload = JSON.parse(inflateSync(compressed, { maxOutputLength: 1024 * 1024 }).toString("utf8"));
  assert.deepEqual(Object.keys(payload).sort(), ["identity", "packedRequirementsSha256", "requirements", "verificationContractSha256"].sort());
  const { identity, packedRequirementsSha256, requirements, verificationContractSha256 } = payload;
  assert.deepEqual(Object.keys(identity).sort(), IDENTITY_FIELDS);
  for (const field of ["sourceSha", "candidateSourceSha"]) assert.match(identity[field] || "", /^[a-f0-9]{40}$/);
  for (const field of ["candidateDigest", "predecessorBackendDigest", "verifierImageDigest"]) assert.match(identity[field] || "", /^sha256:[a-f0-9]{64}$/);
  assert.match(identity.account || "", /^[0-9]{12}$/);
  assert.match(identity.region || "", /^[a-z]{2}-[a-z]+-[0-9]$/);
  assert.match(identity.clusterArn || "", /^arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:cluster\/[A-Za-z0-9_-]+$/);
  assert.match(identity.serviceArn || "", /^arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:service\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/);
  assert.match(identity.predecessorTaskDefinition || "", /^arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/);
  assert.match(identity.databaseHostname || "", /^[a-z0-9.-]{1,253}$/);
  assert.deepEqual(Object.keys(requirements).sort(), ["objects", "requirementsSha256"].sort());
  assert.match(requirements.requirementsSha256 || "", /^[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(requirements.objects || {}).sort(), REQUIREMENT_NAMES);
  for (const name of REQUIREMENT_NAMES) {
    const rows = requirements.objects[name];
    assert.deepEqual(Object.keys(rows || {}).sort(), ["identities", "sha256"]);
    assert.ok(Array.isArray(rows.identities) && rows.identities.length > 0 && rows.identities.length <= 2000);
    assert.ok(rows.identities.every((value) => typeof value === "string" && value.length > 0 && value.length <= 4096));
    assert.equal(new Set(rows.identities).size, rows.identities.length);
    assert.deepEqual(rows.identities, [...rows.identities].sort((a, b) => a.localeCompare(b)));
    assert.match(rows.sha256 || "", /^[a-f0-9]{64}$/);
  }
  assert.equal(packedRequirementsSha256, canonicalSha256(requirements));
  assert.equal(verificationContractSha256, canonicalSha256({ version: CONTRACT_VERSION,
    sourceSha: identity.sourceSha, candidateSourceSha: identity.candidateSourceSha,
    requirementsSha256: requirements.requirementsSha256 }));
  return payload;
}

export async function runAppOnlyVerifier({ payload, env = process.env, createClient, write = (line) => process.stdout.write(`${line}\n`), now = () => new Date().toISOString() }) {
  let client, phase = "CONFIGURATION";
  try {
    // macOS injects this process-local encoding hint; it is not a task input.
    const { ECS_AGENT_URI: ecsAgentUri, ...validationEnv } = env;
    delete validationEnv.__CF_USER_TEXT_ENCODING;
    if (ecsAgentUri) assert.match(ecsAgentUri, /^http:\/\/169\.254\.170\.2\/api\/[^?#]+$/);
    const url = validateConfiguration({ env: validationEnv, argv: [] });
    assert.equal(new URL(url).hostname, payload.identity.databaseHostname);
    if (!createClient) {
      const { PrismaClient } = createRequire(path.join(process.cwd(), "package.json"))("@prisma/client");
      createClient = (databaseUrl) => new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    }
    client = createClient(url);
    phase = "CATALOGUE";
    const catalogue = await collectAppOnlyDatabaseCatalogue(client);
    phase = "COMPARISON";
    const domains = compareCompactAppOnlyRequirements(catalogue, payload.requirements);
    const evidence = { schemaVersion: 1, kind: "APP_ONLY_DATABASE_COMPATIBILITY", identity: payload.identity,
      generatedAt: now(), verificationContractSha256: payload.verificationContractSha256,
      requirementsSha256: payload.requirements.requirementsSha256, domains };
    write(JSON.stringify({ ...evidence, evidenceSha256: canonicalSha256(evidence) }));
    if (!Object.values(domains).every((value) => value === "COMPATIBLE")) process.exitCode = 1;
    return evidence;
  } catch {
    write(JSON.stringify({ status: "APP_ONLY_DATABASE_VERIFICATION_FAILED", phase }));
    process.exitCode = 1;
    return null;
  } finally { await client?.$disconnect(); }
}

if (import.meta.url === new URL(process.argv[1] || "", "file:").href) {
  try {
    assert.deepEqual(process.argv.slice(2, 3), ["--payload"]);
    assert.equal(process.argv.length, 4);
    await runAppOnlyVerifier({ payload: parseVerifierPayload(process.argv[3]) });
  } catch {
    process.stdout.write(`${JSON.stringify({ status: "APP_ONLY_DATABASE_VERIFICATION_FAILED", phase: "INPUT" })}\n`);
    process.exitCode = 1;
  }
}
