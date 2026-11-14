import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { assertSecurityRebaselineInventory } from "./production-security-rebaseline-inventory.mjs";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { PRINTING_ROUTINE_DELTA } from "./apply-production-printing-routine-delta.mjs";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const collections = ["routines", "tables", "policies", "schemas", "roles"];
const predecessorCatalogue = Object.freeze({
  routines: "c6bbc2c99b6ce13261215ee82f14a8b445a584111a877a47fe547770ca7fa3d3",
  tables: "9546a7a6cd84651fc0b0387470d3847f269d6ecb4497cd0a0a97b0494525de63",
  policies: "55a55c5e731e5afdd8d94a83eb3f107f9385ee6e04bb16290398ac441593fe67",
  schemas: "d18a09f2eb4608c1267c78d20c5a7cede0c9fe5dda622ee2f4ea7f4e91aebb0c",
  roles: "8b635d92ee484fc217fb651d6b1bf7fdfd02d23a0fee964a8092ee3050fd7023",
});
const predecessorHashes = Object.freeze({
  "app_rls.printing_readiness(p_capability text, p_purpose text, p_request_id text, p_operation text, p_subject_id text, p_options jsonb)": "78b2049bd8ffa509d0abda3fe1088f8dcab8e01797f7978a01106a7202933f8d",
  "app_rls.printing_reissue_request(p_capability text, p_purpose text, p_request_id text, p_operation text, p_reissue_id text, p_original_job_id text, p_quantity integer, p_range_start text, p_range_end text, p_reason text, p_decision_note text)": "1d5ce67f31e33c0d4081b729a0f49e0a168ffab960669c0ead05779be54468f7",
  "app_rls.printing_worker_reconcile(p_operation text, p_request_id text, p_limit integer)": "6acac67a6886f9899d9a8d18dde525e7302a2a6658af8d4cee7d0d7e5da5f483",
});
const oldTables = Object.freeze({
  PrintItemEvent: "066b6a03b401f329a4c1da214d1c786bc87d54fe0dbb40d0b7b5c50cda16e428",
  PrintJobChunk: "49d0bedb77bd050609dbdbfdd6f7376b17801aa869f955ebca2cc35396ff91a8",
});
const oldBatchPolicy = "764a271df741518e5617e1e8160de04ef22e40eb96ac29fc5ec564184e3355fb";
const batchPolicy = "Batch.printing_lifecycle_batch_update";
const newPolicies = ["PrintItemEvent.printing_lifecycle_printitemevent_select", "PrintJobChunk.printing_lifecycle_printjobchunk_select"];
const names = ["printing_readiness", "printing_reissue_request", "printing_worker_reconcile"];
const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");
const digests = objects => Object.fromEntries(collections.map(name => [name, canonicalSha256(objects[name])]));

export function buildProductionPrintingRestorationPackage({ sourceSha, requirements, securityInventory, databaseIdentity, repositoryRoot = root }) {
  assertAppOnlyRequirements(requirements, { sourceSha, candidateSourceSha: sourceSha, repositoryRoot });
  assertSecurityRebaselineInventory(securityInventory, { protectedMainSha: sourceSha });
  assert.equal(securityInventory.appOnlyRequirementsSha256, requirements.requirementsSha256);
  assert.equal(databaseIdentity?.DBInstanceIdentifier, "mscqr-production-rls-green-phase2");
  assert.equal(databaseIdentity?.DbiResourceId, "db-3C27FYJOJ2IY27X7QGQG5YB4IM");
  assert.equal(databaseIdentity?.EngineVersion, "18.4");
  assert.equal(databaseIdentity?.DBInstanceStatus, "available");
  assert.equal(databaseIdentity?.Endpoint?.Port, 5432);
  assert.match(databaseIdentity?.Endpoint?.Address ?? "", /^[a-z0-9.-]+\.rds\.amazonaws\.com$/);

  const predecessor = structuredClone(requirements.objects);
  for (const [collection, hashes] of [["routines", predecessorHashes], ["tables", oldTables]]) {
    for (const [identity, hash] of Object.entries(hashes)) {
      const row = predecessor[collection].find(item => item.identity === identity);
      assert.ok(row && row.sha256 !== hash, `Expected changed ${collection}: ${identity}`);
      row.sha256 = hash;
    }
  }
  predecessor.policies = predecessor.policies.filter(row => !newPolicies.includes(row.identity));
  assert.equal(requirements.objects.policies.length - predecessor.policies.length, 2);
  const priorBatch = predecessor.policies.find(row => row.identity === batchPolicy);
  assert.ok(priorBatch && priorBatch.sha256 !== oldBatchPolicy);
  priorBatch.sha256 = oldBatchPolicy;
  assert.deepEqual(digests(predecessor), predecessorCatalogue, "Unreviewed production predecessor difference");

  const canonical = new Map(securityInventory.objects.map(row => [`${row.collection}:${row.identity}`, row.fields]));
  const routines = Object.keys(predecessorHashes).map(identity => {
    const fields = canonical.get(`routines:${identity}:f`);
    assert.equal(fields?.owner, "mscqr_prd_rls_phase2_auth_owner");
    assert.equal(fields?.security_definer, true);
    assert.ok(fields?.definition?.startsWith(`CREATE OR REPLACE FUNCTION ${identity.slice(0, identity.indexOf("("))}(`));
    const grants = securityInventory.objects.filter(row => row.collection === "routineGrants"
      && JSON.parse(row.identity)[0] === `${identity}:f`).map(row => JSON.parse(row.identity)[2]).sort();
    assert.deepEqual(grants, identity.includes("printing_worker_reconcile")
      ? ["mscqr_prd_rls_phase2_auth_owner", "mscqr_prd_rls_phase2_worker"]
      : ["mscqr_prd_rls_phase2_app", "mscqr_prd_rls_phase2_auth_owner"]);
    return { identity, owner: "auth", sql: fields.definition };
  });
  const generated = relative => fs.readFileSync(path.join(repositoryRoot, relative), "utf8").split("\n");
  const grants = generated("scripts/rls/sql/generated/21-runtime-grants.sql")
    .filter(line => /^GRANT SELECT \(.+\) ON TABLE public\."(?:PrintItemEvent|PrintJobChunk)" TO "(?:mscqr_rls_cert_|mscqr_prd_rls_phase2_)auth_owner";$/.test(line))
    .map(line => line.replaceAll("mscqr_rls_cert_", "mscqr_prd_rls_phase2_"));
  assert.deepEqual(grants, [
    'GRANT SELECT ("printItemId") ON TABLE public."PrintItemEvent" TO "mscqr_prd_rls_phase2_auth_owner";',
    'GRANT SELECT ("printJobId", "printSessionId") ON TABLE public."PrintJobChunk" TO "mscqr_prd_rls_phase2_auth_owner";',
  ]);
  const lines = generated("scripts/rls/sql/generated/30-policies.sql");
  const policies = [batchPolicy, ...newPolicies].flatMap(identity => {
    const [table, name] = identity.split(".");
    const matches = lines.flatMap((line, index) => line.startsWith(`CREATE POLICY "${name}" ON public."${table}" `) ? [index] : []);
    assert.equal(matches.length, 1);
    assert.ok(lines[matches[0] + 1].startsWith(`COMMENT ON POLICY "${name}" ON public."${table}" IS `));
    return [...(identity === batchPolicy ? [`DROP POLICY "${name}" ON public."${table}"`] : []),
      ...lines.slice(matches[0], matches[0] + 2)].map(line => line.replaceAll("mscqr_rls_cert_", "mscqr_prd_rls_phase2_"));
  });
  const mutations = [...routines, ...grants.map(sql => ({ owner: "schema", sql })), ...policies.map(sql => ({ owner: "schema", sql }))];
  const sql = mutations.map(row => row.sql.trimEnd().replace(/;$/, "")).join(";\n") + ";\n";
  const body = { schemaVersion: 1, kind: "PRODUCTION_PRINTING_RESTORATION_DELTA", sourceSha,
    requirementsSha256: requirements.requirementsSha256, securityInventorySha256: securityInventory.artifactSha256,
    database: "mscqr_production_rls_green_phase2", databaseInstance: databaseIdentity.DBInstanceIdentifier,
    databaseResourceId: databaseIdentity.DbiResourceId, databaseHostname: databaseIdentity.Endpoint.Address,
    predecessorCatalogue, successorCatalogue: digests(requirements.objects), sqlSha256: sha256(sql), mutations };
  assert.deepEqual(routines.map(row => row.identity.split("(")[0].slice("app_rls.".length)), names);
  return Object.freeze({ ...body, packageSha256: canonicalSha256(body) });
}

export function buildProductionPrintingRestorationTaskDefinition({ package: pkg, backendImage }) {
  assert.match(backendImage ?? "", new RegExp(`^${APP_ONLY.backendRepository.replaceAll(".", "\\.")}@sha256:[a-f0-9]{64}$`));
  assert.equal(pkg?.kind, "PRODUCTION_PRINTING_RESTORATION_DELTA");
  const bytes = Buffer.from(canonicalJson(pkg) + "\n");
  assert.ok(bytes.length < 256 * 1024);
  const encoded = gzipSync(bytes).toString("base64");
  assert.ok(encoded.length <= 32768);
  const definition = { family: "mscqr-production-rls-seven-routine", networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"],
    cpu: "1024", memory: "2048", executionRoleArn: PRINTING_ROUTINE_DELTA.executionRoleArn,
    runtimePlatform: STAGE_B.taskRuntimePlatform, volumes: [{ name: "executor-tmp" }],
    containerDefinitions: [{ name: "production-printing-restoration", image: backendImage, essential: true,
      entryPoint: ["node"], command: ["/app/scripts/aws/production-printing-restoration-executor.cjs", encoded, sha256(bytes), pkg.databaseHostname],
      readonlyRootFilesystem: true, mountPoints: [{ sourceVolume: "executor-tmp", containerPath: "/tmp", readOnly: false }],
      privileged: false, interactive: false, pseudoTerminal: false,
      environment: [{ name: "NODE_ENV", value: "production" }, { name: "RELEASE_GIT_SHA", value: pkg.sourceSha }],
      secrets: [{ name: "MSCQR_RLS_SEVEN_ADMIN_PASSWORD", valueFrom: PRINTING_ROUTINE_DELTA.administratorSecretArn }],
      logConfiguration: { logDriver: "awslogs", options: { "awslogs-region": APP_ONLY.region,
        "awslogs-group": PRINTING_ROUTINE_DELTA.logGroup, "awslogs-stream-prefix": "printing-restoration" } },
    }] };
  assert.ok(Buffer.byteLength(JSON.stringify(definition)) <= 60 * 1024);
  return Object.freeze({ definition, taskDefinitionSha256: canonicalSha256(definition), payloadSha256: sha256(bytes) });
}
