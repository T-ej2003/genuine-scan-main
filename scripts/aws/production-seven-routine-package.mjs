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
const scopePath = "scripts/aws/production-seven-routine-scope.json";
const scopeBytes = fs.readFileSync(path.join(root, scopePath));
const scope = JSON.parse(scopeBytes);
const sha256 = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const collections = ["routines", "tables", "policies", "schemas", "roles"];
const catalogueDigest = objects => Object.fromEntries(collections.map(name => [name, canonicalSha256(objects[name])]));

export function buildProductionSevenRoutinePackage({ sourceSha, requirements, securityInventory, databaseIdentity, repositoryRoot = root }) {
  assertAppOnlyRequirements(requirements, { sourceSha, candidateSourceSha: sourceSha, repositoryRoot });
  assertSecurityRebaselineInventory(securityInventory, { protectedMainSha: sourceSha });
  assert.equal(securityInventory.appOnlyRequirementsSha256, requirements.requirementsSha256);
  assert.equal(scope.kind, "PRODUCTION_RLS_SEVEN_ROUTINE_SCOPE");
  assert.equal(scope.objects.length, 7);
  assert.equal(databaseIdentity?.DBInstanceIdentifier, scope.databaseInstance);
  assert.equal(databaseIdentity?.DbiResourceId, scope.databaseResourceId);
  assert.equal(databaseIdentity?.EngineVersion, "18.4");
  assert.equal(databaseIdentity?.DBInstanceStatus, "available");
  assert.equal(databaseIdentity?.Endpoint?.Port, 5432);
  assert.match(databaseIdentity?.Endpoint?.Address ?? "", /^[a-z0-9.-]+\.rds\.amazonaws\.com$/);
  assert.deepEqual(catalogueDigest(requirements.objects), scope.successorCatalogue);
  const canonical = new Map(securityInventory.objects.map(row => [`${row.collection}:${row.identity}`, row.fields]));
  const mutations = scope.objects.map(row => {
    const target = requirements.objects.routines.find(item => item.identity === row.identity);
    assert.equal(target?.sha256, row.targetHash, `Canonical target changed: ${row.identity}`);
    const fields = canonical.get(`routines:${row.identity}:f`);
    assert.equal(fields?.owner, row.owner);
    assert.equal(fields?.security_definer, row.owner === "mscqr_prd_rls_phase2_auth_owner");
    assert.ok(fields?.definition?.startsWith(`CREATE OR REPLACE FUNCTION ${row.identity.slice(0, row.identity.indexOf("("))}(`));
    assert.ok(fields.definition.length < 30000);
    const grants = securityInventory.objects.filter(item => item.collection === "routineGrants"
      && JSON.parse(item.identity)[0] === `${row.identity}:f`).map(item => JSON.parse(item.identity)[2]).sort();
    assert.deepEqual(grants, row.grants);
    assert.ok(!grants.includes("PUBLIC"));
    return { identity: row.identity, owner: row.owner === "mscqr_prd_rls_phase2_auth_owner" ? "auth" : "schema",
      sql: fields.definition };
  });
  assert.deepEqual(mutations.map(item => item.owner), ["auth", "auth", "auth", "auth", "auth", "schema", "schema"]);
  const sql = mutations.map(item => item.sql.trimEnd().replace(/;$/, "")).join(";\n") + ";\n";
  assert.equal(sha256(sql), scope.sqlSha256, "Seven-routine SQL differs from reviewed scope");
  const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_SEVEN_ROUTINE_PACKAGE", sourceSha,
    requirementsSha256: requirements.requirementsSha256, securityInventorySha256: securityInventory.artifactSha256,
    scopeSha256: sha256(scopeBytes), database: "mscqr_production_rls_green_phase2",
    databaseInstance: scope.databaseInstance, databaseResourceId: scope.databaseResourceId,
    databaseHostname: databaseIdentity.Endpoint.Address, predecessorCatalogue: scope.predecessorCatalogue,
    successorCatalogue: scope.successorCatalogue, sqlSha256: scope.sqlSha256, mutations };
  return Object.freeze({ ...body, packageSha256: canonicalSha256(body) });
}

export function buildProductionSevenRoutineTaskDefinition({ package: pkg, backendImage }) {
  assert.match(backendImage ?? "", new RegExp(`^${APP_ONLY.backendRepository.replaceAll(".", "\\.")}@sha256:[a-f0-9]{64}$`));
  assert.equal(pkg?.kind, "PRODUCTION_RLS_SEVEN_ROUTINE_PACKAGE");
  assert.equal(pkg?.scopeSha256, sha256(scopeBytes));
  assert.equal(pkg?.sqlSha256, scope.sqlSha256);
  const bytes = Buffer.from(canonicalJson(pkg) + "\n");
  assert.ok(bytes.length < 256 * 1024);
  const encoded = gzipSync(bytes).toString("base64");
  assert.ok(encoded.length <= 32768);
  const definition = { family: "mscqr-production-rls-seven-routine", networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"],
    cpu: "1024", memory: "2048", executionRoleArn: PRINTING_ROUTINE_DELTA.executionRoleArn,
    runtimePlatform: STAGE_B.taskRuntimePlatform, volumes: [{ name: "executor-tmp" }],
    containerDefinitions: [{ name: "production-rls-seven-routine", image: backendImage, essential: true,
      entryPoint: ["node"], command: ["/app/scripts/aws/production-seven-routine-executor.cjs", encoded, sha256(bytes), pkg.databaseHostname],
      readonlyRootFilesystem: true, mountPoints: [{ sourceVolume: "executor-tmp", containerPath: "/tmp", readOnly: false }],
      privileged: false, interactive: false, pseudoTerminal: false,
      environment: [{ name: "NODE_ENV", value: "production" }, { name: "RELEASE_GIT_SHA", value: pkg.sourceSha }],
      secrets: [{ name: "MSCQR_RLS_SEVEN_ADMIN_PASSWORD", valueFrom: PRINTING_ROUTINE_DELTA.administratorSecretArn }],
      logConfiguration: { logDriver: "awslogs", options: { "awslogs-region": APP_ONLY.region,
        "awslogs-group": PRINTING_ROUTINE_DELTA.logGroup, "awslogs-stream-prefix": "rls-seven-routine" } },
    }] };
  assert.ok(Buffer.byteLength(JSON.stringify(definition)) <= 60 * 1024);
  return Object.freeze({ definition, taskDefinitionSha256: canonicalSha256(definition), payloadSha256: sha256(bytes) });
}

export function authenticateProductionSevenRoutineResult(message, pkg) {
  assert.ok(typeof message === "string" && Buffer.byteLength(message) < 4096);
  const result = JSON.parse(message);
  const { evidenceSha256, ...body } = result;
  assert.equal(evidenceSha256, canonicalSha256(body));
  assert.deepEqual(Object.keys(result).sort(), ["schemaVersion", "kind", "sourceSha", "packageSha256", "sqlSha256",
    "database", "databaseRole", "successorCatalogue", "status", "writeCount", "evidenceSha256"].sort());
  assert.equal(body.schemaVersion, 1);
  assert.equal(body.kind, "PRODUCTION_RLS_SEVEN_ROUTINE_RESULT");
  assert.equal(body.sourceSha, pkg.sourceSha);
  assert.equal(body.packageSha256, pkg.packageSha256);
  assert.equal(body.sqlSha256, scope.sqlSha256);
  assert.equal(body.database, pkg.database);
  assert.equal(body.databaseRole, "mscqr_prod_admin");
  assert.deepEqual(body.successorCatalogue, scope.successorCatalogue);
  assert.ok(body.status === "APPLIED" && body.writeCount === 7 || body.status === "ALREADY_CONVERGED" && body.writeCount === 0);
  return result;
}
