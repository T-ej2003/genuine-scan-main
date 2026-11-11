import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { assertSecurityRebaselineInventory } from "./production-security-rebaseline-inventory.mjs";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { PRINTING_ROUTINE_DELTA } from "./apply-production-printing-routine-delta.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const collections = ["routines", "tables", "policies", "schemas", "roles"];
const sha256 = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const identity = row => row.kind === "policies" ? `public.${row.identity}` : `${row.identity}:f`;
const scopePath = "scripts/aws/production-49-object-scope.json";
const reviewedScope = JSON.parse(fs.readFileSync(path.join(root, scopePath)));

export function buildProduction49ObjectPackage({ sourceSha, requirements, securityInventory, databaseIdentity, repositoryRoot = root }) {
  assertAppOnlyRequirements(requirements, { sourceSha, candidateSourceSha: sourceSha, repositoryRoot });
  assertSecurityRebaselineInventory(securityInventory, { protectedMainSha: sourceSha });
  assert.equal(securityInventory.kind, "PRODUCTION_SECURITY_REBASELINE_CANONICAL_INVENTORY");
  assert.equal(securityInventory.appOnlyRequirementsSha256, requirements.requirementsSha256);
  const scopeBytes = fs.readFileSync(path.join(repositoryRoot, scopePath));
  const scope = JSON.parse(scopeBytes);
  assert.equal(scope.kind, "PRODUCTION_RLS_49_OBJECT_SCOPE");
  assert.equal(scope.objects.length, 49);
  assert.equal(scope.objects.filter(row => row.kind === "routines").length, 7);
  assert.equal(scope.objects.filter(row => row.kind === "policies").length, 42);
  assert.equal(databaseIdentity?.DBInstanceIdentifier, scope.databaseInstance);
  assert.equal(databaseIdentity?.DbiResourceId, scope.databaseResourceId);
  assert.equal(databaseIdentity?.DBInstanceArn, "arn:aws:rds:eu-west-2:368992683803:db:" + scope.databaseInstance);
  assert.equal(databaseIdentity?.EngineVersion, "18.4");
  assert.equal(databaseIdentity?.DBInstanceStatus, "available");
  assert.equal(databaseIdentity?.Endpoint?.Port, 5432);
  assert.match(databaseIdentity?.Endpoint?.Address ?? "", /^[a-z0-9.-]+\.rds\.amazonaws\.com$/);
  const scopeKeys = new Set(scope.objects.map(row => `${row.kind}:${row.identity}`));
  assert.equal(scopeKeys.size, 49);
  const canonical = new Map(securityInventory.objects.map(row => [`${row.collection}:${row.identity}`, row.fields]));
  const predecessor = structuredClone(requirements.objects);
  const targets = Object.fromEntries(collections.map(name => [name, new Map(requirements.objects[name].map(row => [row.identity, row.sha256]))]));
  const auth = [], schemaRoutines = [], policies = [];
  for (const row of scope.objects) {
    assert.ok(["routines", "policies"].includes(row.kind));
    assert.match(row.predecessorHash ?? "", /^(?:|[a-f0-9]{64})$/);
    assert.match(row.targetHash, /^[a-f0-9]{64}$/);
    assert.equal(targets[row.kind].get(row.identity), row.targetHash, `Canonical target changed: ${row.identity}`);
    const index = predecessor[row.kind].findIndex(item => item.identity === row.identity);
    assert.ok(index >= 0);
    if (row.predecessorHash === null) predecessor[row.kind].splice(index, 1);
    else predecessor[row.kind][index].sha256 = row.predecessorHash;
    const fields = canonical.get(`${row.kind}:${identity(row)}`);
    assert.ok(fields, `Canonical security definition absent: ${row.identity}`);
    if (row.kind === "routines") {
      assert.equal(fields.owner, row.owner);
      assert.match(row.identity, /^app_rls\.[a-z_]+\(/);
      assert.ok(fields.definition.startsWith(`CREATE OR REPLACE FUNCTION ${row.identity.slice(0, row.identity.indexOf("("))}(`));
      if (row.owner === "mscqr_prd_rls_phase2_auth_owner") {
        auth.push({ sql: fields.definition, identity: row.identity });
        if (row.predecessorHash === null) {
          assert.equal(row.identity, "app_rls.operational_read_session_deadline()");
          auth.push({ sql: "REVOKE ALL ON FUNCTION app_rls.operational_read_session_deadline() FROM PUBLIC", identity: row.identity });
        }
      }
      schemaRoutines.push(...(row.owner === "mscqr_prd_rls_phase2_owner" ? [{ sql: fields.definition, identity: row.identity }] : []));
    } else {
      assert.equal(row.owner, "mscqr_prd_rls_phase2_owner");
      assert.match(row.identity, /^[A-Za-z][A-Za-z0-9_]*\.[a-z][a-z0-9_]*$/);
      assert.equal(fields.permissive, true);
      const [table, name] = row.identity.split(".");
      const clauses = [];
      if (fields.using !== null) clauses.push(`USING (${fields.using})`);
      if (fields.check !== null) clauses.push(`WITH CHECK (${fields.check})`);
      assert.ok(clauses.length > 0);
      policies.push({ identity: row.identity, sql: `ALTER POLICY "${name}" ON public."${table}" ${clauses.join(" ")}` });
    }
  }
  assert.equal(auth.length + schemaRoutines.length + policies.length, 50);
  assert.equal(auth.length, 5);
  assert.equal(schemaRoutines.length, 3);
  assert.equal(policies.length, 42);
  for (const name of collections) predecessor[name].sort((a, b) => a.identity.localeCompare(b.identity));
  const digest = objects => Object.fromEntries(collections.map(name => [name, canonicalSha256(objects[name])]));
  const mutations = [...auth.map(row => ({ ...row, owner: "auth" })),
    ...schemaRoutines.map(row => ({ ...row, owner: "schema" })), ...policies.map(row => ({ ...row, owner: "schema" }))];
  const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_49_OBJECT_INCREMENTAL_PACKAGE", sourceSha,
    requirementsSha256: requirements.requirementsSha256, securityInventorySha256: securityInventory.artifactSha256,
    scopeSha256: sha256(scopeBytes), database: "mscqr_production_rls_green_phase2",
    databaseInstance: scope.databaseInstance, databaseResourceId: scope.databaseResourceId,
    databaseHostname: databaseIdentity.Endpoint.Address,
    predecessorCatalogue: digest(predecessor), successorCatalogue: digest(requirements.objects),
    sqlSha256: sha256(mutations.map(row => row.sql.trimEnd().replace(/;$/, "")).join(";\n") + ";\n"), mutations };
  assert.equal(body.sqlSha256, scope.sqlSha256, "Incremental SQL differs from reviewed 49-object scope");
  assert.deepEqual(body.predecessorCatalogue, scope.predecessorCatalogue, "Predecessor catalogue differs from reviewed scope");
  assert.deepEqual(body.successorCatalogue, scope.successorCatalogue, "Successor catalogue differs from reviewed scope");
  return Object.freeze({ ...body, packageSha256: canonicalSha256(body) });
}

export function buildProduction49TaskDefinition({ package: pkg, backendImage }) {
  assert.match(backendImage ?? "", new RegExp(`^${APP_ONLY.backendRepository.replaceAll(".", "\\.")}@sha256:[a-f0-9]{64}$`));
  assert.equal(pkg?.kind, "PRODUCTION_RLS_49_OBJECT_INCREMENTAL_PACKAGE");
  assert.equal(pkg?.scopeSha256, sha256(fs.readFileSync(path.join(root, scopePath))));
  assert.equal(pkg?.sqlSha256, reviewedScope.sqlSha256);
  const bytes = Buffer.from(canonicalJson(pkg) + "\n");
  assert.ok(bytes.length < 256 * 1024);
  const encoded = gzipSync(bytes).toString("base64");
  assert.ok(encoded.length <= 32768);
  const definition = {
    family: "mscqr-production-rls-49-object", networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"],
    cpu: "1024", memory: "2048", executionRoleArn: PRINTING_ROUTINE_DELTA.executionRoleArn,
    runtimePlatform: STAGE_B.taskRuntimePlatform, volumes: [{ name: "executor-tmp" }],
    containerDefinitions: [{ name: "production-rls-49-object", image: backendImage, essential: true,
      entryPoint: ["node"], command: ["/app/scripts/aws/production-49-object-executor.cjs", encoded, sha256(bytes), pkg.databaseHostname],
      readonlyRootFilesystem: true, mountPoints: [{ sourceVolume: "executor-tmp", containerPath: "/tmp", readOnly: false }],
      privileged: false, interactive: false, pseudoTerminal: false,
      environment: [{ name: "NODE_ENV", value: "production" }],
      secrets: [{ name: "MSCQR_RLS_49_ADMIN_PASSWORD", valueFrom: PRINTING_ROUTINE_DELTA.administratorSecretArn }],
      logConfiguration: { logDriver: "awslogs", options: { "awslogs-region": APP_ONLY.region,
        "awslogs-group": PRINTING_ROUTINE_DELTA.logGroup, "awslogs-stream-prefix": "rls-49-object" } },
    }],
  };
  assert.ok(Buffer.byteLength(JSON.stringify(definition)) <= 60 * 1024, "ECS task definition exceeds safe transport budget");
  return Object.freeze({ definition, taskDefinitionSha256: canonicalSha256(definition), payloadSha256: sha256(bytes) });
}

export function authenticateProduction49Result(message, pkg) {
  assert.ok(typeof message === "string" && Buffer.byteLength(message) < 4096);
  const result = JSON.parse(message);
  const { evidenceSha256, ...body } = result;
  assert.deepEqual(Object.keys(result).sort(), ["schemaVersion", "kind", "sourceSha", "packageSha256", "sqlSha256",
    "database", "databaseRole", "successorCatalogue", "status", "writeCount", "evidenceSha256"].sort());
  assert.equal(evidenceSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1);
  assert.equal(body.kind, "PRODUCTION_RLS_49_OBJECT_RESULT");
  assert.equal(body.sourceSha, pkg.sourceSha);
  assert.equal(body.packageSha256, pkg.packageSha256);
  assert.equal(body.sqlSha256, reviewedScope.sqlSha256);
  assert.equal(body.database, pkg.database);
  assert.equal(body.databaseRole, "mscqr_prod_admin");
  assert.deepEqual(body.successorCatalogue, reviewedScope.successorCatalogue);
  assert.ok(body.status === "APPLIED" && body.writeCount === 50
    || body.status === "ALREADY_CONVERGED" && body.writeCount === 0);
  return result;
}
