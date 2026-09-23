"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { gunzipSync } = require("node:zlib");

const FAILURE_STAGES = Object.freeze(["BOOTSTRAP","INPUT_AUTHENTICATION","SECRET_ACCESS","DATABASE_CONNECTIVITY","PREDECESSOR_COLLECTION","PREDECESSOR_CLASSIFICATION","TRANSACTION_BEGIN","AUTHORIZED_MUTATION","SUCCESSOR_COLLECTION","SUCCESSOR_CLASSIFICATION","COMMIT","RECEIPT_PRECONDITION"]);

const EXPECTED_MUTATIONS = Object.freeze({
  "bind-predecessor": "72622e72f55b190c36823cd236d98209c4774d3224b902d3891da9991555ffea",
  finalizer: "dda320f80d84478ecf8dea8544456cf203e8ae5f5d27be7c533456c8ef3ffe14",
  "public-revoke": "ea6bc8043988af5a3341c999cc999293b8db7154507a33da755d5bd3ee379bb6",
  "preauth-execute": ["47513f79", "613c902a", "cf12b609", "48a04231", "01a3186c", "a903b0cc", "dad32cc0", "7e4bcf1d"].join(""),
  "payload-select": "75c30a501ecb6b5245350c6fd8814389143c838a686b539a0dfa59627b311b0c",
  "select-policy": "6918201a91575d6d350bb305c6914aaaddc8d874a05ef70c39197ee6e0c1cb41",
  "select-policy-comment": "15ed39f488602730bf3b7a99c0d81a13770babe48c9a8755dea68007dc0d7586",
});
// B01_CATALOGUE_START
const ORIGIN = "0f7ae1a70eec588ef4fdcb2b53e9f42e831c4414";
const ADMIN = ["mscqr", "prod", "admin"].join("_");
const OWNER = ["mscqr", "prd", "rls", "phase2", "auth", "owner"].join("_");
const SCHEMA_OWNER = ["mscqr", "prd", "rls", "phase2", "owner"].join("_");
const PREAUTH = ["mscqr", "prd", "rls", "phase2", "preauth"].join("_");
const DATABASE = ["mscqr", "production", "rls", "green", "phase2"].join("_");
const canonicalJson = (value) => Array.isArray(value) ? `[${value.map(canonicalJson).join(",")}]`
  : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}` : JSON.stringify(value);
const hash = (value) => crypto.createHash("sha256").update(typeof value === "string" || Buffer.isBuffer(value) ? value : canonicalJson(value)).digest("hex");

async function collectB01State(tx) {
  await tx.$executeRawUnsafe("SET LOCAL search_path = pg_catalog");
  const [identity] = await tx.$queryRawUnsafe(`SELECT current_user AS role,session_user AS session_role,current_database() AS database,
    current_setting('transaction_read_only') AS read_only,current_setting('server_version_num')::integer/10000 AS server_major,
    r.rolcanlogin,r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolbypassrls
    FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
  const roles = await tx.$queryRawUnsafe(`SELECT rolname AS name,rolcanlogin AS login,rolsuper AS superuser,rolinherit AS inherit,
    rolcreaterole AS create_role,rolcreatedb AS create_database,rolreplication AS replication,rolbypassrls AS bypass_rls
    FROM pg_catalog.pg_roles WHERE rolname IN ('${OWNER}','${SCHEMA_OWNER}','${PREAUTH}') ORDER BY rolname`);
  const functions = await tx.$queryRawUnsafe(`SELECT p.proname AS name,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,
    o.rolname AS owner,l.lanname AS language,pg_catalog.pg_get_function_result(p.oid) AS result,p.prokind::text AS kind,
    p.prosecdef AS security_definer,p.proleakproof AS leakproof,p.proisstrict AS strict,p.provolatile::text AS volatility,
    p.proparallel::text AS parallel,p.proconfig,p.prosrc AS body,
    EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
      WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') AS public_execute,
    pg_catalog.has_function_privilege('${PREAUTH}',p.oid,'EXECUTE') AS preauth_execute,
    ARRAY(SELECT pg_catalog.format('%s|%s|%s|%s',COALESCE(g.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable)
      FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
      LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=acl.grantor ORDER BY 1) AS acl
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_roles o ON o.oid=p.proowner
    JOIN pg_catalog.pg_language l ON l.oid=p.prolang
    WHERE n.nspname='app_auth' AND p.proname IN ('b01_bind_predecessor','finalize_refresh_token_rotation') ORDER BY p.proname`);
  const policies = await tx.$queryRawUnsafe(`SELECT n.nspname AS schema,c.relname AS "table",p.polname AS name,
    p.polcmd::text AS command,p.polpermissive AS permissive,
    ARRAY(SELECT COALESCE(r.rolname,'PUBLIC') FROM unnest(p.polroles) x LEFT JOIN pg_catalog.pg_roles r ON r.oid=x ORDER BY 1) AS roles,
    pg_catalog.pg_get_expr(p.polqual,p.polrelid) AS "using",pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) AS "with_check",
    pg_catalog.obj_description(p.oid,'pg_policy') AS comment
    FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND p.polname LIKE 'b01\\_%' ESCAPE '\\' ORDER BY c.relname,p.polname`);
  const [catalogue] = await tx.$queryRawUnsafe(`SELECT c.relrowsecurity AS rls,c.relforcerowsecurity AS forced,o.rolname AS table_owner,
    s.rolname AS schema_owner,pg_catalog.pg_has_role(current_user,'${OWNER}','SET') AS owner_set,
    pg_catalog.pg_has_role(current_user,'${SCHEMA_OWNER}','SET') AS schema_owner_set,
    ARRAY(SELECT pg_catalog.format('%s|%s|%s|%s',COALESCE(g.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable)
      FROM pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
      LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=acl.grantor ORDER BY 1) AS table_acl,
    EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
      JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee WHERE a.attrelid=c.oid AND a.attname='payload'
      AND g.rolname='${OWNER}' AND acl.privilege_type='SELECT') AS payload_column_select,
    ARRAY(SELECT pg_catalog.format('%s|%s|%s|%s',COALESCE(g.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable)
      FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
      LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee JOIN pg_catalog.pg_roles grantor ON grantor.oid=acl.grantor
      WHERE a.attrelid=c.oid AND a.attname='payload' ORDER BY 1) AS payload_column_acl
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_catalog.pg_roles o ON o.oid=c.relowner JOIN pg_catalog.pg_namespace an ON an.nspname='app_auth'
    JOIN pg_catalog.pg_roles s ON s.oid=an.nspowner WHERE n.nspname='public' AND c.relname='AuditLogOutbox'`);
  return { identity, roles, functions, policies: policies.map(({ using: usingExpression, with_check: checkExpression, ...policy }) => ({
    ...policy,
    using_sha256: usingExpression === null ? null : hash(usingExpression),
    with_check_sha256: checkExpression === null ? null : hash(checkExpression),
  })), catalogue };
}

function authenticateIdentity(identity, readOnly = "off") {
  assert.deepEqual(identity, { role: ADMIN, session_role: ADMIN, database: DATABASE, read_only: readOnly, server_major: 18, rolcanlogin: true,
    rolsuper: false, rolinherit: false, rolcreaterole: true, rolcreatedb: true, rolreplication: false, rolbypassrls: false });
}

function inspectB01State(state, contract, readOnly = "off") {
  authenticateIdentity(state.identity, readOnly);
  assert.equal(state.catalogue?.rls, true); assert.equal(state.catalogue?.forced, true);
  assert.equal(state.catalogue?.table_owner, SCHEMA_OWNER); assert.equal(state.catalogue?.schema_owner, OWNER);
  assert.equal(state.catalogue?.owner_set, true); assert.equal(state.catalogue?.schema_owner_set, true);
  const identity = hash({ roles: state.roles, functions: state.functions, policies: state.policies, catalogue: state.catalogue });
  if (identity === contract.successorRlsIdentity) return { classification: "SUCCESSOR", identity };
  if (identity === contract.predecessorRlsIdentity) return { classification: "PREDECESSOR", identity };
  return { classification: "PARTIAL", identity };
}

function classify(state, contract, readOnly = "off") {
  const result = inspectB01State(state, contract, readOnly);
  if (result.classification !== "PARTIAL") return result.classification;
  throw new Error("Live B01 catalogue is neither the exact predecessor nor successor.");
}
// B01_CATALOGUE_END

async function executeB01Transaction({ tx, input, collect = collectB01State, checkpoint = async () => {}, stage = () => {} }) {
  assert.equal(input.contract.rlsDeltaOriginSha, ORIGIN);
  assert.equal(input.contract.migrationSetDigest, "6642442a81cd98c7a132d241fa98e50ae231510896c9da67ab70d86b050d02db");
  assert.equal(input.contract.mutations.length, 7);
  assert.deepEqual(input.contract.mutations.map(({ name }) => name), ["bind-predecessor","finalizer","public-revoke","preauth-execute","payload-select","select-policy","select-policy-comment"]);
  for (const mutation of input.contract.mutations) { assert.equal(hash(mutation.sql), mutation.sha256); assert.equal(mutation.sha256, EXPECTED_MUTATIONS[mutation.name]); }
  await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
  await tx.$executeRawUnsafe("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('mscqr-production-b01-prerequisite',0))");
  stage("PREDECESSOR_COLLECTION"); const before = await collect(tx);
  stage("PREDECESSOR_CLASSIFICATION"); const state = classify(before, input.contract);
  if (state === "SUCCESSOR") { stage("COMMIT"); return { status: "ALREADY_CONVERGED", writeCount: 0, predecessorRlsIdentity: input.contract.predecessorRlsIdentity, successorRlsIdentity: input.contract.successorRlsIdentity, liveRlsIdentity: input.contract.successorRlsIdentity }; }
  stage("AUTHORIZED_MUTATION");
  await tx.$executeRawUnsafe(`SET LOCAL ROLE ${OWNER}`);
  for (const mutation of input.contract.mutations.slice(0, 4)) { await tx.$executeRawUnsafe(mutation.sql); await checkpoint(mutation.name); }
  await tx.$executeRawUnsafe("RESET ROLE");
  await tx.$executeRawUnsafe(`SET LOCAL ROLE ${SCHEMA_OWNER}`);
  for (const mutation of input.contract.mutations.slice(4)) { await tx.$executeRawUnsafe(mutation.sql); await checkpoint(mutation.name); }
  await tx.$executeRawUnsafe("RESET ROLE");
  stage("SUCCESSOR_COLLECTION"); const after = await collect(tx);
  stage("SUCCESSOR_CLASSIFICATION"); assert.equal(classify(after, input.contract), "SUCCESSOR");
  stage("COMMIT");
  return { status: "APPLIED", writeCount: 7, predecessorRlsIdentity: input.contract.predecessorRlsIdentity, successorRlsIdentity: input.contract.successorRlsIdentity, liveRlsIdentity: input.contract.successorRlsIdentity };
}

function safeFailure(stage, error) {
  assert.ok(FAILURE_STAGES.includes(stage));
  const prismaCode = typeof error?.code === "string" && /^(?:P1000|P1001|P1002|P1010|P1011|P1017)$/.test(error.code) ? error.code : null;
  return { status: "PRODUCTION_B01_PREREQUISITE_FAILED", stage, code: prismaCode || (error?.name === "AssertionError" ? "CONTRACT_REJECTED" : "UNEXPECTED_FAILURE") };
}

function decode(value, digest) {
  assert.match(value || "", /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
  const bytes = gunzipSync(Buffer.from(value, "base64"), { maxOutputLength: 128 * 1024 }); assert.equal(hash(bytes), digest);
  const parsed = JSON.parse(bytes); assert.equal(canonicalJson(parsed), bytes.toString("utf8")); return parsed;
}

async function main(argv = process.argv.slice(2)) {
  let client, stage = "BOOTSTRAP"; try {
    stage = "INPUT_AUTHENTICATION";
    assert.equal(argv.length, 2); const envelope = decode(argv[0], argv[1]);
    assert.equal(hash(envelope.contract), envelope.contractSha256);
    assert.equal(hash(process.execArgv[1] || ""), envelope.contract.executorSourceSha256);
    assert.equal(envelope.contract.sourceContractSha256, "099399a7d3f4b2392acdba6c54bf1ac6a919ff60691e69d31023d32161d99e71");
    const { PrismaClient } = require("@prisma/client"); stage = "SECRET_ACCESS";
    assert.ok(typeof process.env.MSCQR_B01_PREREQUISITE_ADMIN_PASSWORD === "string" && process.env.MSCQR_B01_PREREQUISITE_ADMIN_PASSWORD.length > 0);
    const url = new URL(`postgresql://${ADMIN}:${encodeURIComponent(process.env.MSCQR_B01_PREREQUISITE_ADMIN_PASSWORD || "")}@${envelope.databaseHostname}:5432/${DATABASE}`);
    url.searchParams.set("sslmode", "require"); url.searchParams.set("application_name", "mscqr-production-b01-prerequisite");
    client = new PrismaClient({ datasources: { db: { url: url.toString() } } });
    stage = "DATABASE_CONNECTIVITY"; await client.$connect();
    stage = "TRANSACTION_BEGIN";
    const result = await client.$transaction((tx) => executeB01Transaction({ tx, input: envelope, stage: (value) => { stage = value; } }), { maxWait: 5000, timeout: 60000 });
    stage = "COMMIT";
    const body = { schemaVersion: 1, kind: "PRODUCTION_B01_PREREQUISITE_RESULT", rlsDeltaOriginSha: ORIGIN,
      contractSha256: envelope.contractSha256, executedAt: new Date().toISOString(), ...result };
    stage = "RECEIPT_PRECONDITION"; process.stdout.write(`${JSON.stringify({ ...body, evidenceSha256: hash(body) })}\n`);
  } catch (error) { process.stderr.write(`${JSON.stringify(safeFailure(stage, error))}\n`); process.exitCode = 1; }
  finally { if (client) try { await client.$disconnect(); } catch {} }
}

module.exports = { collectB01State, executeB01Transaction, inspectB01State, classify, canonicalJson, hash, safeFailure, FAILURE_STAGES };
if (module.id === "[eval]") main(process.argv.slice(1));
