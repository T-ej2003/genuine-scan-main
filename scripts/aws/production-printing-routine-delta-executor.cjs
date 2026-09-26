"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { gunzipSync, inflateRawSync } = require("node:zlib");

const administrator = "mscqr_prod_admin";
const ownerRole = "mscqr_prd_rls_phase2_auth_owner";
const schemaOwnerRole = "mscqr_prd_rls_phase2_owner";
const database = "mscqr_production_rls_green_phase2";
const collections = Object.freeze(["routines", "tables", "policies", "schemas", "roles"]);
const expectedRoutines = Object.freeze(["printing_readiness", "printing_create_job", "printing_connector_identity"]);
const subscriptionProjection = Object.freeze({ owner: "mscqr_prod_subscription_observer", bodySha256: "0bdb8cc2687ed93da82dec724ecb2350f048b2fb9b8b5f4ccd5bbf31085c7958",
  result: 'TABLE(subscription_name text, subscription_owner text, enabled boolean, "binary" boolean, streaming text, two_phase text, disable_on_error boolean, password_required boolean, run_as_owner boolean, failover boolean, slot_name text, synchronous_commit text, publications text[], origin text, connection_info_sha256 text)' });
const expectedPredecessors = Object.freeze({
  "app_rls.printing_connector_identity(p_kind text, p_agent_id text, p_device_fingerprint text, p_printer_selector text, p_gateway_id text, p_gateway_secret_hash text, p_operation text)": "aec14f16d5bf85cc48809a63d3e1a34c8a35c0eb51ac1f46899cfc05a24673b1",
  "app_rls.printing_create_job(p_capability text, p_purpose text, p_request_id text, p_batch_id text, p_printer_id text, p_quantity integer, p_range_start text, p_range_end text, p_print_mode text, p_payload_type text, p_print_lock_token_hash text, p_items jsonb)": "fafcc5b92873b51b786cf937b834f7991bc2eda8ba00b8d5e5a618edd2b1bd1c",
  "app_rls.printing_readiness(p_capability text, p_purpose text, p_request_id text, p_operation text, p_subject_id text, p_options jsonb)": "780215b4db85c6561e7ce8529838f15d72ce4d78f19507078d2e02f8f7e07f83",
});
const classification = Object.freeze({ MATCH: "MATCH", EXPECTED: "EXPECTED_THREE_ROUTINE_DELTA_ONLY", UNEXPECTED: "UNEXPECTED_DRIFT" });
const stages = Object.freeze({
  ARGV_VALIDATION: "ARGV_VALIDATION", TRANSPORT_VALIDATION: "TRANSPORT_VALIDATION", PAYLOAD_DECOMPRESSION: "PAYLOAD_DECOMPRESSION",
  PAYLOAD_AUTHENTICATION: "PAYLOAD_AUTHENTICATION", CONTRACT_AUTHENTICATION: "CONTRACT_AUTHENTICATION", SECRET_VALIDATION: "SECRET_VALIDATION",
  DATABASE_URL_CONSTRUCTION: "DATABASE_URL_CONSTRUCTION", PRISMA_INITIALIZATION: "PRISMA_INITIALIZATION", TRANSACTION_START: "TRANSACTION_START",
  TRANSACTION_SETUP: "TRANSACTION_SETUP",
  DATABASE_IDENTITY_AUTHENTICATION: "DATABASE_IDENTITY_AUTHENTICATION", PREDECESSOR_COLLECTION: "PREDECESSOR_COLLECTION",
  PREDECESSOR_AUTHENTICATION: "PREDECESSOR_AUTHENTICATION", PRIVILEGE_GRANT: "PRIVILEGE_GRANT", ROUTINE_OWNER_SWITCH: "ROUTINE_OWNER_SWITCH",
  REPLACE_PRINTING_READINESS: "REPLACE_PRINTING_READINESS", REPLACE_PRINTING_CREATE_JOB: "REPLACE_PRINTING_CREATE_JOB",
  REPLACE_PRINTING_CONNECTOR_IDENTITY: "REPLACE_PRINTING_CONNECTOR_IDENTITY", PRIVILEGE_RESTORATION: "PRIVILEGE_RESTORATION",
  SUCCESSOR_AUTHENTICATION: "SUCCESSOR_AUTHENTICATION", COMMIT: "COMMIT", SUCCESS_EVIDENCE: "SUCCESS_EVIDENCE", DISCONNECT: "DISCONNECT",
});
const errorClasses = Object.freeze({ ASSERTION: "ASSERTION", PRISMA_INITIALIZATION: "PRISMA_INITIALIZATION",
  PRISMA_KNOWN_REQUEST: "PRISMA_KNOWN_REQUEST", PRISMA_UNKNOWN_REQUEST: "PRISMA_UNKNOWN_REQUEST", SERIALIZATION: "SERIALIZATION", UNKNOWN: "UNKNOWN" });
const serializationStages = new Set([stages.TRANSPORT_VALIDATION, stages.PAYLOAD_DECOMPRESSION, stages.PAYLOAD_AUTHENTICATION]);
const replacementStages = Object.freeze({ printing_readiness: stages.REPLACE_PRINTING_READINESS,
  printing_create_job: stages.REPLACE_PRINTING_CREATE_JOB, printing_connector_identity: stages.REPLACE_PRINTING_CONNECTOR_IDENTITY });

class PrintingRoutineDeltaFailure extends Error {
  constructor(record) { super("Production printing routine delta failed"); this.record = Object.freeze(record); }
}

function failureRecord(stage, error, Prisma = {}) {
  let errorClass = errorClasses.UNKNOWN;
  try {
    if (error instanceof assert.AssertionError) errorClass = errorClasses.ASSERTION;
    else if (stage === stages.PRISMA_INITIALIZATION) errorClass = errorClasses.PRISMA_INITIALIZATION;
    else if (Prisma.PrismaClientInitializationError && error instanceof Prisma.PrismaClientInitializationError) errorClass = errorClasses.PRISMA_INITIALIZATION;
    else if (Prisma.PrismaClientKnownRequestError && error instanceof Prisma.PrismaClientKnownRequestError) errorClass = errorClasses.PRISMA_KNOWN_REQUEST;
    else if (Prisma.PrismaClientUnknownRequestError && error instanceof Prisma.PrismaClientUnknownRequestError) errorClass = errorClasses.PRISMA_UNKNOWN_REQUEST;
    else if (serializationStages.has(stage)) errorClass = errorClasses.SERIALIZATION;
  } catch { errorClass = errorClasses.UNKNOWN; }
  return Object.freeze({ status: "PRODUCTION_PRINTING_ROUTINE_DELTA_FAILED", stage: Object.values(stages).includes(stage) ? stage : stages.ARGV_VALIDATION, errorClass });
}

const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const canonicalSha256 = (value) => sha256(canonicalJson(value));

function appOnlyRequirementIdentity(name, row) {
  return name === "routines" ? `${row.schema}.${row.name}(${row.arguments})`
    : name === "policies" ? `${row.table}.${row.name}` : row.name;
}

function hashProductionRlsCatalogue(catalogue) {
  return Object.fromEntries(collections.map((name) => [name, catalogue[name]
    .map((row) => ({ identity: appOnlyRequirementIdentity(name, row), sha256: canonicalSha256(row) }))
    .sort((left, right) => left.identity.localeCompare(right.identity))]));
}

function catalogueDigestContract(catalogue) {
  return Object.fromEntries(collections.map((name) => [name, canonicalSha256(catalogue[name])]));
}

function classifyPrintingRoutineTransactionCatalogue(catalogue, requirements) {
  const observed = catalogueDigestContract(hashProductionRlsCatalogue(catalogue));
  if (canonicalJson(observed) === canonicalJson(requirements.successor)) return classification.MATCH;
  if (canonicalJson(observed) === canonicalJson(requirements.predecessor)) return classification.EXPECTED;
  return classification.UNEXPECTED;
}

async function collectAppOnlyDatabaseCatalogueRows(tx, validateIdentity = () => {}, afterIdentity = () => {}) {
  // PostgreSQL deparsers consult the effective search path. Pin it locally so
  // identical durable state hashes identically for every authorized principal.
  await tx.$executeRawUnsafe("SET LOCAL search_path = pg_catalog");
  const [identity] = await tx.$queryRawUnsafe(`SELECT current_user AS role, session_user AS session_role,
    current_database() AS database, current_setting('transaction_read_only') AS read_only,
    current_setting('default_transaction_read_only') AS default_read_only,
    r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
    EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid) AS memberships,
    EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
        AND (c.relowner=r.oid OR (c.relkind IN ('r','p','v','m','f') AND
        (pg_catalog.has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') OR
         pg_catalog.has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE'))))) AS write_privileges,
    EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname NOT LIKE 'pg_%'
      AND (n.nspowner=r.oid OR pg_catalog.has_schema_privilege(r.oid,n.oid,'CREATE'))) AS schema_write,
    pg_catalog.has_database_privilege(current_user,current_database(),'CREATE,TEMPORARY') AS database_write
    FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
  validateIdentity(identity);
  afterIdentity();
  const [routines] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.schema,x.name,x.arguments),'[]'::jsonb) AS rows FROM (
    SELECT n.nspname AS schema,p.proname AS name,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,
      pg_catalog.pg_get_function_result(p.oid) AS result,o.rolname AS owner,p.prosecdef AS security_definer,
      p.provolatile::text AS volatility,p.proparallel::text AS parallel,p.proleakproof AS leakproof,p.proisstrict AS strict,
      p.proconfig AS config,p.prosrc AS body,l.lanname AS language,pg_catalog.pg_get_functiondef(p.oid) AS definition,
      COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'privilege',a.privilege_type,'grantable',a.is_grantable)
        ORDER BY COALESCE(g.rolname,'PUBLIC'),a.privilege_type,a.is_grantable)
        FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee),'[]'::jsonb) AS grants
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    JOIN pg_catalog.pg_roles o ON o.oid=p.proowner JOIN pg_catalog.pg_language l ON l.oid=p.prolang
    WHERE n.nspname IN ('app_rls','app_auth','app_public','app_ops')) x`);
  const projectionRows = routines.rows.filter((row) => row.schema === "app_rls" && row.name === "production_security_subscription_inventory");
  assert.ok(projectionRows.length <= 1, "Ambiguous subscription inventory projection");
  if (projectionRows.length) {
    const projection = projectionRows[0];
    assert.equal(projection.arguments, ""); assert.equal(projection.result, subscriptionProjection.result);
    assert.equal(projection.owner, subscriptionProjection.owner); assert.equal(projection.security_definer, true);
    assert.equal(projection.volatility, "s"); assert.deepEqual(projection.config, ["search_path=pg_catalog"]);
    assert.equal(sha256(projection.body), subscriptionProjection.bodySha256);
    const [properties] = await tx.$queryRawUnsafe(`SELECT p.prokind::text AS kind,p.proparallel::text AS parallel,p.proleakproof AS leakproof,p.proisstrict AS strict
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='app_rls' AND p.proname='production_security_subscription_inventory' AND p.pronargs=0`);
    assert.deepEqual(properties, { kind: "f", parallel: "u", leakproof: false, strict: false });
    assert.deepEqual(projection.grants, [
      { role: "mscqr_prod_rls_canary_read", privilege: "EXECUTE", grantable: false },
      { role: subscriptionProjection.owner, privilege: "EXECUTE", grantable: false },
    ]);
    routines.rows.splice(routines.rows.indexOf(projection), 1);
  }
  const [tables] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
    SELECT c.relname AS name,c.relkind::text AS kind,c.relrowsecurity AS rls,c.relforcerowsecurity AS forced,o.rolname AS owner,
      COALESCE((SELECT jsonb_agg(jsonb_build_object('name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'notNull',a.attnotnull,
        'identity',a.attidentity::text,'generated',a.attgenerated::text,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid),
        'enumLabels',COALESCE((SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_catalog.pg_enum e
          WHERE e.enumtypid IN (a.atttypid,(SELECT t.typelem FROM pg_catalog.pg_type t WHERE t.oid=a.atttypid))),'[]'::jsonb)) ORDER BY a.attnum)
        FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
        WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb) AS columns,
      COALESCE((SELECT jsonb_agg(jsonb_build_object('name',k.conname,'definition',pg_catalog.pg_get_constraintdef(k.oid),'validated',k.convalidated)
        ORDER BY k.conname) FROM pg_catalog.pg_constraint k WHERE k.conrelid=c.oid),'[]'::jsonb) AS constraints,
      COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'privilege',acl.privilege_type,'grantable',acl.is_grantable)
        ORDER BY COALESCE(g.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable)
        FROM pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee),'[]'::jsonb) AS grants,
      COALESCE((SELECT jsonb_agg(jsonb_build_object('column',a.attname,'role',COALESCE(g.rolname,'PUBLIC'),'privilege',acl.privilege_type,'grantable',acl.is_grantable)
        ORDER BY a.attname,COALESCE(g.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable)
        FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee
        WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb) AS column_grants
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles o ON o.oid=c.relowner
    WHERE n.nspname='public' AND c.relkind IN ('r','p')) x`);
  const [policies] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x."table",x.name),'[]'::jsonb) AS rows FROM (
    SELECT c.relname AS "table",p.polname AS name,p.polpermissive AS permissive,p.polcmd::text AS command,
      ARRAY(SELECT COALESCE(r.rolname,'PUBLIC') FROM unnest(p.polroles) i LEFT JOIN pg_catalog.pg_roles r ON r.oid=i ORDER BY COALESCE(r.rolname,'PUBLIC')) AS roles,
      pg_catalog.pg_get_expr(p.polqual,p.polrelid) AS "using",pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) AS "check"
    FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') x`);
  const [schemas] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
    SELECT n.nspname AS name,o.rolname AS owner,
      COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'privilege',a.privilege_type,'grantable',a.is_grantable)
        ORDER BY COALESCE(g.rolname,'PUBLIC'),a.privilege_type,a.is_grantable)
        FROM pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee),'[]'::jsonb) AS grants
    FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles o ON o.oid=n.nspowner
    WHERE n.nspname IN ('public','app_rls','app_auth','app_public','app_ops')) x`);
  const [roles] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
    SELECT r.rolname AS name,r.rolcanlogin AS login,r.rolsuper AS superuser,r.rolinherit AS inherit,
      r.rolcreaterole AS create_role,r.rolcreatedb AS create_database,r.rolreplication AS replication,r.rolbypassrls AS bypass_rls,
      COALESCE((SELECT jsonb_agg(jsonb_build_object('role',parent.rolname,'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option)
        ORDER BY parent.rolname,m.admin_option,m.inherit_option,m.set_option) FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid WHERE m.member=r.oid),'[]'::jsonb) AS memberships,
      COALESCE((SELECT jsonb_agg(jsonb_build_object('member',child.rolname,'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option)
        ORDER BY child.rolname,m.admin_option,m.inherit_option,m.set_option) FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles child ON child.oid=m.member WHERE m.roleid=r.oid),'[]'::jsonb) AS members
    FROM pg_catalog.pg_roles r WHERE r.rolname LIKE 'mscqr\\_prd\\_rls\\_phase2\\_%' ESCAPE '\\' OR r.rolname='mscqr_prod_rls_canary_read') x`);
  return { identity, routines: routines.rows, tables: tables.rows, policies: policies.rows, schemas: schemas.rows, roles: roles.rows };
}

async function executePrintingRoutineDeltaTransaction({ tx, input, collect = collectAppOnlyDatabaseCatalogueRows,
  classify = classifyPrintingRoutineTransactionCatalogue, checkpoint = async () => {}, setStage = () => {} } = {}) {
  assert.deepEqual(input.routines.map(({ name }) => name), expectedRoutines);
  assert.deepEqual(input.contract.predecessorSha256, expectedPredecessors);
  setStage(stages.TRANSACTION_SETUP);
  await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
  await tx.$executeRawUnsafe("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('mscqr-production-printing-routine-delta',0))");
  const validateIdentity = (identity) => {
    assert.equal(identity.role, administrator); assert.equal(identity.session_role, administrator);
    assert.equal(identity.database, database); assert.equal(identity.read_only, "off");
    assert.equal(identity.rolsuper, false); assert.equal(identity.rolbypassrls, false);
    assert.equal(identity.rolcreaterole, true); assert.equal(identity.rolcreatedb, true);
  };
  setStage(stages.DATABASE_IDENTITY_AUTHENTICATION);
  const before = await collect(tx, validateIdentity, () => setStage(stages.PREDECESSOR_COLLECTION));
  setStage(stages.PREDECESSOR_AUTHENTICATION);
  const owners = await tx.$queryRawUnsafe("SELECT n.nspname||'.'||p.proname||'('||pg_catalog.pg_get_function_identity_arguments(p.oid)||')' AS identity,o.rolname AS owner,s.rolname AS schema_owner,pg_catalog.pg_has_role(current_user,o.oid,'SET') AS owner_set,pg_catalog.pg_has_role(current_user,s.oid,'SET') AS schema_owner_set,pg_catalog.has_schema_privilege(o.oid,n.oid,'CREATE') AS owner_schema_create FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_roles o ON o.oid=p.proowner JOIN pg_catalog.pg_roles s ON s.oid=n.nspowner WHERE n.nspname='app_rls' AND p.proname=ANY(ARRAY['printing_readiness','printing_create_job','printing_connector_identity']) ORDER BY 1");
  assert.equal(owners.length, 3); assert.deepEqual(owners.map((value) => value.identity), input.contract.identities);
  assert.ok(owners.every((value) => value.owner === ownerRole && value.schema_owner === schemaOwnerRole
    && value.owner_set === true && value.schema_owner_set === true && value.owner_schema_create === false));
  const state = classify(before, input.requirements);
  if (state === classification.MATCH) { setStage(stages.COMMIT); return { status: "ALREADY_CONVERGED", writeCount: 0 }; }
  assert.equal(state, classification.EXPECTED);
  setStage(stages.PRIVILEGE_GRANT);
  await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_prd_rls_phase2_owner");
  await tx.$executeRawUnsafe("GRANT CREATE ON SCHEMA app_rls TO mscqr_prd_rls_phase2_auth_owner");
  await tx.$executeRawUnsafe("RESET ROLE");
  await checkpoint("after-grant");
  const [granted] = await tx.$queryRawUnsafe("SELECT pg_catalog.has_schema_privilege('mscqr_prd_rls_phase2_auth_owner','app_rls','CREATE') AS allowed");
  assert.equal(granted?.allowed, true);
  setStage(stages.ROUTINE_OWNER_SWITCH);
  await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner");
  await checkpoint("after-owner-role");
  let writeCount = 0;
  for (const routine of input.routines) {
    setStage(replacementStages[routine.name]);
    assert.equal(sha256(routine.sql), input.contract.sqlSha256[routine.name]);
    await tx.$executeRawUnsafe(routine.sql); writeCount += 1; await checkpoint(`after-routine-${writeCount}`);
  }
  assert.equal(writeCount, 3);
  setStage(stages.PRIVILEGE_RESTORATION);
  await tx.$executeRawUnsafe("RESET ROLE");
  await checkpoint("before-revoke");
  await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_prd_rls_phase2_owner");
  await tx.$executeRawUnsafe("REVOKE CREATE ON SCHEMA app_rls FROM mscqr_prd_rls_phase2_auth_owner");
  await tx.$executeRawUnsafe("RESET ROLE");
  await checkpoint("after-revoke");
  const [revoked] = await tx.$queryRawUnsafe("SELECT pg_catalog.has_schema_privilege('mscqr_prd_rls_phase2_auth_owner','app_rls','CREATE') AS allowed");
  assert.equal(revoked?.allowed, false);
  setStage(stages.SUCCESSOR_AUTHENTICATION);
  const after = await collect(tx, validateIdentity);
  await checkpoint("after-successor-readback");
  assert.equal(classify(after, input.requirements), classification.MATCH);
  setStage(stages.COMMIT);
  return { status: "APPLIED", writeCount };
}

function gzipDeflateOffset(compressed) {
  assert.ok(compressed.length >= 18 && compressed[0] === 0x1f && compressed[1] === 0x8b && compressed[2] === 8 && (compressed[3] & 0xe0) === 0);
  const flags = compressed[3]; let offset = 10;
  if (flags & 0x04) { assert.ok(offset + 2 <= compressed.length); const length = compressed.readUInt16LE(offset); offset += 2; assert.ok(offset + length <= compressed.length); offset += length; }
  for (const flag of [0x08, 0x10]) if (flags & flag) { const end = compressed.indexOf(0, offset); assert.notEqual(end, -1); offset = end + 1; }
  if (flags & 0x02) offset += 2;
  assert.ok(offset + 8 < compressed.length);
  return offset;
}

function decodeInput(encoded, expectedSha256, setStage = () => {}) {
  setStage(stages.TRANSPORT_VALIDATION);
  assert.ok(typeof encoded === "string" && encoded.length > 0 && encoded.length <= 32768);
  assert.match(encoded, /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
  const compressed = Buffer.from(encoded, "base64"); assert.equal(compressed.toString("base64"), encoded);
  setStage(stages.PAYLOAD_DECOMPRESSION);
  const offset = gzipDeflateOffset(compressed);
  const deflateBytes = inflateRawSync(compressed.subarray(offset), { info: true, maxOutputLength: 65536 }).engine.bytesWritten;
  assert.equal(offset + deflateBytes + 8, compressed.length);
  const bytes = gunzipSync(compressed, { maxOutputLength: 65536 });
  setStage(stages.PAYLOAD_AUTHENTICATION);
  assert.ok(bytes.length > 0 && bytes.length <= 65536); assert.equal(sha256(bytes), expectedSha256);
  const payload = JSON.parse(bytes.toString("utf8"));
  assert.equal(canonicalJson(payload), bytes.toString("utf8"));
  return payload;
}

function validateInput(input) {
  assert.deepEqual(Object.keys(input).sort(), ["contract", "databaseHostname", "requirements", "routines"]);
  assert.deepEqual(Object.keys(input.contract).sort(), ["executorSourceSha256", "identities", "predecessorContractSha256", "predecessorSha256",
    "requirementsSha256", "sourceSha", "sqlSha256", "successorContractSha256", "successorSha256"]);
  assert.deepEqual(Object.keys(input.requirements).sort(), ["predecessor", "successor"]);
  for (const value of Object.values(input.requirements)) {
    assert.deepEqual(Object.keys(value).sort(), [...collections].sort());
    for (const digest of Object.values(value)) assert.match(digest || "", /^[a-f0-9]{64}$/);
  }
  assert.match(input.contract.sourceSha || "", /^[a-f0-9]{40}$/);
  assert.match(input.contract.requirementsSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(input.contract.executorSourceSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(input.databaseHostname || "", /^[a-z0-9.-]+$/);
  assert.deepEqual(input.routines.map(({ name }) => name), expectedRoutines);
  assert.ok(input.routines.every((routine) => Object.keys(routine).sort().join(",") === "name,sql" && typeof routine.sql === "string"));
  assert.deepEqual(input.contract.identities, Object.keys(expectedPredecessors).sort());
  assert.deepEqual(input.contract.predecessorSha256, expectedPredecessors);
  assert.deepEqual(Object.keys(input.contract.successorSha256).sort(), input.contract.identities);
  assert.deepEqual(Object.keys(input.contract.sqlSha256).sort(), [...expectedRoutines].sort());
  for (const digest of [...Object.values(input.contract.successorSha256), ...Object.values(input.contract.sqlSha256)]) assert.match(digest || "", /^[a-f0-9]{64}$/);
  assert.equal(canonicalSha256(input.requirements.predecessor), input.contract.predecessorContractSha256);
  assert.equal(canonicalSha256(input.requirements.successor), input.contract.successorContractSha256);
  for (const routine of input.routines) assert.equal(sha256(routine.sql), input.contract.sqlSha256[routine.name]);
}

async function main({ argv = process.argv, env = process.env, execArgv = process.execArgv,
  PrismaClient, Prisma, onStage = () => {} } = {}) {
  let stage = stages.ARGV_VALIDATION, client, evidence, failure, prismaTypes = Prisma || {};
  const setStage = (value) => { assert.ok(Object.values(stages).includes(value)); stage = value; onStage(value); };
  try {
    setStage(stages.ARGV_VALIDATION); assert.equal(argv.length, 3); assert.match(argv[2] || "", /^[a-f0-9]{64}$/);
    const { input, contractSha256 } = decodeInput(argv[1], argv[2], setStage);
    setStage(stages.CONTRACT_AUTHENTICATION);
    assert.equal(sha256(execArgv[1] || ""), input.contract.executorSourceSha256);
    assert.equal(canonicalSha256(input.contract), contractSha256); validateInput(input);
    setStage(stages.SECRET_VALIDATION); const password = env.MSCQR_PRINTING_DELTA_ADMIN_PASSWORD || ""; assert.ok(password);
    setStage(stages.DATABASE_URL_CONSTRUCTION);
    const url = new URL(`postgresql://unused/${database}`);
    url.username = administrator; url.password = password; url.hostname = input.databaseHostname;
    url.port = "5432"; url.searchParams.set("sslmode", "require"); url.searchParams.set("application_name", "mscqr-production-printing-routine-delta");
    setStage(stages.PRISMA_INITIALIZATION);
    if (!PrismaClient) { const module = require("@prisma/client"); PrismaClient = module.PrismaClient; prismaTypes = module.Prisma; }
    client = new PrismaClient({ datasources: { db: { url: url.toString() } } });
    setStage(stages.TRANSACTION_START);
    const result = await client.$transaction((tx) => executePrintingRoutineDeltaTransaction({ tx, input, setStage }), { maxWait: 10000, timeout: 120000 });
    setStage(stages.SUCCESS_EVIDENCE);
    const body = { schemaVersion: 1, kind: "PRODUCTION_PRINTING_ROUTINE_DELTA_RESULT", sourceSha: input.contract.sourceSha,
      requirementsSha256: input.contract.requirementsSha256, contractSha256, database, databaseRole: administrator,
      status: result.status, writeCount: result.writeCount };
    evidence = JSON.stringify({ ...body, evidenceSha256: canonicalSha256(body) });
  } catch (error) { failure = new PrintingRoutineDeltaFailure(failureRecord(stage, error, prismaTypes)); }
  if (client) {
    try { setStage(stages.DISCONNECT); await client.$disconnect(); }
    catch (error) { if (!failure) failure = new PrintingRoutineDeltaFailure(failureRecord(stage, error, prismaTypes)); }
  }
  if (failure) throw failure;
  setStage(stages.SUCCESS_EVIDENCE); console.log(evidence);
}

module.exports = { canonicalJson, decodeInput, errorClasses, executePrintingRoutineDeltaTransaction, failureRecord, main, stages, validateInput };

if (module.id === "[eval]") main().catch((error) => {
  const record = error instanceof PrintingRoutineDeltaFailure ? error.record : failureRecord(stages.ARGV_VALIDATION, error);
  console.error(JSON.stringify(record)); process.exitCode = 1;
});
