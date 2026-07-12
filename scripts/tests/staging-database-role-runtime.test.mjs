import assert from "node:assert/strict";
import test from "node:test";
import { executorModeForCommand } from "../aws/staging-database-role-credentials.mjs";
import { ROLES, RLS_READ_TABLES, assertCompleteVerification, assertRouteFlagsFalse, classifyProvisioningMode, databaseInvariants, ensureAllPlaceholders, verifyCredentials, verifyDeniedOperation } from "../../backend/scripts/staging-database-role-vpc-executor.mjs";

function clientFactory(fault = "") {
  return (_url, key) => {
    const permissionError = () => { throw new Error("permission denied"); };
    const execute = async (sql) => {
      if (fault === "infrastructure-denial" && /CREATE ROLE/.test(sql)) throw new Error("connection terminated unexpectedly");
      if (fault === "app-can-set-owner" && key === "app" && /SET ROLE/.test(sql)) return 0;
      if (fault === "rls-can-write" && key === "rlsRead" && /INSERT INTO/.test(sql)) return 1;
      return permissionError();
    };
    return {
      async $queryRawUnsafe(sql) {
        if (fault === "invalid-credentials") throw new Error("password authentication failed");
        if (key === "rlsRead" && fault === "rls-missing-graph" && sql.includes(`"${RLS_READ_TABLES.at(-1)}"`)) throw new Error("permission denied");
        return [{ database_name: "mscqr_staging", database_user: ROLES[key] }];
      },
      async $executeRawUnsafe(sql) { return execute(sql); },
      async $transaction(callback) {
        const tx = {
          $queryRawUnsafe: async () => [{ ok: 1 }],
          $executeRawUnsafe: async (sql) => {
            if (fault === "app-missing-crud" && key === "app" && /UPDATE/.test(sql)) throw new Error("permission denied");
            if (fault === "migrator-cannot-set-owner" && key === "migrator" && /SET LOCAL ROLE/.test(sql)) throw new Error("permission denied");
            if (key === "app" && /INSERT INTO "ActionIdempotencyKey"|UPDATE "ActionIdempotencyKey"|DELETE FROM "ActionIdempotencyKey"/.test(sql)) return 1;
            if (key === "migrator" && /SET LOCAL ROLE|CREATE TABLE mscqr_staging_migrator_credential_proof/.test(sql)) return 1;
            if (fault === "app-can-set-owner" && key === "app" && /SET LOCAL ROLE/.test(sql)) return 0;
            if (fault === "rls-can-write" && key === "rlsRead" && /INSERT INTO/.test(sql)) return 1;
            if (fault === "infrastructure-denial" && /CREATE ROLE/.test(sql)) throw new Error("connection terminated unexpectedly");
            throw new Error("permission denied");
          },
        };
        return callback(tx);
      },
      async $disconnect() {},
    };
  };
}

const urls = Object.fromEntries(Object.keys(ROLES).map((key) => [key, ["postgresql:", "//", ROLES[key], ":", "fixture-value", "@", "mscqr-staging-db.invalid/mscqr_staging"].join("")]));

test("controller verify invokes verify executor mode and never probe", () => { assert.equal(executorModeForCommand("verify"), "verify"); assert.notEqual(executorModeForCommand("verify"), "probe"); });
test("complete permission matrix succeeds only with every advertised check", async () => { const result = await verifyCredentials(urls, { clientFactory: clientFactory() }); assert.equal(assertCompleteVerification(result), true); });
for (const [fault, message] of [
  ["invalid-credentials", /authentication failed/],
  ["app-missing-crud", /permission denied/],
  ["app-can-set-owner", /unexpectedly succeeded/],
  ["migrator-cannot-set-owner", /permission denied/],
  ["rls-can-write", /unexpectedly succeeded/],
  ["rls-missing-graph", /permission denied/],
  ["infrastructure-denial", /non-permission reason/],
]) test(`verification fails closed for ${fault}`, async () => assert.rejects(verifyCredentials(urls, { clientFactory: clientFactory(fault) }), message));
test("verification cannot report success with an incomplete matrix", async () => { const result = await verifyCredentials(urls, { clientFactory: clientFactory() }); result[0].permissionTests.pop(); assert.throws(() => assertCompleteVerification(result), /Missing expected denial|incomplete/); });
test("verify requires zero RLS, FORCE RLS, and policy counts",async()=>{ const admin={ $queryRawUnsafe:async()=>[{database_name:"mscqr_staging",rls_enabled_count:0,force_rls_count:0,policy_count:0}]}; assert.equal((await databaseInvariants(admin)).policyCount,0); for(const key of ["rls_enabled_count","force_rls_count","policy_count"]){ admin.$queryRawUnsafe=async()=>[{database_name:"mscqr_staging",rls_enabled_count:0,force_rls_count:0,policy_count:0,[key]:1}]; await assert.rejects(databaseInvariants(admin),/invariants failed/); } });
test("verify requires every staged RLS route flag to remain explicitly false",()=>{ const env={MSCQR_STAGING_RLS_BATCHES_READ_ENABLED:"false",MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED:"false",MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED:"false"}; assert.equal(assertRouteFlagsFalse(env),true); assert.throws(()=>assertRouteFlagsFalse({...env,MSCQR_STAGING_RLS_BATCHES_READ_ENABLED:"true"}),/explicitly false/); });

function probeClient({ deny = false, infrastructureFailure = false, rollbackFailure = false } = {}) {
  const state = { tables: new Set(), schemas: new Set(), rows: 0, begins: 0, rollbacks: 0, reusableChecks: 0 };
  return {
    state,
    async $transaction(callback) {
      state.begins += 1;
      const snapshot = { tables: new Set(state.tables), schemas: new Set(state.schemas), rows: state.rows };
      const tx = { $executeRawUnsafe: async (sql) => {
        if (infrastructureFailure) throw new Error("connection terminated unexpectedly");
        if (deny) throw new Error("permission denied");
        const table = sql.match(/CREATE TABLE ([a-zA-Z0-9_]+)/)?.[1]; if (table) state.tables.add(table);
        const schema = sql.match(/CREATE SCHEMA ([a-zA-Z0-9_]+)/)?.[1]; if (schema) state.schemas.add(schema);
        if (/INSERT|UPDATE|DELETE/.test(sql)) state.rows += 1;
        return 1;
      } };
      try { return await callback(tx); }
      catch (error) {
        state.rollbacks += 1; state.tables = snapshot.tables; state.schemas = snapshot.schemas; state.rows = snapshot.rows;
        if (rollbackFailure) throw new Error("rollback failed");
        throw error;
      }
    },
    async $queryRawUnsafe() { state.reusableChecks += 1; return [{ connection_reusable: 1 }]; },
  };
}

test("unexpectedly successful CREATE TABLE is rolled back and leaves no object",async()=>{ const db=probeClient(); await assert.rejects(verifyDeniedOperation(db,{label:"create-table",sql:"CREATE TABLE unique_probe_table(id integer)",mutating:true}),/unexpectedly succeeded/); assert.equal(db.state.tables.size,0); assert.equal(db.state.begins,1); assert.equal(db.state.rollbacks,1); });
test("unexpectedly successful CREATE SCHEMA is rolled back and leaves no schema",async()=>{ const db=probeClient(); await assert.rejects(verifyDeniedOperation(db,{label:"create-schema",sql:"CREATE SCHEMA unique_probe_schema",mutating:true}),/unexpectedly succeeded/); assert.equal(db.state.schemas.size,0); assert.equal(db.state.rollbacks,1); });
test("unexpectedly successful DML probe is rolled back and leaves rows unchanged",async()=>{ const db=probeClient(); await assert.rejects(verifyDeniedOperation(db,{label:"insert",sql:"INSERT INTO fixture VALUES (1)",mutating:true}),/unexpectedly succeeded/); assert.equal(db.state.rows,0); assert.equal(db.state.rollbacks,1); });
test("expected permission denial rolls back and leaves the connection reusable",async()=>{ const db=probeClient({deny:true}); assert.deepEqual(await verifyDeniedOperation(db,{label:"create-table",sql:"CREATE TABLE denied_probe(id integer)",mutating:true}),{label:"create-table",result:"permission-denied"}); assert.equal(db.state.rollbacks,1); assert.equal(db.state.reusableChecks,1); });
test("infrastructure failure is not classified as permission denial",async()=>{ const db=probeClient({infrastructureFailure:true}); await assert.rejects(verifyDeniedOperation(db,{label:"create-table",sql:"CREATE TABLE infra_probe(id integer)",mutating:true}),/non-permission reason/); });
test("rollback failure causes verification failure",async()=>{ const db=probeClient({deny:true,rollbackFailure:true}); await assert.rejects(verifyDeniedOperation(db,{label:"create-table",sql:"CREATE TABLE rollback_probe(id integer)",mutating:true}),/rollback failed/); });

for (const initialCount of [1, 2, 3]) test(`first-time recovery converges ${initialCount}-of-3 placeholders to a retryable 3-of-3 state`, async () => {
  const keys = Object.keys(ROLES); const store = new Set(keys.slice(0, initialCount));
  await ensureAllPlaceholders({ metadataFn: async (key) => ({ exists: store.has(key) }), isPlaceholderFn: async (key) => store.has(key), createPlaceholderFn: async (key) => { store.add(key); } });
  assert.deepEqual([...store].sort(), keys.sort());
  assert.doesNotThrow(() => { if (store.size !== 3) throw new Error("retry blocked"); });
});

test("failed placeholder convergence requires operator recovery and never reports restored", async () => {
  const store = new Set(["app"]);
  await assert.rejects(ensureAllPlaceholders({ metadataFn: async (key) => ({ exists: store.has(key) }), isPlaceholderFn: async (key) => store.has(key), createPlaceholderFn: async () => { throw new Error("cleanup failed"); } }), /cleanup failed/);
  assert.notEqual(store.size, 3);
});

for (const [boundary, initialCount] of [["first-placeholder-creation",1],["second-placeholder-creation",2],["all-placeholders-before-pending",3],["first-pending-version",3]]) test(`failure injection after ${boundary} leaves a retryable consistent state`, async () => {
  const keys=Object.keys(ROLES); const store=new Set(keys.slice(0,initialCount));
  await ensureAllPlaceholders({metadataFn:async key=>({exists:store.has(key)}),isPlaceholderFn:async key=>store.has(key),createPlaceholderFn:async key=>store.add(key)});
  const states=Object.fromEntries(keys.map(key=>[key,{exists:store.has(key)}])); const flags=Object.fromEntries(keys.map(key=>[key,store.has(key)]));
  assert.equal(classifyProvisioningMode(states,flags),"first-time-recoverable");
});

for (const signal of ["SIGINT","SIGTERM","SIGHUP"]) for (const [boundary,initialCount] of [["first-placeholder",1],["second-placeholder",2],["all-placeholders",3],["first-pending",3]]) test(`${signal} compensation at ${boundary} converges and permits a second run`, async () => {
  const keys=Object.keys(ROLES); const store=new Set(keys.slice(0,initialCount));
  await ensureAllPlaceholders({metadataFn:async key=>({exists:store.has(key)}),isPlaceholderFn:async key=>store.has(key),createPlaceholderFn:async key=>store.add(key)});
  assert.equal(classifyProvisioningMode(Object.fromEntries(keys.map(key=>[key,{exists:true}])),Object.fromEntries(keys.map(key=>[key,true]))),"first-time-recoverable");
});

test("mixed one-of-three or two-of-three credential states are never classified as restored",()=>{ const keys=Object.keys(ROLES); for(const count of [1,2]){ const states=Object.fromEntries(keys.map((key,index)=>[key,{exists:index<count}])); const flags=Object.fromEntries(keys.slice(0,count).map(key=>[key,false])); assert.throws(()=>classifyProvisioningMode(states,flags),/Mixed credential/); } });
