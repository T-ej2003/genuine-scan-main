import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { INCIDENT_DATABASE, INCIDENT_QUERIES, INCIDENT_ROLE, INCIDENT_SCOPE, INCIDENT_SOURCE_SHA } from "../../backend/scripts/production-incident-diagnostic-queries.mjs";

assert.equal(INCIDENT_SOURCE_SHA, "7407b80b7919ca88f53e4a6d05596701fe00d0e0");
assert.equal(INCIDENT_DATABASE, "mscqr_production_rls_green_phase2");
assert.equal(INCIDENT_ROLE, "mscqr_prod_rls_canary_read");
assert.equal(Object.keys(INCIDENT_QUERIES).length, 11);
for (const [name, query] of Object.entries(INCIDENT_QUERIES)) {
  assert.match(query, /^SELECT\s/i, `${name} must be a read`);
  assert.doesNotMatch(query, /;|\b(?:INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|TRUNCATE|FOR\s+UPDATE|FOR\s+SHARE)\b/i, `${name} must contain one nonlocking statement`);
  if (name !== "identity") assert.match(query, /\bLIMIT\s+\d+\s*$/i, `${name} must bound returned rows`);
  assert.doesNotMatch(query, /tokenHash|sessionCapabilityHash|\bcode\b|description|screenshot|password|secret|metadata\s+AS/i, `${name} must not return sensitive columns`);
}
for (const name of ["printJobs", "printEvents", "batch", "qrCounts"]) assert.ok(INCIDENT_QUERIES[name].includes(INCIDENT_SCOPE.batchId));
for (const name of ["printJobs", "printEvents", "sessions", "support"]) assert.ok(INCIDENT_QUERIES[name].includes(INCIDENT_SCOPE.manufacturerId));
assert.ok(INCIDENT_QUERIES.testLabel.includes(INCIDENT_SCOPE.testPrinterId));
assert.ok(INCIDENT_QUERIES.testLabelAudit.includes(INCIDENT_SCOPE.testPrinterId));

// Run against the disposable PostgreSQL 18.4 container when explicitly supplied.
if (process.env.INCIDENT_DIAGNOSTIC_TEST_CONTAINER) {
  const schema = `incident_query_test_${process.pid}`;
  const scoped = (query) => query.replaceAll("public.", `${schema}.`);
  const sql = `BEGIN;
    CREATE SCHEMA ${schema};
    CREATE TABLE ${schema}."PrintJob" (id text, status text, "pipelineState" text, "printerId" text,
      "createdAt" timestamptz, "updatedAt" timestamptz, "sentAt" timestamptz, "completedAt" timestamptz,
      "batchId" text, "manufacturerId" text);
    CREATE TABLE ${schema}."PrintSession" (id text, status text, "printJobId" text,
      "createdAt" timestamptz, "updatedAt" timestamptz, "completedAt" timestamptz,
      "issuedItems" integer, "confirmedItems" integer, "frozenItems" integer,
      "batchId" text, "manufacturerId" text);
    CREATE TABLE ${schema}."PrintItem" (id text, "printSessionId" text);
    CREATE TABLE ${schema}."PrintItemEvent" (id text, "printItemId" text, "eventType" text,
      "previousState" text, "nextState" text, "createdAt" timestamptz);
    INSERT INTO ${schema}."PrintJob"
      SELECT 'history-'||n, 'COMPLETED', NULL, NULL, now()-n*interval '1 minute', now(), NULL, now(),
        '${INCIDENT_SCOPE.batchId}', '${INCIDENT_SCOPE.manufacturerId}' FROM generate_series(1,25) n;
    INSERT INTO ${schema}."PrintJob" VALUES
      ('conflict','PENDING',NULL,NULL,'2020-01-01',now(),NULL,NULL,'${INCIDENT_SCOPE.batchId}','${INCIDENT_SCOPE.manufacturerId}'),
      ('paused','PAUSED',NULL,NULL,'2020-01-02',now(),NULL,NULL,'${INCIDENT_SCOPE.batchId}','${INCIDENT_SCOPE.manufacturerId}'),
      ('resume','SENT',NULL,NULL,'2020-01-03',now(),NULL,NULL,'${INCIDENT_SCOPE.batchId}','${INCIDENT_SCOPE.manufacturerId}'),
      ('orphan','PENDING',NULL,NULL,'2020-01-04',now(),NULL,NULL,'${INCIDENT_SCOPE.batchId}','${INCIDENT_SCOPE.manufacturerId}'),
      ('closed-session','PENDING',NULL,NULL,'2020-01-05',now(),NULL,NULL,'${INCIDENT_SCOPE.batchId}','${INCIDENT_SCOPE.manufacturerId}'),
      ('other-batch','PENDING',NULL,NULL,now(),now(),NULL,NULL,'other','${INCIDENT_SCOPE.manufacturerId}'),
      ('other-manufacturer','PENDING',NULL,NULL,now(),now(),NULL,NULL,'${INCIDENT_SCOPE.batchId}','other');
    INSERT INTO ${schema}."PrintSession" VALUES
      ('s-conflict','ACTIVE','conflict',now(),now(),NULL,1,0,0,'${INCIDENT_SCOPE.batchId}','${INCIDENT_SCOPE.manufacturerId}'),
      ('s-paused','PAUSED','paused',now(),now(),NULL,1,0,0,'${INCIDENT_SCOPE.batchId}','${INCIDENT_SCOPE.manufacturerId}'),
      ('s-resume','RESUME_PENDING','resume',now(),now(),NULL,1,0,0,'${INCIDENT_SCOPE.batchId}','${INCIDENT_SCOPE.manufacturerId}'),
      ('s-closed','COMPLETED','closed-session',now(),now(),now(),1,1,0,'${INCIDENT_SCOPE.batchId}','${INCIDENT_SCOPE.manufacturerId}'),
      ('s-other-batch','ACTIVE','other-batch',now(),now(),NULL,1,0,0,'other','${INCIDENT_SCOPE.manufacturerId}'),
      ('s-other-manufacturer','ACTIVE','other-manufacturer',now(),now(),NULL,1,0,0,'${INCIDENT_SCOPE.batchId}','other');
    INSERT INTO ${schema}."PrintItem" VALUES ('item-conflict','s-conflict'),('item-closed','s-closed'),('item-other','s-other-batch');
    INSERT INTO ${schema}."PrintItemEvent" VALUES
      ('event-conflict','item-conflict','ISSUED',NULL,'ISSUED',now()),
      ('event-closed','item-closed','ISSUED',NULL,'ISSUED',now()),
      ('event-other','item-other','ISSUED',NULL,'ISSUED',now());
    SELECT 'JOBS='||COALESCE((SELECT jsonb_agg(to_jsonb(q))::text FROM (${scoped(INCIDENT_QUERIES.printJobs)}) q),'[]');
    SELECT 'EVENTS='||COALESCE((SELECT jsonb_agg(to_jsonb(q))::text FROM (${scoped(INCIDENT_QUERIES.printEvents)}) q),'[]');
    ROLLBACK;`;
  const output = execFileSync("docker", ["exec", "-i", process.env.INCIDENT_DIAGNOSTIC_TEST_CONTAINER,
    "psql", "-U", "postgres", "-d", "postgres", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"],
    { input: sql, encoding: "utf8", timeout: 15000 });
  const jobs = JSON.parse(output.match(/^JOBS=(.*)$/m)?.[1] ?? "null");
  const events = JSON.parse(output.match(/^EVENTS=(.*)$/m)?.[1] ?? "null");
  assert.deepEqual(jobs.map(({ id }) => id), ["resume", "paused", "conflict", "orphan"]);
  assert.deepEqual(jobs.map(({ active_conflict }) => active_conflict), [true, true, true, false]);
  assert.deepEqual(events.map(({ printItemId }) => printItemId), ["item-conflict"]);
}
console.log("fixed incident diagnostic query contract passed");
