const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_SESSION_C_AUDIT_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_SESSION_C_AUDIT_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_SESSION_C_AUDIT_POSTGRES18_TEST";
const database = "mscqr_rls_wave_c_admin_governance_operator";
const adminUrl = `postgresql://mscqr_rls_cert_admin@127.0.0.1:55434/${database}`;
const appUrl = `postgresql://mscqr_rls_wave_c_app@127.0.0.1:55434/${database}`;

const psql = (sql) => {
  const run = spawnSync("psql", [adminUrl, "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql], { encoding: "utf8" });
  if (run.status !== 0) throw new Error(run.stderr || run.stdout || "psql failed");
  return run.stdout.trim();
};

const psqlFile = (file) => {
  const run = spawnSync("psql", [adminUrl, "-X", "-v", "ON_ERROR_STOP=1", "-f", file], { encoding: "utf8" });
  if (run.status !== 0) throw new Error(run.stderr || run.stdout || "psql file failed");
};

const ids = {
  platform: "00000000-0000-4000-8000-00000000d001",
  tenantAdmin: "00000000-0000-4000-8000-00000000d002",
  manufacturer: "00000000-0000-4000-8000-00000000d003",
  orgA: "00000000-0000-4000-8000-00000000d101",
  orgB: "00000000-0000-4000-8000-00000000d102",
  licenseeA: "00000000-0000-4000-8000-00000000d201",
  licenseeB: "00000000-0000-4000-8000-00000000d202",
  batch: "00000000-0000-4000-8000-00000000d301",
  qrCode: "00000000-0000-4000-8000-00000000d401",
  trace: "00000000-0000-4000-8000-00000000d501",
  audit: "00000000-0000-4000-8000-00000000d601",
  report: "00000000-0000-4000-8000-00000000d602",
  foreignAudit: "00000000-0000-4000-8000-00000000d603",
};

const setupSql = `
GRANT USAGE ON SCHEMA public, app_rls TO mscqr_rls_wave_c_app;
REVOKE ALL ON public."AuditLog", public."SecurityEventOutbox", public."TraceEvent", public."User", public."ManufacturerLicenseeLink", public."Batch", public."QRCode" FROM mscqr_rls_wave_c_app;
GRANT SELECT (id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"createdAt") ON public."AuditLog" TO mscqr_rls_wave_c_app;
GRANT INSERT (id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"ipAddress","ipHash","userAgent") ON public."AuditLog" TO mscqr_rls_wave_c_app;
GRANT INSERT (id,"eventType",payload,"updatedAt") ON public."SecurityEventOutbox" TO mscqr_rls_wave_c_app;
GRANT SELECT (id,name,email,"orgId","licenseeId",role,"isActive",status,"deletedAt","disabledAt") ON public."User" TO mscqr_rls_wave_c_app;
GRANT SELECT ("manufacturerId","licenseeId","isPrimary","createdAt","updatedAt") ON public."ManufacturerLicenseeLink" TO mscqr_rls_wave_c_app;
GRANT SELECT (id,"eventType","licenseeId","batchId","qrCodeId","manufacturerId","userId","sourceAction",details,"createdAt") ON public."TraceEvent" TO mscqr_rls_wave_c_app;
GRANT SELECT (id,name,"licenseeId","manufacturerId") ON public."Batch" TO mscqr_rls_wave_c_app;
GRANT SELECT (id,code,"licenseeId","batchId") ON public."QRCode" TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.c02_audit_trace_actor_valid(text) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.platform_audit_log_details(text[]) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.c02_fraud_report_network_details(text[]) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.c02_respond_fraud_report(text,text,text,boolean) TO mscqr_rls_wave_c_app;

DROP POLICY IF EXISTS c02_audit_select ON public."AuditLog";
CREATE POLICY c02_audit_select ON public."AuditLog" FOR SELECT TO mscqr_rls_wave_c_app USING (
  "licenseeId" = current_setting('app.licensee_id', true)
  AND app_rls.c02_audit_trace_actor_valid("licenseeId")
  AND (current_setting('app.role', true) NOT IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') OR "userId" = current_setting('app.user_id', true))
);
DROP POLICY IF EXISTS c02_audit_insert ON public."AuditLog";
CREATE POLICY c02_audit_insert ON public."AuditLog" FOR INSERT TO mscqr_rls_wave_c_app WITH CHECK (
  "userId" = current_setting('app.user_id', true)
  AND "licenseeId" = current_setting('app.licensee_id', true)
  AND action IN ('AUDIT_LOGS_READ','AUDIT_CSV_EXPORT','AUDIT_FRAUD_REPORTS_READ','TRACE_TIMELINE_READ')
  AND app_rls.c02_audit_trace_actor_valid("licenseeId")
);
DROP POLICY IF EXISTS c02_outbox_insert ON public."SecurityEventOutbox";
CREATE POLICY c02_outbox_insert ON public."SecurityEventOutbox" FOR INSERT TO mscqr_rls_wave_c_app WITH CHECK (
  app_rls.c02_audit_trace_actor_valid(current_setting('app.licensee_id', true))
);
DROP POLICY IF EXISTS c02_user_select ON public."User";
CREATE POLICY c02_user_select ON public."User" FOR SELECT TO mscqr_rls_wave_c_app USING (
  app_rls.c02_audit_trace_actor_valid(current_setting('app.licensee_id', true))
  AND (
    current_setting('app.role', true) IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
    OR (current_setting('app.role', true) IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND id = current_setting('app.user_id', true))
    OR "licenseeId" = current_setting('app.licensee_id', true)
    OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=id AND ml."licenseeId"=current_setting('app.licensee_id', true))
  )
);
DROP POLICY IF EXISTS c02_link_select ON public."ManufacturerLicenseeLink";
CREATE POLICY c02_link_select ON public."ManufacturerLicenseeLink" FOR SELECT TO mscqr_rls_wave_c_app USING (
  "licenseeId" = current_setting('app.licensee_id', true)
  AND app_rls.c02_audit_trace_actor_valid("licenseeId")
  AND (current_setting('app.role', true) NOT IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') OR "manufacturerId"=current_setting('app.user_id', true))
);
DROP POLICY IF EXISTS c02_trace_select ON public."TraceEvent";
CREATE POLICY c02_trace_select ON public."TraceEvent" FOR SELECT TO mscqr_rls_wave_c_app USING (
  "licenseeId" = current_setting('app.licensee_id', true)
  AND app_rls.c02_audit_trace_actor_valid("licenseeId")
  AND (current_setting('app.role', true) NOT IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') OR "manufacturerId"=current_setting('app.user_id', true))
);
DROP POLICY IF EXISTS c02_batch_select ON public."Batch";
CREATE POLICY c02_batch_select ON public."Batch" FOR SELECT TO mscqr_rls_wave_c_app USING (
  "licenseeId" = current_setting('app.licensee_id', true) AND app_rls.c02_audit_trace_actor_valid("licenseeId")
);
DROP POLICY IF EXISTS c02_qr_select ON public."QRCode";
CREATE POLICY c02_qr_select ON public."QRCode" FOR SELECT TO mscqr_rls_wave_c_app USING (
  "licenseeId" = current_setting('app.licensee_id', true) AND app_rls.c02_audit_trace_actor_valid("licenseeId")
);
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['AuditLog','SecurityEventOutbox','TraceEvent','User','ManufacturerLicenseeLink','Batch','QRCode']
  LOOP EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t); END LOOP;
END $$;
`;

const actor = (role, userId, licenseeId, orgId, assurance = "ADMIN_MFA") => ({
  userId,
  email: `${role.toLowerCase()}@session-c.invalid`,
  role,
  orgId,
  licenseeId,
  linkedLicenseeIds: role.startsWith("MANUFACTURER") ? [ids.licenseeA] : [],
  sessionId: `session-c-${role.toLowerCase()}`,
  sessionStage: "ACTIVE",
  authAssurance: assurance,
  authenticatedAt: new Date().toISOString(),
  mfaVerifiedAt: assurance === "ADMIN_MFA" ? new Date().toISOString() : null,
});

const invoke = async (controller, { user, body = {}, params = {}, query = {}, requestId }) => {
  const response = { status: 200, body: null };
  const req = {
    user, body, params, query, requestId, ip: "127.0.0.1", headers: {},
    get(name) { return name.toLowerCase() === "user-agent" ? "session-c-audit-postgres18" : this.headers[name.toLowerCase()]; },
    on() {},
  };
  const res = {
    status(code) { response.status = code; return this; },
    json(payload) { response.body = payload; return this; },
    setHeader() {},
    send(payload) { response.body = payload; return this; },
  };
  await controller(req, res);
  return response;
};

async function main() {
  if (!enabled) return console.log("Session C audit/trace PostgreSQL 18 proof skipped");
  assert(confirmed, "Session C audit/trace PostgreSQL proof confirmation is required");
  assert.equal(Math.floor(Number(psql("select current_setting('server_version_num')::int")) / 10000), 18);
  psqlFile(path.resolve(__dirname, "../../../src/rls-waves/session-c/c02/auditTrace.sql"));
  psql(setupSql);
  psql(`
    DELETE FROM public."SecurityEventOutbox" WHERE payload->>'userId' IN ('${ids.platform}','${ids.tenantAdmin}');
    DELETE FROM public."AuditLog" WHERE id IN ('${ids.audit}','${ids.report}','${ids.foreignAudit}') OR "userId" IN ('${ids.platform}','${ids.tenantAdmin}');
    DELETE FROM public."TraceEvent" WHERE id='${ids.trace}';
    DELETE FROM public."QRCode" WHERE id='${ids.qrCode}';
    DELETE FROM public."Batch" WHERE id='${ids.batch}';
    DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.manufacturer}';
    DELETE FROM public."User" WHERE id IN ('${ids.platform}','${ids.tenantAdmin}','${ids.manufacturer}');
    DELETE FROM public."Licensee" WHERE id IN ('${ids.licenseeA}','${ids.licenseeB}');
    DELETE FROM public."Organization" WHERE id IN ('${ids.orgA}','${ids.orgB}');
    INSERT INTO public."Organization" (id,name,"isActive","updatedAt") VALUES
      ('${ids.orgA}','Session C Audit Org A',true,transaction_timestamp()),
      ('${ids.orgB}','Session C Audit Org B',true,transaction_timestamp());
    INSERT INTO public."Licensee" (id,"orgId",name,prefix,"isActive","updatedAt") VALUES
      ('${ids.licenseeA}','${ids.orgA}','Session C Audit Tenant A','C2A',true,transaction_timestamp()),
      ('${ids.licenseeB}','${ids.orgB}','Session C Audit Tenant B','C2B',true,transaction_timestamp());
    INSERT INTO public."User" (id,email,name,role,status,"isActive","updatedAt") VALUES
      ('${ids.platform}','c02-platform@session-c.invalid','C02 Platform','PLATFORM_SUPER_ADMIN','ACTIVE',true,transaction_timestamp());
    INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES
      ('${ids.tenantAdmin}','c02-admin@session-c.invalid','C02 Tenant Admin','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,transaction_timestamp()),
      ('${ids.manufacturer}','c02-manufacturer@session-c.invalid','C02 Manufacturer','MANUFACTURER','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,transaction_timestamp());
    INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES ('${ids.manufacturer}','${ids.licenseeA}',true,transaction_timestamp());
    INSERT INTO public."Batch" (id,name,"licenseeId","manufacturerId","startCode","endCode","totalCodes","updatedAt") VALUES ('${ids.batch}','C02 Batch','${ids.licenseeA}','${ids.manufacturer}','C02-1','C02-1',1,transaction_timestamp());
    INSERT INTO public."QRCode" (id,code,"licenseeId","batchId","updatedAt") VALUES ('${ids.qrCode}','C02-QR-1','${ids.licenseeA}','${ids.batch}',transaction_timestamp());
    INSERT INTO public."TraceEvent" (id,"eventType","licenseeId","batchId","qrCodeId","manufacturerId","userId","sourceAction",details) VALUES
      ('${ids.trace}','REDEEMED','${ids.licenseeA}','${ids.batch}','${ids.qrCode}','${ids.manufacturer}','${ids.tenantAdmin}','VERIFY_SUCCESS','{"safe":"visible","accessToken":"never-return"}'::jsonb);
    INSERT INTO public."AuditLog" (id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"ipAddress","userAgent") VALUES
      ('${ids.audit}','${ids.tenantAdmin}','${ids.orgA}','${ids.licenseeA}','BATCH_VIEW','Batch','${ids.batch}','{"safe":"visible","refreshToken":"never-return"}'::jsonb,'192.0.2.10','C02 Browser'),
      ('${ids.report}',NULL,'${ids.orgA}','${ids.licenseeA}','CUSTOMER_FRAUD_REPORT','FraudReport','C02-CODE','{"code":"C02-CODE","reason":"duplicate","contactEmail":"reporter@session-c.invalid"}'::jsonb,'192.0.2.20','C02 Reporter'),
      ('${ids.foreignAudit}','${ids.tenantAdmin}','${ids.orgB}','${ids.licenseeB}','BATCH_VIEW','Batch','foreign','{}'::jsonb,'192.0.2.30','Foreign');
  `);

  process.env.NODE_ENV = "test";
  process.env.DATABASE_URL = appUrl;
  process.env.IP_HASH_SALT_CURRENT = "session-c-audit-postgres18-local-proof-only";
  const prismaModule = require("../../../dist/config/database");
  const prisma = prismaModule.default || prismaModule;
  const auditController = require("../../../dist/controllers/auditController");
  const traceController = require("../../../dist/controllers/traceTimelineController");

  const platform = actor("PLATFORM_SUPER_ADMIN", ids.platform, null, null);
  const tenantAdmin = actor("LICENSEE_ADMIN", ids.tenantAdmin, ids.licenseeA, ids.orgA);
  const platformRead = await invoke(auditController.getLogs, {
    user: platform,
    query: { licenseeId: ids.licenseeA, purpose: "incident C02 review", limit: "20" },
    requestId: "00000000-0000-4000-8000-00000000d701",
  });
  assert.equal(platformRead.status, 200, JSON.stringify(platformRead.body));
  assert(platformRead.body.data.logs.some((row) => row.id === ids.audit));
  assert(!platformRead.body.data.logs.some((row) => row.id === ids.foreignAudit));
  assert.equal(platformRead.body.data.logs.find((row) => row.id === ids.audit).ipAddress, "192.0.2.10");
  assert.doesNotMatch(JSON.stringify(platformRead.body), /never-return/);

  const foreign = await invoke(auditController.getLogs, {
    user: tenantAdmin,
    query: { licenseeId: ids.licenseeB },
    requestId: "00000000-0000-4000-8000-00000000d702",
  });
  assert.equal(foreign.status, 403);

  const wrongAssurance = await invoke(auditController.getLogs, {
    user: { ...platform, authAssurance: "PASSWORD", mfaVerifiedAt: null },
    query: { licenseeId: ids.licenseeA, purpose: "review" },
    requestId: "00000000-0000-4000-8000-00000000d703",
  });
  assert.equal(wrongAssurance.status, 403);

  const trace = await invoke(traceController.getTraceTimelineController, {
    user: { ...tenantAdmin, authAssurance: "PASSWORD", mfaVerifiedAt: null },
    query: { limit: "20" },
    requestId: "00000000-0000-4000-8000-00000000d704",
  });
  assert.equal(trace.status, 200, JSON.stringify(trace.body));
  assert.equal(trace.body.data.events[0].id, ids.trace);
  assert.doesNotMatch(JSON.stringify(trace.body), /never-return/);

  const response = await invoke(auditController.respondToFraudReport, {
    user: platform,
    params: { id: ids.report },
    body: { status: "RESOLVED", notifyCustomer: true },
    requestId: "00000000-0000-4000-8000-00000000d705",
  });
  assert.equal(response.status, 200, JSON.stringify(response.body));
  assert.equal(response.body.data.reportId, ids.report);
  assert.equal(response.body.data.status, "RESOLVED");
  assert.equal(response.body.data.delivery.delivered, true);

  psql(`UPDATE public."User" SET "isActive"=false,status='DISABLED',"disabledAt"=transaction_timestamp() WHERE id='${ids.platform}'`);
  const stale = await invoke(auditController.getLogs, {
    user: platform,
    query: { licenseeId: ids.licenseeA, purpose: "stale actor proof" },
    requestId: "00000000-0000-4000-8000-00000000d706",
  });
  assert.notEqual(stale.status, 200);
  psql(`UPDATE public."User" SET "isActive"=true,status='ACTIVE',"disabledAt"=NULL WHERE id='${ids.platform}'`);

  const directRows = await prisma.traceEvent.findMany({ take: 1 });
  assert.deepEqual(directRows, [], "protected direct read without canonical context must return no rows");
  const [readAuditCount, responseCount, outboxCount, forcedCount] = psql(`
    SELECT
      count(*) FILTER (WHERE action IN ('AUDIT_LOGS_READ','TRACE_TIMELINE_READ')),
      count(*) FILTER (WHERE action='CUSTOMER_FRAUD_REPORT_RESPONSE' AND "userId"='${ids.platform}'),
      (SELECT count(*) FROM public."SecurityEventOutbox" WHERE payload->>'userId' IN ('${ids.platform}','${ids.tenantAdmin}')),
      (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('AuditLog','SecurityEventOutbox','TraceEvent','User','ManufacturerLicenseeLink','Batch','QRCode') AND c.relrowsecurity AND c.relforcerowsecurity)
    FROM public."AuditLog" WHERE "licenseeId"='${ids.licenseeA}'
  `).split("|").map(Number);
  assert(readAuditCount >= 2);
  assert.equal(responseCount, 1);
  assert(outboxCount >= 2);
  assert.equal(forcedCount, 7);

  await prisma.$disconnect();
  console.log("Session C audit/trace PostgreSQL 18 application-path proof passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
