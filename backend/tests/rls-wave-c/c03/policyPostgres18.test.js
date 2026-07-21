const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_C03_POLICY_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_C03_POLICY_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_C03_POLICY_POSTGRES18_TEST";
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
  platform: "00000000-0000-4000-8000-00000000e001",
  tenantAdmin: "00000000-0000-4000-8000-00000000e002",
  orgA: "00000000-0000-4000-8000-00000000e101",
  orgB: "00000000-0000-4000-8000-00000000e102",
  licenseeA: "00000000-0000-4000-8000-00000000e201",
  licenseeB: "00000000-0000-4000-8000-00000000e202",
};

const setupSql = `
GRANT CONNECT ON DATABASE ${database} TO mscqr_rls_wave_c_app;
GRANT USAGE ON SCHEMA public, app_rls TO mscqr_rls_wave_c_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_policy_rule_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_policy_context_valid() TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_list_policy_rules(text,boolean,integer,integer) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_create_policy_rule(jsonb) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_update_policy_rule(text,jsonb) TO mscqr_rls_wave_c_app;
GRANT INSERT (id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"ipAddress","ipHash","userAgent") ON public."AuditLog" TO mscqr_rls_wave_c_app;
GRANT INSERT (id,"eventType",payload,"updatedAt") ON public."SecurityEventOutbox" TO mscqr_rls_wave_c_app;

DROP POLICY IF EXISTS c03_policy_audit_insert ON public."AuditLog";
DROP POLICY IF EXISTS c02_audit_insert ON public."AuditLog";
DROP POLICY IF EXISTS session_c_audit_insert ON public."AuditLog";
CREATE POLICY c03_policy_audit_insert ON public."AuditLog" FOR INSERT TO mscqr_rls_wave_c_app WITH CHECK (
  "userId" = current_setting('app.user_id', true)
  AND "orgId" = current_setting('app.organization_id', true)
  AND "licenseeId" = current_setting('app.licensee_id', true)
  AND action IN ('IR_POLICY_RULES_LISTED','POLICY_RULE_CREATED','POLICY_RULE_UPDATED')
  AND app_rls.c03_policy_context_valid()
);
DROP POLICY IF EXISTS c03_policy_outbox_insert ON public."SecurityEventOutbox";
DROP POLICY IF EXISTS c02_outbox_insert ON public."SecurityEventOutbox";
DROP POLICY IF EXISTS session_c_security_outbox_insert ON public."SecurityEventOutbox";
CREATE POLICY c03_policy_outbox_insert ON public."SecurityEventOutbox" FOR INSERT TO mscqr_rls_wave_c_app WITH CHECK (
  app_rls.c03_policy_context_valid()
  AND payload->>'userId' = current_setting('app.user_id', true)
  AND payload->>'orgId' = current_setting('app.organization_id', true)
  AND payload->>'licenseeId' = current_setting('app.licensee_id', true)
);
DO $$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['User','Organization','Licensee','PolicyRule','ActionIdempotencyKey','AuditLog','SecurityEventOutbox']
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', table_name);
  END LOOP;
END $$;
`;

const claims = (overrides = {}) => ({
  userId: ids.platform,
  email: "c03-platform@session-c.invalid",
  role: "PLATFORM_SUPER_ADMIN",
  orgId: null,
  licenseeId: null,
  linkedLicenseeIds: [],
  sessionId: "session-c-c03-platform",
  sessionStage: "ACTIVE",
  authAssurance: "ADMIN_MFA",
  authenticatedAt: new Date().toISOString(),
  mfaVerifiedAt: new Date().toISOString(),
  ...overrides,
});

const invoke = async (controller, { user = claims(), body = {}, params = {}, query = {}, requestId }) => {
  const response = { status: 200, body: null };
  const req = {
    user, body, params, query, requestId, ip: "127.0.0.1", headers: {},
    get(name) { return name.toLowerCase() === "user-agent" ? "session-c-c03-policy" : this.headers[name.toLowerCase()]; },
  };
  const res = {
    status(code) { response.status = code; return this; },
    json(payload) { response.body = payload; return this; },
  };
  await controller(req, res);
  return response;
};

const createBody = (name = "C03 velocity policy") => ({
  licenseeId: ids.licenseeA,
  name,
  description: "Focused PostgreSQL 18 policy proof",
  ruleType: "DISTINCT_DEVICES",
  isActive: true,
  threshold: 3,
  windowMinutes: 30,
  severity: "HIGH",
  autoCreateIncident: true,
  incidentSeverity: "HIGH",
  incidentPriority: "P2",
  actionConfig: { action: "ALERT" },
});

async function main() {
  if (!enabled) return console.log("C03 policy PostgreSQL 18 proof skipped");
  assert(confirmed, "C03 policy PostgreSQL proof confirmation is required");
  assert.equal(Math.floor(Number(psql("select current_setting('server_version_num')::int")) / 10000), 18);
  psqlFile(path.resolve(__dirname, "../../../src/rls-waves/session-c/c03/c03Boundary.sql"));
  psqlFile(path.resolve(__dirname, "../../../src/rls-waves/session-c/c03/c03Policy.sql"));
  psql(setupSql);
  psql(`
    DELETE FROM public."SecurityEventOutbox" WHERE payload->>'userId' IN ('${ids.platform}','${ids.tenantAdmin}');
    DELETE FROM public."AuditLog" WHERE "userId" IN ('${ids.platform}','${ids.tenantAdmin}');
    DELETE FROM public."ActionIdempotencyKey" WHERE action LIKE 'c03-policy-%';
    DELETE FROM public."PolicyRule" WHERE "licenseeId" IN ('${ids.licenseeA}','${ids.licenseeB}');
    DELETE FROM public."User" WHERE id IN ('${ids.platform}','${ids.tenantAdmin}');
    DELETE FROM public."Licensee" WHERE id IN ('${ids.licenseeA}','${ids.licenseeB}');
    DELETE FROM public."Organization" WHERE id IN ('${ids.orgA}','${ids.orgB}');
    INSERT INTO public."Organization" (id,name,"isActive","updatedAt") VALUES
      ('${ids.orgA}','C03 Policy Org A',true,transaction_timestamp()),
      ('${ids.orgB}','C03 Policy Org B',true,transaction_timestamp());
    INSERT INTO public."Licensee" (id,"orgId",name,prefix,"isActive","updatedAt") VALUES
      ('${ids.licenseeA}','${ids.orgA}','C03 Policy Tenant A','C3A',true,transaction_timestamp()),
      ('${ids.licenseeB}','${ids.orgB}','C03 Policy Tenant B','C3B',false,transaction_timestamp());
    INSERT INTO public."User" (id,email,name,role,status,"isActive","updatedAt") VALUES
      ('${ids.platform}','c03-platform@session-c.invalid','C03 Platform','PLATFORM_SUPER_ADMIN','ACTIVE',true,transaction_timestamp());
    INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES
      ('${ids.tenantAdmin}','c03-admin@session-c.invalid','C03 Tenant Admin','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,transaction_timestamp());
  `);

  process.env.NODE_ENV = "test";
  process.env.DATABASE_URL = appUrl;
  process.env.IP_HASH_SALT_CURRENT = "session-c-c03-policy-local-proof-only";
  const prismaModule = require("../../../dist/config/database");
  const prisma = prismaModule.default || prismaModule;
  const controller = require("../../../dist/controllers/irPolicyController");

  const requestId = "00000000-0000-4000-8000-00000000e301";
  const [first, replay] = await Promise.all([
    invoke(controller.createIrPolicy, { body: createBody(), requestId }),
    invoke(controller.createIrPolicy, { body: createBody(), requestId }),
  ]);
  assert.deepEqual([first.status, replay.status].sort(), [201, 201], JSON.stringify([first.body, replay.body]));
  assert.equal(first.body.data.id, replay.body.data.id);
  assert.equal(first.body.data.createdByUserId, ids.platform);
  assert.equal(first.body.data.licenseeId, ids.licenseeA);
  assert.equal(first.body.data.orgId, ids.orgA);
  assert(!Object.prototype.hasOwnProperty.call(first.body.data, "__c03Replay"));

  const listed = await invoke(controller.listIrPolicies, {
    query: { licenseeId: ids.licenseeA, limit: "20", offset: "0" },
    requestId: "00000000-0000-4000-8000-00000000e302",
  });
  assert.equal(listed.status, 200, JSON.stringify(listed.body));
  assert.equal(listed.body.data.total, 1);
  assert.equal(listed.body.data.rules[0].id, first.body.data.id);

  const updateRequestId = "00000000-0000-4000-8000-00000000e303";
  const updated = await invoke(controller.patchIrPolicy, {
    params: { id: first.body.data.id }, body: { threshold: 7 }, requestId: updateRequestId,
  });
  const updateReplay = await invoke(controller.patchIrPolicy, {
    params: { id: first.body.data.id }, body: { threshold: 7 }, requestId: updateRequestId,
  });
  assert.equal(updated.status, 200, JSON.stringify(updated.body));
  assert.equal(updateReplay.status, 200, JSON.stringify(updateReplay.body));
  assert.deepEqual(updateReplay.body.data, updated.body.data);

  const wrongRole = await invoke(controller.createIrPolicy, {
    user: claims({ userId: ids.tenantAdmin, role: "LICENSEE_ADMIN", orgId: ids.orgA, licenseeId: ids.licenseeA }),
    body: createBody("Must be denied"), requestId: "00000000-0000-4000-8000-00000000e304",
  });
  assert.equal(wrongRole.status, 403);
  const wrongAssurance = await invoke(controller.createIrPolicy, {
    user: claims({ authAssurance: "PASSWORD", mfaVerifiedAt: null }),
    body: createBody("Must be denied too"), requestId: "00000000-0000-4000-8000-00000000e305",
  });
  assert.equal(wrongAssurance.status, 403);
  const inactiveParent = await invoke(controller.createIrPolicy, {
    body: { ...createBody("Inactive parent"), licenseeId: ids.licenseeB },
    requestId: "00000000-0000-4000-8000-00000000e306",
  });
  assert.equal(inactiveParent.status, 403);
  const protectedColumn = await invoke(controller.createIrPolicy, {
    body: { ...createBody("Protected column"), createdByUserId: ids.tenantAdmin },
    requestId: "00000000-0000-4000-8000-00000000e307",
  });
  assert.equal(protectedColumn.status, 400);

  psql(`UPDATE public."User" SET "isActive"=false,status='DISABLED',"disabledAt"=transaction_timestamp() WHERE id='${ids.platform}'`);
  const disabled = await invoke(controller.listIrPolicies, {
    query: { licenseeId: ids.licenseeA }, requestId: "00000000-0000-4000-8000-00000000e308",
  });
  assert.equal(disabled.status, 403);
  psql(`UPDATE public."User" SET "isActive"=true,status='ACTIVE',"disabledAt"=NULL WHERE id='${ids.platform}'`);

  await assert.rejects(() => prisma.policyRule.findMany({ take: 1 }), /permission denied|denied/i);
  const [rules, createAudits, updateAudits, outbox, forced] = psql(`
    SELECT concat_ws('|',
      (SELECT count(*) FROM public."PolicyRule" WHERE "licenseeId"='${ids.licenseeA}'),
      (SELECT count(*) FROM public."AuditLog" WHERE action='POLICY_RULE_CREATED' AND "userId"='${ids.platform}'),
      (SELECT count(*) FROM public."AuditLog" WHERE action='POLICY_RULE_UPDATED' AND "userId"='${ids.platform}'),
      (SELECT count(*) FROM public."SecurityEventOutbox" WHERE payload->>'userId'='${ids.platform}' AND payload->>'action' IN ('POLICY_RULE_CREATED','POLICY_RULE_UPDATED')),
      (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relname=ANY(ARRAY['User','Organization','Licensee','PolicyRule','ActionIdempotencyKey','AuditLog','SecurityEventOutbox'])
          AND c.relrowsecurity AND c.relforcerowsecurity))
  `).split("|").map(Number);
  assert.equal(rules, 1);
  assert.equal(createAudits, 1);
  assert.equal(updateAudits, 1);
  assert.equal(outbox, 2);
  assert.equal(forced, 7);

  await prisma.$disconnect();
  console.log("C03 policy PostgreSQL 18 application-path proof passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
