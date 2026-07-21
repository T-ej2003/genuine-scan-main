const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_C03_POLICY_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_C03_POLICY_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_C03_POLICY_POSTGRES18_TEST";
const database = "mscqr_rls_wave_c_admin_governance_operator";
const adminUrl = `postgresql://mscqr_rls_cert_admin@127.0.0.1:55434/${database}`;
const appUrl = `postgresql://mscqr_rls_wave_c03_policy_app@127.0.0.1:55434/${database}`;

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
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mscqr_rls_wave_c03_policy_app') THEN
    CREATE ROLE mscqr_rls_wave_c03_policy_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END $$;
GRANT CONNECT ON DATABASE ${database} TO mscqr_rls_wave_c03_policy_app;
GRANT USAGE ON SCHEMA public, app_rls TO mscqr_rls_wave_c03_policy_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mscqr_rls_wave_c03_policy_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c03_policy_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_platform_actor_scope(jsonb,text,text) TO mscqr_rls_wave_c03_policy_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_policy_rule_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c03_policy_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_policy_context_valid() TO mscqr_rls_wave_c03_policy_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_list_policy_rules(text,boolean,integer,integer) TO mscqr_rls_wave_c03_policy_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_list_platform_policy_rules(text,boolean,integer,integer) TO mscqr_rls_wave_c03_policy_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_create_policy_rule(jsonb) TO mscqr_rls_wave_c03_policy_app;
GRANT EXECUTE ON FUNCTION app_rls.c03_update_policy_rule(text,jsonb) TO mscqr_rls_wave_c03_policy_app;
GRANT INSERT (id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"ipAddress","ipHash","userAgent") ON public."AuditLog" TO mscqr_rls_wave_c03_policy_app;
GRANT INSERT (id,"eventType",payload,"updatedAt") ON public."SecurityEventOutbox" TO mscqr_rls_wave_c03_policy_app;
GRANT SELECT (id,email,role,"licenseeId","orgId","isActive",status,"deletedAt","disabledAt") ON public."User" TO mscqr_rls_wave_c03_policy_app;
GRANT SELECT (id,"userId","isEnabled","verifiedAt","lastUsedAt","backupCodesHash","createdAt","updatedAt") ON public."AdminMfaCredential" TO mscqr_rls_wave_c03_policy_app;
GRANT SELECT (id,"userId",label,transports,"lastUsedAt","createdAt","updatedAt") ON public."AdminWebAuthnCredential" TO mscqr_rls_wave_c03_policy_app;
GRANT SELECT (id,"userId",type,label,"legacySource",transports,"lastUsedAt","createdAt","updatedAt","disabledAt") ON public."UserMfaFactor" TO mscqr_rls_wave_c03_policy_app;
GRANT SELECT (id,"userId","usedAt") ON public."UserBackupCode" TO mscqr_rls_wave_c03_policy_app;

DROP POLICY IF EXISTS c03_policy_checkpoint_user_self_select ON public."User";
CREATE POLICY c03_policy_checkpoint_user_self_select ON public."User" FOR SELECT TO mscqr_rls_wave_c03_policy_app USING (
  id = current_setting('app.user_id', true)
  AND role::text = current_setting('app.role', true)
  AND "isActive" AND status = 'ACTIVE'::public."UserStatus"
  AND "deletedAt" IS NULL AND "disabledAt" IS NULL
);
DROP POLICY IF EXISTS c03_policy_checkpoint_admin_mfa_self_select ON public."AdminMfaCredential";
CREATE POLICY c03_policy_checkpoint_admin_mfa_self_select ON public."AdminMfaCredential" FOR SELECT TO mscqr_rls_wave_c03_policy_app USING (
  "userId" = current_setting('app.user_id', true)
);
DROP POLICY IF EXISTS c03_policy_checkpoint_webauthn_self_select ON public."AdminWebAuthnCredential";
CREATE POLICY c03_policy_checkpoint_webauthn_self_select ON public."AdminWebAuthnCredential" FOR SELECT TO mscqr_rls_wave_c03_policy_app USING (
  "userId" = current_setting('app.user_id', true)
);
DROP POLICY IF EXISTS c03_policy_checkpoint_factor_self_select ON public."UserMfaFactor";
CREATE POLICY c03_policy_checkpoint_factor_self_select ON public."UserMfaFactor" FOR SELECT TO mscqr_rls_wave_c03_policy_app USING (
  "userId" = current_setting('app.user_id', true)
);
DROP POLICY IF EXISTS c03_policy_checkpoint_backup_code_self_select ON public."UserBackupCode";
CREATE POLICY c03_policy_checkpoint_backup_code_self_select ON public."UserBackupCode" FOR SELECT TO mscqr_rls_wave_c03_policy_app USING (
  "userId" = current_setting('app.user_id', true)
);

DROP POLICY IF EXISTS c03_policy_checkpoint_audit_insert ON public."AuditLog";
CREATE POLICY c03_policy_checkpoint_audit_insert ON public."AuditLog" FOR INSERT TO mscqr_rls_wave_c03_policy_app WITH CHECK (
  "userId" = current_setting('app.user_id', true)
  AND "orgId" IS NOT DISTINCT FROM NULLIF(current_setting('app.organization_id', true), '')
  AND "licenseeId" IS NOT DISTINCT FROM NULLIF(current_setting('app.licensee_id', true), '')
  AND action IN ('IR_POLICY_RULES_LISTED','POLICY_RULE_CREATED','POLICY_RULE_UPDATED')
  AND app_rls.c03_policy_context_valid()
);
DROP POLICY IF EXISTS c03_policy_checkpoint_outbox_insert ON public."SecurityEventOutbox";
CREATE POLICY c03_policy_checkpoint_outbox_insert ON public."SecurityEventOutbox" FOR INSERT TO mscqr_rls_wave_c03_policy_app WITH CHECK (
  app_rls.c03_policy_context_valid()
  AND payload->>'userId' = current_setting('app.user_id', true)
  AND payload->>'orgId' IS NOT DISTINCT FROM NULLIF(current_setting('app.organization_id', true), '')
  AND payload->>'licenseeId' IS NOT DISTINCT FROM NULLIF(current_setting('app.licensee_id', true), '')
);
DO $$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['User','Organization','Licensee','PolicyRule','ActionIdempotencyKey','AuditLog','SecurityEventOutbox','AdminMfaCredential','AdminWebAuthnCredential','UserMfaFactor','UserBackupCode']
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

const withServer = async (app, callback) => {
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  try {
    await callback(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
};

const routeRequest = async (baseUrl, method, route, { token, cookie, requestId, body } = {}) => {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (cookie) headers.cookie = cookie;
  if (requestId) headers["x-request-id"] = requestId;
  if (body) headers["content-type"] = "application/json";
  const response = await fetch(`${baseUrl}${route}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: response.status, body: await response.json() };
};

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
    DELETE FROM public."ActionIdempotencyKey"
     WHERE scope='${ids.licenseeA}'
       AND (
         "keyHash"='c03-policy:${ids.licenseeA}:${ids.platform}:create:00000000-0000-4000-8000-00000000e301'
         OR "keyHash" LIKE 'c03-policy:${ids.licenseeA}:${ids.platform}:update:%:00000000-0000-4000-8000-00000000e303'
       );
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
    INSERT INTO public."AdminMfaCredential" (
      id,"userId","secretCiphertext","secretIv","secretTag","backupCodesHash","isEnabled","verifiedAt","updatedAt"
    ) VALUES (
      '00000000-0000-4000-8000-00000000e401','${ids.platform}','local-proof-only','local-proof-only','local-proof-only',ARRAY[]::text[],true,transaction_timestamp(),transaction_timestamp()
    );
  `);

  process.env.NODE_ENV = "test";
  process.env.DATABASE_URL = appUrl;
  process.env.IP_HASH_SALT_CURRENT = "session-c-c03-policy-local-proof-only";
  process.env.JWT_SECRET = "session-c-c03-policy-route-proof-jwt-secret-only";
  process.env.JWT_SECRET_CURRENT = process.env.JWT_SECRET;
  process.env.MSCQR_FULL_RLS_REDUCED_SURFACE_ENABLED = "false";
  const prismaModule = require("../../../dist/config/database");
  const prisma = prismaModule.default || prismaModule;
  const controller = require("../../../dist/controllers/irPolicyController");
  const { signAccessToken } = require("../../../dist/services/auth/tokenService");
  const { sealCookieToken } = require("../../../dist/services/auth/cookieTokenProtectionService");
  const { createBackendApp } = require("../../../dist/app");

  const requestId = "00000000-0000-4000-8000-00000000e301";
  const updateRequestId = "00000000-0000-4000-8000-00000000e303";
  const routeApp = createBackendApp();
  const platformToken = signAccessToken(claims());
  const staleMfaToken = signAccessToken(claims({ mfaVerifiedAt: new Date(0).toISOString() }));
  const tenantToken = signAccessToken(claims({
    userId: ids.tenantAdmin,
    email: "c03-admin@session-c.invalid",
    role: "LICENSEE_ADMIN",
    orgId: ids.orgA,
    licenseeId: ids.licenseeA,
    authAssurance: "PASSWORD",
    mfaVerifiedAt: null,
  }));
  let first;
  await withServer(routeApp, async (baseUrl) => {
    const [created, replay] = await Promise.all([
      routeRequest(baseUrl, "POST", "/api/ir/policies", {
        token: platformToken,
        requestId,
        body: createBody(),
      }),
      routeRequest(baseUrl, "POST", "/api/ir/policies", {
        token: platformToken,
        requestId,
        body: createBody(),
      }),
    ]);
    assert.deepEqual([created.status, replay.status].sort(), [201, 201], JSON.stringify([created.body, replay.body]));
    assert.equal(created.body.data.id, replay.body.data.id);
    first = created;
    assert.equal(first.body.data.createdByUserId, ids.platform);
    assert.equal(first.body.data.licenseeId, ids.licenseeA);
    assert.equal(first.body.data.orgId, ids.orgA);
    assert(!Object.prototype.hasOwnProperty.call(first.body.data, "__c03Replay"));

    const conflictingReplay = await routeRequest(baseUrl, "POST", "/api/ir/policies", {
      token: platformToken,
      requestId,
      body: createBody("Conflicting replay"),
    });
    assert.equal(conflictingReplay.status, 409, JSON.stringify(conflictingReplay.body));

    const listed = await routeRequest(baseUrl, "GET", `/api/ir/policies?licenseeId=${ids.licenseeA}&limit=20&offset=0`, {
      token: platformToken,
      requestId: "00000000-0000-4000-8000-00000000e302",
    });
    assert.equal(listed.status, 200, JSON.stringify(listed.body));
    assert.equal(listed.body.data.total, 1);
    assert.equal(listed.body.data.rules[0].id, first.body.data.id);
    assert.deepEqual(listed.body.data.rules[0].organization, { id: ids.orgA, name: "C03 Policy Org A" });
    assert.deepEqual(listed.body.data.rules[0].licensee, { id: ids.licenseeA, name: "C03 Policy Tenant A", prefix: "C3A" });
    assert.deepEqual(listed.body.data.rules[0].createdByUser, { id: ids.platform, email: "c03-platform@session-c.invalid", name: "C03 Platform" });

    const platformList = await routeRequest(baseUrl, "GET", "/api/ir/policies?limit=20&offset=0", {
      token: platformToken,
      requestId: "00000000-0000-4000-8000-00000000e309",
    });
    assert.equal(platformList.status, 200, JSON.stringify(platformList.body));
    assert(platformList.body.data.rules.some((row) => row.id === first.body.data.id));

    const updated = await routeRequest(baseUrl, "PATCH", `/api/ir/policies/${first.body.data.id}`, {
      token: platformToken,
      requestId: updateRequestId,
      body: { threshold: 7 },
    });
    const updateReplay = await routeRequest(baseUrl, "PATCH", `/api/ir/policies/${first.body.data.id}`, {
      token: platformToken,
      requestId: updateRequestId,
      body: { threshold: 7 },
    });
    assert.equal(updated.status, 200, JSON.stringify(updated.body));
    assert.equal(updateReplay.status, 200, JSON.stringify(updateReplay.body));
    assert.deepEqual(updateReplay.body.data, updated.body.data);

    const noSession = await routeRequest(baseUrl, "GET", "/api/ir/policies", {
      requestId: "00000000-0000-4000-8000-00000000e30b",
    });
    assert.equal(noSession.status, 401);
    const staleMfa = await routeRequest(baseUrl, "POST", "/api/ir/policies", {
      token: staleMfaToken,
      requestId: "00000000-0000-4000-8000-00000000e30c",
      body: createBody("Stale route MFA"),
    });
    assert.equal(staleMfa.status, 428);
    const wrongRouteRole = await routeRequest(baseUrl, "GET", "/api/ir/policies", {
      token: tenantToken,
      requestId: "00000000-0000-4000-8000-00000000e30d",
    });
    assert.equal(wrongRouteRole.status, 403);
    const missingCsrf = await routeRequest(baseUrl, "POST", "/api/ir/policies", {
      cookie: `aq_access=${sealCookieToken(platformToken, "auth.access")}`,
      requestId: "00000000-0000-4000-8000-00000000e30e",
      body: createBody("Missing route CSRF"),
    });
    assert.equal(missingCsrf.status, 403);
  });

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
        WHERE n.nspname='public' AND c.relname=ANY(ARRAY['User','Organization','Licensee','PolicyRule','ActionIdempotencyKey','AuditLog','SecurityEventOutbox','AdminMfaCredential','AdminWebAuthnCredential','UserMfaFactor','UserBackupCode'])
          AND c.relrowsecurity AND c.relforcerowsecurity))
  `).split("|").map(Number);
  assert.equal(rules, 1);
  assert.equal(createAudits, 1);
  assert.equal(updateAudits, 1);
  assert.equal(outbox, 2);
  assert.equal(forced, 11);

  await prisma.$disconnect();
  console.log("C03 policy PostgreSQL 18 application-path proof passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
