const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_C03_BOUNDARY_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_C03_BOUNDARY_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_C03_BOUNDARY_POSTGRES18_TEST";
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
  incidentA: "00000000-0000-4000-8000-00000000e301",
  incidentB: "00000000-0000-4000-8000-00000000e302",
};

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

async function main() {
  if (!enabled) return console.log("C03 actor/resource PostgreSQL 18 boundary proof skipped");
  assert(confirmed, "C03 actor/resource PostgreSQL proof confirmation is required");
  assert.equal(Math.floor(Number(psql("select current_setting('server_version_num')::int")) / 10000), 18);
  psqlFile(path.resolve(__dirname, "../../../src/rls-waves/session-c/c03/c03Boundary.sql"));
  psql(`
    GRANT USAGE ON SCHEMA app_rls TO mscqr_rls_wave_c_app;
    GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c_app;
    GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_incident_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c_app;
    GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_policy_rule_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c_app;
    GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c_app;
    GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_incident_evidence_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c_app;
    GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_incident_evidence_storage_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c_app;
    GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_sensitive_approval_actor_scope(text,jsonb,text,text) TO mscqr_rls_wave_c_app;
    DO $$ DECLARE t text; BEGIN
      FOREACH t IN ARRAY ARRAY['User','Organization','Licensee','ManufacturerLicenseeLink','Incident','PolicyRule','CompliancePackJob','IncidentEvidence','SensitiveActionApproval']
      LOOP EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t); END LOOP;
    END $$;
    DELETE FROM public."Incident" WHERE id IN ('${ids.incidentA}','${ids.incidentB}');
    DELETE FROM public."User" WHERE id IN ('${ids.platform}','${ids.tenantAdmin}');
    DELETE FROM public."Licensee" WHERE id IN ('${ids.licenseeA}','${ids.licenseeB}');
    DELETE FROM public."Organization" WHERE id IN ('${ids.orgA}','${ids.orgB}');
    INSERT INTO public."Organization" (id,name,"isActive","updatedAt") VALUES
      ('${ids.orgA}','C03 Boundary Org A',true,transaction_timestamp()),
      ('${ids.orgB}','C03 Boundary Org B',true,transaction_timestamp());
    INSERT INTO public."Licensee" (id,"orgId",name,prefix,"isActive","updatedAt") VALUES
      ('${ids.licenseeA}','${ids.orgA}','C03 Boundary Tenant A','C3A',true,transaction_timestamp()),
      ('${ids.licenseeB}','${ids.orgB}','C03 Boundary Tenant B','C3B',true,transaction_timestamp());
    INSERT INTO public."User" (id,email,name,role,status,"isActive","updatedAt") VALUES
      ('${ids.platform}','c03-platform@session-c.invalid','C03 Platform','PLATFORM_SUPER_ADMIN','ACTIVE',true,transaction_timestamp());
    INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES
      ('${ids.tenantAdmin}','c03-admin@session-c.invalid','C03 Tenant Admin','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,transaction_timestamp());
    INSERT INTO public."Incident" (id,"qrCodeValue","licenseeId","incidentType",description,photos,tags,"updatedAt") VALUES
      ('${ids.incidentA}','C03-A','${ids.licenseeA}','OTHER','C03 incident A',ARRAY[]::text[],ARRAY[]::text[],transaction_timestamp()),
      ('${ids.incidentB}','C03-B','${ids.licenseeB}','OTHER','C03 incident B',ARRAY[]::text[],ARRAY[]::text[],transaction_timestamp());
  `);

  process.env.NODE_ENV = "test";
  process.env.DATABASE_URL = appUrl;
  const prismaModule = require("../../../dist/config/database");
  const prisma = prismaModule.default || prismaModule;
  const {
    C03AccessError,
    withC03ActorTransaction,
    withC03ResourceTransaction,
  } = require("../../../dist/rls-waves/session-c/c03/c03ActorBoundary");

  const actorBoundary = (user, licenseeId, requestId) => ({
    user,
    requestId,
    purpose: "governance-boundary-proof",
    licenseeId,
    allowedRoles: ["PLATFORM_SUPER_ADMIN", "LICENSEE_ADMIN"],
    requiredAssurance: "mfa-verified",
  });
  const platform = claims();
  const tenant = claims({
    userId: ids.tenantAdmin,
    email: "c03-admin@session-c.invalid",
    role: "LICENSEE_ADMIN",
    orgId: ids.orgA,
    licenseeId: ids.licenseeA,
    sessionId: "session-c-c03-tenant",
  });

  const platformContext = await withC03ActorTransaction(
    actorBoundary(platform, ids.licenseeA, "00000000-0000-4000-8000-00000000e701"),
    async (_tx, context) => context
  );
  assert.equal(platformContext.licenseeId, ids.licenseeA);
  assert.equal(platformContext.organizationId, ids.orgA);

  const tenantContext = await withC03ActorTransaction(
    actorBoundary(tenant, ids.licenseeA, "00000000-0000-4000-8000-00000000e702"),
    async (_tx, context) => context
  );
  assert.equal(tenantContext.organizationId, ids.orgA);

  const resourceContext = await withC03ResourceTransaction({
    user: platform,
    requestId: "00000000-0000-4000-8000-00000000e703",
    purpose: "incident-response-detail",
    resourceId: ids.incidentA,
    resourceType: "incident",
    allowedRoles: ["PLATFORM_SUPER_ADMIN", "LICENSEE_ADMIN"],
    requiredAssurance: "step-up-verified",
  }, async (_tx, context) => context);
  assert.equal(resourceContext.licenseeId, ids.licenseeA);

  await assert.rejects(
    withC03ResourceTransaction({
      user: tenant,
      requestId: "00000000-0000-4000-8000-00000000e704",
      purpose: "incident-response-detail",
      resourceId: ids.incidentB,
      resourceType: "incident",
      allowedRoles: ["LICENSEE_ADMIN"],
      requiredAssurance: "mfa-verified",
    }, async () => null),
    (error) => error instanceof C03AccessError
  );

  psql(`UPDATE public."User" SET "isActive"=false,status='DISABLED',"disabledAt"=transaction_timestamp() WHERE id='${ids.tenantAdmin}'`);
  await assert.rejects(
    withC03ActorTransaction(
      actorBoundary(tenant, ids.licenseeA, "00000000-0000-4000-8000-00000000e705"),
      async () => null
    ),
    /no longer authorized/
  );
  psql(`UPDATE public."User" SET "isActive"=true,status='ACTIVE',"disabledAt"=NULL WHERE id='${ids.tenantAdmin}'`);

  await assert.rejects(
    withC03ActorTransaction(
      actorBoundary({ ...platform, authAssurance: "PASSWORD", mfaVerifiedAt: null }, ids.licenseeA, "00000000-0000-4000-8000-00000000e706"),
      async () => null
    ),
    /MFA/
  );
  await assert.rejects(
    withC03ActorTransaction(actorBoundary(tenant, ids.licenseeB, "00000000-0000-4000-8000-00000000e707"), async () => null),
    /Access denied/
  );

  await assert.rejects(
    prisma.$queryRawUnsafe('SELECT id FROM public."Incident" LIMIT 1'),
    /permission denied/i,
    "protected table read without canonical context must be denied"
  );
  const functionCount = Number(psql(`
    SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='app_rls' AND p.proname IN (
       'c03_revalidate_actor_scope','c03_revalidate_incident_actor_scope','c03_revalidate_policy_rule_actor_scope',
       'c03_revalidate_compliance_pack_job_actor_scope','c03_revalidate_incident_evidence_actor_scope',
       'c03_revalidate_incident_evidence_storage_actor_scope','c03_revalidate_sensitive_approval_actor_scope'
     )
  `));
  assert.equal(functionCount, 7);
  await prisma.$disconnect();
  console.log("C03 actor/resource PostgreSQL 18 boundary proof passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
