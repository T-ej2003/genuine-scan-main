const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_SESSION_C_ADMIN_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_SESSION_C_ADMIN_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_SESSION_C_ADMIN_POSTGRES18_TEST";
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
  platform: "00000000-0000-4000-8000-00000000c001",
  orgA: "00000000-0000-4000-8000-00000000c101",
  orgB: "00000000-0000-4000-8000-00000000c102",
  licenseeA: "00000000-0000-4000-8000-00000000c201",
  licenseeB: "00000000-0000-4000-8000-00000000c202",
  tenantAdmin: "00000000-0000-4000-8000-00000000c301",
};

const setupSql = `
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mscqr_rls_wave_c_app') THEN
    CREATE ROLE mscqr_rls_wave_c_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END $$;
GRANT CONNECT ON DATABASE ${database} TO mscqr_rls_wave_c_app;
GRANT USAGE ON SCHEMA public, app_rls TO mscqr_rls_wave_c_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.session_c_audit_context_valid() TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.session_c_create_licensee(jsonb) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.session_c_update_licensee(jsonb) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.session_c_delete_licensee(jsonb) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.session_c_create_user(jsonb) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.session_c_update_user(jsonb) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.session_c_delete_user(jsonb) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.session_c_restore_manufacturer(jsonb) TO mscqr_rls_wave_c_app;
GRANT EXECUTE ON FUNCTION app_rls.session_c_upsert_manufacturer_licensee_link(jsonb) TO mscqr_rls_wave_c_app;
GRANT INSERT (id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"ipAddress","ipHash","userAgent") ON public."AuditLog" TO mscqr_rls_wave_c_app;
GRANT INSERT (id,"eventType",payload,"updatedAt") ON public."SecurityEventOutbox" TO mscqr_rls_wave_c_app;
DROP POLICY IF EXISTS session_c_audit_insert ON public."AuditLog";
CREATE POLICY session_c_audit_insert ON public."AuditLog" FOR INSERT TO mscqr_rls_wave_c_app
  WITH CHECK ("userId"=current_setting('app.user_id',true) AND app_rls.session_c_audit_context_valid());
DROP POLICY IF EXISTS session_c_security_outbox_insert ON public."SecurityEventOutbox";
CREATE POLICY session_c_security_outbox_insert ON public."SecurityEventOutbox" FOR INSERT TO mscqr_rls_wave_c_app
  WITH CHECK (app_rls.session_c_audit_context_valid());
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['User','Organization','Licensee','ManufacturerLicenseeLink','Batch','QRRange','QRCode','RefreshToken','ActionIdempotencyKey','AuditLog','SecurityEventOutbox']
  LOOP EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t); END LOOP;
END $$;
`;

const platformClaims = () => ({
  userId: ids.platform, email: "platform@example.invalid", role: "PLATFORM_SUPER_ADMIN",
  orgId: null, licenseeId: null, linkedLicenseeIds: [], sessionId: "session-c-platform",
  sessionStage: "ACTIVE", authAssurance: "ADMIN_MFA", authenticatedAt: new Date().toISOString(),
  mfaVerifiedAt: new Date().toISOString(),
});

const tenantClaims = () => ({
  userId: ids.tenantAdmin, email: "admin-a@example.invalid", role: "LICENSEE_ADMIN",
  orgId: ids.orgA, licenseeId: ids.licenseeA, linkedLicenseeIds: [], sessionId: "session-c-tenant",
  sessionStage: "ACTIVE", authAssurance: "ADMIN_MFA", authenticatedAt: new Date().toISOString(),
  mfaVerifiedAt: new Date().toISOString(),
});

const invoke = async (controller, { user, body = {}, params = {}, query = {}, requestId, key }) => {
  const response = { status: 200, body: null };
  const req = {
    user, body, params, query, requestId, ip: "127.0.0.1",
    headers: key ? { "x-idempotency-key": key } : {},
    get(name) { return name.toLowerCase() === "user-agent" ? "session-c-postgres18" : this.headers[name.toLowerCase()]; },
  };
  const res = {
    status(code) { response.status = code; return this; },
    json(payload) { response.body = payload; return this; },
  };
  await controller(req, res);
  return response;
};

const licenseeBody = (prefix, email) => ({
  licensee: { name: `Session C ${prefix}`, prefix, isActive: true },
  admin: { name: `${prefix} Admin`, email, password: "ValidPass123!", sendInvite: false },
});

async function main() {
  if (!enabled) return console.log("Session C administration PostgreSQL 18 proof skipped");
  assert(confirmed, "Session C administration PostgreSQL proof confirmation is required");
  const serverVersion = Number(psql("select current_setting('server_version_num')::int"));
  assert.equal(Math.floor(serverVersion / 10000), 18);
  const sqlPath = path.resolve(__dirname, "../../../src/rls-waves/session-c/c01/administration.sql");
  psqlFile(sqlPath);
  psql(setupSql);
  psql(`
    DELETE FROM public."AuditLog" WHERE "userId" IN ('${ids.platform}','${ids.tenantAdmin}');
    DELETE FROM public."ActionIdempotencyKey" WHERE scope='${ids.platform}';
    DELETE FROM public."User" WHERE email LIKE '%@session-c.invalid' OR id IN ('${ids.platform}','${ids.tenantAdmin}');
    DELETE FROM public."Licensee" WHERE prefix IN ('SCA','SCB','SCC','SCD') OR id IN ('${ids.licenseeA}','${ids.licenseeB}');
    DELETE FROM public."Organization" WHERE id IN ('${ids.orgA}','${ids.orgB}') OR name LIKE 'Session C %';
    INSERT INTO public."Organization" (id,name,"isActive","updatedAt") VALUES ('${ids.orgA}','Session C Org A',true,transaction_timestamp()),('${ids.orgB}','Session C Org B',true,transaction_timestamp());
    INSERT INTO public."Licensee" (id,"orgId",name,prefix,"isActive","updatedAt") VALUES ('${ids.licenseeA}','${ids.orgA}','Session C Tenant A','SCA',true,transaction_timestamp()),('${ids.licenseeB}','${ids.orgB}','Session C Tenant B','SCD',true,transaction_timestamp());
    INSERT INTO public."User" (id,email,name,role,status,"isActive","updatedAt") VALUES ('${ids.platform}','platform@session-c.invalid','Platform Admin','PLATFORM_SUPER_ADMIN','ACTIVE',true,transaction_timestamp());
    INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES ('${ids.tenantAdmin}','admin-a@session-c.invalid','Tenant Admin','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,transaction_timestamp());
  `);

    process.env.NODE_ENV = "test";
    process.env.DATABASE_URL = appUrl;
    process.env.IP_HASH_SALT_CURRENT = "session-c-postgres18-local-proof-only";
    const prismaModule = require("../../../dist/config/database");
    const prisma = prismaModule.default || prismaModule;
    const licenseeController = require("../../../dist/controllers/licenseeController");
    const userController = require("../../../dist/controllers/userController");

    const first = await invoke(licenseeController.createLicensee, {
      user: platformClaims(), body: licenseeBody("SCB", "brand-admin@session-c.invalid"),
      requestId: "00000000-0000-4000-8000-00000000c401", key: "session-c-create-replay",
    });
    assert.equal(first.status, 201, JSON.stringify(first.body));
    const replay = await invoke(licenseeController.createLicensee, {
      user: platformClaims(), body: licenseeBody("SCB", "brand-admin@session-c.invalid"),
      requestId: "00000000-0000-4000-8000-00000000c402", key: "session-c-create-replay",
    });
    assert.equal(replay.status, 200, JSON.stringify(replay.body));
    assert.equal(replay.body.data.licensee.id, first.body.data.licensee.id);

    const concurrent = await Promise.all([
      invoke(licenseeController.createLicensee, { user: platformClaims(), body: licenseeBody("SCC", "winner-1@session-c.invalid"), requestId: "00000000-0000-4000-8000-00000000c403", key: "winner-1" }),
      invoke(licenseeController.createLicensee, { user: platformClaims(), body: licenseeBody("SCC", "winner-2@session-c.invalid"), requestId: "00000000-0000-4000-8000-00000000c404", key: "winner-2" }),
    ]);
    assert.deepEqual(concurrent.map((row) => row.status).sort(), [201, 409], JSON.stringify(concurrent));

    const foreign = await invoke(userController.createUser, {
      user: tenantClaims(), body: { email: "foreign@session-c.invalid", password: "ValidPass123!", name: "Foreign", role: "MANUFACTURER", licenseeId: ids.licenseeB },
      requestId: "00000000-0000-4000-8000-00000000c405",
    });
    assert.equal(foreign.status, 403);

    const createdUser = await invoke(userController.createUser, {
      user: platformClaims(), body: { email: "manufacturer@session-c.invalid", password: "ValidPass123!", name: "Manufacturer", role: "MANUFACTURER", licenseeId: ids.licenseeA },
      requestId: "00000000-0000-4000-8000-00000000c406",
    });
    assert.equal(createdUser.status, 201, JSON.stringify(createdUser.body));
    const manufacturerId = createdUser.body.data.id;
    assert.match(manufacturerId, /^[0-9a-f-]{36}$/i);
    psql(`INSERT INTO public."RefreshToken" (id,"userId","tokenHash","expiresAt") VALUES ('00000000-0000-4000-8000-00000000c501','${manufacturerId}','session-c-refresh-token-hash',transaction_timestamp()+interval '1 day')`);
    const disabled = await invoke(userController.deleteUser, {
      user: platformClaims(), params: { id: manufacturerId }, query: { hard: "false" },
      requestId: "00000000-0000-4000-8000-00000000c407",
    });
    assert.equal(disabled.status, 200, JSON.stringify(disabled.body));
    const [isActive, status, revokedAt] = psql(`SELECT u."isActive",u.status,r."revokedAt" FROM public."User" u JOIN public."RefreshToken" r ON r."userId"=u.id WHERE u.id='${manufacturerId}'`).split("|");
    assert.equal(isActive, "f");
    assert.equal(status, "DISABLED");
    assert(revokedAt);

    psql(`UPDATE public."User" SET "isActive"=false,"disabledAt"=transaction_timestamp(),status='DISABLED' WHERE id='${ids.platform}'`);
    const stale = await invoke(licenseeController.updateLicensee, {
      user: platformClaims(), params: { id: ids.licenseeA }, body: { name: "Must Not Commit" },
      requestId: "00000000-0000-4000-8000-00000000c408",
    });
    assert.equal(stale.status, 403, JSON.stringify(stale.body));
    psql(`UPDATE public."User" SET "isActive"=true,"disabledAt"=NULL,status='ACTIVE' WHERE id='${ids.platform}'`);

    await assert.rejects(() => prisma.$queryRawUnsafe(`SELECT email FROM public."User" LIMIT 1`), /permission denied|denied/i);
    const [audits, outbox, forced] = psql(`
      SELECT concat_ws('|',
        (SELECT count(*) FROM public."AuditLog" WHERE "userId"='${ids.platform}'),
        (SELECT count(*) FROM public."SecurityEventOutbox" WHERE "eventType"='AUDIT_LOG'),
        (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['User','Organization','Licensee','ManufacturerLicenseeLink','Batch','QRRange','QRCode','RefreshToken','ActionIdempotencyKey','AuditLog','SecurityEventOutbox']) AND c.relrowsecurity AND c.relforcerowsecurity))
    `).split("|");
    assert(Number(audits) >= 4);
    assert(Number(outbox) >= 4);
    assert.equal(Number(forced), 11);
    await prisma.$disconnect();
    console.log("Session C administration PostgreSQL 18 application-path proof passed");
}

main().catch((error) => { console.error(error); process.exit(1); });
