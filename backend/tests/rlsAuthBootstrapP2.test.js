const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { createHash, generateKeyPairSync, randomBytes, sign } = require("node:crypto");
const http = require("node:http");
const path = require("node:path");
const { PrismaClient, UserRole, UserStatus } = require("@prisma/client");

const { dropP2TestDatabase, resolveP2TestDatabase, runPrismaSchemaSetup } = require("./helpers/p2TestDb");

const enabled = ["1", "true", "yes", "on"].includes(String(process.env.MSCQR_RLS_AUTH_BOOTSTRAP_TEST || "").toLowerCase());
if (!enabled) {
  console.log("RLS auth bootstrap P2 test skipped; set MSCQR_RLS_AUTH_BOOTSTRAP_TEST=true.");
  process.exit(0);
}

const backendRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(backendRoot, "..");
const candidateSql = path.join(repoRoot, "documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql");
const rollbackSql = path.join(repoRoot, "documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql");
const suffix = `${process.pid}_${Date.now()}`;
const runtimeRole = `mscqr_rls_auth_app_${suffix}`.toLowerCase();
const rlsReadRole = `mscqr_rls_auth_read_${suffix}`.toLowerCase();
const authOwnerRole = `mscqr_rls_auth_owner_${suffix}`.toLowerCase();
const unrelatedRole = `mscqr_rls_auth_other_${suffix}`.toLowerCase();
const ids = {
  orgA: "10000000-0000-4202-8000-000000000001",
  orgB: "10000000-0000-4202-8000-000000000002",
  licenseeA: "10000000-0000-4202-8100-000000000001",
  licenseeB: "10000000-0000-4202-8100-000000000002",
  manufacturerA: "10000000-0000-4202-8200-000000000001",
  manufacturerB: "10000000-0000-4202-8200-000000000002",
};
const emailA = "rls-auth-maker-a@mscqr.test";
const runtimeSecret = () => randomBytes(32).toString("base64url");
const distinctRuntimeSecret = (...excluded) => {
  let value;
  do value = runtimeSecret(); while (excluded.includes(value));
  return value;
};
const passwordA = runtimeSecret();
const wrongPassword = distinctRuntimeSecret(passwordA);
const passwordB = distinctRuntimeSecret(passwordA, wrongPassword);
const duplicatePasswordA = distinctRuntimeSecret(passwordA, wrongPassword, passwordB);
const duplicatePasswordB = distinctRuntimeSecret(passwordA, wrongPassword, passwordB, duplicatePasswordA);
const duplicateEmail = "rls-auth-duplicate@mscqr.test";
const batchA = "rls-auth-bootstrap-batch-a";
const printerA = "rls-auth-bootstrap-printer-a";

const quoteIdent = (value) => {
  assert.match(value, /^[a-z0-9_]+$/i);
  return `"${value}"`;
};
const buildRoleUrl = (databaseUrl, role) => {
  const parsed = new URL(databaseUrl);
  parsed.username = role;
  parsed.password = "";
  return parsed.toString();
};
const applySql = (databaseUrl, file) => execFileSync("psql", [
  databaseUrl,
  "-v", "ON_ERROR_STOP=1",
  "-v", `mscqr_app_role=${runtimeRole}`,
  "-v", `mscqr_rls_read_role=${rlsReadRole}`,
  "-v", `mscqr_auth_owner_role=${authOwnerRole}`,
  "-v", "mscqr_enable_shared_force_rls=true",
  "-v", "mscqr_enable_batch_force_rls=true",
  "-v", "mscqr_enable_printer_force_rls=true",
  "-f", file,
], { cwd: repoRoot, stdio: "inherit", env: { ...process.env } });
const adminSql = (databaseUrl, sql) => execFileSync(
  "psql",
  [databaseUrl, "-v", "ON_ERROR_STOP=1", "-c", sql],
  { cwd: repoRoot, stdio: "pipe", env: { ...process.env } }
);
const clearDistCache = () => {
  const distRoot = path.join(backendRoot, "dist");
  for (const key of Object.keys(require.cache)) if (key.startsWith(distRoot)) delete require.cache[key];
};
const messageOf = async (promise) => {
  try {
    await promise;
  } catch (error) {
    return error.message;
  }
  assert.fail("Expected rejection");
};

const withRlsContext = (client, context, callback) => client.$transaction(async (tx) => {
  const values = {
    "app.user_id": context.userId || "",
    "app.role": context.role,
    "app.licensee_id": context.licenseeId || "",
    "app.manufacturer_id": context.manufacturerId || "",
    "app.organization_id": context.organizationId || "",
    "app.is_platform_admin": context.isPlatformAdmin ? "true" : "false",
  };
  for (const [setting, value] of Object.entries(values)) {
    await tx.$executeRaw`SELECT set_config(${setting}, ${value}, true)`;
  }
  return callback(tx);
});

const toBase64Url = (value) => Buffer.from(value).toString("base64url");
const mergeResponseCookies = (jar, headers) => {
  const values = typeof headers.getSetCookie === "function"
    ? headers.getSetCookie()
    : [headers.get("set-cookie")].filter(Boolean);
  for (const value of values) {
    const pair = String(value).split(";", 1)[0];
    const separator = pair.indexOf("=");
    if (separator > 0) jar.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
};
const cookieHeader = (jar) => [...jar].map(([name, value]) => `${name}=${value}`).join("; ");

const startApp = async () => {
  const { createBackendApp } = require("../dist/app");
  const server = http.createServer(createBackendApp());
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}` };
};

const request = async (baseUrl, method, route, body, jar = new Map(), bearer = null) => {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  if (jar.size) headers.cookie = cookieHeader(jar);
  if (method !== "GET" && jar.has("aq_csrf")) headers["x-csrf-token"] = jar.get("aq_csrf");
  const response = await fetch(`${baseUrl}${route}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  mergeResponseCookies(jar, response.headers);
  const text = await response.text();
  let payload = null;
  try { payload = text ? JSON.parse(text) : null; } catch {}
  return { status: response.status, payload };
};

const main = async () => {
  let dbInfo;
  let admin;
  let app;
  let server;
  let httpDatabase;
  let rlsReadDatabase;
  let candidateApplied = false;
  let primaryError = null;

  try {
    dbInfo = resolveP2TestDatabase();
    runPrismaSchemaSetup(dbInfo.databaseUrl);
    admin = new PrismaClient({ datasources: { db: { url: dbInfo.databaseUrl } } });
    const { hashPassword } = require("../dist/services/auth/passwordService");
    process.env.AUTH_MFA_ENCRYPTION_KEY = process.env.AUTH_MFA_ENCRYPTION_KEY || process.env.JWT_SECRET;
    process.env.WEBAUTHN_RP_ID = "localhost";
    process.env.WEBAUTHN_ALLOWED_ORIGINS = "http://localhost:8080";
    const { createTotpSecret, encryptTotpSecret } = require("../dist/services/auth/totpMfaProvider");
    const totpSecret = createTotpSecret();
    const encryptedTotp = encryptTotpSecret(totpSecret);
    const webAuthnKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const publicKeySpki = webAuthnKeys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
    const webAuthnCredentialId = "rls-auth-bootstrap-webauthn-credential";

    await admin.organization.createMany({ data: [
      { id: ids.orgA, name: "Auth RLS Org A" },
      { id: ids.orgB, name: "Auth RLS Org B" },
    ] });
    await admin.licensee.createMany({ data: [
      { id: ids.licenseeA, orgId: ids.orgA, name: "Auth RLS A", prefix: "ARLA" },
      { id: ids.licenseeB, orgId: ids.orgB, name: "Auth RLS B", prefix: "ARLB" },
    ] });
    await admin.user.createMany({ data: [
      {
        id: ids.manufacturerA,
        email: emailA,
        passwordHash: await hashPassword(passwordA),
        name: "Auth Maker A",
        role: UserRole.MANUFACTURER,
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
        status: UserStatus.ACTIVE,
        emailVerifiedAt: new Date(),
        failedLoginAttempts: 1,
      },
      {
        id: ids.manufacturerB,
        email: "rls-auth-maker-b@mscqr.test",
        passwordHash: await hashPassword(passwordB),
        name: "Auth Maker B",
        role: UserRole.MANUFACTURER,
        orgId: ids.orgB,
        licenseeId: ids.licenseeB,
        status: UserStatus.ACTIVE,
        emailVerifiedAt: new Date(),
      },
      {
        email: duplicateEmail,
        passwordHash: await hashPassword(duplicatePasswordA),
        name: "Duplicate lower",
        role: UserRole.MANUFACTURER,
        status: UserStatus.ACTIVE,
        emailVerifiedAt: new Date(),
      },
      {
        email: duplicateEmail.toUpperCase(),
        passwordHash: await hashPassword(duplicatePasswordB),
        name: "Duplicate upper",
        role: UserRole.MANUFACTURER,
        status: UserStatus.ACTIVE,
        emailVerifiedAt: new Date(),
      },
    ] });
    await admin.manufacturerLicenseeLink.createMany({ data: [
      { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeA, isPrimary: true },
      { manufacturerId: ids.manufacturerB, licenseeId: ids.licenseeB, isPrimary: true },
    ] });
    await admin.adminMfaCredential.create({
      data: {
        userId: ids.manufacturerA,
        ...encryptedTotp,
        backupCodesHash: [],
        isEnabled: true,
        verifiedAt: new Date(),
      },
    });
    await admin.adminWebAuthnCredential.create({
      data: {
        userId: ids.manufacturerA,
        label: "RLS forced test key",
        credentialId: webAuthnCredentialId,
        publicKeySpki,
        publicKeyAlgorithm: -7,
        counter: 0,
        transports: ["internal"],
      },
    });
    await admin.batch.create({
      data: {
        id: batchA,
        name: "RLS Auth Bootstrap Batch A",
        licenseeId: ids.licenseeA,
        manufacturerId: ids.manufacturerA,
        startCode: "RLSAUTH0001",
        endCode: "RLSAUTH0010",
        totalCodes: 10,
      },
    });
    await admin.printer.create({
      data: {
        id: printerA,
        name: "RLS Auth Bootstrap Printer A",
        connectionType: "NETWORK_DIRECT",
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
        assignedUserId: ids.manufacturerA,
      },
    });

    const runtime = quoteIdent(runtimeRole);
    const read = quoteIdent(rlsReadRole);
    const unrelated = quoteIdent(unrelatedRole);
    adminSql(dbInfo.databaseUrl, `
      CREATE ROLE ${runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
      CREATE ROLE ${read} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
      CREATE ROLE ${unrelated} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
      GRANT CONNECT ON DATABASE ${quoteIdent(new URL(dbInfo.databaseUrl).pathname.slice(1))} TO ${runtime}, ${read};
      GRANT USAGE ON SCHEMA public TO ${runtime}, ${read};
      REVOKE CREATE ON SCHEMA public FROM ${runtime}, ${read};
      GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${runtime};
      GRANT SELECT ON TABLE "Organization", "Licensee", "User", "ManufacturerLicenseeLink", "Batch", "InventoryStatusRollup", "QRCode", "PrintJob", "PrintSession", "PrintItem", "PrinterRegistration", "Printer", "PrinterAttestation", "PrinterAgentSession", "PrinterProfile", "PrinterProfileSnapshot" TO ${read};
    `);
    applySql(dbInfo.databaseUrl, candidateSql);
    candidateApplied = true;
    adminSql(dbInfo.databaseUrl, `GRANT USAGE ON SCHEMA app_auth TO ${unrelated};`);

    const runtimeUrl = buildRoleUrl(dbInfo.databaseUrl, runtimeRole);
    app = new PrismaClient({ datasources: { db: { url: runtimeUrl } } });
    const rawUsers = await app.user.findMany({ select: { id: true } });
    assert.deepEqual(rawUsers, [], "empty pre-auth context must not enumerate User");

    const publicGrant = await admin.$queryRaw`
      SELECT has_function_privilege('public', 'app_auth.lookup_password_user(text)', 'EXECUTE') AS allowed
    `;
    assert.equal(publicGrant[0].allowed, false, "PUBLIC must not execute auth bootstrap functions");
    const boundary = await admin.$queryRawUnsafe(`
      SELECT owner.rolcanlogin AS owner_login,
             owner.rolbypassrls AS owner_bypass_rls,
             owner.rolinherit AS owner_inherit,
             has_schema_privilege('${runtimeRole}', 'app_auth', 'CREATE') AS app_can_create_auth,
             has_schema_privilege('${runtimeRole}', 'public', 'CREATE') AS app_can_create_public,
             has_function_privilege('${rlsReadRole}', 'app_auth.lookup_password_user(text)', 'EXECUTE') AS read_can_lookup,
             pg_has_role('${runtimeRole}', '${authOwnerRole}', 'MEMBER') AS app_is_owner_member
      FROM pg_roles owner WHERE owner.rolname = '${authOwnerRole}'
    `);
    assert.deepEqual(boundary, [{
      owner_login: false,
      owner_bypass_rls: false,
      owner_inherit: false,
      app_can_create_auth: false,
      app_can_create_public: false,
      read_can_lookup: false,
      app_is_owner_member: false,
    }]);
    const ownerObjects = await admin.$queryRawUnsafe(`
      SELECT count(*)::integer AS object_count FROM (
        SELECT n.oid FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner WHERE r.rolname = '${authOwnerRole}'
        UNION ALL
        SELECT p.oid FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner WHERE r.rolname = '${authOwnerRole}'
        UNION ALL
        SELECT c.oid FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner WHERE r.rolname = '${authOwnerRole}'
      ) owned
    `);
    assert.equal(ownerObjects[0].object_count, 3, "auth owner must own only app_auth and its two functions");
    const functionSecurity = await admin.$queryRaw`
      SELECT p.proname, p.prosecdef, p.provolatile, p.proparallel, p.proconfig
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'app_auth' ORDER BY p.proname
    `;
    assert.deepEqual(functionSecurity.map((row) => ({ ...row, proconfig: [...row.proconfig] })), [
      { proname: "lookup_password_user", prosecdef: true, provolatile: "s", proparallel: "s", proconfig: ["search_path=pg_catalog"] },
      { proname: "record_password_failure", prosecdef: true, provolatile: "v", proparallel: "u", proconfig: ["search_path=pg_catalog"] },
    ]);
    await assert.rejects(
      admin.$transaction(async (tx) => {
        await tx.$executeRawUnsafe(`SET LOCAL ROLE ${unrelated}`);
        await tx.$queryRaw`SELECT * FROM app_auth.lookup_password_user(${emailA})`;
      }),
      /permission denied/i,
      "unrelated roles must not execute auth bootstrap functions"
    );
    await assert.rejects(
      app.$transaction(async (tx) => tx.$executeRawUnsafe(`SET LOCAL ROLE ${quoteIdent(authOwnerRole)}`)),
      /permission denied/i,
      "runtime role must not SET ROLE to the auth owner"
    );

    const duplicateLookup = await app.$queryRaw`SELECT * FROM app_auth.lookup_password_user(${`  ${duplicateEmail.toUpperCase()}  `})`;
    assert.deepEqual(duplicateLookup, [], "case-variant duplicate email states must fail closed");

    const manipulated = await app.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT set_config('app.user_id', ${ids.manufacturerB}, true)`;
      await tx.$executeRaw`SELECT set_config('app.role', ${"SUPER_ADMIN"}, true)`;
      await tx.$executeRaw`SELECT set_config('app.is_platform_admin', ${"true"}, true)`;
      return tx.$queryRaw`SELECT "id", "email" FROM app_auth.lookup_password_user(${emailA})`;
    });
    assert.deepEqual(manipulated, [{ id: ids.manufacturerA, email: emailA }], "session variables must not redirect exact-email lookup");

    process.env.DATABASE_URL = runtimeUrl;
    process.env.AUTH_MAX_LOGIN_ATTEMPTS = "4";
    process.env.AUTH_LOCKOUT_MINUTES = "15";
    clearDistCache();
    const runtimeDatabase = require("../dist/config/database").default;
    const { loginWithPassword } = require("../dist/services/auth/authService");
    const login = (email, password) => loginWithPassword({ email, password, ipHash: "p2-ip", userAgent: "p2-agent" });

    const unknown = await messageOf(login("unknown@mscqr.test", wrongPassword));
    await admin.user.update({ where: { id: ids.manufacturerA }, data: { failedLoginAttempts: 0, lockedUntil: null } });
    const parallelFailures = await Promise.all(Array.from({ length: 4 }, () => messageOf(login(emailA, wrongPassword))));
    assert.ok(parallelFailures.every((wrong) => wrong === unknown), "parallel wrong passwords and unknown email must be generic");
    const failed = await admin.user.findUnique({ where: { id: ids.manufacturerA } });
    assert.equal(failed.failedLoginAttempts, 4, "parallel failed attempts must not lose increments");
    assert.ok(failed.lockedUntil, "parallel threshold crossing must atomically set lockout");
    const preservedLock = await app.$queryRaw`
      SELECT * FROM app_auth.record_password_failure(${emailA}, ${new Date()}::timestamp without time zone, ${100}::integer, ${15}::integer)
    `;
    assert.equal(preservedLock[0].lockedUntil.toISOString(), failed.lockedUntil.toISOString(), "failure mutation must never clear an existing lock");

    await admin.user.update({
      where: { id: ids.manufacturerA },
      data: { failedLoginAttempts: 1, lockedUntil: null, lastLoginAt: null },
    });
    const loginResult = await login(emailA, passwordA);
    assert.equal(loginResult.sessionStage, "MFA_BOOTSTRAP", "manufacturer password login must reach MFA bootstrap");
    const successful = await admin.user.findUnique({ where: { id: ids.manufacturerA } });
    assert.equal(successful.failedLoginAttempts, 0);
    assert.equal(successful.lockedUntil, null);
    assert.ok(successful.lastLoginAt, "successful password verification must update lastLoginAt");

    const foreignRows = await app.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT set_config('app.user_id', ${ids.manufacturerA}, true)`;
      await tx.$executeRaw`SELECT set_config('app.role', ${"MANUFACTURER"}, true)`;
      await tx.$executeRaw`SELECT set_config('app.licensee_id', ${ids.licenseeA}, true)`;
      await tx.$executeRaw`SELECT set_config('app.manufacturer_id', ${ids.manufacturerA}, true)`;
      await tx.$executeRaw`SELECT set_config('app.organization_id', ${ids.orgA}, true)`;
      return tx.user.findMany({ where: { id: ids.manufacturerB }, select: { id: true } });
    });
    assert.deepEqual(foreignRows, [], "normal authenticated tenant isolation must remain enforced");

    // Shared-table FORCE RLS compatibility characterizations. These assertions
    // describe the reviewed policy exactly; they must not be relaxed to make an
    // application path pass.
    const manufacturerContext = {
      userId: ids.manufacturerA,
      role: "manufacturer",
      licenseeId: ids.licenseeA,
      manufacturerId: ids.manufacturerA,
      organizationId: ids.orgA,
      isPlatformAdmin: false,
    };
    const selfUser = await withRlsContext(app, manufacturerContext, (tx) =>
      tx.user.findUnique({ where: { id: ids.manufacturerA }, select: { id: true } })
    );
    assert.deepEqual(selfUser, { id: ids.manufacturerA }, "self User SELECT is context-repairable");
    const selfUpdate = await withRlsContext(app, manufacturerContext, (tx) =>
      tx.user.updateMany({ where: { id: ids.manufacturerA }, data: { name: "Auth Maker A" } })
    );
    assert.equal(selfUpdate.count, 1, "self User UPDATE is allowed by the reviewed actor-self policy");
    const crossUpdate = await withRlsContext(app, manufacturerContext, (tx) =>
      tx.user.updateMany({ where: { id: ids.manufacturerB }, data: { failedLoginAttempts: 0 } })
    );
    assert.equal(crossUpdate.count, 0, "cross-user UPDATE requires explicitly reviewed policy expansion");
    await assert.rejects(
      withRlsContext(app, manufacturerContext, (tx) => tx.user.create({ data: {
        id: "10000000-0000-4202-8300-000000000001",
        email: "rls-auth-created@mscqr.test",
        name: "Denied creation",
        role: UserRole.MANUFACTURER,
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
      } })),
      /row-level security/i,
      "User INSERT remains blocked without a reviewed INSERT policy"
    );
    const deleteUser = await withRlsContext(app, manufacturerContext, (tx) =>
      tx.user.deleteMany({ where: { id: ids.manufacturerA } })
    );
    assert.equal(deleteUser.count, 0, "User DELETE remains blocked without a reviewed DELETE policy");

    const licenseeAdminContext = {
      userId: ids.manufacturerA,
      role: "licensee_admin",
      licenseeId: ids.licenseeA,
      organizationId: ids.orgA,
      isPlatformAdmin: false,
    };
    const tenantUsers = await withRlsContext(app, licenseeAdminContext, (tx) =>
      tx.user.findMany({ select: { id: true }, orderBy: { id: "asc" } })
    );
    assert.deepEqual(tenantUsers, [{ id: ids.manufacturerA }], "licensee-admin listing is tenant-scoped by context");
    await assert.rejects(
      withRlsContext(app, licenseeAdminContext, (tx) => tx.user.create({ data: {
        id: "10000000-0000-4202-8300-000000000002",
        email: "rls-auth-invite@mscqr.test",
        name: "Denied invite",
        role: UserRole.MANUFACTURER,
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
      } })),
      /row-level security/i,
      "licensee-admin creation/invitation requires a reviewed INSERT policy"
    );

    const platformUsers = await withRlsContext(app, {
      userId: ids.manufacturerA,
      role: "platform_super_admin",
      organizationId: ids.orgA,
      isPlatformAdmin: true,
    }, (tx) => tx.user.findMany({ select: { id: true } }));
    assert.equal(platformUsers.length, 4, "the reviewed SELECT policy permits platform-wide listing when trusted context says platform admin");

    const loginBoundaryLookup = await app.$queryRaw`SELECT "id" FROM app_auth.lookup_password_user(${emailA})`;
    assert.deepEqual(loginBoundaryLookup, [{ id: ids.manufacturerA }], "the reviewed password-login boundary remains available without actor context");
    const passwordResetLookup = await app.user.findFirst({ where: { email: emailA }, select: { id: true } });
    assert.equal(passwordResetLookup, null, "contextless password-reset lookup needs its own narrow function boundary");
    const resetCompletion = await app.user.updateMany({
      where: { id: ids.manufacturerA },
      data: { passwordHash: "denied-password-reset-characterization" },
    });
    assert.equal(resetCompletion.count, 0, "contextless password-reset completion is denied and needs its own narrow boundary");
    const mfaSelfService = await withRlsContext(app, manufacturerContext, (tx) =>
      tx.user.findUnique({ where: { id: ids.manufacturerA }, select: { id: true, passwordHash: true } })
    );
    assert.equal(mfaSelfService.id, ids.manufacturerA, "MFA self-service User read is compatible when actor context is transaction-local");
    const crossUserAdminUpdate = await withRlsContext(app, licenseeAdminContext, (tx) =>
      tx.user.updateMany({ where: { id: ids.manufacturerB }, data: { failedLoginAttempts: 0 } })
    );
    assert.equal(crossUserAdminUpdate.count, 0, "cross-user administrator UPDATE needs reviewed semantics");
    const breakGlassMfaTarget = await app.user.findFirst({ where: { email: emailA }, select: { id: true } });
    assert.equal(breakGlassMfaTarget, null, "contextless break-glass MFA target lookup needs a restricted system authorization design");

    const sharedReads = await withRlsContext(app, manufacturerContext, async (tx) => ({
      organizations: await tx.organization.findMany({ select: { id: true } }),
      licensees: await tx.licensee.findMany({ select: { id: true } }),
      links: await tx.manufacturerLicenseeLink.findMany({ select: { manufacturerId: true, licenseeId: true } }),
    }));
    assert.deepEqual(sharedReads.organizations, [{ id: ids.orgA }], "Organization SELECT is context-repairable");
    assert.deepEqual(sharedReads.licensees, [{ id: ids.licenseeA }], "Licensee SELECT is context-repairable");
    assert.deepEqual(sharedReads.links, [{ manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeA }], "link SELECT uses the reviewed non-recursive predicate");
    await assert.rejects(
      withRlsContext(app, manufacturerContext, (tx) => tx.manufacturerLicenseeLink.create({
        data: { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeB },
      })),
      /row-level security/i,
      "manufacturer-link creation requires a reviewed INSERT policy"
    );
    const removeLink = await withRlsContext(app, manufacturerContext, (tx) =>
      tx.manufacturerLicenseeLink.deleteMany({ where: { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeA } })
    );
    assert.equal(removeLink.count, 0, "manufacturer-link removal requires a reviewed DELETE policy");
    assert.equal(await app.user.count(), 0, "a contextless background User read fails closed and needs system-role redesign");

    process.env.DATABASE_URL = runtimeUrl;
    process.env.RLS_READ_DATABASE_URL = buildRoleUrl(dbInfo.databaseUrl, rlsReadRole);
    process.env.MSCQR_STAGING_RLS_BATCHES_READ_ENABLED = "true";
    process.env.MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED = "true";
    process.env.MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED = "true";
    clearDistCache();
    const listener = await startApp();
    server = listener.server;
    httpDatabase = require("../dist/config/database").default;
    rlsReadDatabase = require("../dist/config/rlsReadDatabase");

    const totpJar = new Map();
    const passwordLogin = await request(listener.baseUrl, "POST", "/api/auth/login", { email: emailA, password: passwordA }, totpJar);
    assert.equal(passwordLogin.status, 200, "forced-RLS password login must succeed");
    assert.equal(passwordLogin.payload?.data?.auth?.sessionStage, "MFA_BOOTSTRAP");
    assert.ok(totpJar.has("aq_access"), "login must set an access cookie");
    const { openCookieToken } = require("../dist/services/auth/cookieTokenProtectionService");
    const bootstrapBearer = openCookieToken(decodeURIComponent(totpJar.get("aq_access")), "auth.access");
    assert.ok(bootstrapBearer, "bootstrap access cookie must be decryptable");
    require("../dist/services/auth/tokenService").verifyMfaBootstrapToken(bootstrapBearer);
    const challengeStart = await request(listener.baseUrl, "POST", "/api/auth/mfa/challenge/begin", {}, totpJar, bootstrapBearer);
    assert.equal(challengeStart.status, 200, `forced-RLS TOTP challenge creation must succeed: ${challengeStart.payload?.error || "unknown"}`);
    const { generateSync } = require("otplib");
    const totpCode = generateSync({ secret: totpSecret });
    const challengeComplete = await request(listener.baseUrl, "POST", "/api/auth/mfa/challenge/complete", {
      ticket: challengeStart.payload.data.ticket,
      method: "totp",
      code: totpCode,
    }, totpJar, bootstrapBearer);
    assert.equal(challengeComplete.status, 200, "forced-RLS TOTP completion must issue an active session");
    assert.equal(challengeComplete.payload?.data?.auth?.sessionStage, "ACTIVE");

    const activeBearer = openCookieToken(decodeURIComponent(totpJar.get("aq_access")), "auth.access");
    assert.ok(activeBearer, "active access cookie must be decryptable");
    const me = await request(listener.baseUrl, "GET", "/api/auth/me", undefined, totpJar, activeBearer);
    assert.equal(me.status, 200, "auth/me must work after forced-RLS MFA completion");
    assert.ok(me.payload?.data?.linkedLicensees?.some((row) => row.id === ids.licenseeA), "linked licensee mapping must survive forced RLS");
    const batches = await request(listener.baseUrl, "GET", "/api/qr/batches", undefined, totpJar, activeBearer);
    assert.equal(batches.status, 200, "manufacturer batch read must work after forced-RLS MFA completion");
    const printers = await request(listener.baseUrl, "GET", "/api/manufacturer/printers", undefined, totpJar, activeBearer);
    assert.equal(printers.status, 200, "manufacturer printer read must work after forced-RLS MFA completion");
    const inaccessible = await request(listener.baseUrl, "GET", "/api/qr/batches/00000000-0000-4000-8000-000000000099/allocation-map", undefined, totpJar, activeBearer);
    assert.equal(inaccessible.status, 404, "inaccessible allocation-map IDs must remain non-enumerating 404 responses");
    const refreshCount = await admin.refreshToken.count({ where: { userId: ids.manufacturerA } });
    const auditCount = await admin.auditLog.count({ where: { userId: ids.manufacturerA } });
    assert.ok(refreshCount > 0, "MFA completion must persist a refresh token");
    assert.ok(auditCount > 0, "MFA completion must persist audit events");

    const webAuthnJar = new Map();
    const webAuthnLogin = await request(listener.baseUrl, "POST", "/api/auth/login", { email: emailA, password: passwordA }, webAuthnJar);
    assert.equal(webAuthnLogin.status, 200);
    const webAuthnBootstrapBearer = openCookieToken(decodeURIComponent(webAuthnJar.get("aq_access")), "auth.access");
    assert.ok(webAuthnBootstrapBearer);
    const webAuthnStart = await request(listener.baseUrl, "POST", "/api/auth/mfa/webauthn/challenge/begin", {}, webAuthnJar, webAuthnBootstrapBearer);
    assert.equal(webAuthnStart.status, 200, "forced-RLS WebAuthn login challenge must start");
    const clientData = Buffer.from(JSON.stringify({
      type: "webauthn.get",
      challenge: webAuthnStart.payload.data.options.challenge,
      origin: "http://localhost:8080",
    }));
    const authenticatorData = Buffer.concat([
      createHash("sha256").update("localhost").digest(),
      Buffer.from([0x01]),
      Buffer.from([0, 0, 0, 1]),
    ]);
    const signature = sign("sha256", Buffer.concat([
      authenticatorData,
      createHash("sha256").update(clientData).digest(),
    ]), webAuthnKeys.privateKey);
    const webAuthnComplete = await request(listener.baseUrl, "POST", "/api/auth/mfa/webauthn/challenge/finish", {
      ticket: webAuthnStart.payload.data.ticket,
      credential: {
        id: webAuthnCredentialId,
        rawId: webAuthnCredentialId,
        type: "public-key",
        response: {
          clientDataJSON: toBase64Url(clientData),
          authenticatorData: toBase64Url(authenticatorData),
          signature: toBase64Url(signature),
        },
      },
    }, webAuthnJar, webAuthnBootstrapBearer);
    assert.equal(webAuthnComplete.status, 200, "forced-RLS WebAuthn login completion must issue a session");
    assert.equal(webAuthnComplete.payload?.data?.auth?.sessionStage, "ACTIVE");

    await new Promise((resolve) => server.close(resolve));
    server = null;
    await rlsReadDatabase.disconnectRlsReadPrisma();
    await httpDatabase.$disconnect();
    rlsReadDatabase = null;
    httpDatabase = null;
    await runtimeDatabase.$disconnect();
    await app.$disconnect();
    app = null;
    applySql(dbInfo.databaseUrl, rollbackSql);
    candidateApplied = false;

    const rolledBack = await admin.$queryRaw`
      SELECT
        to_regnamespace('app_auth') IS NULL AS auth_schema_removed,
        NOT c.relrowsecurity AND NOT c.relforcerowsecurity AS user_rls_removed
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname = 'User'
    `;
    assert.equal(rolledBack[0].auth_schema_removed, true);
    assert.equal(rolledBack[0].user_rls_removed, true);
    const authRole = await admin.$queryRaw`SELECT rolname FROM pg_roles WHERE rolname = ${authOwnerRole}`;
    assert.deepEqual(authRole, [], "rollback must drop the dedicated auth owner role");
  } catch (error) {
    primaryError = error;
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (rlsReadDatabase) await rlsReadDatabase.disconnectRlsReadPrisma().catch(() => {});
    if (httpDatabase) await httpDatabase.$disconnect().catch(() => {});
    if (app) await app.$disconnect().catch(() => {});
    if (candidateApplied && dbInfo?.databaseUrl) {
      try { applySql(dbInfo.databaseUrl, rollbackSql); } catch (rollbackError) {
        if (primaryError) primaryError.rollbackError = rollbackError;
        else primaryError = rollbackError;
      }
    }
    if (admin && dbInfo?.databaseUrl) {
      try {
        adminSql(dbInfo.databaseUrl, `
          DROP OWNED BY ${quoteIdent(unrelatedRole)};
          DROP ROLE IF EXISTS ${quoteIdent(unrelatedRole)};
          DROP OWNED BY ${quoteIdent(rlsReadRole)};
          DROP ROLE IF EXISTS ${quoteIdent(rlsReadRole)};
          DROP OWNED BY ${quoteIdent(runtimeRole)};
          DROP ROLE IF EXISTS ${quoteIdent(runtimeRole)};
        `);
      } catch {}
      await admin.$disconnect().catch(() => {});
    }
    if (dbInfo?.createdDatabaseName) dropP2TestDatabase(dbInfo);
  }

  if (primaryError) throw primaryError;
  console.log("RLS auth bootstrap P2 tests passed");
};

main().catch((error) => {
  console.error(error);
  if (error.rollbackError) console.error("Rollback also failed:", error.rollbackError);
  process.exit(1);
});
