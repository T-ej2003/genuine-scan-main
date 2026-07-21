const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const express = require("express");

const enabled = process.env.MSCQR_RLS_B01_INVITATION_POSTGRES_TEST === "true";
const confirmed = process.env.MSCQR_RLS_B01_INVITATION_CONFIRM === "MSCQR_RUN_LOCAL_B01_INVITATION_POSTGRES_TEST";
const expectedDatabase = "mscqr_rls_wave_b_auth_public_workers";

const ids = {
  licenseeOne: "10000000-0000-4000-8000-000000000001",
  licenseeTwo: "10000000-0000-4000-8000-000000000002",
  organizationOne: "20000000-0000-4000-8000-000000000001",
  organizationTwo: "20000000-0000-4000-8000-000000000002",
  platformActor: "30000000-0000-4000-8000-000000000001",
  licenseeActor: "30000000-0000-4000-8000-000000000002",
  staleActor: "30000000-0000-4000-8000-000000000003",
  disabledActor: "30000000-0000-4000-8000-000000000004",
  wrongRoleActor: "30000000-0000-4000-8000-000000000005",
  weakActor: "30000000-0000-4000-8000-000000000006",
  expiredActor: "30000000-0000-4000-8000-000000000007",
  platformSession: "40000000-0000-4000-8000-000000000001",
  licenseeSession: "40000000-0000-4000-8000-000000000002",
  staleSession: "40000000-0000-4000-8000-000000000003",
  disabledSession: "40000000-0000-4000-8000-000000000004",
  wrongRoleSession: "40000000-0000-4000-8000-000000000005",
  weakSession: "40000000-0000-4000-8000-000000000006",
  expiredSession: "40000000-0000-4000-8000-000000000007",
};

const safeUrl = (raw) => {
  const parsed = new URL(String(raw || ""));
  assert(["postgres:", "postgresql:"].includes(parsed.protocol));
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname));
  assert.equal(decodeURIComponent(parsed.pathname.slice(1)), expectedDatabase);
  assert(!/(prod|production|staging|amazonaws|rds)/i.test(raw));
  return parsed;
};

const roleUrl = (adminUrl, role) => {
  const parsed = new URL(adminUrl);
  parsed.username = role;
  parsed.password = "";
  return parsed.toString();
};

const reject = async (operation, pattern) => {
  let error;
  try {
    await operation();
  } catch (caught) {
    error = caught;
  }
  assert(error, `Expected rejection matching ${pattern}`);
  assert.match(String(error.message || error), pattern);
  return error;
};

const main = async () => {
  if (!enabled) {
    console.log("B01 invitation PostgreSQL 18 proof skipped");
    return;
  }
  assert(confirmed, "Set MSCQR_RLS_B01_INVITATION_CONFIRM=MSCQR_RUN_LOCAL_B01_INVITATION_POSTGRES_TEST");
  const adminUrl = String(process.env.DATABASE_URL || "").trim();
  safeUrl(adminUrl);

  const fixture = path.join(__dirname, "invitationPostgres18.fixture.sql");
  assert(fs.statSync(fixture).isFile());
  execFileSync("psql", [adminUrl, "-v", "ON_ERROR_STOP=1", "-f", fixture], { stdio: "pipe" });

  process.env.TOKEN_HASH_SECRET_CURRENT = "b01-invitation-token-secret";
  process.env.JWT_SECRET_CURRENT = "b01-invitation-jwt-secret";
  process.env.IP_HASH_SALT_CURRENT = "b01-invitation-ip-secret";
  process.env.NODE_ENV = "production";
  process.env.DATABASE_URL = adminUrl;
  process.env.PREAUTH_DATABASE_URL = roleUrl(adminUrl, "mscqr_dev_preauth");
  process.env.AUTHENTICATED_APP_DATABASE_URL = roleUrl(adminUrl, "mscqr_dev_app");
  process.env.EMAIL_DISABLED = "true";
  process.env.MSCQR_FULL_RLS_REDUCED_SURFACE_ENABLED = "false";
  process.env.MSCQR_RLS_B03_WORKER_BOUNDARIES_ENABLED = "true";

  const { PrismaClient } = require("@prisma/client");
  const admin = new PrismaClient({ datasources: { db: { url: adminUrl } } });
  const {
    getB01AuthenticatedPrisma,
    getB01PreAuthPrisma,
  } = require("../../../dist/rls-waves/session-b/b01/runtimeClients");
  const authenticated = getB01AuthenticatedPrisma();
  const preauth = getB01PreAuthPrisma();
  const { installCanonicalDbContext } = require("../../../dist/lib/canonicalDbContext");
  const applicationRoutes = require("../../../dist/routes").default;
  const { acceptInvite } = require("../../../dist/services/auth/inviteService");
  const { hashPassword } = require("../../../dist/services/auth/passwordService");
  const { hashRefreshToken, signAccessToken } = require("../../../dist/services/auth/tokenService");
  const { buildTokenHashCandidates, hashToken } = require("../../../dist/utils/security");

  const now = new Date();
  const later = new Date(now.getTime() + 24 * 60 * 60 * 1000);
  const platformContext = (requestId, purpose = "auth-invite-create") => ({
    userId: ids.platformActor,
    role: "PLATFORM_SUPER_ADMIN",
    organizationId: null,
    licenseeId: null,
    manufacturerId: null,
    authAssurance: "mfa-verified",
    requestId,
    purpose,
  });
  const licenseeContext = (requestId, purpose = "auth-invite-create") => ({
    userId: ids.licenseeActor,
    role: "LICENSEE_ADMIN",
    organizationId: ids.organizationOne,
    licenseeId: ids.licenseeOne,
    manufacturerId: null,
    authAssurance: "mfa-verified",
    requestId,
    purpose,
  });

  const seedActor = async ({
    id,
    sessionId,
    role,
    licenseeId = null,
    organizationId = null,
    active = true,
    membershipActive = true,
    mfaEnabled = true,
    mfaVerifiedAt = now,
    expiresAt = new Date(now.getTime() + 60 * 60 * 1000),
  }) => {
    await admin.$executeRaw`
      INSERT INTO b01_refresh_wave.actor(
        id,email,name,role,organization_id,licensee_id,manufacturer_id,active,email_verified_at,
        mfa_required,mfa_enabled,mfa_last_used_at
      ) VALUES (
        ${id},${`${id}@example.test`},${`Actor ${id.slice(-4)}`},${role},${organizationId},${licenseeId},
        ${role.startsWith("MANUFACTURER") ? id : null},${active},${now},true,${mfaEnabled},${mfaVerifiedAt}
      )
    `;
    if (licenseeId && organizationId) {
      await admin.$executeRaw`
        INSERT INTO b01_refresh_wave.membership(
          user_id,licensee_id,organization_id,licensee_name,licensee_prefix,brand_name,
          is_primary,scope_version,active
        ) VALUES (
          ${id},${licenseeId},${organizationId},${`Membership ${id.slice(-4)}`},${`P${id.slice(-4)}`},
          ${`Brand ${id.slice(-4)}`},true,${now.toISOString()},${membershipActive}
        )
      `;
    }
    const sessionHash = createHash("sha256").update(`session:${sessionId}`).digest("hex");
    await admin.$executeRaw`
      INSERT INTO b01_refresh_wave.refresh_token(
        id,user_id,organization_id,token_hash,expires_at,created_at,created_ip_hash,
        created_user_agent,authenticated_at,mfa_verified_at,last_used_at
      ) VALUES (
        ${sessionId},${id},${organizationId},${sessionHash},${expiresAt},${new Date(now.getTime() - 60_000)},
        ${"a".repeat(64)},${"invitation-postgres-proof"},${now},${mfaVerifiedAt},${now}
      )
    `;
  };

  const claimsFor = ({ id, sessionId, role, licenseeId = null, organizationId = null, mfaVerifiedAt = now }) =>
    signAccessToken({
      userId: id,
      email: `${id}@example.test`,
      role,
      licenseeId,
      orgId: organizationId,
      scopeVersion: null,
      linkedLicenseeIds: null,
      sessionId,
      sessionStage: "ACTIVE",
      authAssurance: mfaVerifiedAt ? "ADMIN_MFA" : "PASSWORD",
      authenticatedAt: now.toISOString(),
      mfaVerifiedAt: mfaVerifiedAt ? mfaVerifiedAt.toISOString() : null,
    });

  const prepareSql = `
    SELECT * FROM app_rls.prepare_invitation(
      $1::text,$2::text,$3::text,$4::text,$5::text,$6::text,$7::text,$8::text,$9::text,
      $10::boolean,$11::boolean,$12::text,$13::timestamp without time zone,
      $14::timestamp without time zone,$15::text,$16::text
    )
  `;
  const defaultPrepareInput = (email, tokenHashValue) => ({
    requestedEmail: email,
    requestedName: "Invited User",
    requestedRole: "LICENSEE_ADMIN",
    requestedLicenseeId: ids.licenseeOne,
    requestedManufacturerId: null,
    allowExistingInvitedUser: false,
    requireExistingUser: false,
    tokenHash: tokenHashValue,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    ipHash: "b".repeat(64),
    userAgent: "invitation-postgres-proof",
  });
  const prepare = (context, actorSessionId, input) => authenticated.$transaction(async (tx) => {
    await installCanonicalDbContext(tx, context);
    return tx.$queryRawUnsafe(
      prepareSql,
      context.userId,
      actorSessionId,
      context.requestId,
      context.purpose,
      input.requestedEmail,
      input.requestedName,
      input.requestedRole,
      input.requestedLicenseeId,
      input.requestedManufacturerId,
      input.allowExistingInvitedUser,
      input.requireExistingUser,
      input.tokenHash,
      input.createdAt,
      input.expiresAt,
      input.ipHash,
      input.userAgent
    );
  });
  const lookup = (hashes, checkedAt = new Date(), client = preauth) => client.$queryRawUnsafe(
    "SELECT * FROM app_auth.lookup_invitation_token($1::text[],$2::timestamp without time zone)",
    hashes,
    checkedAt
  );
  const consume = ({
    hashes,
    passwordHash,
    requestId,
    name = null,
    consumedAt = new Date(),
    ipHash = "c".repeat(64),
    userAgent = "invitation-postgres-proof",
    client = preauth,
  }) => client.$queryRawUnsafe(
    `SELECT * FROM app_auth.consume_invitation_token(
      $1::text[],$2::text,$3::text,$4::timestamp without time zone,$5::text,$6::text,$7::text
    )`,
    hashes,
    passwordHash,
    name,
    consumedAt,
    requestId,
    ipHash,
    userAgent
  );

  let server;
  let baseUrl;
  const routeRequest = async ({ method, route, requestId, token, body }) => {
    const headers = { "user-agent": "invitation-route-proof", "x-request-id": requestId };
    if (token) headers.authorization = `Bearer ${token}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const response = await fetch(`${baseUrl}${route}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: response.status, body: await response.json() };
  };

  const originalConsoleError = console.error;
  console.error = (...args) => {
    if (args[0] === "MAIL delivery skipped" || args[0] === "AUTH_EMAIL audit log failed:") return;
    originalConsoleError(...args);
  };

  try {
    const [{ versionNumber, databaseName }] = await admin.$queryRaw`
      SELECT current_setting('server_version_num')::int AS "versionNumber",current_database() AS "databaseName"
    `;
    assert(versionNumber >= 180000 && versionNumber < 190000);
    assert.equal(databaseName, expectedDatabase);

    await admin.$executeRaw`
      INSERT INTO b01_invite_wave.organization(id,name,active) VALUES
      (${ids.organizationOne},${"Organization One"},true),
      (${ids.organizationTwo},${"Organization Two"},true)
    `;
    await admin.$executeRaw`
      INSERT INTO b01_invite_wave.licensee(id,organization_id,name,active) VALUES
      (${ids.licenseeOne},${ids.organizationOne},${"Licensee One"},true),
      (${ids.licenseeTwo},${ids.organizationTwo},${"Licensee Two"},true)
    `;
    await seedActor({ id: ids.platformActor, sessionId: ids.platformSession, role: "PLATFORM_SUPER_ADMIN" });
    await seedActor({
      id: ids.licenseeActor,
      sessionId: ids.licenseeSession,
      role: "LICENSEE_ADMIN",
      licenseeId: ids.licenseeOne,
      organizationId: ids.organizationOne,
    });
    await seedActor({
      id: ids.staleActor,
      sessionId: ids.staleSession,
      role: "LICENSEE_ADMIN",
      licenseeId: ids.licenseeOne,
      organizationId: ids.organizationOne,
      membershipActive: false,
    });
    await seedActor({
      id: ids.disabledActor,
      sessionId: ids.disabledSession,
      role: "LICENSEE_ADMIN",
      licenseeId: ids.licenseeOne,
      organizationId: ids.organizationOne,
      active: false,
    });
    await seedActor({
      id: ids.wrongRoleActor,
      sessionId: ids.wrongRoleSession,
      role: "MANUFACTURER",
      licenseeId: ids.licenseeOne,
      organizationId: ids.organizationOne,
    });
    await seedActor({
      id: ids.weakActor,
      sessionId: ids.weakSession,
      role: "LICENSEE_ADMIN",
      licenseeId: ids.licenseeOne,
      organizationId: ids.organizationOne,
      mfaEnabled: false,
      mfaVerifiedAt: null,
    });
    await seedActor({
      id: ids.expiredActor,
      sessionId: ids.expiredSession,
      role: "LICENSEE_ADMIN",
      licenseeId: ids.licenseeOne,
      organizationId: ids.organizationOne,
      expiresAt: new Date(now.getTime() - 60_000),
    });

    const app = express();
    app.use(express.json());
    app.use("/api", applicationRoutes);
    server = http.createServer(app);
    await new Promise((resolve, rejectListen) => {
      server.once("error", rejectListen);
      server.listen(0, "127.0.0.1", resolve);
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;

    const platformToken = claimsFor({
      id: ids.platformActor,
      sessionId: ids.platformSession,
      role: "PLATFORM_SUPER_ADMIN",
    });
    const licenseeToken = claimsFor({
      id: ids.licenseeActor,
      sessionId: ids.licenseeSession,
      role: "LICENSEE_ADMIN",
      licenseeId: ids.licenseeOne,
      organizationId: ids.organizationOne,
    });

    const platformCreate = await routeRequest({
      method: "POST",
      route: "/api/auth/invite",
      requestId: "route-platform-create",
      token: platformToken,
      body: {
        email: "platform-created@example.test",
        name: "Platform Created",
        role: "LICENSEE_ADMIN",
        licenseeId: ids.licenseeOne,
      },
    });
    assert.equal(platformCreate.status, 201);
    assert.equal(platformCreate.body.success, true);
    assert.equal(platformCreate.body.data.created, true);
    const platformRawToken = new URL(platformCreate.body.data.inviteLink).searchParams.get("token");
    assert(platformRawToken);

    const preview = await routeRequest({
      method: "GET",
      route: `/api/auth/invite-preview?token=${encodeURIComponent(platformRawToken)}`,
      requestId: "route-preview",
    });
    assert.equal(preview.status, 200);
    assert.deepEqual(Object.keys(preview.body.data).sort(), [
      "email",
      "expiresAt",
      "licenseeName",
      "requiresConnector",
      "role",
    ]);
    assert.equal(preview.body.data.email, "platform-created@example.test");
    assert.equal(preview.body.data.licenseeName, "Licensee One");

    const platformRoleCreate = await routeRequest({
      method: "POST",
      route: "/api/auth/invite",
      requestId: "route-platform-role-create",
      token: platformToken,
      body: {
        email: "platform-admin@example.test",
        name: "Platform Admin",
        role: "PLATFORM_SUPER_ADMIN",
      },
    });
    assert.equal(platformRoleCreate.status, 201);
    assert.equal(platformRoleCreate.body.success, true);
    const [platformRoleState] = await admin.$queryRaw`
      SELECT invite_user.organization_id AS "userOrganizationId",
        invite_user.licensee_id AS "userLicenseeId",
        invite.organization_id AS "inviteOrganizationId",
        organization.name AS "organizationName",organization.active
      FROM b01_invite_wave.invite_user AS invite_user
      JOIN b01_invite_wave.invite AS invite ON invite.email=invite_user.email
      JOIN b01_invite_wave.organization AS organization ON organization.id=invite.organization_id
      WHERE invite_user.email=${"platform-admin@example.test"}
    `;
    assert.deepEqual(platformRoleState, {
      userOrganizationId: null,
      userLicenseeId: null,
      inviteOrganizationId: "00000000-0000-0000-0000-000000000000",
      organizationName: "Platform",
      active: true,
    });

    const tenantCreate = await routeRequest({
      method: "POST",
      route: "/api/auth/invite",
      requestId: "route-tenant-create",
      token: licenseeToken,
      body: {
        email: "tenant-manufacturer@example.test",
        name: "Tenant Manufacturer",
        role: "MANUFACTURER",
        licenseeId: ids.licenseeOne,
      },
    });
    assert.equal(tenantCreate.status, 201);
    assert.equal(tenantCreate.body.success, true);
    const [tenantManufacturerLink] = await admin.$queryRaw`
      SELECT link.licensee_id AS "licenseeId",link.is_primary AS "isPrimary"
      FROM b01_invite_wave.manufacturer_link AS link
      JOIN b01_invite_wave.invite_user AS invite_user ON invite_user.id=link.manufacturer_id
      WHERE invite_user.email=${"tenant-manufacturer@example.test"}
    `;
    assert.deepEqual(tenantManufacturerLink, { licenseeId: ids.licenseeOne, isPrimary: true });

    await admin.$executeRaw`
      INSERT INTO b01_invite_wave.invite_user(
        id,email,name,role,licensee_id,organization_id,status,active,updated_at
      ) VALUES (
        ${"50000000-0000-4000-8000-000000000001"},${"resend-admin@example.test"},${"Resend Admin"},
        ${"ORG_ADMIN"},${ids.licenseeOne},${ids.organizationOne},${"INVITED"},true,${now}
      )
    `;
    const resend = await routeRequest({
      method: "POST",
      route: `/api/licensees/${ids.licenseeOne}/admin-invite/resend`,
      requestId: "route-platform-resend",
      token: platformToken,
      body: { email: "resend-admin@example.test" },
    });
    assert.equal(resend.status, 200);
    assert.equal(resend.body.success, true);
    assert.equal(resend.body.data.created, true);
    const resendRawToken = new URL(resend.body.data.inviteLink).searchParams.get("token");
    assert(resendRawToken);
    const acceptedResend = await acceptInvite({
      rawToken: resendRawToken,
      password: "Correct-Horse-Battery-6",
      name: "Resend Admin Activated",
      requestId: "service-resend-alias-activation",
      ipHash: "a".repeat(64),
      userAgent: "invitation-service-proof",
    });
    assert.equal(acceptedResend.role, "ORG_ADMIN");
    assert.equal(acceptedResend.status, "ACTIVE");
    const [{ resendAuditCount }] = await admin.$queryRaw`
      SELECT count(*)::int AS "resendAuditCount"
      FROM b01_invite_wave.audit_outbox
      WHERE payload->>'requestId'=${"route-platform-resend"}
        AND payload->>'action'='RESEND_LICENSEE_ADMIN_INVITE'
    `;
    assert.equal(resendAuditCount, 1);

    const foreignTenant = await routeRequest({
      method: "POST",
      route: "/api/auth/invite",
      requestId: "deny-foreign-tenant",
      token: licenseeToken,
      body: {
        email: "foreign@example.test",
        name: "Foreign Tenant",
        role: "MANUFACTURER",
        licenseeId: ids.licenseeTwo,
      },
    });
    assert.equal(foreignTenant.status, 400);
    assert.equal(foreignTenant.body.code, "INVITE_CREATE_FAILED");

    const deniedRoute = async ({ actorId, sessionId, role, expectedStatus, requestId, mfaVerifiedAt = now }) => {
      const token = claimsFor({
        id: actorId,
        sessionId,
        role,
        licenseeId: ids.licenseeOne,
        organizationId: ids.organizationOne,
        mfaVerifiedAt,
      });
      const result = await routeRequest({
        method: "POST",
        route: "/api/auth/invite",
        requestId,
        token,
        body: {
          email: `${requestId}@example.test`,
          name: "Denied Actor",
          role: "MANUFACTURER",
          licenseeId: ids.licenseeOne,
        },
      });
      assert.equal(result.status, expectedStatus);
    };
    await deniedRoute({
      actorId: ids.staleActor,
      sessionId: ids.staleSession,
      role: "LICENSEE_ADMIN",
      expectedStatus: 401,
      requestId: "deny-stale-membership",
    });
    await deniedRoute({
      actorId: ids.disabledActor,
      sessionId: ids.disabledSession,
      role: "LICENSEE_ADMIN",
      expectedStatus: 401,
      requestId: "deny-disabled-account",
    });
    await deniedRoute({
      actorId: ids.expiredActor,
      sessionId: ids.expiredSession,
      role: "LICENSEE_ADMIN",
      expectedStatus: 401,
      requestId: "deny-expired-session",
    });
    await deniedRoute({
      actorId: ids.wrongRoleActor,
      sessionId: ids.wrongRoleSession,
      role: "MANUFACTURER",
      expectedStatus: 401,
      requestId: "deny-wrong-role",
    });
    await deniedRoute({
      actorId: ids.weakActor,
      sessionId: ids.weakSession,
      role: "LICENSEE_ADMIN",
      expectedStatus: 428,
      requestId: "deny-wrong-assurance",
      mfaVerifiedAt: null,
    });

    const deterministicInput = defaultPrepareInput("deterministic@example.test", hashToken("deterministic-token"));
    deterministicInput.allowExistingInvitedUser = true;
    const deterministicContext = platformContext("direct-deterministic");
    const deterministicFirst = await prepare(deterministicContext, ids.platformSession, deterministicInput);
    const deterministicRetry = await prepare(deterministicContext, ids.platformSession, deterministicInput);
    assert.equal(deterministicFirst.length, 1);
    assert.equal(deterministicRetry[0].inviteId, deterministicFirst[0].inviteId);
    assert.deepEqual(Object.keys(deterministicFirst[0]).sort(), [
      "actorDisplayName",
      "actorEmail",
      "actorUserId",
      "inviteEmail",
      "inviteExpiresAt",
      "inviteId",
      "inviteRole",
      "licenseeName",
      "linkAction",
      "userEmail",
      "userId",
      "userLicenseeId",
      "userName",
      "userOrganizationId",
      "userRole",
      "userStatus",
      "workspaceOrganizationId",
    ].sort());
    const [{ deterministicAudit }] = await admin.$queryRaw`
      SELECT count(*)::int AS "deterministicAudit" FROM b01_invite_wave.audit_outbox
      WHERE payload->>'requestId'=${deterministicContext.requestId}
        AND payload->>'action'='AUTH_INVITE_CREATED'
    `;
    assert.equal(deterministicAudit, 1);

    const concurrentEmail = "concurrent-create@example.test";
    const concurrentOne = defaultPrepareInput(concurrentEmail, hashToken("concurrent-create-one"));
    const concurrentTwo = defaultPrepareInput(concurrentEmail, hashToken("concurrent-create-two"));
    concurrentOne.allowExistingInvitedUser = true;
    concurrentTwo.allowExistingInvitedUser = true;
    const concurrentResults = await Promise.allSettled([
      prepare(platformContext("concurrent-create-one"), ids.platformSession, concurrentOne),
      prepare(platformContext("concurrent-create-two"), ids.platformSession, concurrentTwo),
    ]);
    assert.deepEqual(concurrentResults.map((result) => result.status).sort(), ["fulfilled", "rejected"]);
    assert.match(
      String(concurrentResults.find((result) => result.status === "rejected").reason?.message || ""),
      /B01_INVITE_ALREADY_ACTIVE/
    );
    const [{ concurrentTotal, concurrentLive, concurrentAudits }] = await admin.$queryRaw`
      SELECT count(*)::int AS "concurrentTotal",
        count(*) FILTER (WHERE invite.used_at IS NULL)::int AS "concurrentLive",
        (SELECT count(*) FROM b01_invite_wave.audit_outbox
          WHERE payload->>'action'='AUTH_INVITE_CREATED'
            AND payload->'details'->>'email'=${concurrentEmail})::int AS "concurrentAudits"
      FROM b01_invite_wave.invite AS invite
      WHERE invite.email=${concurrentEmail}
    `;
    assert.equal(concurrentTotal, 1);
    assert.equal(concurrentLive, 1);
    assert.equal(concurrentAudits, 1);

    await reject(
      () => prepare(
        { ...platformContext("wrong-purpose", "auth-session-list") },
        ids.platformSession,
        defaultPrepareInput("wrong-purpose@example.test", hashToken("wrong-purpose"))
      ),
      /B01_INVITE_ACTOR_DENIED/
    );
    await reject(
      () => prepare(
        {
          userId: ids.wrongRoleActor,
          role: "MANUFACTURER",
          organizationId: ids.organizationOne,
          licenseeId: ids.licenseeOne,
          manufacturerId: ids.wrongRoleActor,
          authAssurance: "mfa-verified",
          requestId: "direct-wrong-role",
          purpose: "auth-invite-create",
        },
        ids.wrongRoleSession,
        defaultPrepareInput("direct-wrong-role@example.test", hashToken("direct-wrong-role"))
      ),
      /B01_INVITE_ACTOR_DENIED/
    );
    await reject(
      () => prepare(
        platformContext("missing-licensee"),
        ids.platformSession,
        {
          ...defaultPrepareInput("missing-licensee@example.test", hashToken("missing-licensee")),
          requestedLicenseeId: null,
        }
      ),
      /B01_INVITE_SCOPE_DENIED/
    );
    await reject(
      () => prepare(
        platformContext("null-role"),
        ids.platformSession,
        { ...defaultPrepareInput("null-role@example.test", hashToken("null-role")), requestedRole: null }
      ),
      /B01_INVITE_INPUT_DENIED/
    );
    await reject(
      () => prepare(
        licenseeContext("direct-foreign-scope"),
        ids.licenseeSession,
        {
          ...defaultPrepareInput("direct-foreign@example.test", hashToken("direct-foreign")),
          requestedLicenseeId: ids.licenseeTwo,
        }
      ),
      /B01_INVITE_SCOPE_DENIED/
    );
    await reject(
      () => admin.$queryRawUnsafe(
        prepareSql,
        ids.platformActor,
        ids.platformSession,
        "wrong-identity",
        "auth-invite-create",
        "wrong-identity@example.test",
        "Wrong Identity",
        "LICENSEE_ADMIN",
        ids.licenseeOne,
        null,
        false,
        false,
        hashToken("wrong-identity"),
        new Date(),
        new Date(Date.now() + 60 * 60 * 1000),
        "d".repeat(64),
        "wrong-identity-proof"
      ),
      /B01_INVITE_ACTOR_DENIED/
    );

    const rollbackCreateEmail = "rollback-create@example.test";
    await reject(
      () => prepare(
        platformContext("force-outbox-failure"),
        ids.platformSession,
        defaultPrepareInput(rollbackCreateEmail, hashToken("rollback-create"))
      ),
      /B01_TEST_AUDIT_OUTBOX_FAILURE/
    );
    const [{ rollbackCreateUsers, rollbackCreateInvites }] = await admin.$queryRaw`
      SELECT
        (SELECT count(*) FROM b01_invite_wave.invite_user WHERE email=${rollbackCreateEmail})::int AS "rollbackCreateUsers",
        (SELECT count(*) FROM b01_invite_wave.invite WHERE email=${rollbackCreateEmail})::int AS "rollbackCreateInvites"
    `;
    assert.equal(rollbackCreateUsers, 0);
    assert.equal(rollbackCreateInvites, 0);

    const accepted = await acceptInvite({
      rawToken: platformRawToken,
      password: "Correct-Horse-Battery-7",
      name: "Activated Platform User",
      requestId: "service-activation",
      ipHash: "e".repeat(64),
      userAgent: "invitation-service-proof",
    });
    assert.deepEqual(Object.keys(accepted).sort(), [
      "email",
      "id",
      "inviteId",
      "licenseeId",
      "name",
      "orgId",
      "role",
      "status",
    ]);
    assert.equal(accepted.status, "ACTIVE");
    await reject(
      () => acceptInvite({
        rawToken: platformRawToken,
        password: "Correct-Horse-Battery-7",
        requestId: "service-replay",
        ipHash: "e".repeat(64),
        userAgent: "invitation-service-proof",
      }),
      /Invalid or expired invite token/
    );

    const consumeRawToken = "concurrent-consume-token";
    const consumeInput = defaultPrepareInput("concurrent-consume@example.test", hashToken(consumeRawToken));
    await prepare(platformContext("prepare-concurrent-consume"), ids.platformSession, consumeInput);
    const consumeHashes = buildTokenHashCandidates(consumeRawToken);
    const passwordHash = await hashPassword("Correct-Horse-Battery-8");
    const consumeResults = await Promise.all([
      consume({ hashes: consumeHashes, passwordHash, requestId: "consume-winner-one", name: "Consume Winner" }),
      consume({ hashes: consumeHashes, passwordHash, requestId: "consume-winner-two", name: "Consume Winner" }),
    ]);
    assert.deepEqual(consumeResults.map((rows) => rows.length).sort(), [0, 1]);
    const winner = consumeResults.find((rows) => rows.length)[0];
    assert.deepEqual(Object.keys(winner).sort(), [
      "email",
      "id",
      "inviteId",
      "licenseeId",
      "name",
      "orgId",
      "role",
      "status",
    ]);
    assert.equal((await consume({ hashes: consumeHashes, passwordHash, requestId: "consume-replay" })).length, 0);

    const expiredRaw = "expired-invitation-token";
    const expiredPrepared = await prepare(
      platformContext("prepare-expired"),
      ids.platformSession,
      defaultPrepareInput("expired-invite@example.test", hashToken(expiredRaw))
    );
    await admin.$executeRaw`
      UPDATE b01_invite_wave.invite SET expires_at=${new Date(now.getTime() - 60_000)}
      WHERE id=${expiredPrepared[0].inviteId}
    `;
    assert.equal((await lookup(buildTokenHashCandidates(expiredRaw))).length, 0);
    assert.equal((await consume({
      hashes: buildTokenHashCandidates(expiredRaw),
      passwordHash,
      requestId: "consume-expired",
    })).length, 0);

    const ambiguousRawOne = "ambiguous-invitation-one";
    const ambiguousRawTwo = "ambiguous-invitation-two";
    await prepare(
      platformContext("prepare-ambiguous-one"),
      ids.platformSession,
      defaultPrepareInput("ambiguous-one@example.test", hashToken(ambiguousRawOne))
    );
    await prepare(
      platformContext("prepare-ambiguous-two"),
      ids.platformSession,
      defaultPrepareInput("ambiguous-two@example.test", hashToken(ambiguousRawTwo))
    );
    const ambiguousHashes = [hashToken(ambiguousRawOne), hashToken(ambiguousRawTwo)];
    assert.equal((await lookup(ambiguousHashes)).length, 0);
    assert.equal((await consume({ hashes: ambiguousHashes, passwordHash, requestId: "consume-ambiguous" })).length, 0);
    await reject(() => lookup(["malformed"]), /B01_INVITE_TOKEN_DENIED/);

    const disabledRaw = "disabled-target-invitation";
    const disabledPrepared = await prepare(
      platformContext("prepare-disabled-target"),
      ids.platformSession,
      defaultPrepareInput("disabled-target@example.test", hashToken(disabledRaw))
    );
    await admin.$executeRaw`
      UPDATE b01_invite_wave.invite_user SET active=false,disabled_at=${now}
      WHERE id=${disabledPrepared[0].userId}
    `;
    assert.equal((await lookup(buildTokenHashCandidates(disabledRaw))).length, 0);
    assert.equal((await consume({
      hashes: buildTokenHashCandidates(disabledRaw),
      passwordHash,
      requestId: "consume-disabled-target",
    })).length, 0);

    const preexistingPasswordRaw = "preexisting-password-invitation";
    const preexistingPasswordPrepared = await prepare(
      platformContext("prepare-preexisting-password"),
      ids.platformSession,
      defaultPrepareInput("preexisting-password@example.test", hashToken(preexistingPasswordRaw))
    );
    const preexistingPasswordHash = "$argon2id$preexisting-password-must-not-change";
    await admin.$executeRaw`
      UPDATE b01_invite_wave.invite_user SET password_hash=${preexistingPasswordHash}
      WHERE id=${preexistingPasswordPrepared[0].userId}
    `;
    assert.equal((await lookup(buildTokenHashCandidates(preexistingPasswordRaw))).length, 0);
    assert.equal((await consume({
      hashes: buildTokenHashCandidates(preexistingPasswordRaw),
      passwordHash,
      requestId: "consume-preexisting-password",
    })).length, 0);
    const [preexistingPasswordState] = await admin.$queryRaw`
      SELECT invite.used_at AS "usedAt",invite_user.status,
        invite_user.password_hash AS "passwordHash"
      FROM b01_invite_wave.invite AS invite
      JOIN b01_invite_wave.invite_user AS invite_user ON invite_user.email=invite.email
      WHERE invite.id=${preexistingPasswordPrepared[0].inviteId}
    `;
    assert.deepEqual(preexistingPasswordState, {
      usedAt: null,
      status: "INVITED",
      passwordHash: preexistingPasswordHash,
    });

    const malformedPlatformRaw = "malformed-platform-scope-invitation";
    const malformedPlatformPrepared = await prepare(
      platformContext("prepare-malformed-platform-scope"),
      ids.platformSession,
      defaultPrepareInput("malformed-platform-scope@example.test", hashToken(malformedPlatformRaw))
    );
    await admin.$executeRaw`
      UPDATE b01_invite_wave.invite_user SET role='PLATFORM_SUPER_ADMIN'
      WHERE id=${malformedPlatformPrepared[0].userId}
    `;
    await admin.$executeRaw`
      UPDATE b01_invite_wave.invite SET role='PLATFORM_SUPER_ADMIN'
      WHERE id=${malformedPlatformPrepared[0].inviteId}
    `;
    assert.equal((await lookup(buildTokenHashCandidates(malformedPlatformRaw))).length, 0);
    assert.equal((await consume({
      hashes: buildTokenHashCandidates(malformedPlatformRaw),
      passwordHash,
      requestId: "consume-malformed-platform-scope",
    })).length, 0);

    const malformedManufacturerRaw = "malformed-manufacturer-scope-invitation";
    const malformedManufacturerPrepared = await prepare(
      platformContext("prepare-malformed-manufacturer-scope"),
      ids.platformSession,
      defaultPrepareInput("malformed-manufacturer-scope@example.test", hashToken(malformedManufacturerRaw))
    );
    await admin.$executeRaw`
      UPDATE b01_invite_wave.invite SET manufacturer_id=${malformedManufacturerPrepared[0].userId}
      WHERE id=${malformedManufacturerPrepared[0].inviteId}
    `;
    assert.equal((await lookup(buildTokenHashCandidates(malformedManufacturerRaw))).length, 0);
    assert.equal((await consume({
      hashes: buildTokenHashCandidates(malformedManufacturerRaw),
      passwordHash,
      requestId: "consume-malformed-manufacturer-scope",
    })).length, 0);
    const malformedStates = await admin.$queryRaw`
      SELECT invite.id,invite.used_at AS "usedAt",invite_user.status,
        invite_user.password_hash AS "passwordHash"
      FROM b01_invite_wave.invite AS invite
      JOIN b01_invite_wave.invite_user AS invite_user ON invite_user.email=invite.email
      WHERE invite.id IN (
        ${malformedPlatformPrepared[0].inviteId},${malformedManufacturerPrepared[0].inviteId}
      )
      ORDER BY invite.id
    `;
    assert.equal(malformedStates.length, 2);
    assert(malformedStates.every((row) =>
      row.usedAt === null && row.status === "INVITED" && row.passwordHash === null
    ));

    const maximumNameRaw = "maximum-invitation-name";
    await prepare(
      platformContext("prepare-maximum-name"),
      ids.platformSession,
      defaultPrepareInput("maximum-name@example.test", hashToken(maximumNameRaw))
    );
    await reject(
      () => consume({
        hashes: buildTokenHashCandidates(maximumNameRaw),
        passwordHash,
        requestId: "consume-name-too-long",
        name: "N".repeat(121),
      }),
      /B01_INVITE_CONSUME_DENIED/
    );
    const maximumNameRows = await consume({
      hashes: buildTokenHashCandidates(maximumNameRaw),
      passwordHash,
      requestId: "consume-name-maximum",
      name: "N".repeat(120),
    });
    assert.equal(maximumNameRows[0].name.length, 120);

    const foreignRaw = "foreign-licensee-invitation";
    await prepare(
      platformContext("prepare-foreign-licensee"),
      ids.platformSession,
      {
        ...defaultPrepareInput("foreign-licensee-target@example.test", hashToken(foreignRaw)),
        requestedLicenseeId: ids.licenseeTwo,
      }
    );
    await admin.$executeRaw`UPDATE b01_invite_wave.licensee SET active=false WHERE id=${ids.licenseeTwo}`;
    assert.equal((await lookup(buildTokenHashCandidates(foreignRaw))).length, 0);
    assert.equal((await consume({
      hashes: buildTokenHashCandidates(foreignRaw),
      passwordHash,
      requestId: "consume-foreign-licensee",
    })).length, 0);
    await admin.$executeRaw`UPDATE b01_invite_wave.licensee SET active=true WHERE id=${ids.licenseeTwo}`;

    const rollbackConsumeRaw = "rollback-consume-invitation";
    const rollbackConsumePrepared = await prepare(
      platformContext("prepare-rollback-consume"),
      ids.platformSession,
      defaultPrepareInput("rollback-consume@example.test", hashToken(rollbackConsumeRaw))
    );
    await reject(
      () => consume({
        hashes: buildTokenHashCandidates(rollbackConsumeRaw),
        passwordHash,
        requestId: "force-outbox-failure",
      }),
      /B01_TEST_AUDIT_OUTBOX_FAILURE/
    );
    const [rollbackState] = await admin.$queryRaw`
      SELECT invite.used_at AS "usedAt",invite_user.status,invite_user.password_hash AS "passwordHash"
      FROM b01_invite_wave.invite AS invite
      JOIN b01_invite_wave.invite_user AS invite_user ON invite_user.email=invite.email
      WHERE invite.id=${rollbackConsumePrepared[0].inviteId}
    `;
    assert.equal(rollbackState.usedAt, null);
    assert.equal(rollbackState.status, "INVITED");
    assert.equal(rollbackState.passwordHash, null);

    const activeManufacturerId = "50000000-0000-4000-8000-000000000002";
    await admin.$executeRaw`
      INSERT INTO b01_invite_wave.invite_user(
        id,email,name,role,organization_id,status,active,updated_at
      ) VALUES (
        ${activeManufacturerId},${"linked-manufacturer@example.test"},${"Linked Manufacturer"},
        ${"MANUFACTURER_ADMIN"},${ids.organizationTwo},${"ACTIVE"},true,${now}
      )
    `;
    const linkResult = await routeRequest({
      method: "POST",
      route: "/api/auth/invite",
      requestId: "link-existing-manufacturer-alias",
      token: platformToken,
      body: {
        email: "linked-manufacturer@example.test",
        name: "Linked Manufacturer",
        role: "MANUFACTURER",
        licenseeId: ids.licenseeOne,
        manufacturerId: activeManufacturerId,
        allowExistingInvitedUser: true,
      },
    });
    assert.equal(linkResult.status, 201);
    assert.equal(linkResult.body.data.inviteId, null);
    assert.equal(linkResult.body.data.linkAction, "LINKED_EXISTING");
    assert.equal(linkResult.body.data.user.role, "MANUFACTURER_ADMIN");
    const [activeManufacturerLink] = await admin.$queryRaw`
      SELECT licensee_id AS "licenseeId",is_primary AS "isPrimary"
      FROM b01_invite_wave.manufacturer_link
      WHERE manufacturer_id=${activeManufacturerId} AND licensee_id=${ids.licenseeOne}
    `;
    assert.deepEqual(activeManufacturerLink, { licenseeId: ids.licenseeOne, isPrimary: true });

    await reject(
      () => authenticated.$queryRawUnsafe("SELECT * FROM b01_invite_wave.invite LIMIT 1"),
      /permission denied/
    );
    await reject(
      () => preauth.$queryRawUnsafe("SELECT * FROM b01_invite_wave.invite_user LIMIT 1"),
      /permission denied/
    );

    const appFunctionSignatures = await admin.$queryRaw`
      SELECT procedure.oid::regprocedure::text AS signature
      FROM pg_catalog.pg_proc AS procedure
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
      WHERE (namespace.nspname='app_rls' AND procedure.proname='prepare_invitation')
         OR (namespace.nspname='app_auth' AND procedure.proname IN (
           'lookup_invitation_token','consume_invitation_token'
         ))
      ORDER BY signature
    `;
    assert.deepEqual(appFunctionSignatures.map((row) => row.signature), [
      "app_auth.consume_invitation_token(text[],text,text,timestamp without time zone,text,text,text)",
      "app_auth.lookup_invitation_token(text[],timestamp without time zone)",
      "app_rls.prepare_invitation(text,text,text,text,text,text,text,text,text,boolean,boolean,text,timestamp without time zone,timestamp without time zone,text,text)",
    ]);

    const functionRows = await admin.$queryRaw`
      SELECT procedure.oid::regprocedure::text AS signature,owner.rolname AS owner,
        procedure.prosecdef AS "securityDefiner",procedure.proconfig AS config
      FROM pg_catalog.pg_proc AS procedure
      JOIN pg_catalog.pg_roles AS owner ON owner.oid=procedure.proowner
      WHERE procedure.oid IN (
        'app_rls.prepare_invitation(text,text,text,text,text,text,text,text,text,boolean,boolean,text,timestamp without time zone,timestamp without time zone,text,text)'::regprocedure,
        'app_auth.lookup_invitation_token(text[],timestamp without time zone)'::regprocedure,
        'app_auth.consume_invitation_token(text[],text,text,timestamp without time zone,text,text,text)'::regprocedure,
        'b01_invite_wave.require_actor(text,text,text,text,timestamp without time zone)'::regprocedure
      )
      ORDER BY signature
    `;
    assert.equal(functionRows.length, 4);
    for (const row of functionRows) {
      assert.equal(row.owner, "mscqr_dev_rls_function_owner");
      assert.equal(row.securityDefiner, true);
      assert.deepEqual(row.config, ["search_path=pg_catalog"]);
    }
    const [ownerRole] = await admin.$queryRaw`
      SELECT rolcanlogin AS "canLogin",rolsuper AS superuser,rolbypassrls AS "bypassRls"
      FROM pg_catalog.pg_roles WHERE rolname='mscqr_dev_rls_function_owner'
    `;
    assert.deepEqual(ownerRole, { canLogin: false, superuser: false, bypassRls: false });

    const [privileges] = await admin.$queryRaw`
      SELECT
        has_function_privilege('mscqr_dev_app','app_rls.prepare_invitation(text,text,text,text,text,text,text,text,text,boolean,boolean,text,timestamp without time zone,timestamp without time zone,text,text)','EXECUTE') AS "appPrepare",
        has_function_privilege('mscqr_dev_preauth','app_rls.prepare_invitation(text,text,text,text,text,text,text,text,text,boolean,boolean,text,timestamp without time zone,timestamp without time zone,text,text)','EXECUTE') AS "preauthPrepare",
        has_function_privilege('mscqr_dev_preauth','app_auth.lookup_invitation_token(text[],timestamp without time zone)','EXECUTE') AS "preauthLookup",
        has_function_privilege('mscqr_dev_app','app_auth.lookup_invitation_token(text[],timestamp without time zone)','EXECUTE') AS "appLookup",
        has_function_privilege('mscqr_dev_preauth','app_auth.consume_invitation_token(text[],text,text,timestamp without time zone,text,text,text)','EXECUTE') AS "preauthConsume",
        has_function_privilege('mscqr_dev_app','app_auth.consume_invitation_token(text[],text,text,timestamp without time zone,text,text,text)','EXECUTE') AS "appConsume"
    `;
    assert.deepEqual(privileges, {
      appPrepare: true,
      preauthPrepare: false,
      preauthLookup: true,
      appLookup: false,
      preauthConsume: true,
      appConsume: false,
    });
    const columnPrivilegeGroups = await admin.$queryRaw`
      SELECT table_name AS "tableName",privilege_type AS privilege,
        string_agg(column_name,',' ORDER BY column_name) AS columns
      FROM information_schema.column_privileges
      WHERE table_schema='b01_invite_wave' AND grantee='mscqr_dev_rls_function_owner'
      GROUP BY table_name,privilege_type
      ORDER BY table_name,privilege_type
    `;
    assert.deepEqual(columnPrivilegeGroups, [
      { tableName: "audit_outbox", privilege: "INSERT", columns: "attempts,created_at,flushed_audit_log_id,id,last_error,next_attempt_at,payload,status,updated_at" },
      { tableName: "audit_outbox", privilege: "SELECT", columns: "payload" },
      { tableName: "invite", privilege: "INSERT", columns: "created_at,created_by_user_id,email,expires_at,id,licensee_id,manufacturer_id,organization_id,role,token_hash" },
      { tableName: "invite", privilege: "SELECT", columns: "accepted_by_user_id,created_at,created_by_user_id,email,expires_at,id,licensee_id,manufacturer_id,organization_id,role,token_hash,used_at" },
      { tableName: "invite", privilege: "UPDATE", columns: "accepted_by_user_id,used_at" },
      { tableName: "invite_user", privilege: "INSERT", columns: "active,email,id,licensee_id,name,organization_id,password_hash,role,status,updated_at" },
      { tableName: "invite_user", privilege: "SELECT", columns: "active,deleted_at,disabled_at,email,email_verified_at,failed_login_attempts,id,licensee_id,locked_until,name,organization_id,password_hash,role,status,updated_at" },
      { tableName: "invite_user", privilege: "UPDATE", columns: "email_verified_at,failed_login_attempts,locked_until,name,password_hash,status,updated_at" },
      { tableName: "licensee", privilege: "SELECT", columns: "active,id,name,organization_id" },
      { tableName: "licensee", privilege: "UPDATE", columns: "id" },
      { tableName: "manufacturer_link", privilege: "INSERT", columns: "created_at,is_primary,licensee_id,manufacturer_id,updated_at" },
      { tableName: "manufacturer_link", privilege: "SELECT", columns: "is_primary,licensee_id,manufacturer_id" },
      { tableName: "organization", privilege: "INSERT", columns: "active,id,name" },
      { tableName: "organization", privilege: "SELECT", columns: "active,id,name" },
    ]);
    const forcedTables = await admin.$queryRaw`
      SELECT relname,relrowsecurity AS rls,relforcerowsecurity AS forced
      FROM pg_catalog.pg_class
      WHERE relnamespace='b01_invite_wave'::regnamespace AND relkind IN ('r','p')
      ORDER BY relname
    `;
    assert.equal(forcedTables.length, 6);
    assert(forcedTables.every((row) => row.rls && row.forced));

    const [{ createAudits, acceptanceAudits, liveInvites }] = await admin.$queryRaw`
      SELECT
        count(*) FILTER (WHERE payload->>'action'='AUTH_INVITE_CREATED')::int AS "createAudits",
        count(*) FILTER (WHERE payload->>'action'='AUTH_INVITE_ACCEPTED')::int AS "acceptanceAudits",
        (SELECT count(*) FROM b01_invite_wave.invite WHERE used_at IS NULL)::int AS "liveInvites"
      FROM b01_invite_wave.audit_outbox
    `;
    assert(createAudits > 0);
    assert(acceptanceAudits >= 2);
    assert(liveInvites > 0);

    console.log(JSON.stringify({
      valid: true,
      proofScope: "b01-invitation-application-path",
      databaseName,
      postgresMajor: 18,
      registeredHttpRootsExercised: 3,
      serviceActivationExercised: true,
      platformCreateAndResend: true,
      sameTenantCreate: true,
      concurrentSingleActiveInvite: true,
      concurrentSingleDeliveryWinner: true,
      concurrentSingleConsumeWinner: true,
      deterministicRetry: true,
      exactProjectionAndPrivileges: true,
      staleDisabledExpiredReplayForeignDenied: true,
      wrongRoleAssurancePurposeIdentityDenied: true,
      directTableDenied: true,
      auditOutboxAtomic: true,
      productionShapedInviteAndOutbox: true,
      nonBypassFunctionOwner: true,
      forceRlsTables: forcedTables.length,
    }));
  } finally {
    console.error = originalConsoleError;
    if (server) await new Promise((resolve) => server.close(resolve));
    await Promise.allSettled([preauth.$disconnect(), authenticated.$disconnect(), admin.$disconnect()]);
  }
};

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
