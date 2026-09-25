const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_CURRENT_RUNTIME_SUPER_ADMIN_INVITATION_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_CURRENT_RUNTIME_SUPER_ADMIN_INVITATION_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_CURRENT_RUNTIME_SUPER_ADMIN_INVITATION_POSTGRES18_TEST";
const ids = {
  adminA: "00000000-0000-4000-8000-000000000307", adminASession: "00000000-0000-4000-9000-000000000701",
  tenantAdmin: "00000000-0000-4000-8000-000000000309", tenantSession: "00000000-0000-4000-9000-000000000710",
  orgA: "00000000-0000-4000-8000-000000000101", licenseeA: "00000000-0000-4000-8000-000000000201",
  licenseeB: "00000000-0000-4000-8000-000000000202",
};
const emails = {
  adminA: "admin-a@synthetic.invalid",
  adminB: "admin-b@synthetic.invalid",
  unaccepted: "admin-unaccepted@synthetic.invalid",
};
const passwordB = ["Synthetic", "Admin", "B", "Password", "31!"].join("-");

const psql = (url, sql) => {
  const result = spawnSync("psql", [url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`${result.stdout || ""}${result.stderr || ""}`);
  return String(result.stdout || "").trim();
};
const listen = (app) => new Promise((resolve) => {
  const server = http.createServer(app).listen(0, "127.0.0.1", () => resolve(server));
});
const cookieJar = () => {
  const values = new Map();
  return {
    absorb(headers) {
      for (const line of headers.getSetCookie()) {
        const [pair] = line.split(";", 1);
        const separator = pair.indexOf("=");
        const name = pair.slice(0, separator);
        const value = pair.slice(separator + 1);
        if (value) values.set(name, value);
        else values.delete(name);
      }
    },
    header: () => [...values].map(([name, value]) => `${name}=${value}`).join("; "),
    csrf: () => values.get("aq_csrf") || "",
  };
};
const tokenFromInviteLink = (link) => {
  const token = new URL(link).searchParams.get("token");
  assert(token, "invite response must contain a tokenized acceptance link");
  return token;
};
const certifyB01AuditVisibility = (bootstrap, preauth, appUrl) => {
  const row = (id, payload) => `('${id}','${JSON.stringify(payload).replaceAll("'", "''")}'::jsonb,transaction_timestamp())`;
  const exact = {
    userId: "b01-policy-user", action: "AUTH_REFRESH_MFA_CHALLENGE_REQUIRED",
    entityType: "RefreshToken", entityId: "b01-policy-successor",
    details: { requestId: "b01-policy-request", boundary: "b01-refresh-rotation" }, probe: "exact",
  };
  const rows = [
    exact,
    { ...exact, userId: "other-user", probe: "wrong-user" },
    { ...exact, entityId: "other-token", probe: "wrong-token" },
    { ...exact, action: "AUTH_REFRESH_ROTATED", probe: "wrong-action" },
    { ...exact, details: { ...exact.details, requestId: "other-request" }, probe: "wrong-request" },
    { ...exact, details: { ...exact.details, boundary: "other-boundary" }, probe: "wrong-boundary" },
    { ...exact, userId: "other-admin", probe: "other-admin" },
    { ...exact, userId: "ordinary-user", probe: "other-user" },
    { action: "AUTH_LOGIN_SUCCESS", userId: exact.userId, entityType: "RefreshToken", entityId: exact.entityId, details: exact.details, probe: "b03-row" },
    { ...exact, details: { ...exact.details, requestId: "historical-request" }, probe: "historical-generation" },
    { ...exact, details: { ...exact.details, requestId: "future-request" }, probe: "future-generation" },
    { userId: exact.userId, action: exact.action, entityType: exact.entityType, entityId: exact.entityId, details: {}, probe: "missing-binding" },
  ];
  psql(bootstrap, `
    INSERT INTO public."AuditLogOutbox" (id,payload,"updatedAt") VALUES
      ${rows.map((payload, index) => row(`b01-policy-${index}`, payload)).join(",\n")};
    CREATE OR REPLACE FUNCTION app_auth.b01_audit_visibility_probe(p_user text,p_token text,p_request text,p_operation text)
    RETURNS text[] LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
    BEGIN
      PERFORM set_config('app.b01_user_id',coalesce(p_user,''),true),
              set_config('app.b01_predecessor_id',coalesce(p_token,''),true),
              set_config('app.b01_request_id',coalesce(p_request,''),true),
              set_config('app.b01_operation',coalesce(p_operation,''),true);
      RETURN ARRAY(SELECT payload->>'probe' FROM public."AuditLogOutbox" ORDER BY payload->>'probe');
    END $fn$;
    ALTER FUNCTION app_auth.b01_audit_visibility_probe(text,text,text,text) OWNER TO mscqr_rls_cert_auth_owner;
    REVOKE ALL ON FUNCTION app_auth.b01_audit_visibility_probe(text,text,text,text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION app_auth.b01_audit_visibility_probe(text,text,text,text) TO mscqr_rls_cert_preauth,mscqr_rls_cert_app;
  `);
  const visible = (url, user, token, requestId, operation) => JSON.parse(psql(url,
    `SELECT to_json(app_auth.b01_audit_visibility_probe('${user}','${token}','${requestId}','${operation}'))::text`));
  assert.deepEqual(visible(preauth, exact.userId, exact.entityId, exact.details.requestId, "finalize-successor"), ["exact"]);
  assert.deepEqual(visible(preauth, "", "", "", ""), []);
  assert.deepEqual(visible(preauth, exact.userId, exact.entityId, "malformed", "finalize-successor"), []);
  assert.deepEqual(visible(appUrl, exact.userId, exact.entityId, exact.details.requestId, "finalize-successor"), []);
  assert.throws(() => psql(preauth, `SELECT count(*) FROM public."AuditLogOutbox"`), /permission denied/);
};

async function main() {
  if (!enabled) return console.log("Current-runtime independent super-admin onboarding PostgreSQL 18 proof skipped");
  assert(confirmed, "Current-runtime independent super-admin onboarding PostgreSQL 18 proof confirmation is required");
  const bootstrap = String(process.env.MSCQR_CURRENT_RUNTIME_INVITATION_BOOTSTRAP_URL || "");
  const appUrl = String(process.env.AUTHENTICATED_APP_DATABASE_URL || "");
  const preauthUrl = String(process.env.PREAUTH_DATABASE_URL || "");
  for (const url of [bootstrap, appUrl, preauthUrl]) {
    const parsed = new URL(url);
    assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname));
  }
  assert.equal(Number(psql(bootstrap, "select current_setting('server_version_num')::int/10000")), 18);
  certifyB01AuditVisibility(bootstrap, preauthUrl, appUrl);

  const passwordHash = "$argon2id$v=19$m=65536,t=3,p=4$QmFzZTY0U2FsdDEyMzQ1Ng$H5LxEgFqUlRkM9wkkSbzu1dO3zJI2GBWB6IlupXMTP0";
  const refreshHash = crypto.createHash("sha256").update("current-runtime-super-admin-refresh").digest("hex");
  psql(bootstrap, `
    DELETE FROM public."Invite" WHERE email IN ('${emails.adminB}','${emails.unaccepted}');
    DELETE FROM public."User" WHERE email IN ('${emails.adminB}','${emails.unaccepted}');
    UPDATE public."User" SET email='${emails.adminA}', role='SUPER_ADMIN', "orgId"=NULL, "licenseeId"=NULL,
      "passwordHash"='${passwordHash}', "emailVerifiedAt"=transaction_timestamp(), "isActive"=true, status='ACTIVE', "disabledAt"=NULL, "deletedAt"=NULL
      WHERE id='${ids.adminA}';
    INSERT INTO public."UserMfaFactor" (id,"userId",type,transports,"createdAt","updatedAt")
      VALUES ('00000000-0000-4000-9000-000000000703','${ids.adminA}','TOTP',ARRAY[]::text[],transaction_timestamp(),transaction_timestamp());
    DELETE FROM public."RefreshToken" WHERE id='${ids.adminASession}';
    INSERT INTO public."RefreshToken" (id,"userId","tokenHash","expiresAt","authenticatedAt","mfaVerifiedAt")
      VALUES ('${ids.adminASession}','${ids.adminA}','${refreshHash}',transaction_timestamp()+interval '1 hour',transaction_timestamp(),transaction_timestamp());
  `);
  const adminABefore = JSON.parse(psql(bootstrap, `SELECT json_build_object(
    'passwordHash',"passwordHash", 'mfaFactors',(SELECT count(*) FROM public."UserMfaFactor" WHERE "userId"='${ids.adminA}'),
    'mfaCredentials',(SELECT count(*) FROM public."AdminMfaCredential" WHERE "userId"='${ids.adminA}'),
    'riskSignals',(SELECT count(*) FROM public."AuthSessionRiskSignal" WHERE "userId"='${ids.adminA}')
  )::text FROM public."User" WHERE id='${ids.adminA}'`));

  process.env.NODE_ENV = "test";
  process.env.JWT_SECRET ||= "current-runtime-super-admin-invitation-test-secret";
  process.env.TOKEN_HASH_SECRET_CURRENT ||= "current-runtime-super-admin-invitation-token-secret";
  process.env.AUTH_MFA_ENCRYPTION_KEY ||= "current-runtime-super-admin-invitation-mfa-encryption";
  process.env.EMAIL_USE_JSON_TRANSPORT = "true";
  const emailCaptureDir = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-invite-activation-cert-"));
  process.env.EMAIL_CAPTURE_DIR = emailCaptureDir;
  const { generateSync } = require("otplib");
  const { createAuthenticatedSessionCapability } = require("../dist/services/auth/authenticatedSessionCapabilityService");
  const { getB01PreAuthPrisma } = require("../dist/rls-waves/session-b/b01/runtimeClients");
  const { hashRefreshToken, signAccessToken } = require("../dist/services/auth/tokenService");
  const { sealCookieToken } = require("../dist/services/auth/cookieTokenProtectionService");
  const { DATABASE_SESSION_CAPABILITY_HEADER } = require("../dist/middleware/auth");
  const { createAuthRoutes } = require("../dist/routes/modules/authRoutes");
  const express = require("express");
  const capability = await createAuthenticatedSessionCapability(getB01PreAuthPrisma(), {
    refreshTokenId: ids.adminASession, refreshTokenHash: refreshHash, assurance: "ADMIN_MFA", expiresAt: new Date(Date.now() + 30 * 60_000),
  });
  const access = signAccessToken({ userId: ids.adminA, email: emails.adminA, role: "SUPER_ADMIN", licenseeId: null, orgId: null, scopeVersion: null, linkedLicenseeIds: [], sessionId: ids.adminASession, authAssurance: "ADMIN_MFA", authenticatedAt: new Date().toISOString(), mfaVerifiedAt: new Date().toISOString() });
  let requestNumber = 0;
  const runtime = express();
  runtime.use(express.json());
  runtime.use((req, _res, next) => { req.requestId = `00000000-0000-4000-8000-${String(++requestNumber).padStart(12, "0")}`; next(); });
  runtime.use("/api", createAuthRoutes());
  const server = await listen(runtime);
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const request = async (path, { method = "GET", body, jar, headers = {} } = {}) => {
    const requestHeaders = { ...headers };
    if (body !== undefined) requestHeaders["content-type"] = "application/json";
    if (jar?.header()) requestHeaders.cookie = jar.header();
    const response = await fetch(`${baseUrl}${path}`, { method, headers: requestHeaders, body: body === undefined ? undefined : JSON.stringify(body) });
    if (jar) jar.absorb(response.headers);
    return { response, body: await response.json() };
  };
  const adminAHeaders = {
    authorization: `Bearer ${access}`,
    [DATABASE_SESSION_CAPABILITY_HEADER]: sealCookieToken(capability.rawCapability, "auth.database-session"),
  };

  try {
    const issueInvite = (allowExistingInvitedUser = false) => request("/api/auth/invite", {
      method: "POST", headers: adminAHeaders,
      body: { email: emails.adminB, name: "Synthetic Admin B", role: "SUPER_ADMIN", allowExistingInvitedUser },
    });
    const firstIssue = await issueInvite();
    assert.equal(firstIssue.response.status, 201, JSON.stringify(firstIssue.body));
    const firstToken = tokenFromInviteLink(firstIssue.body.data.inviteLink);
    const replacementIssue = await issueInvite(true);
    assert.equal(replacementIssue.response.status, 201, JSON.stringify(replacementIssue.body));
    const inviteToken = tokenFromInviteLink(replacementIssue.body.data.inviteLink);
    assert.notEqual(inviteToken, firstToken, "replacement invitation must rotate the raw token");

    const replacedPreview = await request(`/api/auth/invite-preview?token=${encodeURIComponent(firstToken)}`);
    assert.equal(replacedPreview.response.status, 400, "superseded invitation token must be rejected");
    const modifiedToken = `${inviteToken.slice(0, -1)}${inviteToken.endsWith("a") ? "b" : "a"}`;
    const modifiedPreview = await request(`/api/auth/invite-preview?token=${encodeURIComponent(modifiedToken)}`);
    assert.equal(modifiedPreview.response.status, 400, "modified invitation token must be rejected");
    const preview = await request(`/api/auth/invite-preview?token=${encodeURIComponent(inviteToken)}`);
    assert.equal(preview.response.status, 200, JSON.stringify(preview.body));
    assert.equal(preview.body.data.email, emails.adminB);
    assert.equal(preview.body.data.role, "SUPER_ADMIN");

    const bootstrapJar = cookieJar();
    const accepted = await request("/api/auth/accept-invite", {
      method: "POST", jar: bootstrapJar,
      body: { token: inviteToken, password: passwordB, confirmPassword: passwordB, name: "Synthetic Admin B" },
    });
    assert.equal(accepted.response.status, 200, JSON.stringify(accepted.body));
    assert(accepted.body.data.challengeId);
    assert.equal(bootstrapJar.header(), "", "password setup must not issue authentication cookies");
    const adminBId = psql(bootstrap, `SELECT id FROM public."User" WHERE email='${emails.adminB}'`);
    assert.notEqual(adminBId, ids.adminA);
    assert.equal(psql(bootstrap, `SELECT status::text||':'||("emailVerifiedAt" IS NULL)::text FROM public."User" WHERE id='${adminBId}'`), "INVITED:true");
    const captured = fs.readFileSync(path.join(emailCaptureDir, "emails.jsonl"), "utf8").trim().split("\n").map(JSON.parse)
      .filter((entry) => entry.template === "invite_activation_code" && entry.toAddress === emails.adminB);
    assert.equal(captured.length, 1);
    const activationCode = captured[0].text.match(/\b\d{6}\b/)?.[0];
    assert(activationCode, "test-only email capture must contain a six-digit activation code");
    const activated = await request("/api/auth/invite-activation/verify", {
      method: "POST", body: { challengeId: accepted.body.data.challengeId, code: activationCode },
    });
    assert.equal(activated.response.status, 200, JSON.stringify(activated.body));
    assert.equal(activated.body.data.loginRequired, true, "super admin must not receive a password session");
    const initialLogin = await request("/api/auth/login", {
      method: "POST", jar: bootstrapJar, body: { email: emails.adminB, password: passwordB },
    });
    assert.equal(initialLogin.response.status, 200, JSON.stringify(initialLogin.body));
    assert.equal(initialLogin.body.data.auth.sessionStage, "MFA_BOOTSTRAP");
    const passwordOnlyRawRefresh = "current-runtime-password-only-admin-refresh";
    const passwordOnlyRefreshHash = hashRefreshToken(passwordOnlyRawRefresh);
    assert(adminABefore.mfaFactors + adminABefore.mfaCredentials > 0, "password-only refresh proof requires an enrolled administrator");
    psql(bootstrap, `INSERT INTO public."RefreshToken" (id,"userId","tokenHash","expiresAt","authenticatedAt","mfaVerifiedAt")
      VALUES ('00000000-0000-4000-9000-000000000702','${ids.adminA}','${passwordOnlyRefreshHash}',transaction_timestamp()+interval '1 hour',transaction_timestamp(),NULL)`);
    const passwordOnlyJar = cookieJar();
    passwordOnlyJar.absorb({ getSetCookie: () => [
      `aq_refresh=${sealCookieToken(passwordOnlyRawRefresh, "auth.refresh")}; Path=/`,
      `aq_csrf=${bootstrapJar.csrf()}; Path=/`,
    ] });
    const passwordOnlyRefresh = await request("/api/auth/refresh", {
      method: "POST", jar: passwordOnlyJar, headers: { "x-csrf-token": passwordOnlyJar.csrf() }, body: {},
    });
    assert.equal(passwordOnlyRefresh.response.status, 200, JSON.stringify(passwordOnlyRefresh.body));
    assert.equal(passwordOnlyRefresh.body.data.auth.sessionStage, "MFA_BOOTSTRAP");

    const replay = await request("/api/auth/accept-invite", {
      method: "POST", body: { token: inviteToken, password: passwordB, confirmPassword: passwordB, name: "Synthetic Admin B" },
    });
    assert.equal(replay.response.status, 400, "used invitation must not be accepted twice");
    const privilegedBeforeMfa = await request("/api/auth/invite", {
      method: "POST", jar: bootstrapJar, headers: { "x-csrf-token": bootstrapJar.csrf() },
      body: { email: emails.unaccepted, name: "Unaccepted Synthetic Admin", role: "SUPER_ADMIN" },
    });
    assert.notEqual(privilegedBeforeMfa.response.status, 201, "MFA bootstrap session must not authorize privileged operation");

    const setup = await request("/api/auth/mfa/setup/begin", {
      method: "POST", jar: bootstrapJar, headers: { "x-csrf-token": bootstrapJar.csrf() }, body: {},
    });
    assert.equal(setup.response.status, 200, JSON.stringify(setup.body));
    const totpSecret = setup.body.data.secret;
    assert.equal(typeof totpSecret, "string");
    const validTotp = generateSync({ secret: totpSecret });
    const invalidTotp = validTotp === "000000" ? "000001" : "000000";
    const wrongTotp = await request("/api/auth/mfa/setup/confirm", {
      method: "POST", jar: bootstrapJar, headers: { "x-csrf-token": bootstrapJar.csrf() }, body: { code: invalidTotp },
    });
    assert.equal(wrongTotp.response.status, 400, "wrong TOTP must be rejected");
    const bootstrapReplayJar = cookieJar();
    bootstrapReplayJar.absorb({ getSetCookie: () => bootstrapJar.header().split("; ").map((value) => `${value}; Path=/`) });
    const enrolled = await request("/api/auth/mfa/setup/confirm", {
      method: "POST", jar: bootstrapJar, headers: { "x-csrf-token": bootstrapJar.csrf() }, body: { code: validTotp },
    });
    assert.equal(enrolled.response.status, 200, JSON.stringify(enrolled.body));
    assert.equal(enrolled.body.data.auth.sessionStage, "ACTIVE");
    assert.equal(enrolled.body.data.auth.authAssurance, "ADMIN_MFA");
    const enrollmentReplay = await request("/api/auth/mfa/setup/confirm", {
      method: "POST", jar: bootstrapReplayJar, headers: { "x-csrf-token": bootstrapReplayJar.csrf() }, body: { code: validTotp },
    });
    assert.notEqual(enrollmentReplay.response.status, 200, "consumed MFA bootstrap state must not be replayable");

    const firstActiveSessionId = psql(bootstrap, `SELECT id FROM public."RefreshToken" WHERE "userId"='${adminBId}' AND "revokedAt" IS NULL ORDER BY "createdAt" DESC LIMIT 1`);
    assert(firstActiveSessionId);
    assert.notEqual(firstActiveSessionId, ids.adminASession, "Admin B bootstrap session must be independent from Admin A");
    const loginJar = cookieJar();
    const loggedIn = await request("/api/auth/login", { method: "POST", jar: loginJar, body: { email: emails.adminB, password: passwordB } });
    assert.equal(loggedIn.response.status, 200, JSON.stringify(loggedIn.body));
    assert.equal(loggedIn.body.data.user.id, adminBId);
    assert.equal(loggedIn.body.data.auth.sessionStage, "ACTIVE");
    assert.equal(loggedIn.body.data.auth.authAssurance, "ADMIN_MFA");
    for (const generation of ["first", "successive"]) {
      const refreshed = await request("/api/auth/refresh", {
        method: "POST", jar: loginJar, headers: { "x-csrf-token": loginJar.csrf() }, body: {},
      });
      assert.equal(refreshed.response.status, 200, `${generation} active refresh failed: ${JSON.stringify(refreshed.body)}`);
      assert.equal(refreshed.body.data.auth.sessionStage, "ACTIVE");
    }
    const secondActiveSessionId = psql(bootstrap, `SELECT id FROM public."RefreshToken" WHERE "userId"='${adminBId}' AND "revokedAt" IS NULL ORDER BY "createdAt" DESC LIMIT 1`);
    assert.notEqual(secondActiveSessionId, firstActiveSessionId, "subsequent MFA-authenticated login must create an independent session");
    assert.notEqual(secondActiveSessionId, ids.adminASession, "Admin B login session must be independent from Admin A");

    const me = await request("/api/auth/me", { jar: loginJar });
    assert.equal(me.response.status, 200, JSON.stringify(me.body));
    assert.equal(me.body.data.id, adminBId);
    const missingCsrf = await request("/api/auth/invite", {
      method: "POST", jar: bootstrapJar, body: { email: emails.unaccepted, name: "Unaccepted Synthetic Admin", role: "SUPER_ADMIN" },
    });
    assert.equal(missingCsrf.response.status, 403, "cookie-authenticated privileged operation must require CSRF");
    const privileged = await request("/api/auth/invite", {
      method: "POST", jar: bootstrapJar, headers: { "x-csrf-token": bootstrapJar.csrf() },
      body: { email: emails.unaccepted, name: "Unaccepted Synthetic Admin", role: "SUPER_ADMIN" },
    });
    assert.equal(privileged.response.status, 201, JSON.stringify(privileged.body));
    assert.equal(privileged.body.data.actorUserId, adminBId);

    const adminAStillActive = await request("/api/auth/me", { headers: adminAHeaders });
    assert.equal(adminAStillActive.response.status, 200, JSON.stringify(adminAStillActive.body));
    assert.equal(adminAStillActive.body.data.id, ids.adminA);

    const result = JSON.parse(psql(bootstrap, `SELECT json_build_object(
      'adminBId',b.id, 'adminBRole',b.role, 'adminBLicenseeId',b."licenseeId", 'adminBOrgId',b."orgId",
      'adminBActive',b."isActive", 'adminBStatus',b.status, 'adminBVerified',b."emailVerifiedAt" IS NOT NULL,
      'passwordsDistinct',a."passwordHash"<>b."passwordHash",
      'adminBMfaFactors',(SELECT count(*) FROM public."UserMfaFactor" WHERE "userId"=b.id AND "disabledAt" IS NULL),
      'adminBRefreshSessions',(SELECT count(*) FROM public."RefreshToken" WHERE "userId"=b.id),
      'adminBRiskSignals',(SELECT count(*) FROM public."AuthSessionRiskSignal" WHERE "userId"=b.id),
      'adminBAuditActor',(SELECT "userId" FROM public."AuditLog" WHERE action='AUTH_INVITE_CREATED' AND "entityId"=(SELECT id FROM public."Invite" WHERE email='${emails.unaccepted}' ORDER BY "createdAt" DESC LIMIT 1) ORDER BY "createdAt" DESC LIMIT 1)
    )::text FROM public."User" a JOIN public."User" b ON b.email='${emails.adminB}' WHERE a.id='${ids.adminA}'`));
    assert.deepEqual({ role: result.adminBRole, licenseeId: result.adminBLicenseeId, orgId: result.adminBOrgId }, { role: "SUPER_ADMIN", licenseeId: null, orgId: null });
    assert.equal(result.adminBActive, true);
    assert.equal(result.adminBStatus, "ACTIVE");
    assert.equal(result.adminBVerified, true);
    assert.equal(result.passwordsDistinct, true);
    assert(result.adminBMfaFactors > 0);
    assert(result.adminBRefreshSessions > 1);
    assert(result.adminBRiskSignals > 0);
    assert.equal(result.adminBAuditActor, result.adminBId);
    const adminAAfter = JSON.parse(psql(bootstrap, `SELECT json_build_object(
      'passwordHash',"passwordHash", 'mfaFactors',(SELECT count(*) FROM public."UserMfaFactor" WHERE "userId"='${ids.adminA}'),
      'mfaCredentials',(SELECT count(*) FROM public."AdminMfaCredential" WHERE "userId"='${ids.adminA}'),
      'riskSignals',(SELECT count(*) FROM public."AuthSessionRiskSignal" WHERE "userId"='${ids.adminA}')
    )::text FROM public."User" WHERE id='${ids.adminA}'`));
    assert.deepEqual(adminAAfter, adminABefore, "Admin B onboarding must not mutate Admin A credential, MFA, or risk state");

    const tenantRefreshHash = crypto.createHash("sha256").update("phase4-tenant-password-refresh").digest("hex");
    psql(bootstrap, `INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","passwordHash","emailVerifiedAt","updatedAt")
      VALUES ('${ids.tenantAdmin}','phase4-tenant@synthetic.invalid','Phase 4 Tenant','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,'${passwordHash}',transaction_timestamp(),transaction_timestamp());
      INSERT INTO public."RefreshToken" (id,"orgId","userId","tokenHash","expiresAt","authenticatedAt")
      VALUES ('${ids.tenantSession}','${ids.orgA}','${ids.tenantAdmin}','${tenantRefreshHash}',transaction_timestamp()+interval '1 hour',transaction_timestamp())`);
    const tenantCapability = await createAuthenticatedSessionCapability(getB01PreAuthPrisma(), {
      refreshTokenId: ids.tenantSession, refreshTokenHash: tenantRefreshHash, assurance: "PASSWORD", expiresAt: new Date(Date.now() + 30 * 60_000),
    });
    const tenantClaims = {
      userId: ids.tenantAdmin, email: "phase4-tenant@synthetic.invalid", role: "LICENSEE_ADMIN",
      orgId: ids.orgA, licenseeId: ids.licenseeA, linkedLicenseeIds: [], sessionId: ids.tenantSession,
      sessionStage: "ACTIVE", authAssurance: "PASSWORD", authenticatedAt: new Date().toISOString(), mfaVerifiedAt: null,
    };
    const tenantAccess = signAccessToken({ ...tenantClaims, scopeVersion: null });
    const tenantHeaders = {
      authorization: `Bearer ${tenantAccess}`,
      [DATABASE_SESSION_CAPABILITY_HEADER]: sealCookieToken(tenantCapability.rawCapability, "auth.database-session"),
    };
    const inScopeInvite = await request("/api/auth/invite", {
      method: "POST", headers: tenantHeaders,
      body: { email: "phase4-manufacturer@synthetic.invalid", name: "Phase 4 Manufacturer", role: "MANUFACTURER_ADMIN", licenseeId: ids.licenseeA },
    });
    assert.equal(inScopeInvite.response.status, 201, JSON.stringify(inScopeInvite.body));
    const foreignInvite = await request("/api/auth/invite", {
      method: "POST", headers: tenantHeaders,
      body: { email: "phase4-foreign@synthetic.invalid", name: "Foreign Manufacturer", role: "MANUFACTURER_ADMIN", licenseeId: ids.licenseeB },
    });
    assert.notEqual(foreignInvite.response.status, 201, "password assurance must not expand tenant invite authority");
    assert.equal(psql(bootstrap, "SELECT count(*) FROM public.\"User\" WHERE email='phase4-foreign@synthetic.invalid'"), "0", "denied foreign invite must not create an account");
    const { getLogs } = require("../dist/controllers/auditController");
    const auditRead = async (licenseeId) => {
      const response = { status: 200, body: null };
      await getLogs({
        user: tenantClaims, databaseSessionCapability: tenantCapability.rawCapability,
        requestId: crypto.randomUUID(), query: { licenseeId, limit: "20" },
      }, {
        status(code) { response.status = code; return this; },
        json(body) { response.body = body; return this; },
      });
      return response;
    };
    const inScopeAudit = await auditRead(ids.licenseeA);
    assert.equal(inScopeAudit.status, 200, JSON.stringify(inScopeAudit.body));
    assert(Array.isArray(inScopeAudit.body.data.logs));
    const foreignAudit = await auditRead(ids.licenseeB);
    assert.equal(foreignAudit.status, 403, "password assurance must not expand audit tenant scope");
    console.log("Current-runtime super-admin invitation PostgreSQL 18 proof passed");
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(emailCaptureDir, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
