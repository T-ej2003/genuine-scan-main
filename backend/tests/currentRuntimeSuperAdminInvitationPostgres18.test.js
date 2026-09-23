const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_CURRENT_RUNTIME_SUPER_ADMIN_INVITATION_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_CURRENT_RUNTIME_SUPER_ADMIN_INVITATION_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_CURRENT_RUNTIME_SUPER_ADMIN_INVITATION_POSTGRES18_TEST";
const ids = { adminA: "00000000-0000-4000-8000-000000000307", adminASession: "00000000-0000-4000-9000-000000000701" };
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

  const passwordHash = "$argon2id$v=19$m=65536,t=3,p=4$QmFzZTY0U2FsdDEyMzQ1Ng$H5LxEgFqUlRkM9wkkSbzu1dO3zJI2GBWB6IlupXMTP0";
  const refreshHash = crypto.createHash("sha256").update("current-runtime-super-admin-refresh").digest("hex");
  psql(bootstrap, `
    DELETE FROM public."Invite" WHERE email IN ('${emails.adminB}','${emails.unaccepted}');
    DELETE FROM public."User" WHERE email IN ('${emails.adminB}','${emails.unaccepted}');
    UPDATE public."User" SET email='${emails.adminA}', role='SUPER_ADMIN', "orgId"=NULL, "licenseeId"=NULL,
      "passwordHash"='${passwordHash}', "emailVerifiedAt"=transaction_timestamp(), "isActive"=true, status='ACTIVE', "disabledAt"=NULL, "deletedAt"=NULL
      WHERE id='${ids.adminA}';
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
  const { generateSync } = require("otplib");
  const { createAuthenticatedSessionCapability } = require("../dist/services/auth/authenticatedSessionCapabilityService");
  const { getB01PreAuthPrisma } = require("../dist/rls-waves/session-b/b01/runtimeClients");
  const { signAccessToken } = require("../dist/services/auth/tokenService");
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
      body: { token: inviteToken, password: passwordB, name: "Synthetic Admin B" },
    });
    assert.equal(accepted.response.status, 200, JSON.stringify(accepted.body));
    assert.equal(accepted.body.data.user.email, emails.adminB);
    assert.equal(accepted.body.data.user.role, "SUPER_ADMIN");
    assert.equal(accepted.body.data.user.licenseeId, null);
    assert.equal(accepted.body.data.user.orgId, null);
    assert.notEqual(accepted.body.data.user.id, ids.adminA);
    assert.equal(accepted.body.data.auth.sessionStage, "MFA_BOOTSTRAP");

    const replay = await request("/api/auth/accept-invite", {
      method: "POST", body: { token: inviteToken, password: passwordB, name: "Synthetic Admin B" },
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

    const adminBId = accepted.body.data.user.id;
    const firstActiveSessionId = psql(bootstrap, `SELECT id FROM public."RefreshToken" WHERE "userId"='${adminBId}' AND "revokedAt" IS NULL ORDER BY "createdAt" DESC LIMIT 1`);
    assert(firstActiveSessionId);
    assert.notEqual(firstActiveSessionId, ids.adminASession, "Admin B bootstrap session must be independent from Admin A");
    const loginJar = cookieJar();
    const loggedIn = await request("/api/auth/login", { method: "POST", jar: loginJar, body: { email: emails.adminB, password: passwordB } });
    assert.equal(loggedIn.response.status, 200, JSON.stringify(loggedIn.body));
    assert.equal(loggedIn.body.data.user.id, adminBId);
    assert.equal(loggedIn.body.data.auth.sessionStage, "ACTIVE");
    assert.equal(loggedIn.body.data.auth.authAssurance, "ADMIN_MFA");
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
    console.log("Current-runtime super-admin invitation PostgreSQL 18 proof passed");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
