const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_CURRENT_RUNTIME_SUPER_ADMIN_INVITATION_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_CURRENT_RUNTIME_SUPER_ADMIN_INVITATION_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_CURRENT_RUNTIME_SUPER_ADMIN_INVITATION_POSTGRES18_TEST";
const ids = { administration: "00000000-0000-4000-8000-000000000307", session: "00000000-0000-4000-9000-000000000701" };
const adminEmail = "administration@mscqr.com";
const victoriaEmail = "victoria@mscqr.com";

const psql = (url, sql) => {
  const result = spawnSync("psql", [url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`${result.stdout || ""}${result.stderr || ""}`);
  return String(result.stdout || "").trim();
};

const listen = (app) => new Promise((resolve) => {
  const server = http.createServer(app).listen(0, "127.0.0.1", () => resolve(server));
});

async function main() {
  if (!enabled) return console.log("Current-runtime super-admin invitation PostgreSQL 18 proof skipped");
  assert(confirmed, "Current-runtime super-admin invitation PostgreSQL 18 proof confirmation is required");
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
    DELETE FROM public."Invite" WHERE email='${victoriaEmail}';
    DELETE FROM public."User" WHERE email='${victoriaEmail}';
    UPDATE public."User" SET email='${adminEmail}', role='SUPER_ADMIN', "orgId"=NULL, "licenseeId"=NULL,
      "passwordHash"='${passwordHash}', "emailVerifiedAt"=transaction_timestamp(), "isActive"=true, status='ACTIVE', "disabledAt"=NULL, "deletedAt"=NULL
      WHERE id='${ids.administration}';
    DELETE FROM public."RefreshToken" WHERE id='${ids.session}';
    INSERT INTO public."RefreshToken" (id,"userId","tokenHash","expiresAt","authenticatedAt","mfaVerifiedAt")
      VALUES ('${ids.session}','${ids.administration}','${refreshHash}',transaction_timestamp()+interval '1 hour',transaction_timestamp(),transaction_timestamp());
  `);

  process.env.NODE_ENV = "test";
  process.env.JWT_SECRET ||= "current-runtime-super-admin-invitation-test-secret";
  process.env.TOKEN_HASH_SECRET_CURRENT ||= "current-runtime-super-admin-invitation-token-secret";
  process.env.EMAIL_USE_JSON_TRANSPORT = "true";
  const { createAuthenticatedSessionCapability } = require("../dist/services/auth/authenticatedSessionCapabilityService");
  const { getB01PreAuthPrisma } = require("../dist/rls-waves/session-b/b01/runtimeClients");
  const { signAccessToken } = require("../dist/services/auth/tokenService");
  const { sealCookieToken } = require("../dist/services/auth/cookieTokenProtectionService");
  const { authenticate, DATABASE_SESSION_CAPABILITY_HEADER } = require("../dist/middleware/auth");
  const { requireAdministrationMutator } = require("../dist/middleware/rbac");
  const { requireRecentAdminMfa } = require("../dist/middleware/auth");
  const { invite } = require("../dist/controllers/authController");
  const express = require("express");
  const capability = await createAuthenticatedSessionCapability(getB01PreAuthPrisma(), {
    refreshTokenId: ids.session, refreshTokenHash: refreshHash, assurance: "ADMIN_MFA", expiresAt: new Date(Date.now() + 30 * 60_000),
  });
  const access = signAccessToken({ userId: ids.administration, email: adminEmail, role: "SUPER_ADMIN", licenseeId: null, orgId: null, scopeVersion: null, linkedLicenseeIds: [], sessionId: ids.session, authAssurance: "ADMIN_MFA", authenticatedAt: new Date().toISOString(), mfaVerifiedAt: new Date().toISOString() });
  const runtime = express();
  runtime.use(express.json());
  runtime.use((req, _res, next) => { req.requestId = "00000000-0000-4000-8000-000000000702"; next(); });
  runtime.post("/api/auth/invite", authenticate, requireAdministrationMutator, requireRecentAdminMfa, invite);
  const server = await listen(runtime);
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/auth/invite`, {
      method: "POST",
      headers: { authorization: `Bearer ${access}`, [DATABASE_SESSION_CAPABILITY_HEADER]: sealCookieToken(capability.rawCapability, "auth.database-session"), "content-type": "application/json" },
      body: JSON.stringify({ email: victoriaEmail, name: "Victoria", role: "SUPER_ADMIN" }),
    });
    const body = await response.json();
    assert.equal(response.status, 201, JSON.stringify(body));
    assert.equal(body.data.user.email, victoriaEmail);
    assert.equal(body.data.user.role, "SUPER_ADMIN");
    assert.equal(body.data.user.licenseeId, null);
    assert.equal(body.data.user.orgId, null);
    assert.notEqual(body.data.user.id, ids.administration);
    assert.equal(body.data.actorUserId, ids.administration);
    const result = JSON.parse(psql(bootstrap, `SELECT json_build_object('role',u.role,'licenseeId',u."licenseeId",'orgId',u."orgId",'inviteActor',i."createdByUserId",'auditActor',(SELECT "userId" FROM public."AuditLog" WHERE action='AUTH_INVITE_CREATED' AND "entityId"=i.id ORDER BY "createdAt" DESC LIMIT 1))::text FROM public."User" u JOIN public."Invite" i ON i.email=u.email WHERE u.email='${victoriaEmail}'`));
    assert.deepEqual(result, { role: "SUPER_ADMIN", licenseeId: null, orgId: null, inviteActor: ids.administration, auditActor: ids.administration });
    console.log("Current-runtime super-admin invitation PostgreSQL 18 proof passed");
  } finally { server.close(); }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
