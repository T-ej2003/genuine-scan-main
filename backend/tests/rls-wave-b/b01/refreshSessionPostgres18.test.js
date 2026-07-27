const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const express = require("express");

const enabled = process.env.MSCQR_RLS_B01_REFRESH_POSTGRES_TEST === "true";
const confirmed = process.env.MSCQR_RLS_B01_REFRESH_CONFIRM === "MSCQR_RUN_LOCAL_B01_REFRESH_POSTGRES_TEST";
const expectedDatabase = "mscqr_rls_wave_b_auth_public_workers";

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
};

const main = async () => {
  if (!enabled) {
    console.log("B01 refresh PostgreSQL 18 proof skipped");
    return;
  }
  assert(confirmed, "Set MSCQR_RLS_B01_REFRESH_CONFIRM=MSCQR_RUN_LOCAL_B01_REFRESH_POSTGRES_TEST");
  const adminUrl = String(process.env.DATABASE_URL || "").trim();
  safeUrl(adminUrl);

  const fixture = path.join(__dirname, "refreshSessionPostgres18.fixture.sql");
  assert(fs.statSync(fixture).isFile());
  execFileSync("psql", [adminUrl, "-v", "ON_ERROR_STOP=1", "-f", fixture], { stdio: "pipe" });

  process.env.TOKEN_HASH_SECRET_CURRENT = "b01-refresh-token-secret";
  process.env.JWT_SECRET_CURRENT = "b01-refresh-jwt-secret";
  process.env.IP_HASH_SALT_CURRENT = "b01-refresh-ip-secret";
  process.env.NODE_ENV = "production";
  process.env.DATABASE_URL = adminUrl;
  process.env.PREAUTH_DATABASE_URL = roleUrl(adminUrl, "mscqr_dev_preauth");
  process.env.AUTHENTICATED_APP_DATABASE_URL = roleUrl(adminUrl, "mscqr_dev_app");
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
  const {
    createRefreshToken,
    findRefreshTokenByRaw,
    listActiveRefreshTokensForUser,
    revokeAllUserRefreshTokens,
    revokePasswordOnlyRefreshTokensForUser,
    revokeRefreshTokenById,
    revokeRefreshTokenByRaw,
    rotateRefreshToken,
  } = require("../../../dist/services/auth/refreshTokenService");
  const { hashRefreshToken, signAccessToken } = require("../../../dist/services/auth/tokenService");
  const { sealCookieToken } = require("../../../dist/services/auth/cookieTokenProtectionService");
  const { createAuthRoutes } = require("../../../dist/routes/modules/authRoutes");
  const {
    claimRefreshTokenRotation,
    loadRefreshSessionState,
  } = require("../../../dist/rls-waves/session-b/b01/sessionCredentialRepository");
  const { requireRecentMfaSession } = require("../../../dist/rls-waves/session-b/b01/authenticatedSecurityRepository");

  const now = new Date();
  const later = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  const scopeVersion = now.toISOString();

  const seedActor = async ({ id, active = true, membershipActive = true, mfaEnabled = false, role = "MANUFACTURER" }) => {
    const tenantScoped = role.startsWith("MANUFACTURER") || ["LICENSEE_ADMIN", "ORG_ADMIN"].includes(role);
    await admin.$executeRaw`
      INSERT INTO b01_refresh_wave.actor(
        id,email,name,role,organization_id,licensee_id,manufacturer_id,active,email_verified_at,
        mfa_required,mfa_enabled,mfa_last_used_at
      ) VALUES (
        ${id},${`${id}@example.test`},${id},${role},${`${id}-org`},${`${id}-licensee`},
        ${role.startsWith("MANUFACTURER") ? id : null},${active},${now},
        ${true},${mfaEnabled},${mfaEnabled ? now : null}
      )
    `;
    if (tenantScoped) {
      await admin.$executeRaw`
        INSERT INTO b01_refresh_wave.membership(
          user_id,licensee_id,organization_id,licensee_name,licensee_prefix,brand_name,
          is_primary,scope_version,active
        ) VALUES (
          ${id},${`${id}-licensee`},${`${id}-org`},${`${id} Licensee`},${id.slice(0, 8).toUpperCase()},
          ${`${id} Brand`},true,${scopeVersion},${membershipActive}
        )
      `;
    }
  };

  const seedToken = async ({ id, userId, rawToken, expiresAt = later, revokedAt = null, replacedByHash = null, mfaVerifiedAt = null }) => {
    const tokenHash = hashRefreshToken(rawToken);
    await admin.$executeRaw`
      INSERT INTO b01_refresh_wave.refresh_token(
        id,user_id,organization_id,token_hash,expires_at,created_at,created_ip_hash,
        created_user_agent,authenticated_at,mfa_verified_at,last_used_at,revoked_at,revoked_reason,replaced_by_token_hash
      ) VALUES (
        ${id},${userId},${`${userId}-org`},${tokenHash},${expiresAt},${new Date(now.getTime() - 60_000)},
        ${"a".repeat(64)},${"postgres-proof"},${now},${mfaVerifiedAt},${now},${revokedAt},
        ${revokedAt ? "PRESEEDED_REVOKED" : null},${replacedByHash}
      )
    `;
    return tokenHash;
  };

  const rotate = (rawToken, requestId, decide) => rotateRefreshToken({
    rawToken,
    ipHash: "b".repeat(64),
    userAgent: "postgres-18-proof",
    requestId,
    now,
    ...(decide ? { decide } : {}),
  });

  let server;
  let baseUrl;
  const routeRequest = async ({ method, route, requestId, userId, sessionId, rawRefreshToken }) => {
    const headers = {
      "user-agent": "postgres-route-proof",
      "x-request-id": requestId,
    };
    if (userId && sessionId) {
      headers.authorization = `Bearer ${signAccessToken({
        userId,
        email: `${userId}@example.test`,
        role: "LICENSEE_ADMIN",
        licenseeId: `${userId}-licensee`,
        orgId: `${userId}-org`,
        scopeVersion: null,
        linkedLicenseeIds: null,
        sessionId,
        sessionStage: "ACTIVE",
        authAssurance: "PASSWORD",
        authenticatedAt: now.toISOString(),
        mfaVerifiedAt: null,
      })}`;
    }
    if (rawRefreshToken) {
      const csrf = "postgres-route-csrf";
      headers.cookie = `aq_refresh=${encodeURIComponent(sealCookieToken(rawRefreshToken, "auth.refresh"))}; aq_csrf=${csrf}`;
      headers["x-csrf-token"] = csrf;
    }
    const result = await fetch(`${baseUrl}${route}`, { method, headers });
    return {
      status: result.status,
      body: await result.json(),
      setCookie: result.headers.get("set-cookie") || "",
    };
  };

  try {
    const app = express();
    app.use(express.json());
    app.use(createAuthRoutes());
    server = http.createServer(app);
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
    const [{ versionNumber, databaseName }] = await admin.$queryRaw`
      SELECT current_setting('server_version_num')::int AS "versionNumber",current_database() AS "databaseName"
    `;
    assert(versionNumber >= 180000 && versionNumber < 190000);
    assert.equal(databaseName, expectedDatabase);

    await seedActor({ id: "actor-main", mfaEnabled: true });
    await seedToken({ id: "token-main", userId: "actor-main", rawToken: "raw-main", mfaVerifiedAt: now });
    const successful = await rotate("raw-main", "request-main", async ({ tx, token, tokenHashCandidates, now: checkedAt }) => {
      const state = await loadRefreshSessionState(tx, {
        tokenId: token.id,
        tokenHashCandidates,
        requestedLicenseeId: null,
        requestedScopeVersion: null,
        checkedAt,
        requestId: "request-main",
      });
      assert.equal(state.userId, "actor-main");
      assert.equal(state.selectedLicenseeId, "actor-main-licensee");
      assert.deepEqual(state.mfaMethods, ["TOTP", "BACKUP_CODE"]);
      return {
        action: "rotate",
        value: state.userId,
        orgId: state.sessionOrganizationId,
        authenticatedAt: token.authenticatedAt || checkedAt,
        mfaVerifiedAt: token.mfaVerifiedAt,
      };
    });
    assert.equal(successful.ok, true);
    assert.equal(successful.rotated, true);
    assert.equal(successful.value, "actor-main");
    const mainRows = await admin.$queryRaw`
      SELECT id,revoked_reason AS "revokedReason",replaced_by_token_hash IS NOT NULL AS "hasSuccessor"
      FROM b01_refresh_wave.refresh_token WHERE user_id='actor-main' ORDER BY created_at,id
    `;
    assert.equal(mainRows.length, 2);
    assert.deepEqual(mainRows.find((row) => row.id === "token-main"), {
      id: "token-main",
      revokedReason: "ROTATED",
      hasSuccessor: true,
    });

    await seedActor({ id: "controller-root", role: "LICENSEE_ADMIN", mfaEnabled: true });
    await seedToken({
      id: "token-controller-root",
      userId: "controller-root",
      rawToken: "raw-controller-root",
      mfaVerifiedAt: now,
    });
    const controllerSuccess = await routeRequest({
      method: "POST",
      route: "/auth/refresh",
      requestId: "request-controller-root",
      rawRefreshToken: "raw-controller-root",
    });
    assert.equal(controllerSuccess.status, 200);
    assert.equal(controllerSuccess.body.success, true);
    assert.match(controllerSuccess.setCookie, /aq_access=/);
    assert.match(controllerSuccess.setCookie, /aq_csrf=/);
    assert.match(controllerSuccess.setCookie, /aq_refresh=/);
    const [{ controllerActive, controllerRotated }] = await admin.$queryRaw`
      SELECT
        count(*) FILTER (WHERE revoked_at IS NULL)::int AS "controllerActive",
        count(*) FILTER (WHERE revoked_reason='ROTATED')::int AS "controllerRotated"
      FROM b01_refresh_wave.refresh_token WHERE user_id='controller-root'
    `;
    assert.equal(controllerActive, 1);
    assert.equal(controllerRotated, 1);

    await seedActor({ id: "controller-mfa-bootstrap", role: "LICENSEE_ADMIN", mfaEnabled: true });
    await seedToken({
      id: "token-controller-mfa-bootstrap",
      userId: "controller-mfa-bootstrap",
      rawToken: "raw-controller-mfa-bootstrap",
    });
    const controllerBootstrap = await routeRequest({
      method: "POST",
      route: "/auth/refresh",
      requestId: "request-controller-mfa-bootstrap",
      rawRefreshToken: "raw-controller-mfa-bootstrap",
    });
    assert.equal(controllerBootstrap.status, 200);
    assert.equal(controllerBootstrap.body.data.auth.sessionStage, "MFA_BOOTSTRAP");
    assert.match(controllerBootstrap.setCookie, /aq_access=/);
    assert.match(controllerBootstrap.setCookie, /aq_csrf=/);
    assert.match(controllerBootstrap.setCookie, /aq_refresh=/);
    const [{ bootstrapRevoked, challengeCount, challengeAudits, revokeAudits }] = await admin.$queryRaw`
      SELECT
        (SELECT revoked_reason FROM b01_refresh_wave.refresh_token
         WHERE id='token-controller-mfa-bootstrap') AS "bootstrapRevoked",
        (SELECT count(*)::int FROM b01_refresh_wave.mfa_challenge
         WHERE user_id='controller-mfa-bootstrap') AS "challengeCount",
        (SELECT count(*)::int FROM b01_refresh_wave.audit_outbox
         WHERE user_id='controller-mfa-bootstrap' AND action='AUTH_REFRESH_MFA_CHALLENGE_REQUIRED') AS "challengeAudits",
        (SELECT count(*)::int FROM b01_refresh_wave.audit_outbox
         WHERE user_id='controller-mfa-bootstrap' AND action='AUTH_REFRESH_REVOKED') AS "revokeAudits"
    `;
    assert.equal(bootstrapRevoked, "MFA_REQUIRED_AFTER_POLICY_CHANGE");
    assert.equal(challengeCount, 1);
    assert.equal(challengeAudits, 1);
    assert.equal(revokeAudits, 1);

    const controllerDenied = await routeRequest({
      method: "POST",
      route: "/auth/refresh",
      requestId: "request-controller-denied",
      rawRefreshToken: "unknown-controller-token",
    });
    assert.equal(controllerDenied.status, 401);
    assert.match(controllerDenied.setCookie, /aq_access=/);
    assert.match(controllerDenied.setCookie, /aq_csrf=/);
    assert.match(controllerDenied.setCookie, /aq_refresh=/);

    await seedActor({ id: "root-list", role: "LICENSEE_ADMIN", mfaEnabled: true });
    await seedToken({
      id: "root-list-current",
      userId: "root-list",
      rawToken: "raw-root-list",
    });
    const listRoot = await routeRequest({
      method: "GET",
      route: "/auth/sessions",
      userId: "root-list",
      sessionId: "root-list-current",
      requestId: "00000000-0000-4000-8000-000000000101",
    });
    assert.equal(listRoot.status, 200);
    assert.equal(listRoot.body.data.items.length, 1);
    assert.equal(listRoot.body.data.items[0].current, true);

    await seedActor({ id: "root-revoke", role: "LICENSEE_ADMIN", mfaEnabled: true });
    await seedToken({
      id: "root-revoke-current",
      userId: "root-revoke",
      rawToken: "raw-root-revoke-current",
    });
    await seedToken({
      id: "root-revoke-target",
      userId: "root-revoke",
      rawToken: "raw-root-revoke-target",
    });
    const revokeRoot = await routeRequest({
      method: "POST",
      route: "/auth/sessions/root-revoke-target/revoke",
      userId: "root-revoke",
      sessionId: "root-revoke-current",
      requestId: "00000000-0000-4000-8000-000000000102",
    });
    assert.equal(revokeRoot.status, 200);
    assert.equal(revokeRoot.body.data.currentSessionRevoked, false);
    assert.equal(revokeRoot.setCookie, "");
    const [{ targetReason, currentActive, revokeOutbox }] = await admin.$queryRaw`
      SELECT
        (SELECT revoked_reason FROM b01_refresh_wave.refresh_token WHERE id='root-revoke-target') AS "targetReason",
        (SELECT revoked_at IS NULL FROM b01_refresh_wave.refresh_token WHERE id='root-revoke-current') AS "currentActive",
        (SELECT count(*)::int FROM b01_refresh_wave.app_audit_outbox
         WHERE request_id='00000000-0000-4000-8000-000000000102') AS "revokeOutbox"
    `;
    assert.equal(targetReason, "SESSION_REVOKED_BY_USER");
    assert.equal(currentActive, true);
    assert.equal(revokeOutbox, 1);

    await seedActor({ id: "root-logout", role: "LICENSEE_ADMIN", mfaEnabled: true });
    await seedToken({
      id: "root-logout-current",
      userId: "root-logout",
      rawToken: "raw-root-logout",
    });
    const logoutRoot = await routeRequest({
      method: "POST",
      route: "/auth/logout",
      userId: "root-logout",
      sessionId: "root-logout-current",
      requestId: "00000000-0000-4000-8000-000000000103",
    });
    assert.equal(logoutRoot.status, 200);
    assert.equal(logoutRoot.body.data.loggedOut, true);
    assert.match(logoutRoot.setCookie, /aq_access=/);
    assert.match(logoutRoot.setCookie, /aq_csrf=/);
    assert.match(logoutRoot.setCookie, /aq_refresh=/);
    const [{ logoutReason, logoutOutbox }] = await admin.$queryRaw`
      SELECT
        (SELECT revoked_reason FROM b01_refresh_wave.refresh_token WHERE id='root-logout-current') AS "logoutReason",
        (SELECT count(*)::int FROM b01_refresh_wave.app_audit_outbox
         WHERE request_id='00000000-0000-4000-8000-000000000103') AS "logoutOutbox"
    `;
    assert.equal(logoutReason, "LOGOUT");
    assert.equal(logoutOutbox, 1);

    await seedActor({ id: "root-revoke-all", role: "LICENSEE_ADMIN", mfaEnabled: true });
    await seedToken({
      id: "root-revoke-all-current",
      userId: "root-revoke-all",
      rawToken: "raw-root-revoke-all-current",
    });
    await seedToken({
      id: "root-revoke-all-other",
      userId: "root-revoke-all",
      rawToken: "raw-root-revoke-all-other",
    });
    const revokeAllRoot = await routeRequest({
      method: "POST",
      route: "/auth/sessions/revoke-all",
      userId: "root-revoke-all",
      sessionId: "root-revoke-all-current",
      requestId: "00000000-0000-4000-8000-000000000104",
    });
    assert.equal(revokeAllRoot.status, 200);
    assert.equal(revokeAllRoot.body.data.revokedCount, 2);
    const [{ activeAfterRevokeAll, revokeAllOutbox }] = await admin.$queryRaw`
      SELECT
        count(*) FILTER (WHERE revoked_at IS NULL)::int AS "activeAfterRevokeAll",
        (SELECT count(*)::int FROM b01_refresh_wave.app_audit_outbox
         WHERE request_id='00000000-0000-4000-8000-000000000104') AS "revokeAllOutbox"
      FROM b01_refresh_wave.refresh_token WHERE user_id='root-revoke-all'
    `;
    assert.equal(activeAfterRevokeAll, 0);
    assert.equal(revokeAllOutbox, 1);

    for (const denied of [
      { userId: "root-disabled", active: false, membershipActive: true, expiresAt: later, requestId: "00000000-0000-4000-8000-000000000105" },
      { userId: "root-stale", active: true, membershipActive: false, expiresAt: later, requestId: "00000000-0000-4000-8000-000000000106" },
      { userId: "root-expired", active: true, membershipActive: true, expiresAt: new Date(now.getTime() - 1), requestId: "00000000-0000-4000-8000-000000000107" },
    ]) {
      await seedActor({
        id: denied.userId,
        active: denied.active,
        membershipActive: denied.membershipActive,
        role: "LICENSEE_ADMIN",
        mfaEnabled: true,
      });
      const sessionId = `${denied.userId}-current`;
      await seedToken({
        id: sessionId,
        userId: denied.userId,
        rawToken: `raw-${denied.userId}`,
        expiresAt: denied.expiresAt,
        mfaVerifiedAt: now,
      });
      const deniedRoot = await routeRequest({
        method: "GET",
        route: "/auth/sessions",
        userId: denied.userId,
        sessionId,
        requestId: denied.requestId,
      });
      assert.equal(deniedRoot.status, 401);
    }

    assert.deepEqual(await rotate("unknown-token", "request-unknown"), { ok: false, reason: "INVALID" });
    await reject(() => rotate("", "request-blank"), /requires 1\.\.3 token hashes/);
    await reject(
      () => preauth.$transaction((tx) => claimRefreshTokenRotation(tx, {
        tokenHashCandidates: ["malformed"],
        checkedAt: now,
        requestId: "request-malformed",
      })),
      /malformed token hash/
    );

    await seedActor({ id: "actor-expired" });
    await seedToken({ id: "token-expired", userId: "actor-expired", rawToken: "raw-expired", expiresAt: new Date(now.getTime() - 1) });
    assert.deepEqual(await rotate("raw-expired", "request-expired"), {
      ok: false,
      reason: "EXPIRED",
      userId: "actor-expired",
    });

    await seedActor({ id: "actor-revoked" });
    await seedToken({ id: "token-revoked", userId: "actor-revoked", rawToken: "raw-revoked", revokedAt: new Date(now.getTime() - 1) });
    assert.deepEqual(await rotate("raw-revoked", "request-revoked"), {
      ok: false,
      reason: "REVOKED",
      userId: "actor-revoked",
    });

    await seedActor({ id: "actor-disabled", active: false });
    await seedToken({ id: "token-disabled", userId: "actor-disabled", rawToken: "raw-disabled" });
    assert.deepEqual(await rotate("raw-disabled", "request-disabled"), {
      ok: false,
      reason: "REVOKED",
      userId: "actor-disabled",
    });

    await seedActor({ id: "actor-stale", membershipActive: false });
    await seedToken({ id: "token-stale", userId: "actor-stale", rawToken: "raw-stale" });
    assert.deepEqual(await rotate("raw-stale", "request-stale"), {
      ok: false,
      reason: "REVOKED",
      userId: "actor-stale",
    });

    await seedActor({ id: "licensee-stale", role: "LICENSEE_ADMIN", membershipActive: false });
    await seedToken({ id: "token-licensee-stale", userId: "licensee-stale", rawToken: "raw-licensee-stale" });
    assert.deepEqual(await rotate("raw-licensee-stale", "request-licensee-stale"), {
      ok: false,
      reason: "REVOKED",
      userId: "licensee-stale",
    });

    await seedActor({ id: "licensee-active", role: "LICENSEE_ADMIN", mfaEnabled: true });
    await seedToken({
      id: "token-licensee-active",
      userId: "licensee-active",
      rawToken: "raw-licensee-active",
      mfaVerifiedAt: now,
    });
    const licenseeRefresh = await rotate(
      "raw-licensee-active",
      "request-licensee-active",
      async ({ tx, token, tokenHashCandidates, now: checkedAt }) => {
        const state = await loadRefreshSessionState(tx, {
          tokenId: token.id,
          tokenHashCandidates,
          requestedLicenseeId: null,
          requestedScopeVersion: null,
          checkedAt,
          requestId: "request-licensee-active",
        });
        assert.equal(state.sessionLicenseeId, "licensee-active-licensee");
        assert.equal(state.sessionOrganizationId, "licensee-active-org");
        assert.equal(state.selectedLicenseeId, "licensee-active-licensee");
        assert.deepEqual(state.linkedLicensees, []);
        assert.equal(state.scopeVersion, null);
        return {
          action: "rotate",
          value: state.sessionLicenseeId,
          orgId: state.sessionOrganizationId,
          authenticatedAt: token.authenticatedAt || checkedAt,
          mfaVerifiedAt: token.mfaVerifiedAt,
        };
      }
    );
    assert.equal(licenseeRefresh.ok, true);
    assert.equal(licenseeRefresh.rotated, true);
    assert.equal(licenseeRefresh.value, "licensee-active-licensee");

    await seedActor({ id: "actor-scope" });
    await seedToken({ id: "token-scope", userId: "actor-scope", rawToken: "raw-scope" });
    await reject(
      () => rotate("raw-scope", "request-foreign-scope", ({ tx, token, tokenHashCandidates, now: checkedAt }) =>
        loadRefreshSessionState(tx, {
          tokenId: token.id,
          tokenHashCandidates,
          requestedLicenseeId: "foreign-licensee",
          requestedScopeVersion: scopeVersion,
          checkedAt,
          requestId: "request-foreign-scope",
        })
      ),
      /MANUFACTURER_SCOPE_DENIED/
    );
    await reject(
      () => rotate("raw-scope", "request-stale-scope", ({ tx, token, tokenHashCandidates, now: checkedAt }) =>
        loadRefreshSessionState(tx, {
          tokenId: token.id,
          tokenHashCandidates,
          requestedLicenseeId: "actor-scope-licensee",
          requestedScopeVersion: "2026-07-20T00:00:00.000Z",
          checkedAt,
          requestId: "request-stale-scope",
        })
      ),
      /MANUFACTURER_SCOPE_STALE/
    );
    const [{ scopeStillActive }] = await admin.$queryRaw`
      SELECT revoked_at IS NULL AS "scopeStillActive" FROM b01_refresh_wave.refresh_token WHERE id='token-scope'
    `;
    assert.equal(scopeStillActive, true, "denied scope selection must roll back the claim transaction");

    await seedActor({ id: "actor-bearer", mfaEnabled: true });
    const bearerHash = await seedToken({
      id: "token-bearer",
      userId: "actor-bearer",
      rawToken: "raw-bearer",
      mfaVerifiedAt: now,
    });
    await reject(
      () => preauth.$transaction(async (tx) => {
        const claim = await claimRefreshTokenRotation(tx, {
          tokenHashCandidates: [bearerHash],
          checkedAt: now,
          requestId: "request-bearer",
        });
        assert.equal(claim.disposition, "ACTIVE");
        await tx.$executeRaw`
          SELECT
            set_config('app.user_id','actor-bearer',true),
            set_config('app.role','SUPER_ADMIN',true),
            set_config('app.auth_assurance','step-up-verified',true),
            set_config('app.purpose','auth-refresh',true)
        `;
        return loadRefreshSessionState(tx, {
          tokenId: "token-bearer",
          tokenHashCandidates: ["f".repeat(64)],
          requestedLicenseeId: null,
          requestedScopeVersion: null,
          checkedAt: now,
          requestId: "request-bearer",
        });
      }),
      /B01_REFRESH_BEARER_DENIED/
    );

    await seedActor({ id: "actor-ambiguous" });
    await admin.$executeRaw`
      INSERT INTO b01_refresh_wave.refresh_token(
        id,user_id,organization_id,token_hash,expires_at,created_at,authenticated_at,last_used_at
      ) VALUES
        ('token-ambiguous-a','actor-ambiguous','actor-ambiguous-org',${"a".repeat(64)},${later},${now},${now},${now}),
        ('token-ambiguous-b','actor-ambiguous','actor-ambiguous-org',${"b".repeat(64)},${later},${now},${now},${now})
    `;
    await reject(
      () => preauth.$transaction((tx) => claimRefreshTokenRotation(tx, {
        tokenHashCandidates: ["a".repeat(64), "b".repeat(64)],
        checkedAt: now,
        requestId: "request-ambiguous",
      })),
      /B01_REFRESH_CLAIM_AMBIGUOUS/
    );

    await seedActor({ id: "actor-concurrent", mfaEnabled: true });
    await seedToken({
      id: "token-concurrent",
      userId: "actor-concurrent",
      rawToken: "raw-concurrent",
      mfaVerifiedAt: now,
    });
    let releaseWinner;
    let winnerClaimed;
    const winnerHold = new Promise((resolve) => { releaseWinner = resolve; });
    const winnerReady = new Promise((resolve) => { winnerClaimed = resolve; });
    const winningRotation = rotate(
      "raw-concurrent",
      "request-concurrent-a",
      async ({ token, now: checkedAt }) => {
        winnerClaimed();
        await winnerHold;
        return {
          action: "rotate",
          value: token.userId,
          orgId: token.orgId,
          authenticatedAt: token.authenticatedAt || checkedAt,
          mfaVerifiedAt: token.mfaVerifiedAt,
        };
      }
    );
    await winnerReady;
    const losingRotation = await rotate("raw-concurrent", "request-concurrent-b");
    releaseWinner();
    const concurrent = [await winningRotation, losingRotation];
    assert.equal(concurrent.filter((result) => result.ok && result.rotated).length, 1);
    assert.equal(concurrent.filter((result) => !result.ok && result.reason === "REVOKED").length, 1);
    const winner = concurrent.find((result) => result.ok && result.rotated);
    assert(winner);
    const winnerHash = hashRefreshToken(winner.newRawToken);
    const [{ activeAfterContention, lostAudits, plaintextPersisted }] = await admin.$queryRaw`
      SELECT
        count(*) FILTER (WHERE token.revoked_at IS NULL)::int AS "activeAfterContention",
        (SELECT count(*)::int FROM b01_refresh_wave.audit_outbox outbox
         WHERE outbox.action='AUTH_REFRESH_ROTATION_LOST' AND outbox.user_id='actor-concurrent') AS "lostAudits",
        bool_or(token.token_hash = ${winner.newRawToken}) AS "plaintextPersisted"
      FROM b01_refresh_wave.refresh_token token WHERE token.user_id='actor-concurrent'
    `;
    assert.equal(activeAfterContention, 1);
    assert.equal(lostAudits, 1);
    assert.equal(plaintextPersisted, false);
    const usableSuccessor = await preauth.$transaction((tx) => claimRefreshTokenRotation(tx, {
      tokenHashCandidates: [winnerHash],
      checkedAt: new Date(now.getTime() + 1),
      requestId: "request-successor-usable",
    }));
    assert.equal(usableSuccessor.disposition, "ACTIVE");
    assert.equal(usableSuccessor.tokenId, winner.newTokenId);

    assert.deepEqual(await rotate("raw-concurrent", "request-later-replay"), {
      ok: false,
      reason: "REUSE_DETECTED",
      userId: "actor-concurrent",
    });
    const [{ activeAfterReplay, reuseAudits }] = await admin.$queryRaw`
      SELECT
        count(*) FILTER (WHERE token.revoked_at IS NULL)::int AS "activeAfterReplay",
        (SELECT count(*)::int FROM b01_refresh_wave.audit_outbox outbox
         WHERE outbox.action='AUTH_REFRESH_REUSE_DETECTED' AND outbox.user_id='actor-concurrent') AS "reuseAudits"
      FROM b01_refresh_wave.refresh_token token WHERE token.user_id='actor-concurrent'
    `;
    assert.equal(activeAfterReplay, 0);
    assert.equal(reuseAudits, 1);

    await seedActor({ id: "auth-user", role: "LICENSEE_ADMIN" });
    const authContext = (overrides = {}) => ({
      userId: "auth-user",
      role: "LICENSEE_ADMIN",
      organizationId: "auth-user-org",
      licenseeId: "auth-user-licensee",
      manufacturerId: null,
      authAssurance: "password-verified",
      requestId: "request-authenticated",
      purpose: "auth-password-login-session",
      ...overrides,
    });
    const created = await authenticated.$transaction(async (tx) => {
      await installCanonicalDbContext(tx, authContext());
      return createRefreshToken({
        userId: "auth-user",
        orgId: "auth-user-org",
        rawToken: "raw-authenticated",
        ipHash: "c".repeat(64),
        userAgent: "authenticated-proof",
        authenticatedAt: now,
        now,
      }, tx);
    });
    assert(created.row.id);
    const sessions = await authenticated.$transaction(async (tx) => {
      await installCanonicalDbContext(tx, authContext({ purpose: "auth-session-list" }));
      const found = await findRefreshTokenByRaw("raw-authenticated", tx);
      assert.equal(found.id, created.row.id);
      return listActiveRefreshTokensForUser("auth-user", tx, now);
    });
    assert.equal(sessions.length, 1);
    assert.equal(sessions[0].createdIpHash, "c".repeat(64));
    assert.equal(sessions[0].createdUserAgent, "authenticated-proof");

    await seedActor({ id: "recent-mfa-user", role: "LICENSEE_ADMIN", mfaEnabled: true });
    await seedToken({
      id: "recent-mfa-token",
      userId: "recent-mfa-user",
      rawToken: "recent-mfa-raw",
      mfaVerifiedAt: now,
    });
    const recentMfaContext = {
      userId: "recent-mfa-user",
      role: "LICENSEE_ADMIN",
      organizationId: "recent-mfa-user-org",
      licenseeId: "recent-mfa-user-licensee",
      manufacturerId: null,
      authAssurance: "mfa-verified",
      requestId: "request-recent-mfa",
      purpose: "auth-recent-admin-mfa",
    };
    const recentMfa = await authenticated.$transaction(async (tx) => {
      await installCanonicalDbContext(tx, recentMfaContext);
      return requireRecentMfaSession({ sessionId: "recent-mfa-token", checkedAt: now, maxAgeMinutes: 15 }, tx);
    });
    assert.equal(new Date(recentMfa.verifiedAt).getTime(), now.getTime());
    await admin.$executeRaw`UPDATE b01_refresh_wave.actor SET mfa_enabled=false WHERE id='recent-mfa-user'`;
    await reject(
      () => authenticated.$transaction(async (tx) => {
        await installCanonicalDbContext(tx, recentMfaContext);
        return requireRecentMfaSession({ sessionId: "recent-mfa-token", checkedAt: now, maxAgeMinutes: 15 }, tx);
      }),
      /invalid row count/
    );

    await reject(
      () => authenticated.$transaction(async (tx) => {
        await installCanonicalDbContext(tx, authContext({ role: "SUPER_ADMIN", purpose: "auth-session-list" }));
        return listActiveRefreshTokensForUser("auth-user", tx, now);
      }),
      /B01_AUTHENTICATED_ROLE_STALE/
    );
    await reject(
      () => authenticated.$transaction(async (tx) => {
        await installCanonicalDbContext(tx, authContext({ authAssurance: "none", purpose: "auth-session-list" }));
        return listActiveRefreshTokensForUser("auth-user", tx, now);
      }),
      /B01_AUTHENTICATED_CONTEXT_DENIED/
    );
    await reject(
      () => authenticated.$transaction(async (tx) => {
        await installCanonicalDbContext(tx, authContext({ purpose: "foreign-purpose" }));
        return listActiveRefreshTokensForUser("auth-user", tx, now);
      }),
      /B01_AUTHENTICATED_CONTEXT_DENIED/
    );
    await reject(
      () => authenticated.$transaction(async (tx) => {
        await installCanonicalDbContext(tx, authContext({ purpose: "auth-session-list" }));
        return listActiveRefreshTokensForUser("actor-main", tx, now);
      }),
      /B01_AUTHENTICATED_CONTEXT_DENIED/
    );

    const revokedRaw = await authenticated.$transaction(async (tx) => {
      await installCanonicalDbContext(tx, authContext({ purpose: "auth-logout" }));
      return revokeRefreshTokenByRaw({ rawToken: "raw-authenticated", reason: "LOGOUT", now }, tx);
    });
    assert.equal(revokedRaw.revokedCount, 1);

    await seedActor({ id: "revoke-user", role: "LICENSEE_ADMIN" });
    for (const rawToken of ["raw-revoke-a", "raw-revoke-b"]) {
      await authenticated.$transaction(async (tx) => {
        await installCanonicalDbContext(tx, {
          ...authContext(), userId: "revoke-user", organizationId: "revoke-user-org",
          licenseeId: "revoke-user-licensee", requestId: `request-${rawToken}`,
        });
        await createRefreshToken({
          userId: "revoke-user", orgId: "revoke-user-org", rawToken, ipHash: null,
          userAgent: null, authenticatedAt: now, now,
        }, tx);
      });
    }
    const allRevoked = await authenticated.$transaction(async (tx) => {
      await installCanonicalDbContext(tx, {
        ...authContext({ purpose: "auth-session-revoke-all" }), userId: "revoke-user",
        organizationId: "revoke-user-org", licenseeId: "revoke-user-licensee",
      });
      return revokeAllUserRefreshTokens({
        userId: "revoke-user", reason: "ALL_SESSIONS_REVOKED_BY_USER", now,
      }, tx);
    });
    assert.equal(allRevoked.revokedCount, 2);

    await seedActor({ id: "policy-user", role: "LICENSEE_ADMIN" });
    const policyContext = (purpose, assurance = "mfa-verified") => ({
      ...authContext({ purpose, authAssurance: assurance }), userId: "policy-user",
      organizationId: "policy-user-org", licenseeId: "policy-user-licensee",
    });
    for (const [rawToken, mfaVerifiedAt] of [["raw-policy-password", null], ["raw-policy-mfa", now]]) {
      await authenticated.$transaction(async (tx) => {
        await installCanonicalDbContext(tx, policyContext("auth-password-login-session"));
        await createRefreshToken({
          userId: "policy-user", orgId: "policy-user-org", rawToken, ipHash: null,
          userAgent: null, authenticatedAt: now, mfaVerifiedAt, now,
        }, tx);
      });
    }
    const passwordOnly = await authenticated.$transaction(async (tx) => {
      await installCanonicalDbContext(tx, policyContext("auth-refresh-policy-change"));
      return revokePasswordOnlyRefreshTokensForUser({
        userId: "policy-user", reason: "MFA_REQUIRED_AFTER_POLICY_CHANGE", now,
      }, tx);
    });
    assert.equal(passwordOnly.revokedCount, 1);
    const byId = await authenticated.$transaction(async (tx) => {
      await installCanonicalDbContext(tx, policyContext("auth-session-revoke"));
      const remaining = await findRefreshTokenByRaw("raw-policy-mfa", tx);
      assert(remaining);
      return revokeRefreshTokenById({
        sessionId: remaining.id, userId: "policy-user", reason: "SESSION_REVOKED_BY_USER", now,
      }, tx);
    });
    assert.equal(byId, true);

    await reject(
      () => authenticated.$queryRawUnsafe("SELECT * FROM b01_refresh_wave.refresh_token"),
      /permission denied/
    );
    await reject(
      () => preauth.$queryRawUnsafe("SELECT * FROM b01_refresh_wave.refresh_token"),
      /permission denied/
    );
    await reject(
      () => authenticated.$queryRawUnsafe(
        "SELECT * FROM app_auth.claim_refresh_token_rotation(ARRAY['" + "d".repeat(64) + "']::text[],clock_timestamp()::timestamp,'wrong-identity')"
      ),
      /permission denied/
    );
    await reject(
      () => preauth.$queryRawUnsafe(
        "SELECT * FROM app_rls.list_active_refresh_tokens('actor-main',clock_timestamp()::timestamp)"
      ),
      /permission denied/
    );

    const rls = await admin.$queryRaw`
      SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_catalog.pg_class
      WHERE relnamespace='b01_refresh_wave'::regnamespace AND relkind='r' ORDER BY relname
    `;
    assert.equal(rls.length, 6);
    assert(rls.every((row) => row.relrowsecurity && row.relforcerowsecurity));
    const [{ policyCount }] = await admin.$queryRaw`
      SELECT count(*)::int AS "policyCount"
      FROM pg_catalog.pg_policies
      WHERE schemaname='b01_refresh_wave' AND roles=ARRAY['mscqr_dev_rls_function_owner']::name[]
    `;
    assert.equal(policyCount, 6);
    const [functionOwner] = await admin.$queryRaw`
      SELECT rolsuper AS "superuser",rolbypassrls AS "bypassRls",rolcanlogin AS "canLogin"
      FROM pg_catalog.pg_roles WHERE rolname='mscqr_dev_rls_function_owner'
    `;
    assert.deepEqual(functionOwner, { superuser: false, bypassRls: false, canLogin: false });
    const [{ ownedFunctionCount }] = await admin.$queryRaw`
      SELECT count(*)::int AS "ownedFunctionCount"
      FROM pg_catalog.pg_proc AS proc
      WHERE proc.oid = ANY (ARRAY[
        'b01_refresh_wave.require_refresh_bearer(text,text,text[],timestamp without time zone,text,text)'::regprocedure,
        'app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text)'::regprocedure,
        'app_auth.load_refresh_session_state(text,text[],text,text,timestamp without time zone,text)'::regprocedure,
        'app_auth.create_refresh_mfa_challenge(text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text)'::regprocedure,
        'app_auth.revoke_refresh_token_scope(text,text[],text,text,text,timestamp without time zone)'::regprocedure,
        'app_auth.complete_refresh_token_rotation(text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone)'::regprocedure,
        'app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text)'::regprocedure,
        'app_rls.require_recent_mfa_session(text,timestamp without time zone,integer)'::regprocedure,
        'b01_refresh_wave.require_authenticated_context(text,text[],text[])'::regprocedure,
        'app_rls.load_authenticated_actor()'::regprocedure,
        'app_rls.enqueue_audit_log_outbox(jsonb,text,text,text,text,text,text,text,text,timestamp without time zone,text)'::regprocedure,
        'app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone)'::regprocedure,
        'app_rls.find_refresh_token_by_hashes(text[])'::regprocedure,
        'app_rls.find_refresh_token_by_id(text,text)'::regprocedure,
        'app_rls.list_active_refresh_tokens(text,timestamp without time zone)'::regprocedure,
        'app_rls.revoke_refresh_token_by_hashes(text[],text,timestamp without time zone)'::regprocedure,
        'app_rls.revoke_all_refresh_tokens(text,text,timestamp without time zone)'::regprocedure,
        'app_rls.revoke_password_only_refresh_tokens(text,text,timestamp without time zone)'::regprocedure,
        'app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone)'::regprocedure
      ])
      AND pg_catalog.pg_get_userbyid(proc.proowner)='mscqr_dev_rls_function_owner'
    `;
    assert.equal(ownedFunctionCount, 19);
    const [functionOwnerPrivileges] = await admin.$queryRaw`
      SELECT
        has_table_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.actor','INSERT') AS "actorInsert",
        has_table_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.membership','UPDATE') AS "membershipUpdate",
        has_table_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.mfa_challenge','UPDATE') AS "challengeUpdate",
        has_table_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.audit_outbox','UPDATE') AS "auditUpdate",
        has_table_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.app_audit_outbox','UPDATE') AS "appAuditUpdate",
        has_column_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.actor','id','UPDATE') AS "actorLockColumn",
        has_column_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.actor','email','UPDATE') AS "actorEmailUpdate",
        has_column_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.membership','user_id','UPDATE') AS "membershipLockColumn",
        has_column_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.membership','organization_id','UPDATE') AS "membershipOrganizationUpdate",
        has_column_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.refresh_token','token_hash','SELECT') AS "tokenHashSelect",
        has_column_privilege('mscqr_dev_rls_function_owner','b01_refresh_wave.refresh_token','rotation_request_id','UPDATE') AS "rotationRequestUpdate"
    `;
    assert.deepEqual(functionOwnerPrivileges, {
      actorInsert: false,
      membershipUpdate: false,
      challengeUpdate: false,
      auditUpdate: false,
      appAuditUpdate: false,
      actorLockColumn: true,
      actorEmailUpdate: false,
      membershipLockColumn: true,
      membershipOrganizationUpdate: false,
      tokenHashSelect: true,
      rotationRequestUpdate: true,
    });
    const privilege = await admin.$queryRaw`
      SELECT
        has_function_privilege('public','app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text)','EXECUTE') AS "publicClaim",
        has_function_privilege('mscqr_dev_app','app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text)','EXECUTE') AS "authClaim",
        has_function_privilege('mscqr_dev_preauth','app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text)','EXECUTE') AS "preauthClaim",
        has_function_privilege('mscqr_dev_preauth','app_rls.list_active_refresh_tokens(text,timestamp without time zone)','EXECUTE') AS "preauthList",
        has_function_privilege('mscqr_dev_app','app_rls.list_active_refresh_tokens(text,timestamp without time zone)','EXECUTE') AS "appList",
        has_function_privilege('mscqr_dev_app','app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text)','EXECUTE') AS "appRevalidate",
        has_function_privilege('public','app_rls.require_recent_mfa_session(text,timestamp without time zone,integer)','EXECUTE') AS "publicRecentMfa",
        has_function_privilege('mscqr_dev_preauth','app_rls.require_recent_mfa_session(text,timestamp without time zone,integer)','EXECUTE') AS "preauthRecentMfa",
        has_function_privilege('mscqr_dev_app','app_rls.require_recent_mfa_session(text,timestamp without time zone,integer)','EXECUTE') AS "appRecentMfa",
        has_function_privilege('mscqr_dev_app','app_rls.load_authenticated_actor()','EXECUTE') AS "appLoadActor",
        has_function_privilege('mscqr_dev_app','app_rls.enqueue_audit_log_outbox(jsonb,text,text,text,text,text,text,text,text,timestamp without time zone,text)','EXECUTE') AS "appEnqueue"
    `;
    assert.deepEqual(privilege, [{
      publicClaim: false,
      authClaim: false,
      preauthClaim: true,
      preauthList: false,
      appList: true,
      appRevalidate: true,
      publicRecentMfa: false,
      preauthRecentMfa: false,
      appRecentMfa: true,
      appLoadActor: true,
      appEnqueue: true,
    }]);

    await authenticated.$transaction(async (tx) => {
      await installCanonicalDbContext(tx, authContext({ purpose: "auth-session-list" }));
      await listActiveRefreshTokensForUser("auth-user", tx, now);
    });
    const [{ leakedUser, leakedPurpose }] = await authenticated.$queryRaw`
      SELECT current_setting('app.user_id',true) AS "leakedUser",current_setting('app.purpose',true) AS "leakedPurpose"
    `;
    assert(!leakedUser && !leakedPurpose);

    console.log(JSON.stringify({
      valid: true,
      proofScope: "b01-local-function-contract",
      databaseName,
      postgresMajor: 18,
      rotationAtomic: true,
      concurrentSingleWinner: true,
      replayRevokesSuccessor: true,
      expiredRevokedDisabledStaleDenied: true,
      foreignAndStaleScopeDenied: true,
      authenticatedCreateListRevoke: true,
      wrongRoleAssurancePurposeForeignDenied: true,
      directTableAndWrongIdentityDenied: true,
      registeredHttpRootsExercised: 5,
      callerSetContextCannotReplaceBearer: true,
      mfaBootstrapConsumptionAtomic: true,
      nonBypassFunctionOwner: true,
      exactFunctionOwnerGrants: true,
      controllerAuditOutboxAtomic: true,
      forceRlsTables: rls.length,
    }));
  } finally {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await Promise.allSettled([admin.$disconnect(), authenticated.$disconnect(), preauth.$disconnect()]);
  }
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
