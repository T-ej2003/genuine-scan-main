import { runStrictOnboardingProbes } from "./production-strict-onboarding.mjs";
import { assertOnboardingPaths } from "./production-onboarding-contract.mjs";
import { readStageBPrivateFileBytes } from "../aws/stage-b-artifact-contract.mjs";

const REQUIRED_PATHS = Object.freeze(["tenantIsolation", "rbac", "auditPath", "printerTrust", "antiCloning", "artifactSigning", "publicQrVerification"]);
const trim = (value) => String(value || "").replace(/\/+$/, "");
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const QR_VERIFICATION_TOKEN_HEADER = "x-mscqr-verification-token";

function splitSetCookieHeader(value) {
  return String(value || "").split(/,(?=\s*[^=;,\s]+=)/).map((part) => part.trim()).filter(Boolean);
}

const readRotationQrFixture = (fixtureFile, expectedSha256) => {
  if (typeof fixtureFile !== "string" || !fixtureFile || !/^[a-f0-9]{64}$/.test(expectedSha256 || "")) throw new Error("Hash-bound rotation QR fixture is required for public verification probes.");
  let fixture;
  try {
    const captured = readStageBPrivateFileBytes({ filePath: fixtureFile, repositoryRoot: process.cwd(), label: "Rotation QR fixture" });
    if (captured.sha256 !== expectedSha256) throw new Error("changed");
    fixture = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
  } catch { throw new Error("Rotation QR fixture is unavailable, changed, or malformed."); }
  if (typeof fixture?.token !== "string" || !fixture.token.trim()) throw new Error("Rotation QR fixture token is missing.");
  const historicalContinuity = fixture.historicalContinuity === undefined ? "VERIFIED_PREVIOUS_QR" : fixture.historicalContinuity;
  if (!["VERIFIED_PREVIOUS_QR", "LEGACY_QR_KEYPAIR_UNRECOVERABLE"].includes(historicalContinuity)) throw new Error("Rotation QR fixture historical continuity is invalid.");
  return { token: fixture.token.trim(), historicalContinuity };
};

const tamperToken = (token) => `${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`;

const resolveQrProbePath = (template) => {
  if (typeof template !== "string" || !template.endsWith("/:code")) throw new Error("QR onboarding probe must use the reviewed /api/verify/:code route.");
  return template.replace(/:code$/, "ROTATION-SYNTHETIC");
};

export function parseSetCookieHeaders(values) {
  const lines = (Array.isArray(values) ? values : splitSetCookieHeader(values)).flatMap((value) => splitSetCookieHeader(value));
  return lines.map((line) => {
    const [pair, ...attributes] = line.split(";");
    const index = pair.indexOf("=");
    if (index <= 0) return null;
    return { name: pair.slice(0, index).trim(), value: pair.slice(index + 1).trim(), attributes: attributes.map((attribute) => attribute.trim().toLowerCase()) };
  }).filter(Boolean);
}

export function createCookieAuthenticatedRequest({ baseUrl, fetchImpl = fetch } = {}) {
  if (!/^https:\/\//.test(String(baseUrl || "")) || typeof fetchImpl !== "function") throw new Error("Cookie-authenticated request transport is invalid.");
  const cookieJar = new Map();
  const request = async (path, { method = "GET", body, headers: extraHeaders = {} } = {}) => {
    const normalizedMethod = String(method).toUpperCase();
    const headers = { Accept: "application/json", ...extraHeaders };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (cookieJar.size) headers.Cookie = [...cookieJar].map(([name, value]) => `${name}=${value}`).join("; ");
    if (UNSAFE_METHODS.has(normalizedMethod) && cookieJar.has("aq_csrf")) headers["x-csrf-token"] = cookieJar.get("aq_csrf");
    const response = await fetchImpl(`${trim(baseUrl)}${path}`, { method: normalizedMethod, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const setCookieHeaders = typeof response.headers?.getSetCookie === "function" ? response.headers.getSetCookie() : response.headers?.get("set-cookie");
    for (const { name, value, attributes } of parseSetCookieHeaders(setCookieHeaders)) {
      if (attributes.includes("max-age=0")) cookieJar.delete(name);
      else cookieJar.set(name, value);
    }
    let payload = null;
    try { payload = await response.json(); } catch { payload = null; }
    return { response, payload };
  };
  return { request, cookieJar };
}

export function createStrictHttpOnboardingAdapter({ baseUrl, paths, credentials, getMfaCode, tenantCredentials, getTenantMfaCode, runtimeReadback, ecsExecEvidence, rotationStateReadback, rotationFixtureFile, fetchImpl = fetch } = {}) {
  if (!/^https:\/\//.test(String(baseUrl || ""))) throw new Error("Strict onboarding base URL must use HTTPS.");
  const reviewedPaths = assertOnboardingPaths(paths);
  if (REQUIRED_PATHS.some((name) => typeof reviewedPaths[name] !== "string" || !reviewedPaths[name])) throw new Error("Strict onboarding endpoint map is incomplete.");
  if (typeof runtimeReadback !== "function" || typeof ecsExecEvidence !== "function" || typeof rotationStateReadback !== "function") throw new Error("Strict onboarding runtime evidence adapters are required.");
  const { request } = createCookieAuthenticatedRequest({ baseUrl, fetchImpl });
  let tenantRequest;
  let tenantAuthenticated = false;
  let mfaCompleted = false;
  let runtimeProof;
  const proofCheck = async (name) => {
    if (!runtimeProof) {
      const evidence = await ecsExecEvidence({});
      if (evidence?.valid !== true || !evidence.proof || typeof evidence.proof !== "object") return false;
      runtimeProof = evidence.proof;
    }
    return runtimeProof[name] === true;
  };
  const ok = async (path, options) => { const { response } = await request(path, options); return response.status >= 200 && response.status < 300; };
  const login = async ({ request: sessionRequest, sessionCredentials, sessionMfaCode, requireTenantScope = false }) => {
    const result = await sessionRequest("/api/auth/login", { method: "POST", body: { email: sessionCredentials?.email, password: sessionCredentials?.password } });
    if (!result.response.ok) return false;
    const auth = result.payload?.data?.auth;
    if (requireTenantScope) {
      const user = result.payload?.data?.user;
      const targetId = reviewedPaths.tenantIsolation.match(/^\/api\/licensees\/([a-f0-9-]+)$/i)?.[1];
      if (user?.role !== "LICENSEE_ADMIN" || typeof user.licenseeId !== "string" || !user.licenseeId || user.licenseeId === targetId) return false;
    }
    if (auth?.sessionStage === "MFA_BOOTSTRAP") {
      const mfaCode = typeof sessionMfaCode === "function" ? await sessionMfaCode() : undefined;
      if (!/^[0-9]{6,8}$/.test(String(mfaCode || ""))) return false;
      const begun = await sessionRequest("/api/auth/mfa/challenge/begin", { method: "POST", body: {} });
      if (!begun.response.ok || typeof begun.payload?.data?.ticket !== "string") return false;
      const completed = await sessionRequest("/api/auth/mfa/challenge/complete", { method: "POST", body: { ticket: begun.payload.data.ticket, code: mfaCode } });
      return completed.response.ok;
    }
    return auth?.mfaVerified === true;
  };
  return async ({ sourceSha, imageDigest, taskDefinitionArn, taskArn, rotationId, rotationStateSha256, rotationFixtureSha256 }) => {
    const rotationQrFixture = readRotationQrFixture(rotationFixtureFile, rotationFixtureSha256);
    const rotationQrToken = rotationQrFixture.token;
    return runStrictOnboardingProbes({
    expected: { sourceSha, imageDigest, taskDefinitionArn, taskArn, rotationId, rotationStateSha256 },
    probes: {
      deployedReleaseSha: async () => { const { response, payload } = await request("/version"); return response.ok && (payload?.releaseGitSha === sourceSha || payload?.gitSha === sourceSha); },
      deployedImageDigest: async () => (await runtimeReadback({ sourceSha, imageDigest, taskDefinitionArn, taskArn })).imageDigest === imageDigest,
      serviceStable: async () => (await runtimeReadback({ sourceSha, imageDigest, taskDefinitionArn, taskArn })).serviceStable === true,
      taskDefinition: async () => (await runtimeReadback({ sourceSha, imageDigest, taskDefinitionArn, taskArn })).taskDefinitionArn === taskDefinitionArn,
      taskMarker: async () => (await runtimeReadback({ sourceSha, imageDigest, taskDefinitionArn, taskArn })).taskMarker === true,
      ecsExecProof: async () => { const evidence = await ecsExecEvidence({ sourceSha, taskDefinitionArn, taskArn }); runtimeProof = evidence?.proof; return evidence?.valid === true && runtimeProof && typeof runtimeProof === "object"; },
      health: async () => { const { payload } = await request("/api/health/ready"); return payload?.status === "ready" || payload?.status === "ok"; },
      databaseReady: async () => { const { payload } = await request("/api/health/ready"); return payload?.dependencies?.database?.ready === true; },
      redisReady: async () => { const { payload } = await request("/api/health/ready"); return payload?.dependencies?.redis?.ready === true; },
      objectStorageReady: async () => { const { payload } = await request("/api/health/ready"); return payload?.dependencies?.objectStorage?.ready === true; },
      superAdminLogin: async () => {
        mfaCompleted = await login({ request, sessionCredentials: credentials, sessionMfaCode: getMfaCode });
        return mfaCompleted;
      },
      mfa: async () => mfaCompleted === true,
      authMe: async () => ok("/api/auth/me"),
      refresh: async () => ok("/api/auth/refresh", { method: "POST", body: {} }),
      dashboardStats: async () => ok("/api/dashboard/stats"),
      qrStats: async () => ok("/api/qr/stats"),
      publicQrVerification: async () => ok(resolveQrProbePath(reviewedPaths.publicQrVerification), { headers: { [QR_VERIFICATION_TOKEN_HEADER]: rotationQrToken } }),
      artifactSigning: async () => ok(reviewedPaths.artifactSigning),
      tenantIsolation: async () => {
        if (!tenantRequest) tenantRequest = createCookieAuthenticatedRequest({ baseUrl, fetchImpl }).request;
        tenantAuthenticated = await login({ request: tenantRequest, sessionCredentials: tenantCredentials, sessionMfaCode: getTenantMfaCode, requireTenantScope: true });
        if (!tenantAuthenticated) return false;
        const { response } = await tenantRequest(reviewedPaths.tenantIsolation);
        return [403, 404].includes(response.status);
      },
      rbac: async () => { const { response } = await request(reviewedPaths.rbac); return [403, 404].includes(response.status); },
      auditPath: async () => ok(reviewedPaths.auditPath),
      printerTrust: async () => ok(reviewedPaths.printerTrust),
      antiCloning: async () => { const { response } = await request(resolveQrProbePath(reviewedPaths.antiCloning), { headers: { [QR_VERIFICATION_TOKEN_HEADER]: tamperToken(rotationQrToken) } }); return [400, 401, 403, 409, 422].includes(response.status); },
      jwtCurrentRuntimeVerify: async () => proofCheck("jwtCurrentRuntimeVerify"),
      jwtPreviousRuntimeVerify: async () => proofCheck("jwtPreviousRuntimeVerify"),
      jwtInvalidRuntimeRejected: async () => proofCheck("jwtInvalidRuntimeRejected"),
      qrCurrentRuntimeVerify: async () => proofCheck("qrCurrentRuntimeVerify"),
      qrPreviousRuntimeVerify: async () => proofCheck("qrPreviousRuntimeVerify"),
      legacyQrKeypairUnrecoverable: async () => proofCheck("legacyQrKeypairUnrecoverable") && runtimeProof?.historicalContinuity === rotationQrFixture.historicalContinuity,
      qrTamperMatchingKeyTest: async () => proofCheck("qrTamperMatchingKeyTest"),
      qrUnknownKeyRejected: async () => proofCheck("qrUnknownKeyRejected"),
      artifactCurrentRuntimeVerify: async () => proofCheck("artifactCurrentRuntimeVerify"),
      artifactHistoricalRuntimeVerify: async () => proofCheck("artifactHistoricalRuntimeVerify"),
      rotationState: async () => {
        const readback = await rotationStateReadback({ rotationId });
        return readback?.sha256 === rotationStateSha256 && readback.state?.rotationId === rotationId && readback.state?.phase === "overlap-deploy-required";
      },
    },
    });
  };
}
