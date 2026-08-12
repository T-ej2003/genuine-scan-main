import { runStrictOnboardingProbes } from "./production-strict-onboarding.mjs";

const REQUIRED_PATHS = Object.freeze(["tenantIsolation", "rbac", "auditPath", "printerTrust", "antiCloning", "artifactSigning", "publicQrVerification"]);
const trim = (value) => String(value || "").replace(/\/+$/, "");
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function splitSetCookieHeader(value) {
  return String(value || "").split(/,(?=\s*[^=;,\s]+=)/).map((part) => part.trim()).filter(Boolean);
}

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
  const request = async (path, { method = "GET", body } = {}) => {
    const normalizedMethod = String(method).toUpperCase();
    const headers = { Accept: "application/json" };
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

export function createStrictHttpOnboardingAdapter({ baseUrl, paths, credentials, getMfaCode, runtimeReadback, ecsExecEvidence, rotationStateReadback, fetchImpl = fetch } = {}) {
  if (!/^https:\/\//.test(String(baseUrl || ""))) throw new Error("Strict onboarding base URL must use HTTPS.");
  if (!paths || REQUIRED_PATHS.some((name) => typeof paths[name] !== "string" || !paths[name])) throw new Error("Strict onboarding endpoint map is incomplete.");
  if (typeof runtimeReadback !== "function" || typeof ecsExecEvidence !== "function" || typeof rotationStateReadback !== "function") throw new Error("Strict onboarding runtime evidence adapters are required.");
  const { request } = createCookieAuthenticatedRequest({ baseUrl, fetchImpl });
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
  return async ({ sourceSha, imageDigest, taskDefinitionArn, taskArn, rotationId }) => runStrictOnboardingProbes({
    expected: { sourceSha, imageDigest, taskDefinitionArn, taskArn, rotationId },
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
        const login = await request("/api/auth/login", { method: "POST", body: { email: credentials?.email, password: credentials?.password } });
        if (!login.response.ok) return false;
        const auth = login.payload?.data?.auth;
        if (auth?.sessionStage === "MFA_BOOTSTRAP") {
          const mfaCode = typeof getMfaCode === "function" ? getMfaCode() : undefined;
          if (!/^[0-9]{6,8}$/.test(String(mfaCode || ""))) return false;
          const begun = await request("/api/auth/mfa/challenge/begin", { method: "POST", body: {} });
          if (!begun.response.ok || typeof begun.payload?.data?.ticket !== "string") return false;
          const completed = await request("/api/auth/mfa/challenge/complete", { method: "POST", body: { ticket: begun.payload.data.ticket, code: mfaCode } });
          mfaCompleted = completed.response.ok;
          return mfaCompleted;
        }
        mfaCompleted = auth?.mfaVerified === true;
        return mfaCompleted;
      },
      mfa: async () => mfaCompleted === true,
      authMe: async () => ok("/api/auth/me"),
      refresh: async () => ok("/api/auth/refresh", { method: "POST", body: {} }),
      dashboardStats: async () => ok("/api/dashboard/stats"),
      qrStats: async () => ok("/api/qr/stats"),
      publicQrVerification: async () => ok(paths.publicQrVerification),
      artifactSigning: async () => ok(paths.artifactSigning),
      tenantIsolation: async () => { const { response } = await request(paths.tenantIsolation); return [403, 404].includes(response.status); },
      rbac: async () => { const { response } = await request(paths.rbac); return [403, 404].includes(response.status); },
      auditPath: async () => ok(paths.auditPath),
      printerTrust: async () => ok(paths.printerTrust),
      antiCloning: async () => { const { response } = await request(paths.antiCloning); return [400, 401, 403, 409, 422].includes(response.status); },
      jwtCurrentRuntimeVerify: async () => proofCheck("jwtCurrentRuntimeVerify"),
      jwtPreviousRuntimeVerify: async () => proofCheck("jwtPreviousRuntimeVerify"),
      jwtInvalidRuntimeRejected: async () => proofCheck("jwtInvalidRuntimeRejected"),
      qrCurrentRuntimeVerify: async () => proofCheck("qrCurrentRuntimeVerify"),
      qrPreviousRuntimeVerify: async () => proofCheck("qrPreviousRuntimeVerify"),
      qrTamperMatchingKeyTest: async () => proofCheck("qrTamperMatchingKeyTest"),
      qrUnknownKeyRejected: async () => proofCheck("qrUnknownKeyRejected"),
      artifactCurrentRuntimeVerify: async () => proofCheck("artifactCurrentRuntimeVerify"),
      artifactHistoricalRuntimeVerify: async () => proofCheck("artifactHistoricalRuntimeVerify"),
      rotationState: async () => {
        const state = await rotationStateReadback({ rotationId });
        return state?.rotationId === rotationId && state?.phase === "overlap-deploy-required";
      },
    },
  });
}
