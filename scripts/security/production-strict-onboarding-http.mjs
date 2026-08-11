import { runStrictOnboardingProbes } from "./production-strict-onboarding.mjs";

const REQUIRED_PATHS = Object.freeze(["tenantIsolation", "rbac", "auditPath", "printerTrust", "antiCloning", "artifactSigning", "publicQrVerification"]);
const trim = (value) => String(value || "").replace(/\/+$/, "");

export function createStrictHttpOnboardingAdapter({ baseUrl, paths, credentials, runtimeReadback, ecsExecEvidence, rotationStateReadback } = {}) {
  if (!/^https:\/\//.test(String(baseUrl || ""))) throw new Error("Strict onboarding base URL must use HTTPS.");
  if (!paths || REQUIRED_PATHS.some((name) => typeof paths[name] !== "string" || !paths[name])) throw new Error("Strict onboarding endpoint map is incomplete.");
  if (typeof runtimeReadback !== "function" || typeof ecsExecEvidence !== "function" || typeof rotationStateReadback !== "function") throw new Error("Strict onboarding runtime evidence adapters are required.");
  const cookieJar = new Map();
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
  const request = async (path, { method = "GET", body } = {}) => {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (cookieJar.size) headers.Cookie = [...cookieJar].map(([name, value]) => `${name}=${value}`).join("; ");
    const response = await fetch(`${trim(baseUrl)}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const setCookie = response.headers.get("set-cookie");
    if (setCookie) { const [pair] = setCookie.split(";"); const index = pair.indexOf("="); if (index > 0) cookieJar.set(pair.slice(0, index), pair.slice(index + 1)); }
    let payload = null;
    try { payload = await response.json(); } catch { payload = null; }
    return { response, payload };
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
          if (!/^[0-9]{6,8}$/.test(String(credentials?.mfaCode || ""))) return false;
          const begun = await request("/api/auth/mfa/challenge/begin", { method: "POST", body: {} });
          if (!begun.response.ok || typeof begun.payload?.data?.ticket !== "string") return false;
          const completed = await request("/api/auth/mfa/challenge/complete", { method: "POST", body: { ticket: begun.payload.data.ticket, code: credentials.mfaCode } });
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
