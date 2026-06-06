const assert = require("assert");
const Module = require("module");

process.env.RELEASE_GIT_SHA = "abcdef1234567890abcdef1234567890abcdef12";
process.env.GITHUB_SHA = "github-sha-should-not-win";
process.env.COMMIT_SHA = "commit-sha-should-not-win";

const originalLoad = Module._load;
Module._load = function patchedLoad(request, parent, isMain) {
  if (request === "../config/database" || request.endsWith("/config/database")) {
    return { __esModule: true, default: { $queryRaw: async () => [{ "?column?": 1 }] } };
  }
  if (request === "../services/redisService" || request.endsWith("/services/redisService")) {
    return { getRedisHealth: async () => ({ configured: false, ready: true }) };
  }
  if (request === "../services/objectStorageService" || request.endsWith("/services/objectStorageService")) {
    return { getObjectStorageHealth: async () => ({ configured: false, ready: true }) };
  }
  if (request === "../services/qrTokenService" || request.endsWith("/services/qrTokenService")) {
    return { getQrSigningProfile: () => ({ mode: "test", provider: "env", keyVersion: "test", keyRef: null }) };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const { buildReadyPayload, liveHealthCheck } = require("../dist/controllers/healthController");

const createMockResponse = () => {
  const response = {
    statusCode: 200,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.payload = payload;
      return this;
    },
  };
  return response;
};

(async () => {
  const liveResponse = createMockResponse();
  liveHealthCheck({}, liveResponse);

  assert.strictEqual(liveResponse.statusCode, 200);
  assert.strictEqual(liveResponse.payload.release.gitSha, process.env.RELEASE_GIT_SHA);
  assert.strictEqual(liveResponse.payload.release.shortGitSha, "abcdef123456");

  const readyPayload = await buildReadyPayload();
  assert.strictEqual(readyPayload.release.gitSha, process.env.RELEASE_GIT_SHA);
  assert.strictEqual(readyPayload.release.shortGitSha, "abcdef123456");

  console.log("health release metadata tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
