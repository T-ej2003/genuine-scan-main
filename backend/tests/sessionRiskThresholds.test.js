const assert = require("assert");
const path = require("path");
const { UserRole } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");
const repositoryPath = require.resolve(path.join(distRoot, "rls-waves/session-b/b01/authenticatedSecurityRepository.js"));
let riskInputs = { recentSessions: [], actorState: {} };
require.cache[repositoryPath] = {
  id: repositoryPath,
  filename: repositoryPath,
  loaded: true,
  exports: {
    loadRecentAuthSessionRiskInputs: async () => riskInputs,
    recordAuthSessionRiskSignal: async () => null,
  },
};

const { assessAuthSessionRisk } = require("../dist/services/auth/sessionRiskService");
const savedBlock = process.env.AUTH_RISK_BLOCK_THRESHOLD;
const savedStepup = process.env.AUTH_RISK_STEPUP_THRESHOLD;

const assess = async (overrides = {}) => assessAuthSessionRisk({
  userId: "admin-1",
  role: UserRole.SUPER_ADMIN,
  ipHash: null,
  userAgent: null,
  failedLoginAttempts: 0,
  ...overrides,
}, {});

const withEnv = async (key, value, action) => {
  const previous = process.env[key];
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
  try {
    return await action();
  } finally {
    if (previous === undefined) delete process.env[key];
    else process.env[key] = previous;
  }
};

const run = async () => {
  for (const value of [undefined, "", "   ", "invalid", "0", "-1", "0.5", "0.999"]) {
    const risk = await withEnv("AUTH_RISK_BLOCK_THRESHOLD", value, assess);
    assert.equal(risk.score, 18);
    assert.equal(risk.shouldBlock, false, `block threshold ${String(value)} must fall back to 85`);
  }

  assert.equal((await withEnv("AUTH_RISK_BLOCK_THRESHOLD", "1", assess)).shouldBlock, true);
  assert.equal((await withEnv("AUTH_RISK_BLOCK_THRESHOLD", "17", assess)).shouldBlock, true);
  assert.equal((await withEnv("AUTH_RISK_BLOCK_THRESHOLD", "85", assess)).shouldBlock, false);
  assert.equal((await withEnv("AUTH_RISK_BLOCK_THRESHOLD", "18.9", assess)).shouldBlock, true, "positive fractions above one retain floor normalization");

  for (const value of [undefined, "", "   ", "invalid", "0", "-1", "0.5", "0.999"]) {
    const risk = await withEnv("AUTH_RISK_STEPUP_THRESHOLD", value, assess);
    assert.equal(risk.shouldStepUp, false, `step-up threshold ${String(value)} must fall back to 55`);
  }
  assert.equal((await withEnv("AUTH_RISK_STEPUP_THRESHOLD", "1", assess)).shouldStepUp, true);
  assert.equal((await withEnv("AUTH_RISK_STEPUP_THRESHOLD", "18.9", assess)).shouldStepUp, true, "positive fractions above one retain floor normalization");

  riskInputs = {
    recentSessions: [
      { createdAt: new Date(), createdIpHash: "prior-ip", createdUserAgent: "prior-agent" },
      { createdAt: new Date(), createdIpHash: "ip-2", createdUserAgent: "prior-agent" },
      { createdAt: new Date(), createdIpHash: "ip-3", createdUserAgent: "prior-agent" },
    ],
    actorState: {},
  };
  const critical = await withEnv("AUTH_RISK_BLOCK_THRESHOLD", undefined, () => assess({
    ipHash: "new-ip",
    userAgent: "new-agent",
    failedLoginAttempts: 20,
  }));
  assert(critical.score >= 85);
  assert.equal(critical.shouldBlock, true, "scores at or above the fallback block threshold must still block");
};

run().then(() => {
  if (savedBlock === undefined) delete process.env.AUTH_RISK_BLOCK_THRESHOLD;
  else process.env.AUTH_RISK_BLOCK_THRESHOLD = savedBlock;
  if (savedStepup === undefined) delete process.env.AUTH_RISK_STEPUP_THRESHOLD;
  else process.env.AUTH_RISK_STEPUP_THRESHOLD = savedStepup;
  console.log("session risk threshold tests passed");
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
