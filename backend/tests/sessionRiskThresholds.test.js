const assert = require("assert");
const path = require("path");
const { UserRole } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");
const savedTokenHashSecret = process.env.TOKEN_HASH_SECRET_CURRENT;
process.env.TOKEN_HASH_SECRET_CURRENT = savedTokenHashSecret || "session-risk-threshold-test-secret";
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
const savedCanonicalStepup = process.env.AUTH_RISK_STEP_UP_THRESHOLD;

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

const withEnvPair = async (canonical, legacy, action) => {
  const priorCanonical = process.env.AUTH_RISK_STEP_UP_THRESHOLD;
  const priorLegacy = process.env.AUTH_RISK_STEPUP_THRESHOLD;
  if (canonical === undefined) delete process.env.AUTH_RISK_STEP_UP_THRESHOLD;
  else process.env.AUTH_RISK_STEP_UP_THRESHOLD = canonical;
  if (legacy === undefined) delete process.env.AUTH_RISK_STEPUP_THRESHOLD;
  else process.env.AUTH_RISK_STEPUP_THRESHOLD = legacy;
  try { return await action(); } finally {
    if (priorCanonical === undefined) delete process.env.AUTH_RISK_STEP_UP_THRESHOLD;
    else process.env.AUTH_RISK_STEP_UP_THRESHOLD = priorCanonical;
    if (priorLegacy === undefined) delete process.env.AUTH_RISK_STEPUP_THRESHOLD;
    else process.env.AUTH_RISK_STEPUP_THRESHOLD = priorLegacy;
  }
};

const run = async () => {
  const fallback = await withEnvPair(undefined, undefined, () => withEnv("AUTH_RISK_BLOCK_THRESHOLD", undefined, assess));
  assert.equal(fallback.score, 18);
  assert.equal(fallback.shouldStepUp, false);
  assert.equal(fallback.shouldBlock, false);
  assert.equal((await withEnvPair("18", undefined, assess)).shouldStepUp, true);
  assert.equal((await withEnvPair(undefined, "18", assess)).shouldStepUp, true, "legacy key remains supported");
  assert.equal((await withEnvPair("18", "18", assess)).shouldStepUp, true);
  await assert.rejects(() => withEnvPair("55", "54", assess), /conflicts/);
  for (const value of ["", "invalid", "-1", "0.5", "101"]) {
    await assert.rejects(() => withEnvPair(value, undefined, assess), /must be an integer/);
    await assert.rejects(() => withEnv("AUTH_RISK_BLOCK_THRESHOLD", value, assess), /must be an integer/);
  }
  await assert.rejects(() => withEnvPair("85", undefined, assess), /must be lower/);

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

  riskInputs = { recentSessions: [{ createdAt: new Date(), createdIpHash: "same", createdUserAgent: "same-agent" }], actorState: {} };
  const low = await assess({ ipHash: "same", userAgent: "same-agent" });
  const newIp = await assess({ ipHash: "new", userAgent: "same-agent" });
  const newAgent = await assess({ ipHash: "same", userAgent: "new-agent" });
  const newDevice = await assess({ ipHash: "new", userAgent: "new-agent" });
  const failedAttempts = await assess({ ipHash: "same", userAgent: "same-agent", failedLoginAttempts: 5 });
  assert.deepEqual([low.score, newIp.score, newAgent.score, newDevice.score, failedAttempts.score], [10, 45, 30, 65, 35]);
  assert.equal(newDevice.shouldStepUp, true, "a normal new device must step up");
  assert.equal(newDevice.shouldBlock, false, "a normal new device must not hard block");
};

run().then(() => {
  if (savedBlock === undefined) delete process.env.AUTH_RISK_BLOCK_THRESHOLD;
  else process.env.AUTH_RISK_BLOCK_THRESHOLD = savedBlock;
  if (savedStepup === undefined) delete process.env.AUTH_RISK_STEPUP_THRESHOLD;
  else process.env.AUTH_RISK_STEPUP_THRESHOLD = savedStepup;
  if (savedCanonicalStepup === undefined) delete process.env.AUTH_RISK_STEP_UP_THRESHOLD;
  else process.env.AUTH_RISK_STEP_UP_THRESHOLD = savedCanonicalStepup;
  if (savedTokenHashSecret === undefined) delete process.env.TOKEN_HASH_SECRET_CURRENT;
  else process.env.TOKEN_HASH_SECRET_CURRENT = savedTokenHashSecret;
  console.log("session risk threshold tests passed");
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
