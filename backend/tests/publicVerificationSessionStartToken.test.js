const assert = require("assert");
const path = require("path");

const distRoot = path.resolve(__dirname, "../dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

let evidence = {
  id: "evidence-1",
  verificationDecisionId: "decision-1",
  metadata: {
    presentationSnapshot: { code: "MSC0001" },
  },
};

mockModule("config/database.js", {
  __esModule: true,
  default: {
    verificationDecision: {},
    verificationEvidenceSnapshot: {
      findFirst: async (args) => {
        const expectedHash = args?.where?.metadata?.equals;
        if (expectedHash && evidence.metadata?.publicSessionStart?.tokenHash !== expectedHash) return null;
        return evidence;
      },
      update: async ({ data }) => {
        evidence = {
          ...evidence,
          ...data,
        };
        return evidence;
      },
    },
  },
});

mockModule("observability/verificationTrustMetrics.js", {
  recordVerificationTrustMetric: () => undefined,
});

mockModule("utils/security.js", {
  hashToken: (value) => `hash:${value}`,
  buildTokenHashCandidates: (value) => [`hash:${value}`],
});

(async () => {
  const {
    issuePublicVerificationSessionStartToken,
    resolvePublicVerificationSessionStartToken,
  } = require("../dist/services/verificationDecisionService");

  const token = await issuePublicVerificationSessionStartToken("decision-1");
  assert.match(token, /^\d{40}$/);
  assert.strictEqual(evidence.metadata.publicSessionStart.tokenHash, `hash:${token}`);
  assert(!JSON.stringify(evidence).includes(token), "raw public session-start token must not be persisted");

  const decisionId = await resolvePublicVerificationSessionStartToken(token);
  assert.strictEqual(decisionId, "decision-1");

  const missing = await resolvePublicVerificationSessionStartToken("wrong-token");
  assert.strictEqual(missing, null);

  console.log("public verification session start token test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
