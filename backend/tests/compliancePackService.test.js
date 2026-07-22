const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { UserRole } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const filename = require.resolve(path.join(distRoot, relativePath));
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};

let startInput = null;
let completeInput = null;
class C03AccessError extends Error {
  constructor(message, statusCode = 403) {
    super(message);
    this.statusCode = statusCode;
  }
}
mockModule("rls-waves/session-c/c03/c03ActorBoundary.js", {
  C03AccessError,
  withC03ActorTransaction: async (boundary, callback) => callback({}, {
    ...boundary,
    userId: ids.actor,
    role: UserRole.PLATFORM_SUPER_ADMIN,
    organizationId: null,
    manufacturerId: null,
    authAssurance: "mfa-verified",
    sessionId: "00000000-0000-4000-8000-000000000901",
  }),
  withC03ResourceTransaction: async (boundary, callback) => callback({}, {
    ...boundary,
    userId: ids.actor,
    role: UserRole.PLATFORM_SUPER_ADMIN,
    organizationId: null,
    licenseeId: ids.licensee,
    manufacturerId: null,
    authAssurance: "mfa-verified",
    sessionId: "00000000-0000-4000-8000-000000000901",
  }),
});
mockModule("rls-waves/session-c/c03/c03CompliancePackRepository.js", {
  startCompliancePackJobInTransaction: async (_tx, _authority, input) => {
    startInput = input;
    return {
      job: {
        id: "00000000-0000-4000-8000-000000000401",
        licenseeId: "00000000-0000-4000-8000-000000000201",
      },
      report: {
        generatedAt: new Date().toISOString(),
        controls: [{ controlId: "SOC2-CC6.1", framework: "SOC2", status: "PASS", evidenceRefs: ["audit.logs"] }],
      },
    };
  },
  completeCompliancePackJobInTransaction: async (_tx, _authority, jobId, input) => {
    completeInput = input;
    return { id: jobId, status: "COMPLETED", ...input };
  },
  failCompliancePackJobInTransaction: async () => ({ status: "FAILED" }),
});

const { buildSignedComplianceEvidencePack, runCompliancePackJob } = require("../dist/services/compliancePackService");

const ids = {
  actor: "00000000-0000-4000-8000-000000000301",
  licensee: "00000000-0000-4000-8000-000000000201",
  request: "00000000-0000-4000-8000-000000000501",
};
const report = {
  generatedAt: new Date().toISOString(),
  controls: [{ controlId: "SOC2-CC6.1", framework: "SOC2", status: "PASS", evidenceRefs: ["incident.timeline"] }],
};

const run = async () => {
  const secret = process.env.QR_SIGN_HMAC_SECRET;
  delete process.env.QR_SIGN_PRIVATE_KEY;
  process.env.QR_SIGN_HMAC_SECRET = "compliance-pack-test-secret";
  let filePath = null;
  try {
    await assert.rejects(
      () => buildSignedComplianceEvidencePack({
        actor: { userId: ids.actor, role: UserRole.PLATFORM_SUPER_ADMIN },
        licenseeId: ids.licensee,
      }),
      /snapshot is required/
    );

    const pack = await buildSignedComplianceEvidencePack({
      actor: { userId: ids.actor, role: UserRole.PLATFORM_SUPER_ADMIN },
      licenseeId: ids.licensee,
      from: new Date("2026-03-01T00:00:00.000Z"),
      to: new Date("2026-03-02T00:00:00.000Z"),
      report,
    });
    assert(Buffer.isBuffer(pack.buffer));
    assert.equal(pack.buffer.subarray(0, 2).toString("utf8"), "PK");
    assert.equal(pack.metadata.controls, 1);

    const user = {
      userId: ids.actor,
      role: UserRole.PLATFORM_SUPER_ADMIN,
      orgId: null,
      licenseeId: null,
      sessionStage: "ACTIVE",
      authAssurance: "ADMIN_MFA",
      mfaVerifiedAt: new Date(),
    };
    const result = await runCompliancePackJob({
      triggerType: "MANUAL",
      actor: { userId: ids.actor, role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null },
      licenseeId: ids.licensee,
      from: new Date("2026-03-01T00:00:00.000Z"),
      to: new Date("2026-03-02T00:00:00.000Z"),
      securityContext: { databaseSessionCapability: "A".repeat(43), requestId: ids.request },
    });
    filePath = result.filePath;
    assert.equal(startInput.triggerType, "MANUAL");
    assert.equal(result.job.status, "COMPLETED");
    assert.equal(completeInput.integrityHash.length, 64);
    assert(filePath && fs.existsSync(filePath));
    console.log("compliance pack service tests passed");
  } finally {
    if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath);
    process.env.QR_SIGN_HMAC_SECRET = secret;
  }
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
