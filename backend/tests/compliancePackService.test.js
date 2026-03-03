const fs = require("fs");

const { UserRole } = require("@prisma/client");
const prisma = require("../dist/config/database").default;
const governanceService = require("../dist/services/governanceService");
const auditService = require("../dist/services/auditService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = async () => {
  const backupReport = governanceService.generateComplianceReport;
  const backupAudit = auditService.createAuditLog;
  const backupCreate = prisma.compliancePackJob.create;
  const backupUpdate = prisma.compliancePackJob.update;

  const envBackup = {
    QR_SIGN_PRIVATE_KEY: process.env.QR_SIGN_PRIVATE_KEY,
    QR_SIGN_HMAC_SECRET: process.env.QR_SIGN_HMAC_SECRET,
  };

  delete process.env.QR_SIGN_PRIVATE_KEY;
  process.env.QR_SIGN_HMAC_SECRET = "compliance-pack-test-secret";

  let createPayload = null;
  let updatePayload = null;

  governanceService.generateComplianceReport = async () => ({
    generatedAt: new Date().toISOString(),
    controls: [
      {
        controlId: "SOC2-CC6.1",
        framework: "SOC2",
        status: "PASS",
        evidenceRefs: ["incident.timeline", "audit.logs"],
      },
    ],
  });

  auditService.createAuditLog = async () => ({ id: "audit-1" });

  prisma.compliancePackJob.create = async ({ data }) => {
    createPayload = data;
    return {
      id: "job-1",
      ...data,
    };
  };

  prisma.compliancePackJob.update = async ({ data }) => {
    updatePayload = data;
    return {
      id: "job-1",
      ...data,
    };
  };

  const { buildSignedComplianceEvidencePack, runCompliancePackJob } = require("../dist/services/compliancePackService");

  try {
    const pack = await buildSignedComplianceEvidencePack({
      actor: { userId: "admin-1", role: UserRole.SUPER_ADMIN },
      licenseeId: "lic-1",
      from: new Date("2026-03-01T00:00:00.000Z"),
      to: new Date("2026-03-02T00:00:00.000Z"),
    });

    assert(Buffer.isBuffer(pack.buffer), "Compliance pack builder should return a zip buffer");
    assert(pack.buffer.subarray(0, 2).toString("utf8") === "PK", "Compliance pack should be a ZIP payload");
    assert(pack.metadata.controls === 1, "Compliance pack metadata should include mapped control count");

    const result = await runCompliancePackJob({
      triggerType: "MANUAL",
      actor: { userId: "admin-1", role: UserRole.SUPER_ADMIN },
      licenseeId: "lic-1",
      from: new Date("2026-03-01T00:00:00.000Z"),
      to: new Date("2026-03-02T00:00:00.000Z"),
    });

    assert(createPayload && createPayload.status === "RUNNING", "Job should be created in RUNNING state");
    assert(updatePayload && updatePayload.status === "COMPLETED", "Job should transition to COMPLETED state");
    assert(fs.existsSync(result.filePath), "Generated compliance pack file should be written to disk");

    fs.unlinkSync(result.filePath);

    console.log("compliance pack service tests passed");
  } finally {
    governanceService.generateComplianceReport = backupReport;
    auditService.createAuditLog = backupAudit;
    prisma.compliancePackJob.create = backupCreate;
    prisma.compliancePackJob.update = backupUpdate;

    process.env.QR_SIGN_PRIVATE_KEY = envBackup.QR_SIGN_PRIVATE_KEY;
    process.env.QR_SIGN_HMAC_SECRET = envBackup.QR_SIGN_HMAC_SECRET;
  }
};

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
